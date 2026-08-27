"""
shared/mssql_health.py

Состояние баз MSSQL: журналы транзакций, давность DBCC CHECKDB, что
происходит на сервере прямо сейчас, свободное место в файловых группах.

Отвечает на вопросы, которые обычно задают уже после аварии: почему LDF
разросся на десятки гигабайт, проверялась ли вообще целостность баз и
почему «всё встало».
"""
from mssql_log import run_query, friendly_sql_error   # noqa: F401  (реэкспорт)

# log_reuse_wait_desc — главное поле при разборе раздувшегося журнала:
# оно прямо говорит, что мешает его переиспользовать.
LOG_WAIT_REASONS = {
    "NOTHING": "ничего не мешает, журнал переиспользуется штатно",
    "CHECKPOINT": "ждёт контрольную точку — обычно проходит само",
    "LOG_BACKUP": "нужен бэкап журнала: модель Full или Bulk-logged без "
                  "регулярного BACKUP LOG. Самая частая причина роста LDF",
    "ACTIVE_BACKUP_OR_RESTORE": "идёт резервное копирование или восстановление",
    "ACTIVE_TRANSACTION": "открыта долгая транзакция — приложение не закрыло её",
    "DATABASE_MIRRORING": "отстаёт зеркало",
    "REPLICATION": "репликация не вычитала изменения",
    "DATABASE_SNAPSHOT_CREATION": "создаётся снимок базы",
    "LOG_SCAN": "идёт сканирование журнала",
    "AVAILABILITY_REPLICA": "отстаёт реплика Always On",
    "OLDEST_PAGE": "старая страница ещё не записана на диск",
    "XTP_CHECKPOINT": "контрольная точка In-Memory OLTP",
}


def explain_log_wait(value: str) -> str:
    return LOG_WAIT_REASONS.get((value or "").strip().upper(), "")


def read_log_files(server: dict, limit: int = 40) -> list:
    """Журналы транзакций: размер, модель восстановления, что мешает очистке.

    Размер журнала сам по себе ни о чём не говорит — важна пара
    «модель восстановления + log_reuse_wait_desc»: Full без BACKUP LOG
    растёт бесконечно, и это самая частая причина внезапно кончившегося
    места на диске.
    """
    tsql = f"""SET NOCOUNT ON;
SELECT TOP {limit} d.name AS db, d.recovery_model_desc AS model,
       d.log_reuse_wait_desc AS waitfor,
       CAST(SUM(CASE WHEN mf.type = 1 THEN mf.size ELSE 0 END) * 8.0 / 1048576.0 AS DECIMAL(10,2)) AS log_gb,
       CAST(SUM(CASE WHEN mf.type = 0 THEN mf.size ELSE 0 END) * 8.0 / 1048576.0 AS DECIMAL(10,2)) AS data_gb
FROM sys.databases d
JOIN sys.master_files mf ON mf.database_id = d.database_id
WHERE d.database_id > 4 AND d.state = 0
GROUP BY d.name, d.recovery_model_desc, d.log_reuse_wait_desc
ORDER BY SUM(CASE WHEN mf.type = 1 THEN mf.size ELSE 0 END) DESC;"""
    rows = run_query(server, tsql, "db,model,waitfor,log_gb,data_gb")
    for row in rows:
        row["why"] = explain_log_wait(row.get("waitfor"))
    return rows


def read_checkdb(server: dict, limit: int = 40) -> list:
    """Когда каждая база последний раз проходила DBCC CHECKDB.

    Дата лежит в служебном поле dbi_dbccLastKnownGood, достать её можно
    только через DBCC DBINFO по каждой базе — курсором. Пустая дата
    (1900-01-01) означает, что проверки не было ни разу с момента
    создания или переноса базы.
    """
    tsql = f"""SET NOCOUNT ON;
DECLARE @res TABLE (dbname sysname, lastgood datetime);
DECLARE @info TABLE (ParentObject varchar(255), Object varchar(255),
                     Field varchar(255), Value varchar(255));
DECLARE @n sysname, @sql nvarchar(500);
DECLARE dbs CURSOR LOCAL FAST_FORWARD FOR
  SELECT name FROM sys.databases WHERE state = 0 AND database_id > 4;
OPEN dbs;
FETCH NEXT FROM dbs INTO @n;
WHILE @@FETCH_STATUS = 0
BEGIN
  DELETE FROM @info;
  SET @sql = N'DBCC DBINFO(' + QUOTENAME(@n, '''') + ') WITH TABLERESULTS, NO_INFOMSGS';
  BEGIN TRY
    INSERT INTO @info EXEC (@sql);
    INSERT INTO @res SELECT @n, MAX(TRY_CONVERT(datetime, Value))
      FROM @info WHERE Field = 'dbi_dbccLastKnownGood';
  END TRY BEGIN CATCH END CATCH;
  FETCH NEXT FROM dbs INTO @n;
END
CLOSE dbs; DEALLOCATE dbs;
SELECT TOP {limit} dbname AS db, CONVERT(VARCHAR(19), lastgood, 120) AS lastgood,
       DATEDIFF(day, lastgood, GETDATE()) AS days
FROM @res ORDER BY lastgood;"""
    return run_query(server, tsql, "db,lastgood,days", timeout_sec=120)


def read_activity(server: dict, min_seconds: int = 5, limit: int = 20) -> list:
    """Что выполняется прямо сейчас: долгие запросы и кто кого блокирует.

    Для случая «1С встала, никто не понимает почему»: видно сессию-виновника
    (blocking_session_id), сколько она держит блокировку и из какой программы
    пришла.
    """
    tsql = f"""SET NOCOUNT ON;
SELECT TOP {limit} r.session_id AS spid, r.status AS state,
       r.blocking_session_id AS blocker, r.wait_type AS waittype,
       r.total_elapsed_time / 1000 AS sec, DB_NAME(r.database_id) AS db,
       s.login_name AS login, s.host_name AS hostname,
       LEFT(ISNULL(s.program_name, ''), 60) AS app,
       LEFT(ISNULL(t.text, ''), 200) AS sqltext
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE r.session_id <> @@SPID AND s.is_user_process = 1
  AND (r.total_elapsed_time >= {min_seconds * 1000} OR r.blocking_session_id <> 0)
ORDER BY r.total_elapsed_time DESC;"""
    return run_query(server, tsql,
                    "spid,state,blocker,waittype,sec,db,login,hostname,app,sqltext")


def read_file_space(server: dict, limit: int = 40) -> list:
    """Файлы БД и их потолок роста.

    Место на диске и возможность вырасти — разные вещи: файл с выключенным
    автоприростом или с достигнутым max_size встаёт, когда на диске ещё
    половина свободна. Ошибка при этом выглядит как «база не пишется».

    Берём sys.master_files, а не sp_MSforeachdb: процедура
    недокументированная, требует контекста каждой базы и на сервере с
    десятками баз выполняется долго.
    """
    tsql = f"""SET NOCOUNT ON;
SELECT TOP {limit} DB_NAME(mf.database_id) AS db, mf.name AS fname,
       mf.type_desc AS kind,
       CAST(mf.size * 8.0 / 1048576.0 AS DECIMAL(10,2)) AS size_gb,
       mf.max_size AS maxsize, mf.growth AS growth,
       mf.is_percent_growth AS is_percent
FROM sys.master_files mf
JOIN sys.databases d ON d.database_id = mf.database_id
WHERE d.database_id > 4 AND d.state = 0
ORDER BY mf.size DESC;"""
    rows = run_query(server, tsql,
                     "db,fname,kind,size_gb,maxsize,growth,is_percent")
    for row in rows:
        row["capped"] = _is_capped(row)
        row["limit_gb"] = _max_size_gb(row.get("maxsize"))
    return rows


def _max_size_gb(max_size):
    """max_size: -1 — без ограничения, 0 — расти нельзя, иначе страницы 8 КБ."""
    try:
        value = int(max_size)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return round(value * 8.0 / 1048576.0, 2)


def _is_capped(row) -> bool:
    """Файл не сможет вырасти: автоприрост выключен или задан жёсткий предел."""
    try:
        if int(row.get("growth") or 0) == 0:
            return True
    except (TypeError, ValueError):
        pass
    try:
        return int(row.get("maxsize")) == 0
    except (TypeError, ValueError):
        return False
