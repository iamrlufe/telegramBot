"""
shared/mssql_log.py

Чтение журналов MSSQL через WinRM: ERRORLOG (xp_readerrorlog), история джоб
SQL Agent и история копий из msdb.

Форму запросов диктуют три ограничения:
  * ERRORLOG на нагруженном сервере — десятки тысяч строк в сутки, поэтому
    период и TOP обязательны: без них запрос не укладывается в таймаут WinRM,
    а бот выглядит зависшим;
  * PowerShell-скрипт ограничен 8000 символов после кодирования
    (winrm_client.MAX_PS_COMMAND_CHARS) — T-SQL держим сжатым;
  * тексты SQL приходят на локали сервера, в том числе кириллицей — вывод
    гоняем через base64 (PS_OUT_B64_HELPER), иначе получаем «?????».

Разбор текста вынесен в чистые функции (parse_login_failure,
group_login_failures, decode_agent_datetime) — они покрыты тестами без сети.
"""
import re
from datetime import datetime, timedelta

from winrm_client import run_ps, ps_json, PS_OUT_B64_HELPER

# ERRORLOG обнуляется при рестарте SQL и по sp_cycle_errorlog. За сутки хватает
# текущего файла, за неделю — почти никогда, поэтому подключаем архивы.
ARCHIVE_FILES_24H = (0,)
ARCHIVE_FILES_LONG = (0, 1, 2, 3)
LONG_PERIOD_HOURS = 48

DEFAULT_LIMIT = 60


# ─── Расшифровка причин отказа входа ─────────────────────────

# Голый «State: 8» ничего не говорит дежурному, а именно он отличает перебор
# паролей от опечатки в строке подключения приложения.
LOGIN_STATE_REASONS = {
    "2": "логина не существует",
    "5": "логина не существует",
    "6": "Windows-логин пытается войти как SQL-логин",
    "7": "логин отключён или неверный пароль",
    "8": "неверный пароль",
    "9": "недопустимый пароль",
    "11": "Windows-логину не выдан доступ к SQL",
    "12": "Windows-логину не выдан доступ к SQL",
    "18": "требуется смена пароля",
    "38": "нет доступа к базе",
    "40": "не удалось открыть базу",
    "46": "база не найдена",
    "58": "SQL-логин при режиме «только Windows-аутентификация»",
}

# Локаль сервера бывает и русской: ищем оба варианта, кавычки тоже разные.
_RE_USER = re.compile(r"""for user '([^']*)'|пользовател\w*\s+["'«]([^"'»]+)["'»]""",
                      re.IGNORECASE)
_RE_CLIENT = re.compile(r"\[CLIENT:\s*([^\]]+)\]", re.IGNORECASE)
_RE_STATE = re.compile(r"State:\s*(\d+)|Состояние:\s*(\d+)", re.IGNORECASE)
_RE_DB = re.compile(
    r"""(?:database|баз\w+\s+данных)[,\s]*["'«\[]([^"'»\]]+)["'»\]]""",
    re.IGNORECASE)


def parse_login_failure(text: str) -> dict:
    """Разбирает строку ERRORLOG об отказе входа: кто, откуда, куда, почему."""
    text = (text or "").strip()

    m = _RE_USER.search(text)
    user = next((g for g in m.groups() if g), "") if m else ""

    m = _RE_CLIENT.search(text)
    client = m.group(1).strip() if m else ""
    # SQL пишет <local machine> для входа с самого сервера — оставляем как есть,
    # но без угловых скобок: в Telegram с parse_mode они ломают разметку.
    client = client.strip("<>")

    m = _RE_STATE.search(text)
    state = next((g for g in m.groups() if g), "") if m else ""

    m = _RE_DB.search(text)
    database = m.group(1) if m else ""

    reason = LOGIN_STATE_REASONS.get(state, "")
    if not reason:
        # Без state причина всё же бывает в самом тексте (Reason: ...).
        m = re.search(r"Reason:\s*([^.\[]+)", text, re.IGNORECASE)
        reason = m.group(1).strip() if m else ""

    return {
        "user": user,
        "client": client,
        "database": database,
        "state": state,
        "reason": reason,
        "text": text,
    }


_RE_ERROR_18456 = re.compile(r"Error:\s*18456.*State:\s*(\d+)", re.IGNORECASE)


def states_by_time(rows: list) -> dict:
    """Собирает State из служебных строк «Error: 18456 … State: N».

    SQL пишет отказ входа двумя строками с одной секундой: в первой код
    состояния, во второй логин, база и адрес. Отдельно взятая вторая строка
    причины не содержит — отсюда и «причина не указана» в первой версии.
    """
    found = {}
    for row in rows:
        m = _RE_ERROR_18456.search(row.get("t", "") or "")
        if m:
            found[row.get("d", "")] = m.group(1)
    return found


def group_login_failures(rows: list) -> list:
    """Схлопывает повторы по (логин, источник, база, причина).

    База обязана быть в ключе: один и тот же логин ломится в разные базы, и
    без неё серии склеивались бы в одну строку с чужим именем базы.
    Один сломанный сервис приложения даёт сотни одинаковых отказов в час,
    поэтому такая серия показывается одной строкой со счётчиком.
    Порядок — по времени последней попытки, свежие сверху.
    """
    states = states_by_time(rows)
    grouped = {}
    for row in rows:
        text = row.get("t", "") or ""
        # Служебная строка с кодом уже разобрана в states_by_time; сама по себе
        # она не несёт ни логина, ни базы и в списке была бы мусором.
        if _RE_ERROR_18456.search(text) and "failed" not in text.lower() \
                and "ошибка входа" not in text.lower():
            continue

        parsed = parse_login_failure(text)
        when = row.get("d", "")
        if not parsed["state"]:
            parsed["state"] = states.get(when, "")
            if parsed["state"] and not parsed["reason"]:
                parsed["reason"] = LOGIN_STATE_REASONS.get(parsed["state"], "")

        key = (parsed["user"], parsed["client"], parsed["database"], parsed["state"])
        item = grouped.get(key)
        if item is None:
            parsed["count"] = 1
            parsed["last"] = when
            parsed["first"] = when
            grouped[key] = parsed
        else:
            item["count"] += 1
            item["last"] = max(item["last"], when)
            item["first"] = min(item["first"], when)
    return sorted(grouped.values(), key=lambda i: i["last"], reverse=True)


def decode_agent_datetime(run_date: int, run_time: int) -> str:
    """msdb хранит дату и время джоба целыми: 20260827 и 31500 (03:15:00)."""
    try:
        run_date, run_time = int(run_date), int(run_time)
    except (TypeError, ValueError):
        return ""
    if not run_date:
        return ""
    s = f"{run_date:08d}"
    hh, mm, ss = run_time // 10000, (run_time // 100) % 100, run_time % 100
    return f"{s[:4]}-{s[4:6]}-{s[6:8]} {hh:02d}:{mm:02d}:{ss:02d}"


def decode_agent_duration(run_duration: int) -> str:
    """run_duration тоже целое HHMMSS: 132 — это 1 минута 32 секунды."""
    try:
        run_duration = int(run_duration)
    except (TypeError, ValueError):
        return ""
    hh, mm, ss = run_duration // 10000, (run_duration // 100) % 100, run_duration % 100
    if hh:
        return f"{hh} ч {mm} мин"
    if mm:
        return f"{mm} мин {ss} с"
    return f"{ss} с"


# ─── Понятные ошибки вместо трейсов ──────────────────────────

def friendly_sql_error(error: str) -> str:
    """Частые отказы SQL переводим в действие, а не в текст исключения."""
    text = str(error)
    low = text.lower()
    if "xp_readerrorlog" in low and ("denied" in low or "отказано" in low):
        return ("нет прав на чтение ERRORLOG — учётной записи мониторинга "
                "нужна роль securityadmin или sysadmin")
    if "sysjobhistory" in low or ("msdb" in low and "denied" in low):
        return ("нет прав на историю джоб — нужна роль SQLAgentReaderRole "
                "в базе msdb")
    if "invoke-sqlcmd" in low and "not recognized" in low:
        return ("на сервере нет командлета Invoke-Sqlcmd — поставьте модуль "
                "SqlServer (Install-Module SqlServer)")
    if "login failed" in low or "ошибка входа" in low:
        return "SQL отказал во входе учётной записи мониторинга"
    return text.splitlines()[0][:300] if text else "неизвестная ошибка"


# ─── Выполнение запроса ──────────────────────────────────────

def _run_sql(server: dict, tsql: str, columns: str,
             timeout_sec: int = 90) -> list:
    """Гоняет T-SQL через Invoke-Sqlcmd и возвращает список словарей.

    Колонки перечисляем явно: Invoke-Sqlcmd отдаёт DataRow, и `Select-Object *`
    утащил бы в JSON служебные свойства (Table, RowError, ItemArray) — ответ
    раздувается в разы и упирается в лимиты передачи.
    """
    script = PS_OUT_B64_HELPER + f"""
    $q = @'
{tsql}
'@
    $rows = Invoke-Sqlcmd -ServerInstance "localhost" -Query $q -QueryTimeout {timeout_sec} -ErrorAction Stop
    if ($null -eq $rows) {{ Out-B64 @() }} else {{ Out-B64 @($rows | Select-Object {columns}) }}
    """
    raw = run_ps(server["host"], script,
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=timeout_sec + 30,
                 read_timeout_sec=timeout_sec + 60)
    data = ps_json(raw) or []
    if isinstance(data, dict):
        data = [data]
    return data


def _since(hours: int) -> str:
    return (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def _errorlog_query(hours: int, where: str, limit: int) -> str:
    """xp_readerrorlog нельзя фильтровать напрямую — собираем в переменную.

    Встроенный фильтр командлета умеет только две подстроки, а нам нужен
    разбор по нескольким признакам, поэтому WHERE идёт уже по таблице.
    Архивные файлы читаем в TRY/CATCH: у сервера их может не быть,
    и тогда весь батч упал бы целиком.
    """
    since = _since(hours)
    files = ARCHIVE_FILES_LONG if hours > LONG_PERIOD_HOURS else ARCHIVE_FILES_24H
    inserts = "\n".join(
        f"BEGIN TRY INSERT INTO @log EXEC xp_readerrorlog {n}, 1, NULL, NULL, "
        f"'{since}', NULL, N'desc'; END TRY BEGIN CATCH END CATCH;"
        for n in files
    )
    return f"""SET NOCOUNT ON;
DECLARE @log TABLE (LogDate DATETIME, ProcessInfo NVARCHAR(64), LogText NVARCHAR(MAX));
{inserts}
SELECT TOP {limit} CONVERT(VARCHAR(19), LogDate, 120) AS d, LogText AS t
FROM @log WHERE {where}
ORDER BY LogDate DESC;"""


def read_login_errors(server: dict, hours: int = 24,
                      limit: int = DEFAULT_LIMIT) -> list:
    """Отказы входа: кто, с какого адреса, на какую базу и почему."""
    # Error: 18456 берём намеренно: в нём лежит State, без которого причина
    # отказа остаётся неизвестной. Склейка со строкой логина — по времени.
    where = ("(LogText LIKE '%Login failed%' OR LogText LIKE '%Ошибка входа%' "
             "OR LogText LIKE '%Cannot open database%' "
             "OR LogText LIKE '%открыть базу данных%' "
             "OR LogText LIKE '%Error: 18456%')")
    rows = _run_sql(server, _errorlog_query(hours, where, limit), "d,t")
    return group_login_failures(rows)


def read_backup_errors(server: dict, hours: int = 24,
                       limit: int = 30) -> dict:
    """Ошибки копирования: текст движка + упавшие шаги джоб.

    По отдельности они не отвечают на вопрос «почему»: ERRORLOG знает ошибку
    ОС и путь, история джоб — какой джоб и на каком шаге встал.
    """
    where = ("(LogText LIKE '%BACKUP failed%' OR LogText LIKE '%RESTORE failed%' "
             "OR LogText LIKE '%Ошибка BACKUP%' "
             "OR (LogText LIKE '%Operating system error%' AND LogText NOT LIKE '%Login%') "
             "OR LogText LIKE '%ошибка операционной системы%')")
    result = {"engine": [], "jobs": [], "errors": []}
    try:
        result["engine"] = _run_sql(server, _errorlog_query(hours, where, limit), "d,t")
    except Exception as e:
        result["errors"].append(f"ERRORLOG: {friendly_sql_error(e)}")
    try:
        result["jobs"] = read_agent_jobs(server, hours=hours, limit=limit,
                                         failed_only=True, backup_only=True)
    except Exception as e:
        result["errors"].append(f"Джобы: {friendly_sql_error(e)}")
    return result


def read_engine_errors(server: dict, hours: int = 24,
                       limit: int = DEFAULT_LIMIT) -> list:
    """Серьёзные ошибки движка: severity ≥ 17, повреждения, тормоза ввода-вывода.

    Штатный шум (успешные входы, рутинные сообщения о копиях) отфильтрован —
    иначе разделом никто не пользуется со второго раза.
    """
    where = ("(LogText LIKE '%Severity: 1[7-9]%' OR LogText LIKE '%Severity: 2%' "
             "OR LogText LIKE '%Error: 82[3-5]%' "
             "OR LogText LIKE '%taking longer than 15 seconds%' "
             "OR LogText LIKE '%deadlock%' OR LogText LIKE '%взаимоблокиров%') "
             "AND LogText NOT LIKE '%Login failed%' "
             "AND LogText NOT LIKE '%Ошибка входа%'")
    return _run_sql(server, _errorlog_query(hours, where, limit), "d,t")


def read_agent_jobs(server: dict, hours: int = 24, limit: int = 30,
                    failed_only: bool = False, backup_only: bool = False) -> list:
    """История запусков джоб SQL Agent.

    step_id = 0 — итоговая запись по джобу; для сводки берём именно её,
    а для разбора ошибки бэкапа — конкретные упавшие шаги.
    """
    since = _since(hours)
    conditions = [
        f"msdb.dbo.agent_datetime(h.run_date, h.run_time) > '{since}'",
    ]
    if failed_only:
        conditions.append("h.run_status = 0")
        conditions.append("h.step_id > 0")
    else:
        conditions.append("h.step_id = 0")
    if backup_only:
        conditions.append("(j.name LIKE '%backup%' OR j.name LIKE '%бэкап%' "
                          "OR j.name LIKE '%копи%' OR h.message LIKE '%BACKUP%')")
    where = " AND ".join(conditions)
    tsql = f"""SET NOCOUNT ON;
SELECT TOP {limit} j.name AS job, h.step_id AS step, h.step_name AS stepname,
       h.run_status AS status, h.run_date AS rundate, h.run_time AS runtime,
       h.run_duration AS duration, LEFT(h.message, 400) AS msg
FROM msdb.dbo.sysjobhistory h
JOIN msdb.dbo.sysjobs j ON j.job_id = h.job_id
WHERE {where}
ORDER BY h.instance_id DESC;"""
    rows = _run_sql(server, tsql,
                    "job,step,stepname,status,rundate,runtime,duration,msg")
    for row in rows:
        row["when"] = decode_agent_datetime(row.get("rundate"), row.get("runtime"))
        row["took"] = decode_agent_duration(row.get("duration"))
    return rows


def read_backup_history(server: dict, days: int = 7, limit: int = 30) -> list:
    """Что сам SQL считает сделанным: база, тип копии, время, размер, путь.

    Независимая сверка с файловым мониторингом: файл на диске есть, а записи
    в msdb нет — значит копию делал не SQL (например, снапшот гипервизора).
    """
    tsql = f"""SET NOCOUNT ON;
SELECT TOP {limit} bs.database_name AS db, bs.type AS btype,
       CONVERT(VARCHAR(19), bs.backup_finish_date, 120) AS finished,
       CAST(bs.backup_size / 1073741824.0 AS DECIMAL(10,2)) AS size_gb,
       LEFT(bmf.physical_device_name, 200) AS device
FROM msdb.dbo.backupset bs
JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
WHERE bs.backup_finish_date > DATEADD(day, -{days}, GETDATE())
ORDER BY bs.backup_finish_date DESC;"""
    return _run_sql(server, tsql, "db,btype,finished,size_gb,device")
