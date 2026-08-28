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
_RE_CLIENT = re.compile(r"\[(?:CLIENT|КЛИЕНТ):\s*([^\]]+)\]", re.IGNORECASE)
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
    # Угловые скобки ломают разметку Telegram, а «local machine» само по себе
    # не читается как ответ на вопрос «откуда» — переводим.
    client = client.strip("<>")
    if client.lower() in ("local machine", "локальный компьютер"):
        client = "локально, с самого сервера"

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


_RE_ERROR_18456 = re.compile(
    r"(?:Error|Ошибка):\s*18456.*?(?:State|состояние):\s*(\d+)", re.IGNORECASE)


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


# ─── Суть сообщения джоба ────────────────────────────────────

# Планы обслуживания (Maintenance Plan) выполняются через dtexec, и его
# вывод начинается с полустраничной шапки: «Executed as user … Microsoft (R)
# SQL Server Execute Package Utility … Started … Progress …». Настоящая
# ошибка идёт дальше, после Description, а иногда только в самом конце.
# Обрезка по первым N символам показывала ровно эту шапку и ничего больше.
_JOB_DESCRIPTION = re.compile(
    r"Description:\s*(.+?)(?=\s+(?:End|Started:|Source:|Progress:)|$)",
    re.IGNORECASE | re.DOTALL)

# Шапка и протокол выполнения dtexec целиком: баннер утилиты, время старта,
# строки Progress и Executing query. SQL Agent пишет в историю только первые
# ~1024 символа шага, и у длинных планов обслуживания в них не остаётся
# ничего кроме этой шапки — раньше она и уезжала в алерт как «причина».
_JOB_NOISE_PARTS = [
    r"Executed as user:\s*[^.]*\.",
    r"Microsoft \(R\)[^.]*?Utility",
    r"(?:Version\s+)?[\d.]{3,}\s+for\s+(?:32|64)-bit",
    r"Copyright \(C\)[^.]*\.",
    r"All rights reserved\.",
    r"Started:\s*[\d:.]+",
    r"(?:End\s+)?Progress:?\s*(?:\d{4}-\d{2}-\d{2}\s+[\d:.]+)?",
    r"Source:\s*\{[^}]*\}",
    r"Executing query\s*\"[^\"]*\"?",
    r":\s*\d+% complete",
]
_JOB_NOISE = re.compile("|".join(_JOB_NOISE_PARTS), re.IGNORECASE)

# Осмысленный остаток отличается от мусора наличием букв: точки, двоеточия
# и обрывки кавычек после вычистки шапки смысла не несут.
_JOB_MEANINGFUL = re.compile(r"[A-Za-zА-Яа-я]{3,}")

# Что сказать, когда в истории осталась одна шапка. Дежурному нужно знать,
# что причина существует, но лежит не здесь.
JOB_MESSAGE_TRUNCATED = (
    "SQL Agent сохранил только шапку dtexec — сама ошибка в историю не "
    "поместилась. Причину смотрите в журнале плана обслуживания "
    "(Management → Maintenance Plans → View History) или включите в шаге "
    "джоба «Include step output in history»"
)


# Причины, которые видно прямо в тексте шага. Дежурному нужно действие,
# а не код возврата dtexec.
BACKUP_ERROR_RULES = [
    (r"operating system error 3\b|cannot find the path specified|"
     r"не удается найти указанный путь|не удаётся найти указанный путь",
     "путь не найден: каталога нет или служба SQL его не видит. Буквы "
     "сетевых дисков (G:, Z:) службе недоступны — нужен UNC-путь "
     "\\\\сервер\\шара"),
    (r"operating system error 5\b|отказано в доступе|access is denied",
     "отказано в доступе: у учётной записи службы SQL нет прав на запись "
     "в этот каталог"),
    (r"operating system error 112\b|недостаточно места|not enough space",
     "на диске назначения кончилось место"),
    (r"operating system error 53\b|network path was not found|"
     r"не найден сетевой путь",
     "сетевой путь недоступен: сервер или шара не отвечают"),
    (r"cannot open backup device|не удается открыть устройство",
     "устройство копирования недоступно — проверьте путь и права"),
    (r"the media set has \d+ media famil|носитель",
     "несовпадение набора носителей: файл занят другой копией"),
    (r"timeout|время ожидания",
     "операция не уложилась в таймаут"),
]

_BACKUP_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), t)
                    for p, t in BACKUP_ERROR_RULES]


def explain_backup_error(text: str) -> str:
    """Человеческая причина сбоя копирования. Пусто — если правила нет."""
    for pattern, explanation in _BACKUP_COMPILED:
        if pattern.search(text or ""):
            return explanation
    return ""


def summarize_job_message(message: str, limit: int = 250) -> str:
    """Вытаскивает суть из вывода шага джоба, отбрасывая шапку dtexec.

    Пусто — если сути в сообщении нет: SQL Agent обрезал его на шапке.
    Тогда честнее промолчать, чем выдавать баннер утилиты за причину.
    """
    text = " ".join((message or "").split())
    if not text:
        return ""

    parts = _JOB_DESCRIPTION.findall(text)
    if parts:
        # Описаний бывает несколько (вложенные задачи плана) — берём самое
        # длинное: короткие обычно повторяют «The package execution failed».
        summary = max(parts, key=len).strip()
        if len(summary) > limit:
            summary = summary[:limit - 1] + "…"
        return summary

    summary = " ".join(_JOB_NOISE.sub(" ", text).split()).strip(" .:;,\"'…")
    if not _JOB_MEANINGFUL.search(summary):
        return ""
    # Без Description полезное лежит в конце (Error … The step failed),
    # поэтому при переполнении отрезаем начало, а не хвост.
    if len(summary) > limit:
        summary = "…" + summary[-(limit - 1):]
    return summary


# ─── Расшифровка записей движка ──────────────────────────────

# Строка ERRORLOG вида «Error: 824, Severity: 24, State: 2» дежурному не
# говорит ничего. Правила проверяются сверху вниз, первое совпавшее и
# объясняет запись; порядок важен — коды конкретнее, чем severity.
ENGINE_EXPLAIN_RULES = [
    (r"Error:\s*823\b",
     "диск не отдал страницу данных: запрос к файлу БД завершился ошибкой "
     "ОС. Проверьте диск и контроллер, запустите DBCC CHECKDB"),
    (r"Error:\s*824\b",
     "страница прочиталась, но с повреждением (контрольная сумма не сошлась). "
     "Нужен DBCC CHECKDB и проверка диска — данные уже испорчены"),
    (r"Error:\s*825\b",
     "страницу удалось прочитать только с повторной попытки. Диск начинает "
     "сыпаться: ошибка не фатальна, но это предупреждение до 823/824"),
    (r"Error:\s*9002\b|log file .* is full|журнал транзакций.*заполнен",
     "журнал транзакций заполнен: транзакции встали. Нужен бэкап журнала "
     "или место на диске"),
    (r"Error:\s*1105\b|Could not allocate space",
     "в файловой группе кончилось место — БД не может расти"),
    (r"Error:\s*17053\b|Operating system error",
     "ошибка на уровне ОС: чаще всего недоступен путь или нет прав"),
    (r"taking longer than 15 seconds",
     "дисковая подсистема не успевает: операция ввода-вывода ждала дольше "
     "15 секунд. Обычно перегружено хранилище"),
    (r"deadlock|взаимоблокиров",
     "взаимоблокировка: две транзакции ждали друг друга, одну SQL снял "
     "принудительно. Проблема в запросах приложения, не в сервере"),
    (r"Severity:\s*2[0-5]",
     "фатальная ошибка: соединение разорвано, возможна проблема с самой БД"),
    (r"Severity:\s*19",
     "исчерпан лимит ресурса SQL — редкая и серьёзная ситуация"),
    (r"Severity:\s*18",
     "внутренняя ошибка движка: запрос завершён, соединение осталось"),
    (r"Severity:\s*17",
     "не хватило ресурса: места на диске, памяти или блокировок"),
]

_ENGINE_COMPILED = [(re.compile(p, re.IGNORECASE), text)
                    for p, text in ENGINE_EXPLAIN_RULES]


def explain_engine_error(text: str) -> str:
    """Человеческое объяснение записи ERRORLOG. Пусто — если правила нет."""
    for pattern, explanation in _ENGINE_COMPILED:
        if pattern.search(text or ""):
            return explanation
    return ""


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


# Публичное имя для соседних модулей (mssql_health): та же обвязка,
# чтобы не плодить второй способ ходить в SQL.
run_query = _run_sql


def _errorlog_query(hours: int, where: str, limit: int) -> str:
    """xp_readerrorlog нельзя фильтровать напрямую — собираем в переменную.

    Встроенный фильтр командлета умеет только две подстроки, а нам нужен
    разбор по нескольким признакам, поэтому WHERE идёт уже по таблице.
    Архивные файлы читаем в TRY/CATCH: у сервера их может не быть,
    и тогда весь батч упал бы целиком.
    """
    files = ARCHIVE_FILES_LONG if hours > LONG_PERIOD_HOURS else ARCHIVE_FILES_24H
    inserts = "\n".join(
        f"BEGIN TRY INSERT INTO @log EXEC xp_readerrorlog {n}, 1, NULL, NULL, "
        f"@since, NULL, N'desc'; END TRY BEGIN CATCH END CATCH;"
        for n in files
    )
    # Границу периода считает сам SQL: контейнер живёт по UTC, сервер — по
    # местному времени, и окно уезжало на несколько часов.
    return f"""SET NOCOUNT ON;
DECLARE @since DATETIME = DATEADD(hour, -{hours}, GETDATE());
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
             "OR LogText LIKE '%Error: 18456%' "
             "OR LogText LIKE '%Ошибка: 18456%')")
    rows = _run_sql(server, _errorlog_query(hours, where, limit), "d,t")
    # Ровно limit строк почти всегда означает, что лог глубже выборки:
    # иначе счётчик «60 шт.» выдавался бы за полное число отказов за сутки.
    return {"rows": group_login_failures(rows), "truncated": len(rows) >= limit}


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
        result["jobs"] = _agent_job_rows(server, hours=hours, limit=limit,
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


def _agent_job_rows(server: dict, hours: int = 24, limit: int = 30,
                    failed_only: bool = False, backup_only: bool = False) -> list:
    """История запусков джоб SQL Agent.

    step_id = 0 — итоговая запись по джобу; для сводки берём именно её,
    а для разбора ошибки бэкапа — конкретные упавшие шаги.

    Фильтр по времени идёт по числовым run_date/run_time, а не через
    msdb.dbo.agent_datetime: функция недокументированная, вызывается на
    каждой строке и падает на мусорных значениях.
    """
    conditions = [
        "(h.run_date > @sd OR (h.run_date = @sd AND h.run_time >= @st))",
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
DECLARE @since DATETIME = DATEADD(hour, -{hours}, GETDATE());
DECLARE @sd INT = CONVERT(INT, CONVERT(VARCHAR(8), @since, 112));
DECLARE @st INT = DATEPART(hour, @since) * 10000 + DATEPART(minute, @since) * 100 + DATEPART(second, @since);
SELECT TOP {limit} j.name AS job, h.step_id AS step, h.step_name AS stepname,
       h.run_status AS status, h.run_date AS rundate, h.run_time AS runtime,
       h.run_duration AS duration, LEFT(h.message, 1500) AS msg
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


def count_agent_jobs(server: dict) -> int:
    """Сколько джоб вообще видно этой учётной записи.

    Ключевая диагностика для пустой истории: без роли SQLAgentReaderRole
    в msdb учётная запись видит только собственные джобы — чужие просто
    не попадают в выборку, и SQL при этом не возвращает ошибки. Пустой
    список тогда означает «нет прав», а вовсе не «Agent не работает».
    """
    rows = _run_sql(server, "SET NOCOUNT ON;\nSELECT COUNT(*) AS n "
                            "FROM msdb.dbo.sysjobs;", "n")
    if not rows:
        return 0
    try:
        return int(rows[0].get("n") or 0)
    except (TypeError, ValueError):
        return 0


def read_agent_jobs(server: dict, hours: int = 24, limit: int = 30) -> dict:
    """Сводка запусков + сколько джоб видно, чтобы объяснить пустой список."""
    rows = _agent_job_rows(server, hours=hours, limit=limit)
    total = 0
    if not rows:
        try:
            total = count_agent_jobs(server)
        except Exception:
            total = -1        # прав нет даже на список джоб
    return {"rows": rows, "jobs_total": total}


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
