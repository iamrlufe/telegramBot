"""
shared/log_summary.py

Сводка журналов Windows и SQL в одном формате — для хранения в базе и показа
в дашборде.

Разделы «📜 Логи Windows» и «🗄 SQL-логи» в карточке сервера читают журналы
живьём в момент нажатия: пять запросов Get-WinEvent и четыре обращения к
msdb на сервер. Для карточки это нормально — смотрят один сервер и ждут
ответа. Для дашборда нет: на десятке серверов это под сотню удалённых
вызовов, минуты ожидания и простукивание всей инфраструктуры при каждой
плановой рассылке.

Поэтому сводку собирает монитор в фоне, а дашборд читает готовое из базы.
Здесь — только приведение разнородных ответов к общему виду:

    {"category", "level", "event_at", "event_id", "title", "detail", "count"}

level — "crit" или "warn"; порог тот же, что глазами: сыплющийся диск и
упавший бэкап критичны, единичная ошибка приложения — нет.

event_at хранится строкой в том виде, в каком его отдал сервер
(YYYY-MM-DD HH:MM:SS по локальному времени сервера). Приводить к UTC не
к чему: часовой пояс удалённой машины монитору неизвестен, а сортировка
и показ по строке работают одинаково.
"""
from datetime import datetime, timedelta

from winlog import (
    read_reboots, read_service_failures, read_disk_errors,
    read_app_errors, read_failed_logons, group_failed_logons,
    explain_event, friendly_winlog_error,
)
from settings import int_env
from mssql_log import (
    read_login_errors, read_backup_errors, read_engine_errors,
    read_agent_jobs, read_job_schedules, friendly_sql_error,
    explain_engine_error, explain_backup_error, summarize_job_message,
)


# (ключ, иконка, подпись) — порядок задаёт порядок колонок в дашборде.
WIN_CATEGORIES = (
    ("reboot",  "🔄", "перезагрузки"),
    ("service", "⚙️", "падения служб"),
    ("disk",    "💽", "ошибки дисков"),
    ("app",     "🧩", "ошибки приложений"),
    ("logon",   "🔑", "отказы входа"),
)
SQL_CATEGORIES = (
    ("login",  "🔑", "отказы входа"),
    ("backup", "💾", "ошибки копирования"),
    ("engine", "⚠️", "ошибки движка"),
    ("job",    "🕐", "упавшие джобы"),
    ("run",    "▶️", "запуски джоб"),
    ("miss",   "🗓", "не отработали"),
)

CATEGORY_TITLES = {
    ("win", key): (icon, label) for key, icon, label in WIN_CATEGORIES
}
CATEGORY_TITLES.update({
    ("sql", key): (icon, label) for key, icon, label in SQL_CATEGORIES
})

# Коды, при которых запись критична сама по себе. Остальные того же раздела
# остаются предупреждением: штатная перезагрузка и служба, поднявшаяся сама,
# не должны красить сервер в красный.
REBOOT_CRIT_IDS = {6008, 41}
SERVICE_CRIT_IDS = {7000, 7022, 7023, 7024, 7034}

# Серия отказов входа — это уже не «кто-то ошибся паролем», а перебор.
LOGON_BRUTE_FORCE = 20

# Джоба, идущая дольше этого, съедает ночное окно целиком: формально успех,
# а по существу повод посмотреть. На больших базах перестроение индексов
# идёт часами, поэтому порог высокий.
JOB_LONG_HOURS = int_env("SQL_JOB_LONG_HOURS", 12)

# Имена, по которым джоба опознаётся как бэкапная. Тот же приём, что в
# mssql_log для ошибок копирования: явного признака у джобы нет.
BACKUP_JOB_MARKERS = ("backup", "бэкап", "копи", "bkp", "dump")

# Сколько ждать после назначенного времени, прежде чем считать запуск
# пропущенным. Джоба стартует не секунда в секунду, а очередь Agent бывает
# занята соседней задачей.
JOB_MISS_GRACE_MINUTES = int_env("SQL_JOB_MISS_GRACE_MINUTES", 60)

# Как msdb описывает периодичность (freq_type в sysschedules).
FREQ_ONCE = 1
FREQ_DAILY = 4
FREQ_WEEKLY = 8
FREQ_MONTHLY = 16

# Дни недели в freq_interval недельного расписания — битовая маска, где
# воскресенье это 1. Ключ здесь — weekday() из Python (понедельник 0).
WEEKDAY_BITS = {0: 2, 1: 4, 2: 8, 3: 16, 4: 32, 5: 64, 6: 1}
WEEKDAY_NAMES = ("понедельникам", "вторникам", "средам", "четвергам",
                 "пятницам", "субботам", "воскресеньям")

# Сколько записей одной категории имеет смысл хранить: в дашборде видно
# первые несколько, полный разбор всё равно в карточке сервера.
KEEP_PER_CATEGORY = 5


def job_seconds(run_duration) -> int:
    """run_duration в msdb — целое HHMMSS: 72900 это 7 ч 29 мин."""
    try:
        value = int(run_duration)
    except (TypeError, ValueError):
        return 0
    return (value // 10000) * 3600 + ((value // 100) % 100) * 60 + value % 100


def is_backup_job(name: str) -> bool:
    """Бэкапная ли джоба — по имени. Явного признака у джобы нет, а знать
    полезно: молчание бэкапной джобы значит, что копии сегодня не будет."""
    low = (name or "").lower()
    return any(marker in low for marker in BACKUP_JOB_MARKERS)


def _short(text, limit: int = 200) -> str:
    text = " ".join(str(text or "").split())
    return text[:limit - 1] + "…" if len(text) > limit else text


def _event(category, level, event_at, event_id, title, detail, count=1) -> dict:
    return {
        "category": category,
        "level": level,
        "event_at": (event_at or "")[:19],
        "event_id": str(event_id) if event_id not in (None, "") else "",
        "title": _short(title, 200),
        "detail": _short(detail, 400),
        "count": int(count or 1),
    }


def _group_windows(rows: list) -> list:
    """Одна и та же запись повторяется десятками строк — падающая по кругу
    служба, сыплющийся диск. Схлопываем так же, как это делает карточка
    сервера, иначе сводка занята одной бедой."""
    grouped = {}
    for row in rows:
        key = (row.get("id"), _short(row.get("msg"), 120))
        item = grouped.get(key)
        if item is None:
            grouped[key] = {"id": row.get("id"), "src": row.get("src"),
                            "msg": row.get("msg") or "",
                            "last": row.get("d") or "", "count": 1}
        else:
            item["count"] += 1
            item["last"] = max(item["last"], row.get("d") or "")
    return sorted(grouped.values(), key=lambda i: i["last"], reverse=True)


def _win_level(category: str, event_id) -> str:
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = None
    if category == "disk":
        return "crit"
    if category == "reboot":
        return "crit" if event_id in REBOOT_CRIT_IDS else "warn"
    if category == "service":
        return "crit" if event_id in SERVICE_CRIT_IDS else "warn"
    return "warn"


def _win_title(category: str, item: dict) -> str:
    explanation = explain_event(item.get("id"))
    if explanation:
        head = explanation.split(" — ")[0].split(",")[0]
        title = head[:1].upper() + head[1:]
    else:
        title = f"Событие {item.get('id')}"
    if item.get("src"):
        title = f"{title} · {item['src']}"
    if item.get("count", 1) > 1:
        title = f"{title} · {item['count']} раз"
    return title


def windows_events(server: dict, hours: int = 24) -> tuple[list, str]:
    """Сводка Event Log одного сервера. Вторым значением — текст ошибки
    сбора: раздел журнала может быть недоступен по правам, и об этом надо
    сказать, а не показывать пустоту."""
    readers = (
        ("reboot",  read_reboots),
        ("service", read_service_failures),
        ("disk",    read_disk_errors),
        ("app",     read_app_errors),
    )
    events, problems = [], []

    for category, reader in readers:
        try:
            rows = reader(server, hours=hours)
        except Exception as e:
            message = friendly_winlog_error(e)
            if message:
                problems.append(message)
            continue
        for item in _group_windows(rows)[:KEEP_PER_CATEGORY]:
            events.append(_event(
                category, _win_level(category, item.get("id")),
                item.get("last"), item.get("id"),
                _win_title(category, item), item.get("msg"),
                item.get("count", 1),
            ))

    try:
        logons = group_failed_logons(read_failed_logons(server, hours=hours))
    except Exception as e:
        message = friendly_winlog_error(e)
        if message:
            problems.append(message)
        logons = []

    for item in logons[:KEEP_PER_CATEGORY]:
        count = item.get("count", 1)
        who = item.get("user") or "—"
        where = item.get("ip") or item.get("host") or "источник неизвестен"
        detail = " · ".join(part for part in (
            f"пользователь {who}", where, item.get("how"), item.get("reason")
        ) if part)
        events.append(_event(
            "logon", "crit" if count >= LOGON_BRUTE_FORCE else "warn",
            item.get("last"), item.get("eid") or 4625,
            f"{count} отказов входа" if count > 1 else "Отказ входа",
            detail, count,
        ))

    return events, "; ".join(problems)


def sql_events(server: dict, hours: int = 24) -> tuple[list, str]:
    """Сводка SQL Server: отказы входа, ошибки копирования и движка,
    упавшие джобы Agent."""
    events, problems = [], []

    try:
        logins = read_login_errors(server, hours=hours)
        for item in logins.get("rows", [])[:KEEP_PER_CATEGORY]:
            count = item.get("count", 1)
            detail = " · ".join(part for part in (
                f"логин {item.get('user') or '—'}", item.get("client"),
                f"база {item['database']}" if item.get("database") else "",
                item.get("reason"),
            ) if part)
            events.append(_event(
                "login", "crit" if count >= LOGON_BRUTE_FORCE else "warn",
                item.get("last"), 18456,
                f"{count} отказов входа" if count > 1 else "Отказ входа",
                detail, count,
            ))
    except Exception as e:
        problems.append(f"отказы входа: {friendly_sql_error(e)}")

    try:
        backup = read_backup_errors(server, hours=hours)
        problems.extend(backup.get("errors") or [])
        for row in (backup.get("engine") or [])[:KEEP_PER_CATEGORY]:
            text = row.get("t") or ""
            events.append(_event(
                "backup", "crit", row.get("d"), None,
                "Ошибка копирования",
                explain_backup_error(text) or text,
            ))
        for row in (backup.get("jobs") or [])[:KEEP_PER_CATEGORY]:
            events.append(_event(
                "backup", "crit", row.get("when"), None,
                f"Джоба «{row.get('job')}» упала",
                summarize_job_message(row.get("msg")),
            ))
    except Exception as e:
        problems.append(f"ошибки копирования: {friendly_sql_error(e)}")

    try:
        for row in read_engine_errors(server, hours=hours)[:KEEP_PER_CATEGORY]:
            text = row.get("t") or ""
            events.append(_event(
                "engine", "warn", row.get("d"), None,
                "Ошибка движка", explain_engine_error(text) or text,
            ))
    except Exception as e:
        problems.append(f"ошибки движка: {friendly_sql_error(e)}")

    try:
        jobs = read_agent_jobs(server, hours=hours)
        rows = jobs.get("rows", [])
        failed = [row for row in rows if str(row.get("status")) == "0"]
        for row in failed[:KEEP_PER_CATEGORY]:
            events.append(_event(
                "job", "warn", row.get("when"), None,
                f"Джоба «{row.get('job')}» упала",
                " · ".join(part for part in (
                    f"длилась {row.get('took')}" if row.get("took") else "",
                    summarize_job_message(row.get("msg")),
                ) if part),
            ))
        events.extend(job_runs(rows))
        ran = {row.get("job") for row in rows if row.get("job")}
    except Exception as e:
        problems.append(f"джобы Agent: {friendly_sql_error(e)}")
        ran = None

    # Расписания — только если историю запусков прочитать удалось: без неё
    # «не запускалась» будет у всех подряд.
    if ran is not None:
        try:
            events.extend(job_schedule_events(read_job_schedules(server), ran))
        except Exception as e:
            problems.append(f"расписания джоб: {friendly_sql_error(e)}")

    return events, "; ".join(problems)


def job_runs(rows: list) -> list:
    """Запуски джоб — по строке на джобу, а не на запуск.

    Успешные запуски раньше выбрасывались целиком: в суточной сводке они
    только шумели. Но так пропадали два случая, которые как раз важны.

    Джоба, которая **не запускалась вовсе**, не падает — её просто нет, и ни
    один счётчик этого не показывал. Список запусков делает молчание
    видимым: вчера четырнадцать, сегодня две.

    И джоба, отработавшая успешно, но **необычно долго**: формально успех, а
    по существу съеденное ночное окно, в которое не влезли остальные
    задания. Такие помечаются предупреждением.
    """
    by_job = {}
    for row in rows:
        name = row.get("job")
        if not name:
            continue
        entry = by_job.setdefault(name, {"runs": 0, "seconds": 0, "last": "",
                                         "failed": 0})
        entry["runs"] += 1
        entry["seconds"] = max(entry["seconds"], job_seconds(row.get("duration")))
        entry["last"] = max(entry["last"], row.get("when") or "")
        if str(row.get("status")) == "0":
            entry["failed"] += 1

    events = []
    ordered = sorted(by_job.items(), key=lambda i: (-i[1]["seconds"], i[0]))
    for name, entry in ordered[:KEEP_PER_CATEGORY * 2]:
        long_run = entry["seconds"] >= JOB_LONG_HOURS * 3600
        detail = [f"{entry['runs']} запусков"]
        if entry["seconds"]:
            detail.append(f"дольше всего {decode_agent_duration_seconds(entry['seconds'])}")
        if entry["failed"]:
            detail.append(f"падений: {entry['failed']}")
        if is_backup_job(name):
            detail.append("бэкапная")
        events.append(_event(
            "run", "warn" if long_run else "ok", entry["last"], None,
            f"Джоба «{name}»" + (" — идёт слишком долго" if long_run else ""),
            " · ".join(detail), entry["runs"],
        ))
    return events


def decode_agent_duration_seconds(seconds: int) -> str:
    """Секунды в человеческий вид — msdb хранит длительность как HHMMSS,
    и обратно её удобнее собирать уже из секунд."""
    hours, rest = divmod(int(seconds or 0), 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours} ч {minutes} мин"
    if minutes:
        return f"{minutes} мин {secs} с"
    return f"{secs} с"


def _hhmmss(value) -> tuple:
    """active_start_time в msdb — целое HHMMSS: 13000 это 01:30:00."""
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        value = 0
    return value // 10000, (value // 100) % 100, value % 100


def schedule_text(row: dict) -> str:
    """Расписание словами. Пусто — если разобрать не смогли."""
    hour, minute, _sec = _hhmmss(row.get("ast"))
    at = f"в {hour:02d}:{minute:02d}"
    ft, fi, rf = int(row.get("ft") or 0), int(row.get("fi") or 0), int(row.get("rf") or 0)
    if ft == FREQ_DAILY:
        return f"ежедневно {at}" if fi <= 1 else f"раз в {fi} дн {at}"
    if ft == FREQ_WEEKLY:
        days = [WEEKDAY_NAMES[i] for i, bit in WEEKDAY_BITS.items() if fi & bit]
        days.sort(key=lambda d: WEEKDAY_NAMES.index(d))
        every = "" if rf <= 1 else f" раз в {rf} нед"
        return f"по {', '.join(days)}{every} {at}" if days else ""
    if ft == FREQ_MONTHLY:
        return f"{fi}-го числа {at}"
    return ""


def expected_today(row: dict, now) -> bool:
    """Ждём ли запуск этой джобы сегодня к текущему моменту.

    Разбираются три периодичности: ежедневная, недельная и «N-го числа».
    Остальные — однократная, «при старте Agent», «в простое» и относительная
    месячная — сознательно не разбираются: угадывать по ним пропуск значит
    поднимать ложную тревогу, а молчать честнее.
    """
    if not int(row.get("sen") or 0):
        return False

    ft, fi, rf = int(row.get("ft") or 0), int(row.get("fi") or 0), int(row.get("rf") or 0)
    if ft == FREQ_DAILY:
        due = fi <= 1
    elif ft == FREQ_WEEKLY:
        due = bool(fi & WEEKDAY_BITS[now.weekday()]) and rf <= 1
    elif ft == FREQ_MONTHLY:
        due = now.day == fi
    else:
        return False
    if not due:
        return False

    # Время уже должно было наступить, и с запасом: джоба стартует не
    # секунда в секунду, а очередь Agent бывает занята соседней задачей.
    hour, minute, _sec = _hhmmss(row.get("ast"))
    planned = now.replace(hour=min(hour, 23), minute=min(minute, 59),
                          second=0, microsecond=0)
    return now >= planned + timedelta(minutes=JOB_MISS_GRACE_MINUTES)


def job_schedule_events(rows: list, ran: set, now=None) -> list:
    """Джобы, которые должны были отработать, но не отработали, и выключенные.

    Это то, чего не видно в истории запусков: не отработавшая джоба не падает
    и в sysjobhistory не появляется вовсе. Отличить «не была нужна» от «не
    запустилась» можно только по расписанию, и знает его сам сервер.

    Выключенная джоба — отдельный случай и самый тихий: она не падает, не
    пропадает и не жалуется. Обычно её выключают на время ручной операции
    и забывают включить обратно.
    """
    now = now or datetime.now()
    ran = {str(name).lower() for name in (ran or set())}

    by_job = {}
    for row in rows or []:
        name = row.get("job")
        if not name:
            continue
        entry = by_job.setdefault(name, {"enabled": int(row.get("jen") or 0),
                                         "running": 0, "due": False, "plan": ""})
        entry["running"] = max(entry["running"], int(row.get("run") or 0))
        if expected_today(row, now):
            entry["due"] = True
            entry["plan"] = entry["plan"] or schedule_text(row)

    events = []
    for name, entry in sorted(by_job.items()):
        level = "crit" if is_backup_job(name) else "warn"
        if not entry["enabled"]:
            events.append(_event(
                "miss", level, "", None, f"Джоба «{name}» отключена",
                "в списке есть, но выключена — запусков не будет"
                + (" · бэкапная" if is_backup_job(name) else ""),
            ))
            continue
        if entry["due"] and not entry["running"] and name.lower() not in ran:
            events.append(_event(
                "miss", level, "", None, f"Джоба «{name}» не запускалась",
                " · ".join(part for part in (
                    f"по расписанию {entry['plan']}" if entry["plan"] else "",
                    "бэкапная" if is_backup_job(name) else "",
                ) if part),
            ))
    return events


def count_by_category(events: list, source: str) -> list:
    """Счётчики по категориям в порядке, заданном константами: в дашборде
    колонки не должны прыгать от сервера к серверу."""
    categories = WIN_CATEGORIES if source == "win" else SQL_CATEGORIES
    totals = {key: {"count": 0, "level": ""} for key, _icon, _label in categories}
    for event in events:
        bucket = totals.get(event["category"])
        if bucket is None:
            continue
        bucket["count"] += event.get("count", 1)
        if event["level"] == "crit":
            bucket["level"] = "crit"
        elif event["level"] == "warn" and bucket["level"] != "crit":
            bucket["level"] = "warn"
        elif not bucket["level"]:
            bucket["level"] = "ok"
    return [
        {"key": key, "icon": icon, "label": label,
         "count": totals[key]["count"], "level": totals[key]["level"]}
        for key, icon, label in categories
    ]
