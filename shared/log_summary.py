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
from winlog import (
    read_reboots, read_service_failures, read_disk_errors,
    read_app_errors, read_failed_logons, group_failed_logons,
    explain_event, friendly_winlog_error,
)
from mssql_log import (
    read_login_errors, read_backup_errors, read_engine_errors,
    read_agent_jobs, friendly_sql_error, explain_engine_error,
    explain_backup_error, summarize_job_message,
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

# Сколько записей одной категории имеет смысл хранить: в дашборде видно
# первые несколько, полный разбор всё равно в карточке сервера.
KEEP_PER_CATEGORY = 5


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
        failed = [row for row in jobs.get("rows", []) if str(row.get("status")) == "0"]
        for row in failed[:KEEP_PER_CATEGORY]:
            events.append(_event(
                "job", "warn", row.get("when"), None,
                f"Джоба «{row.get('job')}» упала",
                " · ".join(part for part in (
                    f"длилась {row.get('took')}" if row.get("took") else "",
                    summarize_job_message(row.get("msg")),
                ) if part),
            ))
    except Exception as e:
        problems.append(f"джобы Agent: {friendly_sql_error(e)}")

    return events, "; ".join(problems)


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
        elif not bucket["level"]:
            bucket["level"] = "warn"
    return [
        {"key": key, "icon": icon, "label": label,
         "count": totals[key]["count"], "level": totals[key]["level"]}
        for key, icon, label in categories
    ]
