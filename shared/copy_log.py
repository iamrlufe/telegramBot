"""
shared/copy_log.py

Разбор журнала скрипта копирования — того, который скрипт ведёт сам.

Зачем отдельно от журнала бота. Бот пишет свой файл на каждый рейс и
знает ровно две вещи: код возврата и консольный вывод. А скрипт ведёт
подробный журнал: какие базы обошёл, какой файл нашёл, что залил, что
пропустил, сколько было попыток. Для ответа «как прошло копирование»
нужен именно он.

Раскладка задана самим скриптом и потому вычисляется, а не настраивается:
рядом со скриптом лежит каталог logs, в нём каталог на дату, в нём общий
журнал на каждый тип копии и подкаталог на каждую базу с подробностями
от WinSCP:

    C:\\roman\\2026\\upload_full.cmd
    C:\\roman\\2026\\logs\\2026-09-05\\common_FULL.log
    C:\\roman\\2026\\logs\\2026-09-05\\new_pro_akt\\FULL.log

Строки общего журнала выглядят так:

    [05.09.2026 11:17:42,10] [new_pro_akt] [FULL] Найден файл: ...bak

Разбор устойчив к незнакомым строкам: WinSCP пишет свой вывод в тот же
файл без отметки времени, и это нормально — такие строки в сводку не
идут, но и разбор не ломают.
"""
import re
from datetime import datetime

# [05.09.2026 11:17:42,10] [база] [FULL] текст
LINE_RE = re.compile(
    r"^\[(\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2})[,.]\d+\]\s*"
    r"(?:\[([^\]]+)\]\s*\[([^\]]+)\]\s*)?(.*)$"
)

# Слова, по которым узнаются события. Взяты из самого скрипта; если он
# изменится, сводка обеднеет, но не соврёт — неузнанные строки просто
# не учитываются, а посмотреть журнал целиком можно кнопкой.
MARKERS = {
    "found": "Найден файл",
    "size": "Локальный размер",
    "skip": "SKIP",
    "upload": "Режим: UPLOAD",
    "attempt": "Попытка",
    "done": "END upload_common",
}

# Признаки беды в строках WinSCP: у него свой формат, отметки времени нет.
#
# Считаются они ТОЛЬКО во время самой заливки. До неё скрипт спрашивает
# у приёмника, есть ли там файл, и «No such file or directory / Error
# code: 2» в этот момент — нормальный ответ «нет, заливай». Без такого
# разделения каждая новая копия помечалась бы ошибкой.
ERROR_MARKERS = ("Error code:", "No such file or directory",
                 "Access denied", "Permission denied", "Connection failed",
                 "Timeout", "Network error", "Host does not exist")

DIR_DATE_FORMAT = "%Y-%m-%d"


def log_dir(script: str, day: datetime = None) -> str:
    """Каталог журналов за дату — рядом со скриптом копирования."""
    base = script.replace("/", "\\").rsplit("\\", 1)[0]
    day = day or datetime.now()
    return f"{base}\\logs\\{day.strftime(DIR_DATE_FORMAT)}"


def common_log(script: str, btype: str, day: datetime = None) -> str:
    """Общий журнал рейса: один файл на тип копии за сутки."""
    return f"{log_dir(script, day)}\\common_{_type_word(btype)}.log"


def database_log(script: str, btype: str, database: str,
                 day: datetime = None) -> str:
    """Подробности WinSCP по одной базе."""
    return f"{log_dir(script, day)}\\{database}\\{_type_word(btype)}.log"


def _type_word(btype: str) -> str:
    """D/I/L — как их называет msdb; FULL/DIFF/LOG — как называет скрипт."""
    return {"D": "FULL", "I": "DIFF", "L": "LOG"}.get(
        str(btype or "").upper()[:1], str(btype or "").upper())


def _parse_time(text: str):
    try:
        return datetime.strptime(text, "%d.%m.%Y %H:%M:%S")
    except ValueError:
        return None


def parse_common_log(text: str) -> dict:
    """Журнал рейса → сводка.

    {"type", "started", "ended", "finished" (дошёл ли до END),
     "databases": [{"name", "status", "file", "size_gb", "attempts",
                    "errors": [...]}]}

    status: 'skip' — файл уже на приёмнике, 'upload' — заливался,
    'unknown' — база в журнале есть, а чем кончилось, не сказано (обычно
    это и значит «прямо сейчас заливается»).
    """
    summary = {"type": "", "started": None, "ended": None,
               "finished": False, "databases": []}
    by_name = {}
    current = None

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        match = LINE_RE.match(line)
        if not match:
            # Строка без отметки времени — вывод WinSCP. Свои ошибки он
            # печатает именно так, и они относятся к последней базе.
            if (current and current.get("uploading")
                    and any(m in line for m in ERROR_MARKERS)):
                current["errors"].append(line.strip())
            continue

        stamp, database, btype, message = match.groups()
        when = _parse_time(stamp)
        if when:
            summary["started"] = summary["started"] or when
            summary["ended"] = when

        if message.startswith("TYPE="):
            summary["type"] = message.split("=", 1)[1].strip()
        if MARKERS["done"] in message:
            summary["finished"] = True

        if not database:
            continue
        if btype and not summary["type"]:
            summary["type"] = btype

        current = by_name.get(database)
        if current is None:
            current = {"name": database, "status": "unknown", "file": None,
                       "size_gb": None, "attempts": 0, "errors": [],
                       "uploading": False}
            by_name[database] = current
            summary["databases"].append(current)

        _apply_message(current, message)

    return summary


def _apply_message(entry: dict, message: str):
    if message.startswith(MARKERS["found"]):
        entry["file"] = message.split(":", 1)[-1].strip()
    elif message.startswith(MARKERS["size"]):
        entry["size_gb"] = _size_gb(message)
    elif message.startswith(MARKERS["skip"]):
        entry["status"] = "skip"
        entry["uploading"] = False
        entry["errors"].clear()
    elif message.startswith(MARKERS["upload"]):
        entry["status"] = "upload"
        # Всё, что WinSCP сказал до этого, относилось к проверке «а есть
        # ли файл на приёмнике» — это не ошибки.
        entry["uploading"] = True
        entry["errors"].clear()
    elif message.startswith(MARKERS["attempt"]):
        entry["attempts"] += 1


def _size_gb(message: str):
    digits = re.search(r"(\d+)", message)
    if not digits:
        return None
    return round(int(digits.group(1)) / 1024 ** 3, 2)


def summary_lines(summary: dict) -> list:
    """Сводка человеческим текстом. Отдельно от разбора: разбор проверяем
    тестами, а вид сообщения меняется чаще правил."""
    databases = summary.get("databases") or []
    skipped = [d for d in databases if d["status"] == "skip"]
    uploaded = [d for d in databases if d["status"] == "upload"]
    unknown = [d for d in databases if d["status"] == "unknown"]
    failed = [d for d in databases if d["errors"]]

    head = f"📄 Журнал скрипта · {summary.get('type') or '?'}"
    started, ended = summary.get("started"), summary.get("ended")
    when = ""
    if started:
        when = started.strftime("%d.%m.%Y %H:%M")
        if ended and ended != started:
            minutes = round((ended - started).total_seconds() / 60)
            when += f" → {ended.strftime('%H:%M')} ({minutes} мин)"
    lines = [head]
    if when:
        lines.append(f"🕒 {when}")
    lines.append(
        f"💾 Баз: {len(databases)} · залито {len(uploaded)} · "
        f"пропущено {len(skipped)}"
        + (f" · с ошибками {len(failed)}" if failed else "")
    )
    if not summary.get("finished"):
        lines.append("⏳ Журнал не закончен — рейс ещё идёт "
                     "(или оборвался на полуслове)")
    lines.append("")

    for entry in databases:
        icon = {"skip": "✅", "upload": "⬆️"}.get(entry["status"], "⏳")
        if entry["errors"]:
            icon = "❌"
        size = f", {entry['size_gb']} ГБ" if entry.get("size_gb") else ""
        attempts = (f", попыток {entry['attempts']}"
                    if entry.get("attempts", 0) > 1 else "")
        lines.append(f"{icon} {entry['name']}{size}{attempts}")
        if entry.get("file"):
            lines.append(f"    {entry['file']}")
        for error in entry["errors"][:2]:
            lines.append(f"    ⛔ {error[:120]}")

    if unknown and summary.get("finished"):
        lines.append("")
        lines.append("⏳ — журнал не сказал, чем кончилось: смотрите "
                     "подробности по базе")
    return lines
