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
    "remote": "Remote:",
    "size": "Локальный размер",
    "skip": "SKIP",
    "upload": "Режим: UPLOAD",
    "attempt": "Попытка",
    "success": "SUCCESS",
    "uploaded": "Файл успешно загружен",
    "exit": "WinSCP exit code=",
    "failed": "FAILED",
    "end": "END upload_common",
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

# Ругань, которая ошибкой не является. Скрипт на всякий случай делает
# mkdir на каталог назначения; когда он уже есть, сервер отвечает отказом
# — и WinSCP печатает целую простыню с «Error code: 4». Передаче это не
# мешает, а база из-за таких строк помечалась бы аварийной каждый раз.
BENIGN_MARKERS = (
    "Cannot create a file when that file already exists",
    "Error creating folder",
    "Common reasons for the Error code",
    "Script: mkdir",
)

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
            if not (current and current.get("uploading")):
                continue
            if any(m in line for m in BENIGN_MARKERS):
                # Следом за такой строкой WinSCP печатает «Error code: N»
                # и «Error message from server» про тот же безобидный
                # отказ — их тоже пропускаем.
                current["_benign"] = True
                continue
            if any(m in line for m in ERROR_MARKERS):
                if current.get("_benign"):
                    continue
                current["errors"].append(line.strip())
            else:
                current["_benign"] = False
            continue

        stamp, database, btype, message = match.groups()
        when = _parse_time(stamp)
        if when:
            summary["started"] = summary["started"] or when
            summary["ended"] = when

        if message.startswith("TYPE="):
            summary["type"] = message.split("=", 1)[1].strip()
        if MARKERS["end"] in message:
            summary["finished"] = True

        if not database:
            continue
        if btype and not summary["type"]:
            summary["type"] = btype

        current = by_name.get(database)
        if current is None:
            current = {"name": database, "status": "unknown", "file": None,
                       "size_gb": None, "attempts": 0, "errors": [],
                       "uploading": False, "remote": None, "bytes": None,
                       "started_at": None,
                       "ended_at": None, "done_at": None, "exit_code": None}
            by_name[database] = current
            summary["databases"].append(current)

        _apply_message(current, message, when)

    return summary


def _apply_message(entry: dict, message: str, when=None):
    if when:
        entry["started_at"] = entry.get("started_at") or when
        entry["ended_at"] = when

    if message.startswith(MARKERS["success"]) or \
            message.startswith(MARKERS["uploaded"]):
        # Скрипт говорит об успехе сам: «SUCCESS», «WinSCP exit code=0»
        # и «Файл успешно загружен». Без этого залитая база оставалась бы
        # в состоянии «заливается» до конца времён.
        entry["status"] = "done"
        entry["uploading"] = False
        entry["done_at"] = when or entry.get("ended_at")
    elif message.startswith(MARKERS["failed"]):
        entry["status"] = "failed"
        entry["uploading"] = False
    elif message.startswith(MARKERS["exit"]):
        code = message.split("=", 1)[-1].strip()
        entry["exit_code"] = code
        if code and code != "0":
            entry["status"] = "failed"
            entry["uploading"] = False
    elif message.startswith(MARKERS["remote"]):
        # Путь на приёмнике, как его видит SFTP: /база/тип/файл.bak.
        # По нему считается процент — размер растущего файла там.
        entry["remote"] = message.split(":", 1)[-1].strip()
    elif message.startswith(MARKERS["found"]):
        entry["file"] = message.split(":", 1)[-1].strip()
    elif message.startswith(MARKERS["size"]):
        entry["size_gb"] = _size_gb(message)
        entry["bytes"] = _size_bytes(message)
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


def _size_bytes(message: str):
    digits = re.search(r"(\d+)", message)
    return int(digits.group(1)) if digits else None


def _size_gb(message: str):
    digits = re.search(r"(\d+)", message)
    if not digits:
        return None
    return round(int(digits.group(1)) / 1024 ** 3, 2)


# Шкала рисуется символами блока: ▰ прошло, ▱ осталось. Десять делений —
# по одному на 10%, больше в строку Telegram не втиснуть без переносов.
BAR_WIDTH = 10
BAR_DONE = "▰"
BAR_LEFT = "▱"


def progress_bar(percent, width: int = BAR_WIDTH) -> str:
    """Шкала готовности: «▰▰▰▱▱▱▱▱▱▱»."""
    if percent is None:
        return ""
    filled = max(0, min(width, round(width * percent / 100)))
    return BAR_DONE * filled + BAR_LEFT * (width - filled)


def eta_minutes(done_bytes, total_bytes, elapsed_minutes):
    """Сколько ещё ехать, по средней скорости с начала заливки.

    Средняя, а не мгновенная: мгновенную по двум замерам не измерить, а
    у большого файла с докачкой она всё равно скачет. Поэтому в тексте
    стоит «≈» — это оценка, а не обещание.
    """
    if not done_bytes or not total_bytes or not elapsed_minutes:
        return None
    if done_bytes >= total_bytes:
        return 0
    speed = done_bytes / elapsed_minutes
    if speed <= 0:
        return None
    return round((total_bytes - done_bytes) / speed)


def human_minutes(minutes) -> str:
    """«2 ч 20 мин» вместо «140 мин»: для длинных копий так понятнее."""
    if minutes is None:
        return ""
    if minutes < 60:
        return f"{minutes} мин"
    hours, rest = divmod(int(minutes), 60)
    return f"{hours} ч {rest} мин" if rest else f"{hours} ч"


def _progress(entry: dict) -> str:
    """Сколько уже доехало. Заполняется снаружи (progress_percent):
    сам журнал процента не знает, его знает только приёмник."""
    percent = entry.get("percent")
    if percent is None:
        return ""
    done_gb = entry.get("remote_gb")
    where = f", {done_gb} ГБ" if done_gb is not None else ""
    eta = entry.get("eta_minutes")
    left = (f", ещё ≈{human_minutes(eta)}" if eta else "")
    return (f"\n    {progress_bar(percent)} {percent}%{where}{left}")


def progress_percent(local_bytes, remote_bytes):
    """Процент готовности: сколько байт уже лежит на приёмнике.

    Единственный честный источник — сам приёмник: у SFTP нет обратной
    связи о ходе передачи, и на стороне отправителя процента взять
    неоткуда. Больше 100% не показываем: файл на приёмнике может быть
    чуть длиннее из-за докачки.
    """
    if not local_bytes or remote_bytes is None:
        return None
    return min(100, round(remote_bytes / local_bytes * 100))


def _took(entry: dict) -> str:
    """Сколько шла заливка этой базы — от первой её строки до SUCCESS."""
    started, done = entry.get("started_at"), entry.get("done_at")
    if not started or not done or done <= started:
        return ""
    minutes = round((done - started).total_seconds() / 60)
    return f", за {minutes} мин" if minutes else ", меньше минуты"


def summary_lines(summary: dict) -> list:
    """Сводка человеческим текстом. Отдельно от разбора: разбор проверяем
    тестами, а вид сообщения меняется чаще правил."""
    databases = summary.get("databases") or []
    skipped = [d for d in databases if d["status"] == "skip"]
    done = [d for d in databases if d["status"] == "done"]
    running = [d for d in databases if d["status"] == "upload"]
    unknown = [d for d in databases if d["status"] == "unknown"]
    failed = [d for d in databases
              if d["status"] == "failed" or (d["errors"] and d["status"] != "done")]

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
        f"💾 Баз: {len(databases)} · залито {len(done)} · "
        f"пропущено {len(skipped)}"
        + (f" · в пути {len(running)}" if running else "")
        + (f" · с ошибками {len(failed)}" if failed else "")
    )
    if not summary.get("finished"):
        lines.append("⏳ Журнал не закончен — рейс ещё идёт "
                     "(или оборвался на полуслове)")
    lines.append("")

    for entry in databases:
        icon = {"done": "✅", "skip": "⏭", "upload": "⏳",
                "failed": "❌"}.get(entry["status"], "⏳")
        size = f", {entry['size_gb']} ГБ" if entry.get("size_gb") else ""
        attempts = (f", попыток {entry['attempts']}"
                    if entry.get("attempts", 0) > 1 else "")
        lines.append(f"{icon} {entry['name']}{size}{attempts}"
                     f"{_took(entry)}{_progress(entry)}")
        if entry.get("file"):
            lines.append(f"    {entry['file']}")
        for error in entry["errors"][:2]:
            lines.append(f"    ⛔ {error[:120]}")

    if running:
        lines.append("")
        lines.append("⏳ — заливка ещё идёт: скрипт не сказал SUCCESS")
    if unknown and summary.get("finished"):
        lines.append("")
        lines.append("⏳ — журнал не сказал, чем кончилось: смотрите "
                     "подробности по базе")
    return lines


# ─── Журнал WinSCP по одной базе ─────────────────────────────
#
# Это не человеческий отчёт, а протокольный лог: на каждые 32 КБ данных
# приходится десяток строк вида «Type: SSH_FXP_WRITE» и «Status code: 0».
# На копии в 44 ГБ такого набегает под гигабайт, и читать его глазами
# бессмысленно — нужны только значимые строки.
#
# Разметка WinSCP: «.» — отладка, «>» — отправлено, «<» — получено,
# «!» — то, что он сам считает важным (ошибки и итоги).

WINSCP_NOISE = (". ", "> ", "< ")

WINSCP_KEEP = (
    "Transfer done", "Copying", "Script:", "Session started", "Authenticated",
    "Starting the session", "Disconnected", "Timeout", "Error", "error",
    "Access denied", "Permission denied", "No such file", "abort",
)

WINSCP_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def winscp_highlights(text: str, limit: int = 20) -> list:
    """Значимые строки из протокольного лога WinSCP.

    Простыня про «mkdir: каталог уже есть» сюда не идёт: это обычный
    ответ сервера на профилактический mkdir, и в списке важного он
    вытеснял бы то, ради чего этот список нужен.
    """
    kept = []
    benign = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if any(m in line for m in BENIGN_MARKERS):
            benign = True
            continue
        if benign and ("Error code:" in line or "Error message from server" in line):
            continue
        benign = False
        if line.startswith("! "):
            kept.append(line[2:].strip())
            continue
        if line.startswith(WINSCP_NOISE):
            body = line[2:].strip()
            if any(word in body for word in WINSCP_KEEP):
                kept.append(body)
            continue
        if any(word in line for word in WINSCP_KEEP):
            kept.append(line)
    return kept[-limit:]


def winscp_last_time(text: str) -> str:
    """Время последней записи в логе — по нему видно, жив ли перенос."""
    stamps = WINSCP_TIME_RE.findall(text or "")
    return stamps[-1] if stamps else ""


def winscp_is_transferring(text: str) -> bool:
    """Идёт ли прямо сейчас передача: в хвосте одни записи в файл."""
    return "SSH_FXP_WRITE" in (text or "")
