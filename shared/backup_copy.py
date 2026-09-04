"""
shared/backup_copy.py

Копирование копий на приёмник запускает бот, а не планировщик Windows.

Зачем. Планировщик стартует по часам, а бэкап заканчивается когда придётся:
сегодня в 3:00, завтра в 4:00, потому что шла проверка базы или сервер был
занят. Значит скрипт копирования может стартовать раньше, чем файл готов,
а ждать копию «через N минут после появления файла» бессмысленно: момент
старта копирования отсюда не виден, и 70 ГБ не уезжают за фиксированные
три четверти часа.

Точный сигнал «файл готов» знает сам SQL: `msdb.dbo.backupset` пишет
`backup_finish_date` в момент, когда копия закончена и закрыта. По нему и
работаем: увидели новую запись — запустили скрипт копирования на самом
сервере-источнике; знаем момент старта — знаем, сколько копия реально едет,
и ждём её ровно столько, сколько она идёт, а не сколько угадали.

Всё это — опция: нет copy_script, значит копированием по-прежнему
занимается планировщик, и ничего не меняется.

Здесь только чистая логика: разбор настроек, выбор «той самой» записи
из msdb, решение «пора» и «слишком долго», текст запускающего скрипта.
Сеть и состояние — в monitor/backup_transfer.py.
"""
import json
import os
import tempfile
from datetime import datetime, timedelta

from settings import SERVERS_FILE, ALMATY, int_env
from winrm_client import run_ps, ps_json


# Типы копий в msdb: D — полная, I — разностная, L — журнал транзакций.
# По умолчанию возим полные и разностные: журналы делают каждые 15–60 минут,
# и гонять на них скрипт копирования — то же самое, что копировать
# непрерывно.
BACKUP_TYPE_LABELS = {"D": "полная", "I": "разностная", "L": "журнал"}
DEFAULT_COPY_TYPES = ("D", "I")

# Сколько ждать после отметки «копия закончена», прежде чем запускать
# копирование. SQL закрывает файл раньше, чем система дописывает его на
# диск, а на сервере может доделываться сжатие.
COPY_DELAY_MINUTES = int_env("BACKUP_COPY_DELAY_MINUTES", 5)

# Сколько ждать окончания копирования, прежде чем считать его зависшим.
# Считается от старта скрипта, а не от появления файла: это и есть ответ
# на «70 ГБ не успеют за 45 минут».
COPY_TIMEOUT_MINUTES = int_env("BACKUP_COPY_TIMEOUT_MINUTES", 360)

# Насколько свежей должна быть запись в msdb, чтобы по ней запускать
# копирование. Защита от «монитор перезапустили, состояние потеряли»:
# без неё бот погнал бы копировать вчерашний файл.
COPY_FRESH_MINUTES = int_env("BACKUP_COPY_FRESH_MINUTES", 180)


def copy_settings(server: dict) -> dict:
    """Настройки копирования сервера-источника или None, если не заданы.

    Поля плоские (copy_script, copy_types, ...), а не вложенным объектом,
    чтобы их можно было править из бота: мастер ⚙️ Настройка спрашивает
    именно плоские поля.
    """
    script = (server.get("copy_script") or "").strip()
    if not script:
        return None

    types = server.get("copy_types")
    if isinstance(types, str):
        types = [t.strip() for t in types.replace(";", ",").split(",")]
    types = [str(t).strip().upper()[:1] for t in (types or []) if str(t).strip()]

    return {
        "script": script,
        "types": tuple(types) if types else DEFAULT_COPY_TYPES,
        "auto": server.get("copy_after_backup", True) is not False,
        "delay_minutes": _minutes(server.get("copy_delay_minutes"), COPY_DELAY_MINUTES),
        "timeout_minutes": _minutes(server.get("copy_timeout_minutes"),
                                    COPY_TIMEOUT_MINUTES),
    }


def _minutes(value, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_finished(text):
    """`2026-09-05 00:34:52` из msdb → datetime. Время местное для сервера
    SQL: backup_finish_date пишется по его часам, не в UTC."""
    if isinstance(text, datetime):
        return text
    if not text:
        return None
    try:
        return datetime.strptime(str(text)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def pick_ready_backup(rows: list, settings: dict) -> dict:
    """Самая свежая законченная копия нужного типа из выдачи msdb."""
    best = None
    for row in rows or []:
        btype = str(row.get("btype") or "").strip().upper()[:1]
        if btype not in settings["types"]:
            continue
        finished = parse_finished(row.get("finished"))
        if not finished:
            continue
        if best is None or finished > best["finished"]:
            best = {
                "db": row.get("db"),
                "type": btype,
                "finished": finished,
                "size_gb": row.get("size_gb"),
                "device": row.get("device"),
            }
    return best


def should_start(ready: dict, state: dict, settings: dict, now: datetime):
    """Пора ли запускать копирование. Возвращает (да/нет, причина отказа).

    Причина возвращается ради лога: «почему бот не запустил копирование» —
    первый вопрос, который зададут, и отвечать на него догадками плохо.
    """
    state = state or {}
    if not settings["auto"]:
        return False, "автозапуск выключен"
    if not ready:
        return False, "в msdb нет законченных копий нужного типа"

    marker = ready["finished"].strftime("%Y-%m-%d %H:%M:%S")
    if state.get("last_finished") == marker:
        return False, "эта копия уже отправлена"
    if state.get("run"):
        return False, "предыдущее копирование ещё идёт"

    waited = (now - ready["finished"]).total_seconds() / 60
    if waited < settings["delay_minutes"]:
        return False, f"копия закончена {round(waited)} мин назад, ждём дозаписи"
    if waited > COPY_FRESH_MINUTES:
        # Первый цикл после перезапуска монитора: состояние пустое, а в msdb
        # лежит вчерашняя копия. Её везти незачем — она давно уехала.
        return False, "копия слишком старая, копирование не нужно"

    return True, None


def run_verdict(run: dict, settings: dict, now: datetime) -> str:
    """Что с идущим копированием: 'running' или 'timeout'."""
    started = run.get("started")
    if isinstance(started, str):
        started = parse_finished(started)
    if not started:
        return "running"
    if now - started > timedelta(minutes=settings["timeout_minutes"]):
        return "timeout"
    return "running"


def launch_script_ps(script: str) -> str:
    """PowerShell, который запускает скрипт копирования и СРАЗУ отдаёт PID.

    Ждать окончания нельзя: сессия WinRM живёт минуты, а копирование
    большой базы идёт часами. Поэтому процесс отвязывается, а следим за
    ним по PID на следующих циклах.
    """
    quoted = script.replace("'", "''")
    return f"""
    $cmd = '{quoted}'
    $ext = [System.IO.Path]::GetExtension(($cmd -split '"')[0].Trim()).ToLower()
    if ($ext -eq '.ps1') {{
        $p = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden `
             -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$cmd
    }} else {{
        $p = Start-Process -FilePath 'cmd.exe' -PassThru -WindowStyle Hidden `
             -ArgumentList '/c',$cmd
    }}
    ConvertTo-Json @{{ Pid = $p.Id; Started = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }} -Compress
    """


def check_process_ps(pid: int) -> str:
    """Жив ли запущенный процесс копирования."""
    return f"""
    $p = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue
    ConvertTo-Json @{{ Alive = [bool]$p }} -Compress
    """


def type_label(btype: str) -> str:
    return BACKUP_TYPE_LABELS.get(str(btype or "").upper()[:1], str(btype or "?"))


# ─── Состояние копирований ───────────────────────────────────
#
# Файл общий для монитора и бота: монитор запускает копирование по
# готовности копии, бот — кнопкой «📤 Скопировать сейчас», и оба обязаны
# видеть одно и то же. /app/data примонтирован в оба контейнера.
#
#   {"<сервер>": {"last_finished": "...",
#                 "run": {"pid", "started", "source_finished", "db", "type",
#                         "size_gb", "by"},
#                 "last_run": {... + "ended", "minutes"}}}

TRANSFER_STATE_FILE = "/app/data/backup_transfer.json"


def load_state(path: str = None) -> dict:
    # Путь берётся при вызове, а не при объявлении: так его можно подменить
    # в тестах, не трогая боевой /app/data.
    path = path or TRANSFER_STATE_FILE
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict, path: str = None):
    """Атомарная запись: два процесса (монитор и бот) пишут один файл, и
    обрыв на полуслове оставил бы битый JSON — а он читается как «состояний
    нет», то есть копия поехала бы второй раз."""
    path = path or TRANSFER_STATE_FILE
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def now_local() -> datetime:
    """Местное время без tzinfo: msdb пишет backup_finish_date по часам
    самого SQL-сервера, а серверы стоят в том же поясе, что и бот."""
    return datetime.now(ALMATY).replace(tzinfo=None)


def marker(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def load_servers(path: str = SERVERS_FILE) -> list:
    with open(path) as f:
        return json.load(f)


def copy_servers() -> list:
    """Серверы, у которых задан скрипт копирования, — им есть что запускать."""
    try:
        servers = load_servers()
    except Exception as e:
        print(f"[copy] Ошибка чтения {SERVERS_FILE}: {e}", flush=True)
        return []
    return [s["name"] for s in servers if copy_settings(s)]


def find_server(server_name: str) -> dict:
    for server in load_servers():
        if server.get("name") == server_name:
            return server
    return None


def launch_copy(server: dict, settings: dict, ready: dict = None,
                by: str = "монитор") -> dict:
    """Запускает скрипт копирования на сервере-источнике и возвращает запись
    о запуске. Бросает исключение, если запустить не удалось.

    Ждать окончания нельзя: сессия WinRM живёт минуты, а копия едет часами,
    поэтому процесс отвязывается и дальше опознаётся по PID.
    """
    raw = run_ps(server["host"], launch_script_ps(settings["script"]),
                 server.get("username"), server.get("password"))
    data = ps_json(raw) or {}
    pid = data.get("Pid")
    if not pid:
        raise RuntimeError("сервер не вернул PID запущенного скрипта")
    return {
        "pid": int(pid),
        "started": marker(now_local()),
        "source_finished": marker(ready["finished"]) if ready else None,
        "db": (ready or {}).get("db"),
        "type": (ready or {}).get("type"),
        "size_gb": (ready or {}).get("size_gb"),
        "by": by,
    }


def start_copy_now(server_name: str, by: str = "бот") -> dict:
    """Ручной запуск копирования кнопкой в боте.

    Отметку `last_finished` НЕ трогаем: ручной запуск не отменяет обычного
    хода дел — если следом SQL закончит новую копию, её всё равно повезут.
    """
    server = find_server(server_name)
    if not server:
        raise RuntimeError(f"сервера {server_name} нет в конфиге")
    settings = copy_settings(server)
    if not settings:
        raise RuntimeError("у сервера не задан скрипт копирования (copy_script)")

    state = load_state()
    entry = state.get(server_name) or {}
    if entry.get("run"):
        raise RuntimeError(
            f"копирование уже идёт с {entry['run'].get('started')} "
            f"(PID {entry['run'].get('pid')})"
        )

    entry["run"] = launch_copy(server, settings, by=by)
    state[server_name] = entry
    save_state(state)
    return entry["run"]
