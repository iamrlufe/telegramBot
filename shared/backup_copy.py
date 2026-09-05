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
import base64
import binascii
import json
import os
import tempfile
from datetime import datetime, timedelta

from settings import SERVERS_FILE, ALMATY, int_env
from winrm_client import run_ps, ps_json, PS_OUT_B64_HELPER


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


def copy_scripts(server: dict) -> dict:
    """Скрипты копирования: {тип копии: путь}.

    Полную и разностную копии обычно возят РАЗНЫМИ скриптами: у них разные
    каталоги на приёмнике и разное расписание. Поэтому copy_script — либо
    один путь на все типы, либо карта вида {"D": full.cmd, "I": diff.cmd}.
    """
    value = server.get("copy_script")
    if isinstance(value, dict):
        out = {}
        for btype, script in value.items():
            btype = str(btype).strip().upper()[:1]
            script = str(script or "").strip()
            if btype and script:
                out[btype] = script
        return out

    script = str(value or "").strip()
    if not script:
        return {}
    types = _types_field(server.get("copy_types")) or DEFAULT_COPY_TYPES
    return {btype: script for btype in types}


def _types_field(types) -> tuple:
    if isinstance(types, str):
        types = [t.strip() for t in types.replace(";", ",").split(",")]
    return tuple(str(t).strip().upper()[:1] for t in (types or []) if str(t).strip())


def copy_settings(server: dict) -> dict:
    """Настройки копирования сервера-источника или None, если не заданы.

    Поля плоские (copy_script, copy_types, ...), а не вложенным объектом,
    чтобы их можно было править из бота: мастер ⚙️ Настройка спрашивает
    именно плоские поля.
    """
    scripts = copy_scripts(server)
    if not scripts:
        return None

    return {
        "scripts": scripts,
        # Типы берутся из самих скриптов: заданный скрипт и есть согласие
        # возить копии этого типа, а второго списка, который разъедется
        # с первым, лучше не заводить.
        "types": tuple(scripts.keys()),
        "auto": server.get("copy_after_backup", True) is not False,
        "delay_minutes": _minutes(server.get("copy_delay_minutes"), COPY_DELAY_MINUTES),
        "timeout_minutes": _minutes(server.get("copy_timeout_minutes"),
                                    COPY_TIMEOUT_MINUTES),
    }


def script_for(settings: dict, btype: str) -> str:
    """Каким скриптом везти копию этого типа."""
    return (settings.get("scripts") or {}).get(str(btype or "").upper()[:1], "")


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


def pick_ready_backups(rows: list, settings: dict) -> list:
    """Самые свежие законченные копии — по одной на каждый тип, который
    возим. Полная и разностная считаются отдельно: у них свои скрипты и
    своя очередь, и свежая разностная не отменяет неотправленную полную.

    Порядок — от самой свежей к старой: если ждут обе, первой поедет та,
    что закончилась позже.
    """
    best = {}
    for row in rows or []:
        btype = str(row.get("btype") or "").strip().upper()[:1]
        if btype not in settings["types"]:
            continue
        finished = parse_finished(row.get("finished"))
        if not finished:
            continue
        if btype not in best or finished > best[btype]["finished"]:
            best[btype] = {
                "db": row.get("db"),
                "type": btype,
                "finished": finished,
                "size_gb": row.get("size_gb"),
                "device": row.get("device"),
            }
    return sorted(best.values(), key=lambda i: i["finished"], reverse=True)


def pick_ready_backup(rows: list, settings: dict) -> dict:
    """Самая свежая законченная копия любого из возимых типов."""
    ready = pick_ready_backups(rows, settings)
    return ready[0] if ready else None


def sent_marker(state: dict, btype: str) -> str:
    """Отметка «эту копию уже отправили» — своя на каждый тип.

    Старый формат (одна строка на сервер) читается как отметка для всех
    типов сразу: иначе после обновления бот повёз бы заново то, что уже
    уехало.
    """
    last = (state or {}).get("last_finished")
    if isinstance(last, dict):
        return last.get(str(btype or "").upper()[:1])
    return last


def mark_sent(state: dict, btype: str, marker_text: str) -> dict:
    last = state.get("last_finished")
    if not isinstance(last, dict):
        # Переезд со старого формата: прежняя строка была отметкой для
        # всех типов, ею и остаётся, пока каждый тип не отметится своей.
        last = {t: last for t in ("D", "I", "L") if last}
    last[str(btype or "").upper()[:1]] = marker_text
    state["last_finished"] = last
    return state


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
    if not script_for(settings, ready["type"]):
        return False, f"для копий типа {ready['type']} скрипт не задан"

    marker_text = ready["finished"].strftime("%Y-%m-%d %H:%M:%S")
    if sent_marker(state, ready["type"]) == marker_text:
        return False, "эта копия уже отправлена"
    if state.get("run"):
        # Копирование грузит и сеть, и диск: два рейса разом идут вдвое
        # дольше каждый. Второй тип поедет следующим циклом.
        return False, "предыдущее копирование ещё идёт"

    waited = (now - ready["finished"]).total_seconds() / 60
    if waited < settings["delay_minutes"]:
        return False, f"копия закончена {round(waited)} мин назад, ждём дозаписи"
    if waited > COPY_FRESH_MINUTES:
        # Первый цикл после перезапуска монитора: состояние пустое, а в msdb
        # лежит вчерашняя копия. Её везти незачем — она давно уехала.
        return False, "копия слишком старая, копирование не нужно"

    return True, None


def next_to_send(rows: list, state: dict, settings: dict, now: datetime):
    """Что везти сейчас: (копия, причина отказа по самой свежей).

    Перебираются все ждущие типы, а не только самый свежий: пока едет
    разностная, полная не должна выпасть из очереди.
    """
    candidates = pick_ready_backups(rows, settings)
    if not candidates:
        return None, "в msdb нет законченных копий нужного типа"

    first_reason = None
    for ready in candidates:
        ok, reason = should_start(ready, state, settings, now)
        if ok:
            return ready, None
        if first_reason is None:
            first_reason = reason
        if reason == "предыдущее копирование ещё идёт":
            # Остальные типы всё равно подождут этого же рейса
            break
    return None, first_reason


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


# Куда складывать журнал запуска и код возврата. Каталог общий и
# предсказуемый: логи должны переживать перезапуск бота и открываться
# на сервере руками, когда захочется посмотреть глазами.
WORK_DIR_PS = "Join-Path $env:ProgramData 'bot\\copy'"

# Сколько строк журнала показывать в алерте. Больше — простыня в
# Telegram, меньше — не видно самой ошибки, она обычно в конце.
LOG_TAIL_LINES = 15

# Сколько байт хвоста журнала забирать с сервера. Читаем байтами, а не
# строками, ровно по одной причине: в одном файле лежат ДВЕ кодировки.
# Сам cmd пишет свои строки в кодировке консоли (обычно CP866), а WinSCP
# при перенаправлении вывода — в UTF-8. Любая единая кодировка при чтении
# превращает половину журнала в «РС‰Сѓ СЃРµСЂРІРµСЂ». Разбираем построчно.
LOG_TAIL_BYTES = 4096

# Сколько дней держать журналы рейсов на сервере. Файлы крошечные, но
# рейсов несколько в сутки, и без уборки каталог растёт вечно — а следом
# за ним и время листинга. Чистится при запуске очередного рейса: своего
# похода на сервер ради уборки не заводим.
LOG_KEEP_DAYS = int_env("BACKUP_COPY_LOG_KEEP_DAYS", 30)


def run_id(now: datetime = None, btype: str = None) -> str:
    """Имя пары файлов «журнал + код возврата» для одного рейса."""
    now = now or datetime.now()
    return f"{now.strftime('%Y%m%d-%H%M%S')}-{(btype or 'X').upper()[:1]}"


def _invocation(script: str) -> str:
    """Чем запускать: .ps1 — powershell, всё остальное — cmd напрямую."""
    if script.lower().endswith(".ps1"):
        return f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{script}"'
    return f'call "{script}"'


def launch_script_ps(script: str, ident: str) -> str:
    """PowerShell, который запускает скрипт копирования и СРАЗУ отдаёт PID.

    Ждать окончания нельзя: сессия WinRM живёт минуты, а копирование
    большой базы идёт часами. Поэтому процесс отвязывается — но одного
    PID мало: по нему видно только «что-то запущено». Скрипт, упавший на
    первой же строке (нет прав, нет сессии WinSCP, не смонтирован диск),
    для наблюдателя за PID выглядел бы точно так же, как идущая копия.

    Поэтому запуск идёт через cmd с перенаправлением: весь вывод — в
    журнал, код возврата — в файл-метку. Метка и есть ответ на вопрос
    «сработало ли», а журнал — на вопрос «почему нет».

    Собственный журнал скрипта это не отменяет и не трогает: сюда попадает
    то, что скрипт пишет в консоль (stdout и stderr), включая сообщения
    оболочки о том, что запуск вообще не состоялся, — их в журнале самого
    скрипта не будет по определению.

    Win32_Process.Create вместо Start-Process намеренно: он принимает одну
    строку командной строки целиком, и её не переписывает разбор массива
    аргументов — с перенаправлениями и кавычками это единственный
    предсказуемый способ.

    Две ловушки cmd, на которых это уже ломалось, — обе в одной строке:

    * `%ERRORLEVEL%` в составной команде подставляется при РАЗБОРЕ строки,
      то есть ДО запуска скрипта. Нужен `/v:on` и `!ERRORLEVEL!` —
      отложенная подстановка, в момент выполнения;
    * `echo !ERRORLEVEL!> файл` без пробела перед `>` — это не вывод в
      файл, а перенаправление ПОТОКА с таким номером: `0>` для cmd значит
      stdin. Файл-метка не появлялась вовсе, и удачный рейс выглядел как
      «процесс исчез, не дописав код возврата».
    """
    if '"' in script:
        raise ValueError("в пути к скрипту не должно быть кавычек")
    invoke = _invocation(script).replace("'", "''")
    return f"""
    $dir = {WORK_DIR_PS}
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
        Where-Object {{ $_.LastWriteTime -lt (Get-Date).AddDays(-{LOG_KEEP_DAYS}) }} |
        Remove-Item -Force -ErrorAction SilentlyContinue
    $log = Join-Path $dir '{ident}.log'
    $done = Join-Path $dir '{ident}.done'
    if (Test-Path -LiteralPath $done) {{ Remove-Item -LiteralPath $done -Force }}
    $line = 'cmd.exe /v:on /c {invoke} >> "' + $log + '" 2>&1 & echo !ERRORLEVEL! > "' + $done + '"'
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = $line }}
    ConvertTo-Json @{{ Pid = $r.ProcessId; Ret = $r.ReturnValue; Log = $log; Done = $done }} -Compress
    """


def check_run_ps(run: dict) -> str:
    """Что с рейсом: жив ли процесс, есть ли код возврата, что в журнале.

    Код возврата важнее живого процесса: появился файл-метка — рейс
    закончился, и дальше вопрос только в том, чем именно.

    Живой процесс сам по себе тоже ничего не доказывает: номера PID
    переиспользуются, и через пару часов под тем же номером работает
    чужая программа. Поэтому процесс опознаётся по номеру рейса в его
    командной строке — иначе закончившийся рейс висел бы «идёт» до
    самого таймаута.
    """
    pid = int(run.get("pid") or 0)
    done = str(run.get("done") or "").replace("'", "''")
    log = str(run.get("log") or "").replace("'", "''")
    # Номер рейса есть в командной строке запущенного процесса (он в путях
    # журнала и метки). По нему процесс и опознаётся: PID сам по себе
    # ничего не доказывает — номера переиспользуются, и через пару часов
    # под тем же номером работает чужая программа. Без этой проверки
    # закончившийся рейс мог висеть «идёт» до самого таймаута.
    ident = str(run.get("ident") or "").replace("'", "''")
    return PS_OUT_B64_HELPER + f"""
    $proc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId={pid}" -ErrorAction SilentlyContinue
    $alive = $false
    if ($proc) {{
        if ('{ident}') {{ $alive = ($proc.CommandLine -like '*{ident}*') }}
        else {{ $alive = $true }}
    }}
    $code = $null
    $tail = ''
    if ('{done}' -and (Test-Path -LiteralPath '{done}')) {{
        $code = (Get-Content -LiteralPath '{done}' -Raw -ErrorAction SilentlyContinue).Trim()
    }}
    if ('{log}' -and (Test-Path -LiteralPath '{log}')) {{
        try {{
            $fs = [IO.File]::Open('{log}', 'Open', 'Read', 'ReadWrite')
            $len = [Math]::Min($fs.Length, {LOG_TAIL_BYTES})
            $null = $fs.Seek(-$len, 'End')
            $buf = New-Object byte[] $len
            $null = $fs.Read($buf, 0, $len)
            $fs.Close()
            $tail = [Convert]::ToBase64String($buf)
        }} catch {{ $tail = '' }}
    }}
    Out-B64 @{{ Alive = $alive; Code = $code; TailB64 = $tail }}
    """


# Однобайтовые кодировки, в которых может оказаться строка от cmd:
# CP866 — кодировка консоли по умолчанию, CP1251 — если в скрипте
# стоит `chcp 1251` и сам .cmd сохранён в ней же. Обе «валидны» для
# любых байтов, поэтому выбирать приходится по виду результата.
FALLBACK_ENCODINGS = ("cp866", "cp1251")

# Кириллица и обычная пунктуация — признак того, что кодировку угадали.
# Промах даёт псевдографику (═ ╣ ▒) или мусор вроде «ЁЎ»: их здесь нет.
_CYRILLIC = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")


def _score(text: str) -> int:
    """Насколько текст похож на осмысленный русский. Считаем буквы:
    у промаха их почти нет — вместо них рамки и значки."""
    return sum(1 for char in text if char in _CYRILLIC)


def _decode_line(chunk: bytes) -> str:
    """Одна строка журнала → текст.

    Порядок такой: UTF-8 строгим разбором (в него мусор не пролезает,
    и если строка в нём читается — она в нём и записана), иначе выбор
    между CP866 и CP1251 по числу русских букв. Байты у них пересекаются
    полностью, отличить можно только по виду результата: CP1251-строка,
    прочитанная как CP866, превращается в псевдографику.
    """
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        pass
    best, best_score = None, -1
    for encoding in FALLBACK_ENCODINGS:
        text = chunk.decode(encoding, errors="replace")
        score = _score(text)
        if score > best_score:
            best, best_score = text, score
    return best


def decode_log_tail(b64: str, lines: int = None) -> str:
    """Хвост журнала из base64 → текст.

    Строки декодируются ПООТДЕЛЬНОСТИ: WinSCP при перенаправлении вывода
    пишет в UTF-8, а cmd — в кодировке консоли, и в одном файле они
    соседствуют. Единая кодировка при чтении превращает половину журнала
    в «РС‰Сѓ СЃРµСЂРІРµСЂ» — какую именно половину, зависит от того,
    какую кодировку выбрать.
    """
    lines = lines or LOG_TAIL_LINES
    try:
        raw = base64.b64decode(b64 or "", validate=True)
    except (binascii.Error, ValueError):
        return ""
    if not raw:
        return ""

    chunks = raw.split(b"\n")
    # Читали с конца файла по байтам: первая строка почти наверняка
    # обрезана посередине — и посередине символа тоже.
    if len(raw) >= LOG_TAIL_BYTES and len(chunks) > 1:
        chunks = chunks[1:]

    out = []
    for chunk in chunks:
        text = _decode_line(chunk).rstrip("\r")
        if text.strip():
            out.append(text)
    return "\n".join(out[-lines:])


def run_outcome(data: dict, run: dict) -> dict:
    """Вердикт по ответу сервера: {state, code, tail}.

    state: 'running' — рейс идёт; 'ok' — закончился успешно; 'failed' —
    закончился с ошибкой; 'lost' — процесса нет, а кода возврата не
    появилось (скрипт убили или сервер перезагрузили).
    """
    data = data or {}
    # Tail — старый формат (текст как есть), TailB64 — новый (байты).
    tail = (decode_log_tail(data.get("TailB64"))
            or (data.get("Tail") or "")).strip()
    code = data.get("Code")
    if code is not None and str(code).strip() != "":
        try:
            value = int(str(code).strip())
        except ValueError:
            value = None
        return {"state": "ok" if value == 0 else "failed",
                "code": value, "tail": tail}

    if data.get("Alive"):
        return {"state": "running", "code": None, "tail": tail}

    # Старые рейсы (заведённые до появления файла-метки) знают только PID.
    # Для них «процесса нет» — по-прежнему единственный признак конца.
    if not run.get("done"):
        return {"state": "ok", "code": None, "tail": tail}
    return {"state": "lost", "code": None, "tail": tail}


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


def find_server_loose(name: str) -> dict:
    """Сервер по имени, а если точного совпадения нет — по хосту или по
    началу имени.

    Имя приёмника человек вводит руками, и «is-cc» вместо
    «is-cc.rcku.net» — самая обычная описка. Отказ «такого сервера нет»
    в этом случае формально верен и совершенно бесполезен.
    """
    wanted = str(name or "").strip().lower()
    if not wanted:
        return None
    try:
        servers = load_servers()
    except Exception:
        return None

    for server in servers:
        if str(server.get("name") or "").lower() == wanted:
            return server
    for server in servers:
        if str(server.get("host") or "").lower() == wanted:
            return server
    matches = [s for s in servers
               if str(s.get("name") or "").lower().startswith(wanted + ".")]
    # Только когда совпадение одно: два сервера с общим началом имени —
    # повод спросить человека, а не угадывать за него.
    return matches[0] if len(matches) == 1 else None


def running_copy_ps(script: str) -> str:
    """PowerShell: не работает ли уже копирование этим скриптом.

    Ищем два вида процессов. Обёртка `cmd` называет сам скрипт в
    командной строке. А вот у самого WinSCP.com в командной строке
    скрипта нет — там временный файл задания и путь к журналу; журнал
    лежит рядом со скриптом, поэтому вторым признаком идёт каталог.
    Без него осиротевший WinSCP (родителя сняли, он остался) прошёл бы
    незамеченным — а он и есть самый опасный случай.
    """
    quoted = str(script).replace("'", "''")
    directory = str(script).replace("/", "\\").rsplit("\\", 1)[0].replace("'", "''")
    return PS_OUT_B64_HELPER + f"""
    $items = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {{ ($_.Name -eq 'cmd.exe' -or $_.Name -eq 'WinSCP.com') -and
                       $_.CommandLine -and
                       ($_.CommandLine -like '*{quoted}*' -or
                        $_.CommandLine -like '*{directory}*') }} |
        ForEach-Object {{ @{{ Pid = $_.ProcessId; Name = $_.Name; Cmd = $_.CommandLine }} }})
    Out-B64 @{{ Items = $items }}
    """


def running_copies(server: dict, script: str) -> list:
    """[{pid, name, cmd}] — копирования этим скриптом, идущие сейчас."""
    raw = run_ps(server["host"], running_copy_ps(script),
                 server.get("username"), server.get("password"))
    data = ps_json(raw) or {}
    items = data.get("Items") or []
    if isinstance(items, dict):
        items = [items]
    return [{"pid": int(i.get("Pid") or 0), "name": i.get("Name") or "",
             "cmd": i.get("Cmd") or ""} for i in items if i.get("Pid")]


def launch_copy(server: dict, settings: dict, ready: dict = None,
                by: str = "монитор") -> dict:
    """Запускает скрипт копирования на сервере-источнике и возвращает запись
    о запуске. Бросает исключение, если запустить не удалось.

    Ждать окончания нельзя: сессия WinRM живёт минуты, а копия едет часами,
    поэтому процесс отвязывается и дальше опознаётся по PID.
    """
    script = script_for(settings, (ready or {}).get("type")) or _only_script(settings)
    if not script:
        raise RuntimeError("не задан скрипт копирования для этого типа копии")
    # Предохранитель от второго рейса. Состояние в файле может разойтись
    # с действительностью — процесс убили руками, монитор перезапустили,
    # рейс сбросили кнопкой, — и тогда бот запустил бы копирование поверх
    # идущего. Две программы, дописывающие один файл на приёмнике, это
    # худшее, что может случиться с копией. Поэтому спрашиваем сервер.
    try:
        busy = running_copies(server, script)
    except Exception as e:
        # Не смогли спросить — не запускаем: цена ошибки здесь выше цены
        # задержки, следующий цикл попробует снова.
        raise RuntimeError(f"не проверить, не идёт ли уже копирование: "
                           f"{str(e).splitlines()[0][:150]}")
    if busy:
        where = ", ".join(f"{b['name']} PID {b['pid']}" for b in busy[:3])
        raise RuntimeError(f"копирование этим скриптом уже идёт на сервере "
                           f"({where}) — второй запуск испортил бы файл")

    ident = run_id(now_local(), (ready or {}).get("type"))
    raw = run_ps(server["host"], launch_script_ps(script, ident),
                 server.get("username"), server.get("password"))
    data = ps_json(raw) or {}
    pid = data.get("Pid")
    # ReturnValue Win32_Process.Create: 0 — процесс создан, всё прочее —
    # отказ (2 нет прав, 8 неизвестная ошибка, 9 путь не найден, 21 неверный
    # параметр). Без этой проверки отказ выглядел бы как удачный запуск.
    if data.get("Ret") not in (0, None):
        raise RuntimeError(f"сервер отказался запускать скрипт "
                           f"(Win32_Process.Create вернул {data['Ret']})")
    if not pid:
        raise RuntimeError("сервер не вернул PID запущенного скрипта")
    return {
        "pid": int(pid),
        "started": marker(now_local()),
        "source_finished": (marker(ready["finished"])
                            if (ready or {}).get("finished") else None),
        "db": (ready or {}).get("db"),
        "type": (ready or {}).get("type"),
        "size_gb": (ready or {}).get("size_gb"),
        "script": script,
        "log": data.get("Log"),
        "done": data.get("Done"),
        "ident": ident,
        "by": by,
    }


def _only_script(settings: dict) -> str:
    """Единственный скрипт сервера — для ручного запуска, когда тип не
    назван. Если скриптов несколько, тип обязателен: гадать, что человек
    имел в виду, нельзя."""
    scripts = list(dict.fromkeys((settings.get("scripts") or {}).values()))
    return scripts[0] if len(scripts) == 1 else ""


# ─── Сколько уже доехало ─────────────────────────────────────

def target_settings(server: dict) -> dict:
    """Куда этот источник возит копии: сервер-приёмник и корень на нём.

    Нужно ровно для одного — показать процент. У SFTP нет обратной связи
    о ходе передачи: сколько доехало, знает только приёмник, и спросить
    его можно, лишь зная, где там лежит файл.
    """
    name = str(server.get("copy_target") or "").strip()
    root = str(server.get("copy_target_root") or "").strip()
    if not name or not root:
        return None
    return {"server": name, "root": root.rstrip("\\")}


def target_path(root: str, remote: str) -> str:
    """`/new_pro_akt/FULL/файл.bak` + корень → путь на приёмнике."""
    tail = str(remote or "").replace("/", "\\").lstrip("\\")
    return f"{root}\\{tail}" if tail else ""


def file_size_ps(path: str) -> str:
    """Размер файла на приёмнике. Заодно смотрим `.filepart`: WinSCP
    пишет туда, пока файл не доехал, и переименовывает в конце."""
    quoted = str(path).replace("'", "''")
    return PS_OUT_B64_HELPER + f"""
    $size = $null
    foreach ($p in @('{quoted}', '{quoted}.filepart')) {{
        if (Test-Path -LiteralPath $p) {{
            $size = (Get-Item -LiteralPath $p -Force).Length
            break
        }}
    }}
    Out-B64 @{{ Size = $size }}
    """


def remote_file_size(server: dict, path: str):
    """Сколько байт уже лежит на приёмнике. None — файла ещё нет."""
    raw = run_ps(server["host"], file_size_ps(path),
                 server.get("username"), server.get("password"))
    data = ps_json(raw) or {}
    size = data.get("Size")
    return int(size) if size is not None else None


# ─── Чтение журналов скрипта с сервера ───────────────────────

def read_tail_ps(path: str, tail_bytes: int = None) -> str:
    """PowerShell: хвост файла байтами в base64.

    Байтами по той же причине, что и журнал бота: в одном файле
    соседствуют кодировка консоли и UTF-8 от WinSCP (см. decode_log_tail).
    Файл читается с общим доступом — его прямо сейчас может писать
    идущий рейс.
    """
    quoted = str(path).replace("'", "''")
    tail_bytes = tail_bytes or LOG_TAIL_BYTES
    return PS_OUT_B64_HELPER + f"""
    $tail = ''
    $size = 0
    if (Test-Path -LiteralPath '{quoted}') {{
        try {{
            $fs = [IO.File]::Open('{quoted}', 'Open', 'Read', 'ReadWrite')
            $size = $fs.Length
            $len = [Math]::Min($fs.Length, {tail_bytes})
            $null = $fs.Seek(-$len, 'End')
            $buf = New-Object byte[] $len
            $null = $fs.Read($buf, 0, $len)
            $fs.Close()
            $tail = [Convert]::ToBase64String($buf)
        }} catch {{ $tail = '' }}
    }}
    Out-B64 @{{ TailB64 = $tail; Size = $size }}
    """


def read_remote_log_info(server: dict, path: str, tail_bytes: int = None,
                         lines: int = 400) -> dict:
    """{"text", "size"} — хвост файла и его полный размер.

    Размер нужен не для красоты: журнал WinSCP на отладочном уровне
    вырастает до гигабайта на одну большую копию, и сказать об этом
    важнее, чем показать хвост.
    """
    raw = run_ps(server["host"], read_tail_ps(path, tail_bytes),
                 server.get("username"), server.get("password"))
    data = ps_json(raw) or {}
    size = int(data.get("Size") or 0)
    if not size:
        return {"text": "", "size": 0}
    return {"text": decode_log_tail(data.get("TailB64"), lines=lines),
            "size": size}


def clear_run(server_name: str) -> dict:
    """Забыть идущий рейс. Процесс на сервере при этом НЕ убивается —
    бот его не рождал управляемым и убивать чужую работу не должен.

    Нужна, когда состояние разошлось с действительностью: процесс убили
    руками, сервер перезагрузили, PID переиспользован. Без сброса сервер
    остался бы «вечно копирующим», и следующая копия не поехала бы.
    """
    state = load_state()
    entry = state.get(server_name) or {}
    run = entry.get("run")
    if not run:
        raise RuntimeError("для этого сервера копирование не числится идущим")
    entry["last_run"] = dict(run, ended=marker(now_local()), state="reset")
    entry["run"] = None
    state[server_name] = entry
    save_state(state)
    return run


def start_copy_now(server_name: str, by: str = "бот", btype: str = None) -> dict:
    """Ручной запуск копирования кнопкой в боте.

    btype нужен, когда у сервера скрипты разные для полной и разностной
    копии: гадать, что человек имел в виду, нельзя.

    Отметку `last_finished` НЕ трогаем: ручной запуск не отменяет обычного
    хода дел — если следом SQL закончит новую копию, её всё равно повезут.
    """
    server = find_server(server_name)
    if not server:
        raise RuntimeError(f"сервера {server_name} нет в конфиге")
    settings = copy_settings(server)
    if not settings:
        raise RuntimeError("у сервера не задан скрипт копирования (copy_script)")
    if btype and not script_for(settings, btype):
        raise RuntimeError(f"для копий типа {btype} скрипт не задан")

    state = load_state()
    entry = state.get(server_name) or {}
    if entry.get("run"):
        raise RuntimeError(
            f"копирование уже идёт с {entry['run'].get('started')} "
            f"(PID {entry['run'].get('pid')})"
        )

    ready = {"type": str(btype).upper()[:1]} if btype else None
    entry["run"] = launch_copy(server, settings, ready, by=by)
    state[server_name] = entry
    save_state(state)
    return entry["run"]
