"""
shared/alerts_ack.py

Приём алертов: кнопка «Принято, не напоминать» под каждым сообщением.

Нужна, когда причина известна и уже устранена, а источник ещё какое-то
время отдаёт старые записи: джоб удалён, но его ошибки лежат в логе SQL
сутки; диск дочищается; служба выведена из эксплуатации.

Живёт в shared/, потому что участников двое и они в разных контейнерах:
монитор проверяет подавление перед отправкой и рисует кнопку, бот
обрабатывает нажатие. Общего у них только каталог /app/data.
"""
import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from settings import ALMATY

ACK_FILE = "/app/data/alert_ack.json"

# Сколько держится подавление. Сутки — практичный срок: за это время либо
# чинят, либо причина уходит сама (старые записи выпадают из логов).
ACK_HOURS = int(os.getenv("ALERT_ACK_HOURS", "24"))

# Метка бессрочного подавления вместо времени «до». Кнопка «Принял» в
# сводке проблем нужна для того, что не чинится за сутки и повторным
# напоминанием не станет полезнее: диск на 0% у списанной ВМ, служба,
# выведенная из эксплуатации. Снимается только вручную —
# ⚙️ Настройка → ✅ Принятые алерты.
ACK_FOREVER = "forever"

# callback_data ограничен 64 байтами, а ключ алерта содержит имя сервера,
# путь к бэкапу или имя службы. В кнопку кладём короткий хеш, а
# соответствие «хеш → ключ» пишем в файл: память у процессов разная.
ACK_HASH_LEN = 12

# Файл живёт годами; соответствия старых алертов чистим пачкой.
ACK_KEYS_MAX = 2000

_lock = threading.Lock()


def _load() -> dict:
    try:
        with open(ACK_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data.setdefault("keys", {})
    data.setdefault("acks", {})
    return data


def _save(data: dict):
    """Запись через временный файл: оборванная запись оставила бы битый
    JSON, и подавление молча перестало бы работать."""
    directory = os.path.dirname(ACK_FILE)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, ACK_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ack_hash(key: str) -> str:
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:ACK_HASH_LEN]


def register_ack_key(key: str) -> str:
    """Запоминает, какому алерту соответствует хеш в кнопке."""
    digest = ack_hash(key)
    with _lock:
        data = _load()
        if data["keys"].get(digest) != key:
            data["keys"][digest] = key
            if len(data["keys"]) > ACK_KEYS_MAX:
                for old in list(data["keys"])[:ACK_KEYS_MAX // 4]:
                    if old not in data["acks"]:
                        data["keys"].pop(old, None)
            _save(data)
    return digest


def _is_active(until: str, now_iso: str) -> bool:
    """ACK_FOREVER сравнивается с ISO как обычная строка: «f» больше любой
    цифры, поэтому бессрочное подавление активно всегда и сортируется в
    конец списка — отдельной ветки не нужно."""
    return bool(until) and until > now_iso


def is_acked(key: str) -> bool:
    """Подавлен ли этот алерт прямо сейчас."""
    if not key:
        return False
    until = _load()["acks"].get(ack_hash(key))
    return _is_active(until, datetime.now(timezone.utc).isoformat())


def active_ack_digests() -> set:
    """Хеши подавленных сейчас алертов — одним чтением файла.

    Сводка проблем проверяет несколько десятков ключей за раз, и is_acked
    на каждый означал бы столько же чтений одного и того же файла.
    """
    data = _load()
    now_iso = datetime.now(timezone.utc).isoformat()
    return {digest for digest, until in data["acks"].items()
            if _is_active(until, now_iso)}


def ack_alert(digest: str, hours: int = None, forever: bool = False) -> tuple:
    """Подавляет алерт по хешу из кнопки.

    Возвращает (ключ, до какого времени); для бессрочного подавления время
    None — «навсегда, пока не вернут вручную».
    """
    if forever:
        until_value, until_local = ACK_FOREVER, None
    else:
        hours = hours or ACK_HOURS
        until = datetime.now(timezone.utc) + timedelta(hours=hours)
        until_value, until_local = until.isoformat(), until.astimezone(ALMATY)
    with _lock:
        data = _load()
        key = data["keys"].get(digest)
        if key is None:
            return None, None
        data["acks"][digest] = until_value
        _save(data)
    return key, until_local


def ack_key_forever(key: str) -> str:
    """Подавляет алерт по самому ключу и навсегда — для кнопки «Принял»
    в сводке проблем, где ключ известен заранее и хеш регистрировать
    отдельно незачем."""
    digest = register_ack_key(key)
    ack_alert(digest, forever=True)
    return digest


def unack_alert(digest: str) -> str:
    """Снимает подавление досрочно."""
    with _lock:
        data = _load()
        key = data["keys"].get(digest)
        data["acks"].pop(digest, None)
        _save(data)
    return key


def active_acks() -> list:
    """Подавленные сейчас алерты — для списка в настройке."""
    data = _load()
    now = datetime.now(timezone.utc).isoformat()
    items = [
        {"digest": digest, "key": data["keys"].get(digest, "?"), "until": until,
         "forever": until == ACK_FOREVER}
        for digest, until in data["acks"].items() if _is_active(until, now)
    ]
    return sorted(items, key=lambda i: i["until"])


def purge_acks_for_server(server_name: str):
    """Убирает подавления сервера — при удалении его из конфига."""
    prefix_forms = (f"{server_name}:", f":{server_name}:")
    with _lock:
        data = _load()
        digests = [
            digest for digest, key in data["keys"].items()
            if key.startswith(server_name + ":")
            or any(form in key for form in prefix_forms)
        ]
        for digest in digests:
            data["keys"].pop(digest, None)
            data["acks"].pop(digest, None)
        if digests:
            _save(data)


def with_ack_button(reply_markup: dict, key: str) -> dict:
    """Добавляет к клавиатуре алерта кнопку «принято»."""
    digest = register_ack_key(key)
    button = {"text": f"✅ Принято, не напоминать {ACK_HOURS} ч",
              "callback_data": f"ack:{digest}"}
    keyboard = list((reply_markup or {}).get("inline_keyboard") or [])
    keyboard.append([button])
    return {"inline_keyboard": keyboard}
