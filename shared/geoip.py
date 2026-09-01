"""
shared/geoip.py

Страна, флаг и город по IP-адресу — для разделов, где адрес сам по себе
ничего не говорит: входы в OWA, сканирование IIS, неудачные пароли.

Три источника, строго в этом порядке:

1. **Свои метки подсетей** (`ip_labels`). Точнее любой геобазы и работают
   там, где геобазы бессильны: у 10.20.30.5 географии нет в принципе, а
   «🏢 Главный офис» — есть. Метку можно повесить и на внешний адрес: у
   филиала статический IP, и «🏢 Филиал» полезнее, чем «🇰🇿 Алматы».
2. **Кеш** (`ip_geo`). Адреса сотрудников меняются редко, а раздел
   открывают по многу раз в день.
3. **ip-api.com**, пачкой до 100 адресов за запрос.

Про третий пункт надо понимать прямо: это внешний сервис, и в него уходят
IP-адреса тех, кто заходил в почту. Своих адресов (RFC1918, CGNAT, ULA) он
не увидит — они отсекаются до запроса, и заодно потому, что ответить по ним
всё равно нечего. Выключается `GEOIP_ENABLED=false`: тогда остаются метки
подсетей, и раздел работает без единого внешнего запроса.

Обогащение никогда не должно ронять раздел: любая ошибка сети, таймаут или
недоступная база означают адрес без пометки, а не пустой экран.
"""
import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from pgconn import get_conn

_ready = False
_ready_lock = threading.Lock()

# Сети, у которых географии нет: спрашивать про них внешний сервис
# бессмысленно, а отправлять — незачем.
PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
                "fc00::/7", "fe80::/10", "::1/128")

BATCH_URL = "http://ip-api.com/batch?fields=status,country,countryCode,city,query"

# Сколько адресов уходит одним запросом. Потолок самого ip-api.
BATCH_SIZE = 100

# Держим ответ 90 дней: город по адресу меняется не чаще, чем провайдер
# перекраивает сети. Неудачу — сутки, чтобы не долбить сервис по кругу
# из-за одного адреса, о котором он не знает.
TTL_DAYS = 90
TTL_FAIL_DAYS = 1

# Таймаут маленький намеренно: это украшение экрана, и ждать его
# пользователь не должен. Не успели — покажем адрес без пометки.
TIMEOUT_SEC = 4

# Свободный тариф ip-api разрешает 15 запросов в минуту. Считаем свои и
# молча пропускаем обогащение, если упёрлись: остаться без флажка лучше,
# чем получить бан адреса сервера.
RATE_PER_MINUTE = 12

_calls = []
_calls_lock = threading.Lock()
_PRIVATE = None


def enabled() -> bool:
    return (os.getenv("GEOIP_ENABLED", "true").strip().lower()
            not in ("false", "0", "no", "off"))


def ensure_tables():
    global _ready
    if _ready:
        return
    with _ready_lock:
        if _ready:
            return
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_geo (
                    address      TEXT PRIMARY KEY,
                    country      TEXT,
                    country_code TEXT,
                    city         TEXT,
                    found        BOOLEAN NOT NULL DEFAULT FALSE,
                    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_labels (
                    network    TEXT PRIMARY KEY,
                    label      TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
        _ready = True


# ─── Свои и чужие адреса ─────────────────────────────────────

def is_private(address: str) -> bool:
    global _PRIVATE

    if _PRIVATE is None:
        _PRIVATE = [ipaddress.ip_network(n) for n in PRIVATE_NETS]
    try:
        parsed = ipaddress.ip_address((address or "").strip())
    except ValueError:
        return False
    return any(parsed in net for net in _PRIVATE)


def _valid(address: str) -> bool:
    try:
        ipaddress.ip_address((address or "").strip())
        return True
    except ValueError:
        return False


def flag(country_code: str) -> str:
    """Двухбуквенный код страны → эмодзи флага.

    Флаг собирается из двух regional indicator symbols, отдельной таблицы
    стран для этого не нужно: 'KZ' → 🇰🇿.
    """
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(ord(c) - ord("A") + 0x1F1E6) for c in code)


# ─── Метки подсетей ──────────────────────────────────────────

def list_labels() -> list:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT network, label FROM ip_labels ORDER BY network")
        return [{"network": row[0], "label": row[1]} for row in cur.fetchall()]


def add_label(network: str, label: str):
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO ip_labels (network, label) VALUES (%s, %s)
            ON CONFLICT (network) DO UPDATE SET label = EXCLUDED.label
        """, (network, label))


def remove_label(network: str) -> bool:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM ip_labels WHERE network = %s", (network,))
        return cur.rowcount > 0


def match_label(address: str, labels: list) -> str:
    """Метка самой узкой подходящей сети.

    Узкой, а не первой попавшейся: 10.0.0.0/8 «Вся сеть» и 10.20.30.0/24
    «Главный офис» могут быть заданы обе, и правильный ответ — второй.
    """
    if not _valid(address):
        return ""
    parsed = ipaddress.ip_address(address.strip())
    best, best_len = "", -1
    for item in labels or []:
        try:
            net = ipaddress.ip_network(item["network"])
        except ValueError:
            continue
        if parsed.version != net.version or parsed not in net:
            continue
        if net.prefixlen > best_len:
            best, best_len = item["label"], net.prefixlen
    return best


# ─── Кеш ─────────────────────────────────────────────────────

def _read_cache(addresses) -> dict:
    ensure_tables()
    fresh = datetime.now(timezone.utc) - timedelta(days=TTL_DAYS)
    fresh_fail = datetime.now(timezone.utc) - timedelta(days=TTL_FAIL_DAYS)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT address, country, country_code, city, found, updated_at
            FROM ip_geo WHERE address = ANY(%s)
        """, (list(addresses),))
        result = {}
        for address, country, code, city, found, updated in cur.fetchall():
            if found and updated < fresh:
                continue
            if not found and updated < fresh_fail:
                continue
            result[address] = {"country": country, "country_code": code,
                               "city": city, "found": found}
    return result


def _write_cache(rows: dict):
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        for address, item in rows.items():
            cur.execute("""
                INSERT INTO ip_geo (address, country, country_code, city,
                                    found, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (address) DO UPDATE
                  SET country = EXCLUDED.country,
                      country_code = EXCLUDED.country_code,
                      city = EXCLUDED.city,
                      found = EXCLUDED.found,
                      updated_at = NOW()
            """, (address, item.get("country"), item.get("country_code"),
                  item.get("city"), bool(item.get("found"))))


# ─── Внешний сервис ──────────────────────────────────────────

def _rate_ok() -> bool:
    now = time.monotonic()
    with _calls_lock:
        while _calls and now - _calls[0] > 60:
            _calls.pop(0)
        if len(_calls) >= RATE_PER_MINUTE:
            return False
        _calls.append(now)
    return True


def _fetch(addresses: list) -> dict:
    """Пачка адресов → {адрес: данные}. Ошибки не поднимаются наверх:
    раздел должен открыться и без пометок."""
    if not addresses or not _rate_ok():
        return {}
    body = json.dumps(addresses).encode()
    request = urllib.request.Request(
        BATCH_URL, data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SEC) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
        print(f"[geoip] Запрос не удался: {str(e)[:120]}", flush=True)
        return {}

    result = {}
    for item in payload if isinstance(payload, list) else []:
        address = item.get("query")
        if not address:
            continue
        ok = item.get("status") == "success"
        result[address] = {
            "country": item.get("country") if ok else None,
            "country_code": item.get("countryCode") if ok else None,
            "city": item.get("city") if ok else None,
            "found": ok,
        }
    return result


# ─── Основной вход ───────────────────────────────────────────

def resolve(addresses) -> dict:
    """{адрес: готовая пометка} для списка адресов.

    Один вызов на весь экран, а не по вызову на строку: иначе сорок
    адресов раздела почты — это сорок обращений к базе и сорок к сервису.
    """
    unique = [a for a in dict.fromkeys(
        str(a).strip() for a in addresses if a) if _valid(a)]
    if not unique:
        return {}

    try:
        labels = list_labels()
    except Exception as e:
        print(f"[geoip] Метки сетей недоступны: {str(e)[:120]}", flush=True)
        labels = []

    out, ask = {}, []
    for address in unique:
        label = match_label(address, labels)
        if label:
            out[address] = label
        elif is_private(address):
            out[address] = "🏢 локальная сеть"
        else:
            ask.append(address)

    if not ask or not enabled():
        return out

    try:
        cached = _read_cache(ask)
    except Exception as e:
        print(f"[geoip] Кеш недоступен: {str(e)[:120]}", flush=True)
        cached = {}

    missing = [a for a in ask if a not in cached]
    fetched = {}
    for start in range(0, len(missing), BATCH_SIZE):
        fetched.update(_fetch(missing[start:start + BATCH_SIZE]))
    if fetched:
        try:
            _write_cache(fetched)
        except Exception as e:
            print(f"[geoip] Кеш не записан: {str(e)[:120]}", flush=True)

    for address in ask:
        item = fetched.get(address) or cached.get(address)
        out[address] = describe(item)
    return out


def describe(item: dict) -> str:
    """Ответ сервиса → пометка вида «🇰🇿 Астана».

    Город без страны не показываем: одноимённых городов много, и «Астана»
    без флага читается хуже, чем ничего.
    """
    if not item or not item.get("found"):
        return ""
    mark = flag(item.get("country_code"))
    country = item.get("country") or ""
    city = (item.get("city") or "").strip()
    head = f"{mark} {city}" if city and mark else (mark or country)
    if city and not mark:
        head = f"{country} {city}".strip()
    return head.strip()


def tag(address: str, geo: dict) -> str:
    """Пометка для подстановки в строку: « · 🇰🇿 Астана» или пусто."""
    label = (geo or {}).get(str(address or "").strip())
    return f" · {label}" if label else ""
