"""
monitor/exchange_collector.py

Сводка почты Exchange для вкладки 📮 Почта: кто заходил в OWA, кто
ошибался паролем, чем ходят с телефонов.

Отдельный сборщик, а не чтение по нажатию, по той же причине, что и у
остальных разделов дашборда: один проход по логам IIS — это сотни
мегабайт строк и минуты ожидания, а отчёт рассылается по расписанию.

Раздел в карточке сервера (bot/exchange_bot.py) продолжает читать живьём:
там ждут ответа на конкретный вопрос и готовы подождать полминуты. Здесь
же нужна картина по всем серверам сразу, и она обязана быть уже готовой.

Алертов тут нет намеренно. Подбор пароля в Exchange виден в журнале
Security, и его разбирает общий сбор журналов Windows (log_collector) —
второй источник тревог по тому же событию означал бы двойные сообщения.
"""
import time
from concurrent.futures import ThreadPoolExecutor

from exchange_log import (
    has_exchange, is_service_client, read_activesync, read_owa_failures,
    read_owa_logins,
)
from exchange_track import read_tracking
from geoip import resolve as geo_resolve
from mail_store import SUMMARY_ROWS, save_snapshot
from settings import int_env


def _int_env(name: str, default: int) -> int:
    """settings.int_env с префиксом этого модуля в логе о некорректном значении."""
    return int_env(name, default, tag="exchange")


EXCHANGE_SCAN_MINUTES = _int_env("EXCHANGE_SCAN_MINUTES", 60)
MAX_PARALLEL_EXCHANGE_SERVERS = _int_env("MAX_PARALLEL_EXCHANGE_SERVERS", 2)

# Окно разбора — сутки: столько же показывает дашборд.
WINDOW_HOURS = 24

# Отказов входа с одного адреса на одну учётку за сутки, после которых это
# уже не «забыл пароль». Порог тот же, что у подбора в Zimbra по смыслу:
# человек ошибается несколько раз и идёт к администратору.
FAIL_ALERT = _int_env("EXCHANGE_FAIL_ALERT", 20)

# Писем в очереди транспорта. Здоровая очередь на живом сервере — единицы;
# сотни означают, что почта не уходит.
QUEUE_ALERT = _int_env("EXCHANGE_QUEUE_ALERT", 100)

# Писем от одного отправителя за сутки. Всплеск у своей учётки — первый
# признак того, что ею начали рассылать спам.
SEND_ALERT = _int_env("EXCHANGE_SEND_ALERT", 500)

_last_scan = None


def summary_for(owa: dict, eas: dict, failures: list, geo: dict = None,
                track: dict = None) -> dict:
    """Сводка одного сервера в общей для почты форме: kpis, groups, alarms.

    Чистая функция ради теста: правила здесь важнее, чем то, как читались
    логи.
    """
    owa = owa or {}
    eas = eas or {}
    failures = failures or []
    tag = {a: (geo or {}).get(a) or "" for a in geo or {}}

    def place(ip):
        return f" ({tag[ip]})" if tag.get(ip) else ""

    # Пробы Managed Availability из обзора убраны: HealthMailbox-* дёргают
    # каждый протокол раз в минуту и давали больше обращений, чем живые
    # пользователи, занимая треть списка телефонов.
    rows = [r for r in (owa.get("rows") or [])
            if not is_service_client(r.get("user"), r.get("ua"))]
    mobile = [r for r in (eas.get("rows") or [])
              if not is_service_client(r.get("user"), r.get("ua"))]
    users = {str(r.get("user") or "").lower() for r in rows} - {""}
    attempts = sum(int(r.get("count") or 0) for r in failures)
    brute = [r for r in failures if int(r.get("count") or 0) >= FAIL_ALERT]

    track = track or {}
    queue = track.get("queue")
    poison = track.get("poison") or 0

    # Плитки те же по смыслу, что у Zimbra: сначала объём почты, потом
    # состояние транспорта, потом безопасность. Пока трассировка не
    # читается (старый снимок, нет прав), верх занимают счётчики OWA —
    # прежнее поведение, а не пустые нули.
    kpis = []
    if track:
        kpis += [
            {"value": track.get("messages_in") or 0, "label": "писем принято",
             "level": "ok"},
            {"value": track.get("messages_out") or 0, "label": "отправлено",
             "level": "ok"},
            {"value": queue if queue is not None else "?", "label": "в очереди",
             "level": "warn" if (queue or 0) > QUEUE_ALERT else "ok"},
        ]
    else:
        kpis += [
            {"value": owa.get("scanned") or 0, "label": "обращений в OWA",
             "level": "ok"},
            {"value": len(users), "label": "пользователей", "level": "ok"},
            {"value": len(mobile), "label": "мобильных клиентов", "level": "ok"},
        ]
    kpis.append({"value": attempts, "label": "неверных паролей",
                 "level": "crit" if brute else "warn" if attempts else "ok"})

    groups = []

    def sender_rows(items):
        return [
            {"level": "warn" if (i.get("messages") or 0) >= SEND_ALERT else "ok",
             "left": str(i.get("messages") or 0),
             "title": i.get("sender") or "",
             # Голое число слева не читается: писем это или адресов?
             "detail": f"писем · на {i.get('recipients') or 0} адресов"}
            for i in items[:SUMMARY_ROWS]
        ]

    if track.get("senders_out"):
        groups.append({"title": "Кто отправляет", "level": "ok",
                       "rows": sender_rows(track["senders_out"])})
    if track.get("senders_in"):
        groups.append({"title": "Кто пишет вам", "level": "ok",
                       "rows": sender_rows(track["senders_in"])})
    if track.get("fail_reasons"):
        groups.append({"title": "Не доставлено", "level": "warn", "rows": [
            {"level": "warn", "left": str(i.get("count") or 0),
             "title": (i.get("reason") or "")[:90], "detail": ""}
            for i in track["fail_reasons"][:SUMMARY_ROWS]
        ]})

    if failures:
        groups.append({"title": "Пароль не подошёл", "level": "warn", "rows": [
            {"level": "crit" if int(r.get("count") or 0) >= FAIL_ALERT else "warn",
             "left": str(r.get("count") or 0),
             "title": f"{r.get('user') or 'неизвестный логин'} ← "
                      f"{r.get('ip') or 'адрес не записан'}" + place(r.get("ip")),
             "detail": r.get("reason") or f"код {r.get('code') or '?'}"}
            for r in failures[:SUMMARY_ROWS]
        ]})

    if rows:
        groups.append({"title": "Кто работает в OWA", "level": "ok", "rows": [
            {"level": "ok", "left": str(r.get("count") or 0),
             "title": f"{r.get('user') or '—'} ← {r.get('ip') or '—'}"
                      + place(r.get("ip")),
             "detail": r.get("last") or ""}
            for r in rows[:SUMMARY_ROWS]
        ]})

    if mobile:
        groups.append({"title": "Телефоны (ActiveSync)", "level": "ok", "rows": [
            {"level": "ok", "left": str(r.get("count") or 0),
             "title": r.get("user") or "—",
             "detail": (r.get("ua") or "")[:120]}
            for r in mobile[:SUMMARY_ROWS]
        ]})

    alarms = sorted({f"подбор пароля с {r.get('ip') or '?'}" for r in brute})
    if poison:
        alarms.append(f"{poison} писем в poison-очереди")
    if queue is not None and queue > QUEUE_ALERT:
        alarms.append(f"очередь {queue} при пороге {QUEUE_ALERT}")
    return {"kpis": kpis, "groups": groups, "alarms": alarms}


def collect_server(server: dict):
    """Три чтения одного сервера. Сбой одного не отменяет остальные: журнал
    Security читается, даже если каталог логов IIS не найден."""
    name = server["name"]
    owa, eas, failures, errors = {}, {}, [], []

    track = {}
    for label, call in (("OWA", lambda: read_owa_logins(server, WINDOW_HOURS)),
                        ("ActiveSync", lambda: read_activesync(server, WINDOW_HOURS)),
                        ("Security", lambda: read_owa_failures(server, WINDOW_HOURS)),
                        ("Трассировка", lambda: read_tracking(server, WINDOW_HOURS))):
        try:
            result = call()
        except Exception as e:
            errors.append(f"{label} — {str(e).splitlines()[0][:200]}")
            print(f"[exchange] {name}: {errors[-1]}", flush=True)
            continue
        if label == "OWA":
            owa = result
        elif label == "ActiveSync":
            eas = result
        elif label == "Security":
            failures = result
        else:
            track = result

    if not owa and not eas and not failures and not track:
        # Прежняя сводка остаётся, к ней дописывается причина: пустая
        # карточка выглядела бы как «в почту никто не заходил».
        save_snapshot(name, "exchange", None, error="; ".join(errors))
        return

    addresses = [r.get("ip") for r in (owa.get("rows") or []) + failures]
    try:
        geo = geo_resolve([a for a in addresses if a])
    except Exception:
        geo = {}
    save_snapshot(name, "exchange",
                  summary_for(owa, eas, failures, geo, track),
                  error="; ".join(errors))


def _collect_safe(server: dict):
    try:
        collect_server(server)
    except Exception as e:
        print(f"[exchange] ❌ {server.get('name')}: {e}", flush=True)


def exchange_scan_due(now: float, last: float) -> bool:
    if EXCHANGE_SCAN_MINUTES <= 0:
        return True
    if last is None:
        return True
    return now - last >= EXCHANGE_SCAN_MINUTES * 60


def run_exchange_cycle(servers: list, on_progress=None) -> int:
    work = [s for s in servers if has_exchange(s)]
    if not work:
        return 0

    with ThreadPoolExecutor(
        max_workers=min(MAX_PARALLEL_EXCHANGE_SERVERS, len(work))
    ) as pool:
        for _ in pool.map(_collect_safe, work):
            if on_progress:
                on_progress()

    print(f"[exchange] Почта собрана: серверов {len(work)}", flush=True)
    return len(work)


def maybe_run_exchange_cycle(servers: list, on_progress=None) -> bool:
    global _last_scan
    now = time.monotonic()
    if not exchange_scan_due(now, _last_scan):
        return False
    _last_scan = now
    run_exchange_cycle(servers, on_progress=on_progress)
    return True
