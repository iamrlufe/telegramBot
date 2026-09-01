"""
monitor/iis_collector.py

Фоновый сбор сводки IIS: логи сайта по смещению, HTTPERR и конфигурация.

Раз в LOG_SCAN_MINUTES по умолчанию — тот же ритм, что у журналов Windows.
Стоит это дёшево именно из-за смещений: суточный файл читается целиком один
раз, дальше берётся только дописанное.

Сервер считается IIS-сервером, если среди его `services` есть `W3SVC` —
тот же принцип, что `dbsize` для MSSQL и `MSExchange*` для почты. Ничего
дописывать в servers.json не требуется.
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor

from alerts import check_iis_alerts
from iis_log import read_site_logs, read_httperr_and_config, SLOW_MS
from iis_store import (
    load_state, save_state, save_events, save_fact, cleanup, iis_findings,
)
from server_check import server_type

IIS_SERVICE = "w3svc"


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        print(f"[iis] Некорректный {name}={raw!r}, беру {default}", flush=True)
        return default


IIS_SCAN_MINUTES = _int_env("IIS_SCAN_MINUTES", 60)
IIS_SLOW_MS = _int_env("IIS_SLOW_MS", SLOW_MS)
MAX_PARALLEL_IIS_SERVERS = _int_env("MAX_PARALLEL_IIS_SERVERS", 2)

_last_scan = None


def has_iis(server: dict) -> bool:
    if server_type(server) != "windows":
        return False
    services = [str(s).lower() for s in (server.get("services") or [])]
    return IIS_SERVICE in services


def iis_scan_due(now: float, last: float) -> bool:
    """Отдельной функцией ради теста: решение зависит только от времени."""
    if IIS_SCAN_MINUTES <= 0:
        return True
    if last is None:
        return True
    return now - last >= IIS_SCAN_MINUTES * 60


def _rows_from_site(data: dict) -> list:
    """Ответ скрипта → строки счётчиков для базы."""
    rows = [
        ("total", "requests", data.get("total") or 0),
        ("total", "alien", data.get("alien") or 0),
        ("total", "slow", data.get("slow") or 0),
    ]
    lists = {
        "alienuri": "alienuris", "pub": "pubs", "scan": "scan",
        "hit": "hits", "login": "logins", "ip": "ips", "error": "errors",
        "slowuri": "slows", "hour": "hours",
    }
    for category, key in lists.items():
        for row in data.get(key) or []:
            item = row.get("k")
            if item is None:
                continue
            rows.append((category, item, row.get("n") or 0))
    return rows


def _rows_from_extra(data: dict) -> list:
    rows = []
    for row in data.get("reasons") or []:
        if row.get("k") is not None:
            rows.append(("herr", row["k"], row.get("n") or 0))
    for row in data.get("details") or []:
        if row.get("k") is not None:
            rows.append(("herrd", row["k"], row.get("n") or 0))
    return rows


def collect_server(server: dict) -> tuple:
    """Оба вызова к одному серверу. Возвращает (имя, строки, факты, ошибка)."""
    name = server["name"]
    rows, facts, problems = [], {}, []

    try:
        state = load_state(name, "site")
        data = read_site_logs(server, state, slow_ms=IIS_SLOW_MS)
        rows.extend(_rows_from_site(data))
        save_state(name, "site", data.get("state") or {})
    except Exception as e:
        problems.append(f"логи сайта: {str(e).splitlines()[0][:200]}")

    try:
        state = load_state(name, "httperr")
        extra = read_httperr_and_config(server, state)
        rows.extend(_rows_from_extra(extra))
        save_state(name, "httperr", extra.get("state") or {})
        facts["apps"] = extra.get("apps") or []
        facts["pools"] = extra.get("pools") or []
        facts["logs_mb"] = extra.get("logs_mb") or 0
        facts["oldest_log"] = extra.get("oldest") or ""
    except Exception as e:
        problems.append(f"HTTPERR и конфигурация: {str(e).splitlines()[0][:200]}")

    return name, rows, facts, "; ".join(problems)


def _collect_safe(server: dict) -> tuple:
    try:
        return collect_server(server)
    except Exception as e:
        print(f"[iis] ❌ {server.get('name')}: {e}", flush=True)
        return server.get("name"), [], {}, str(e)[:200]


def run_iis_cycle(servers: list, on_progress=None) -> int:
    """Обходит серверы с IIS и складывает счётчики.

    Сбой одного вызова не отменяет второй: HTTPERR и конфигурация читаются,
    даже если логи сайта недоступны по правам, — и наоборот.
    """
    work = [s for s in servers if has_iis(s)]
    if not work:
        return 0

    saved = 0
    with ThreadPoolExecutor(
        max_workers=min(MAX_PARALLEL_IIS_SERVERS, len(work))
    ) as pool:
        for name, rows, facts, error in pool.map(_collect_safe, work):
            try:
                if rows:
                    save_events(name, rows)
                    saved += 1
                for fact, value in facts.items():
                    save_fact(name, fact, value)
                save_fact(name, "scan", {"ok": not error}, error=error)
            except Exception as e:
                print(f"[iis] ❌ {name}: запись не выполнена: {e}", flush=True)
            if on_progress:
                on_progress()

    # Находки считаются после записи: правило перебора смотрит на последний
    # час, и без свежих строк оно ничего не увидит.
    try:
        check_iis_alerts(iis_findings())
    except Exception as e:
        print(f"[iis] Алерты не отправлены: {e}", flush=True)

    try:
        cleanup()
    except Exception as e:
        print(f"[iis] Очистка счётчиков не выполнена: {e}", flush=True)

    print(f"[iis] Сводка IIS обновлена: {saved} из {len(work)} серверов", flush=True)
    return saved


def maybe_run_iis_cycle(servers: list, on_progress=None) -> bool:
    global _last_scan
    now = time.monotonic()
    if not iis_scan_due(now, _last_scan):
        return False
    _last_scan = now
    run_iis_cycle(servers, on_progress=on_progress)
    return True
