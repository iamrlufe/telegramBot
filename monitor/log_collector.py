"""
monitor/log_collector.py

Сбор сводки журналов Windows и SQL в базу — чтобы дашборд читал готовое.

Раньше журналы существовали только в карточке сервера и читались живьём по
нажатию кнопки. В дашборде так нельзя: на десятке серверов это под сотню
удалённых вызовов, минуты ожидания и простукивание всей инфраструктуры при
каждой плановой рассылке. Здесь тот же сбор идёт в фоне, раз в
LOG_SCAN_MINUTES, и складывается снимком в log_events.

Журналы читаются реже метрик намеренно: диск заполняется в любую минуту, а
сводка за сутки от того, что её обновили час назад, не устаревает.
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor

from log_store import save_snapshot, save_failure
from log_summary import windows_events, sql_events
from server_check import server_type


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        print(f"[logs] Некорректный {name}={raw!r}, беру {default}", flush=True)
        return default


# Час по умолчанию: сводка показывается дважды в сутки, чаще читать журналы
# незачем. 0 — каждый цикл монитора.
LOG_SCAN_MINUTES = _int_env("LOG_SCAN_MINUTES", 60)
LOG_WINDOW_HOURS = _int_env("LOG_WINDOW_HOURS", 24)
MAX_PARALLEL_LOG_SERVERS = _int_env("MAX_PARALLEL_LOG_SERVERS", 4)

_last_scan = None


def log_scan_due(now: float, last: float) -> bool:
    """Пора ли читать журналы. Отдельной функцией ради теста: решение
    зависит только от времени."""
    if LOG_SCAN_MINUTES <= 0:
        return True
    if last is None:
        return True
    return now - last >= LOG_SCAN_MINUTES * 60


def collect_server(server: dict) -> list:
    """Оба источника одного сервера. Возвращает список того, что удалось
    прочитать: [(source, events, error)] либо [(source, None, error)], если
    сервер не ответил вовсе."""
    name = server.get("name")
    results = []

    if server_type(server) == "windows":
        try:
            events, problems = windows_events(server, hours=LOG_WINDOW_HOURS)
            results.append(("win", events, problems))
        except Exception as e:
            results.append(("win", None, str(e)))

    # dbsize и означает «здесь MSSQL» — тот же признак, по которому кнопка
    # SQL-логов появляется в карточке. Отдельного флага намеренно нет.
    if server.get("dbsize"):
        try:
            events, problems = sql_events(server, hours=LOG_WINDOW_HOURS)
            results.append(("sql", events, problems))
        except Exception as e:
            results.append(("sql", None, str(e)))

    return [(name, source, events, error) for source, events, error in results]


def _collect_safe(server: dict) -> list:
    try:
        return collect_server(server)
    except Exception as e:
        print(f"[logs] ❌ {server.get('name')}: {e}", flush=True)
        return []


def run_log_cycle(servers: list, on_progress=None):
    """Читает журналы у всех подходящих серверов и складывает снимками.

    Сервер, до которого не достучались, снимок не теряет: остаётся прошлый,
    а неудачная попытка отмечается в log_scans — дашборд подпишет данные
    как несвежие. Пустой экран вместо вчерашних записей был бы хуже.
    """
    work = [s for s in servers if server_type(s) == "windows" or s.get("dbsize")]
    if not work:
        return 0

    saved = 0
    with ThreadPoolExecutor(
        max_workers=min(MAX_PARALLEL_LOG_SERVERS, len(work))
    ) as pool:
        for results in pool.map(_collect_safe, work):
            for name, source, events, error in results:
                try:
                    if events is None:
                        save_failure(name, source, error)
                    else:
                        save_snapshot(name, source, events, error)
                        saved += 1
                except Exception as e:
                    print(f"[logs] ❌ {name}/{source}: запись не выполнена: {e}",
                          flush=True)
            if on_progress:
                on_progress()

    print(f"[logs] Сводка журналов обновлена: {saved} из {len(work)} серверов",
          flush=True)
    return saved


def maybe_run_log_cycle(servers: list, on_progress=None) -> bool:
    """Раз в LOG_SCAN_MINUTES, а не каждый цикл монитора."""
    global _last_scan
    now = time.monotonic()
    if not log_scan_due(now, _last_scan):
        return False
    _last_scan = now
    run_log_cycle(servers, on_progress=on_progress)
    return True
