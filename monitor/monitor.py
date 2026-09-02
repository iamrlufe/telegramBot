import json
import time
import os
import subprocess
import tempfile
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from server_check import check_server, server_type
from service_details import save_details_from_info
from winrm_errors import parse_status
from backup_collector import run_backup_cycle
from log_collector import maybe_run_log_cycle
from iis_collector import maybe_run_iis_cycle
from firewall_maintenance import run_firewall_expiry
from zimbra_collector import maybe_run_zimbra_cycle
from exchange_collector import maybe_run_exchange_cycle
from log_store import forget_server as forget_log_events
from iis_store import forget_server as forget_iis_data
from firewall_store import forget_server as forget_firewall_data
from mail_store import forget_server as forget_mail_data
from backup_maintenance import run_backup_maintenance
from db import (
    ensure_time_indexes,
    save_disk_metrics,
    save_server_status,
    save_service_statuses,
    save_process_metrics,
    get_disk_free_history,
    cleanup_removed_servers,
    cleanup_old_data
)
from disk_forecast import free_space_trend
from disk_health import purge_disk_health, save_disk_health
from settings import SERVERS_FILE, int_env
from alerts import (
    check_disk_alert,
    check_disk_forecast_alert,
    check_snapshot_alerts,
    check_disk_temp_alert,
    check_raid_alert,
    alert_server_online,
    alert_server_offline,
    alert_server_down,
    check_cpu_alert,
    check_ram_alert,
    check_service_alert,
    check_docker_alerts,
    check_smart_alert,
    check_time_drift,
    flush_deferred,
    notify_quiet_hours_start,
    purge_server_state,
    send_or_defer,
    load_json,
    save_json,
    DEFERRED_FILE,
    ALMATY,
)


def _int_env(name: str, default: int) -> int:
    """settings.int_env с префиксом этого модуля в логе о некорректном значении."""
    return int_env(name, default, tag="monitor")


# Основной цикл опроса серверов.
INTERVAL = _int_env("CHECK_INTERVAL_SECONDS", 300)

# Через сколько минут застывшего пульса процесс убивает себя сам.
# Docker не перезапускает контейнер за то, что healthcheck стал unhealthy —
# он лишь показывает состояние. Зависший монитор молчал бы вечно, а молчащий
# монитор хуже шумного: с restart: unless-stopped выход поднимает его заново.
# 0 — выключить самоубийство (например, при отладке).
STALL_EXIT_MINUTES = _int_env("MONITOR_STALL_EXIT_MINUTES", 30)
RETRY_DELAY = 30       # пауза перед повторной попыткой WinRM (сек)
RETRY_COUNT = 2        # количество попыток WinRM перед алертом офлайн
MAX_PARALLEL_CHECKS = 5   # сколько серверов опрашиваем одновременно

# Пинг — чистое ожидание ответа, поэтому потоков берём больше, чем на полный
# опрос: недоступный хост стоит до 4 секунд, и в один поток цикл из десятка
# серверов переставал укладываться в интервал.
MAX_PARALLEL_PINGS = 16

# Как часто пингуем, когда всё в порядке.
PING_INTERVAL = _int_env("PING_INTERVAL_SECONDS", 30)

# Как часто, когда кто-то не отвечает. Пока сервер лежит, важны обе границы:
# быстрее объявить падение и не проспать момент, когда он поднялся. Пинг
# дешёвый и идёт во все хосты разом, поэтому учащение почти ничего не стоит.
PING_DOWN_INTERVAL = _int_env("PING_DOWN_INTERVAL_SECONDS", 10)

# Сколько секунд подряд хост должен молчать, чтобы это считалось падением.
# Раньше порог считался в попытках (15 штук) и молча зависел от интервала:
# опрос замедлялся — и «7,5 минут» превращались в десять. Время честнее.
PING_FAIL_SECONDS = _int_env("PING_FAIL_SECONDS", 120)


DISK_STATE_FILE = "/app/data/disk_alert_state.json"
SERVER_STATE_FILE = "/app/data/server_alert_state.json"
ALERTS_DISABLED_FILE = "/app/data/alerts_disabled.json"
CLEANUP_STATE_FILE = "/app/data/last_cleanup.txt"
CPU_STATE_FILE = "/app/data/cpu_alert_state.json"
RAM_STATE_FILE = "/app/data/ram_alert_state.json"
HEARTBEAT_FILE = "/app/data/heartbeat"
SELF_REPORT_STATE_FILE = "/app/data/self_report_state.json"

# Сколько дней держим историю. Отдельный, более короткий срок — у таблиц,
# из которых читается только последняя запись (службы и топ процессов):
# история там не используется нигде, а места занимала больше половины базы.
RETAIN_DAYS = _int_env("RETAIN_DAYS", 30)
SNAPSHOT_RETAIN_DAYS = _int_env("SNAPSHOT_RETAIN_DAYS", 3)


# Как часто обходить каталоги бэкапов. Копия появляется раз в сутки, а обход
# каталога на NAS — это удалённая сессия на каждый путь и десятки тысяч файлов
# в выдаче; делать это каждые 5 минут значит греть хранилище и писать в базу
# 288 одинаковых замеров в сутки на каждый путь. 0 — как раньше, каждый цикл.
BACKUP_SCAN_MINUTES = _int_env("BACKUP_SCAN_MINUTES", 30)

# Момент последнего обхода бэкапов (monotonic). None — ещё не было: первый
# цикл после старта собирает метрики сразу, ждать полчаса незачем.
_last_backup_scan = None

# Ежедневный отчёт «монитор жив»: час по Алматы. Пусто в .env — выключено.
SELF_REPORT_HOUR = os.getenv("SELF_REPORT_HOUR", "9").strip()

# Итог последнего цикла для самоотчёта: {"online", "offline", "total"}
_last_cycle_tally: dict = {}

# Пинг-состояние в памяти: с какого момента (monotonic) хост молчит и по кому
# уже отправлен алерт. Монотонные часы, а не системные: перевод времени на
# хосте не должен ни поднимать ложную тревогу, ни прятать настоящую.
_ping_fail_since: dict = {}   # { server_name: monotonic первого промаха }
_ping_down: set = set()       # { server_name } — падение уже объявлено
_ping_lock = threading.Lock()


def touch_heartbeat():
    """Обновляет файл-пульс: docker healthcheck проверяет его свежесть.

    Вызывается не только в конце цикла, но и по ходу — после каждого
    опрошенного сервера. Иначе долгий, но живой цикл (десяток серверов с
    таймаутами плюс обход бэкапов) выглядел для healthcheck зависшим.

    Запись через временный файл: пульс трогают несколько потоков сразу, и
    оборванная запись оставила бы пустой файл — то есть ложную тревогу."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(HEARTBEAT_FILE))
        with os.fdopen(fd, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())
        os.replace(tmp, HEARTBEAT_FILE)
    except OSError as e:
        print(f"[monitor] Не удалось обновить heartbeat: {e}", flush=True)
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def ping_host(host: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4
        )
        return result.returncode == 0
    except Exception:
        return False


def load_servers() -> list:
    with open(SERVERS_FILE) as f:
        return json.load(f)


def run_server_checks(servers: list) -> dict:
    """Опрос серверов пулом потоков; неудачные повторяются отдельным проходом.

    Раньше повтор жил внутри воркера: поток засыпал на RETRY_DELAY, не
    отпуская слот пула. Один сервер с живым ping и сломанным WinRM держал
    пятую часть параллелизма полминуты, а при нескольких таких очередь
    вставала. Теперь пауза одна на весь проход и берётся между проходами.

    Возвращает {имя сервера: "online" | "offline"}.
    """
    pending = list(servers)
    outcomes = {}

    for attempt in range(1, RETRY_COUNT + 1):
        # На последней попытке process_server уже шлёт алерт офлайна
        final = attempt == RETRY_COUNT

        def check(server, final=final):
            outcome = process_server(server, final=final)
            # Пульс по ходу дела: цикл из десятка серверов с таймаутами живой,
            # но длинный, и без этого healthcheck считал бы его зависшим
            touch_heartbeat()
            return outcome

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_CHECKS) as pool:
            results = list(pool.map(check, pending))

        retry = []
        for server, outcome in zip(pending, results):
            if outcome == "retry":
                retry.append(server)
            else:
                outcomes[server["name"]] = outcome

        pending = retry
        if not pending:
            break

        names = ", ".join(server["name"] for server in pending)
        print(
            f"  ⏳ Повтор через {RETRY_DELAY} сек "
            f"(попытка {attempt + 1}/{RETRY_COUNT}): {names}",
            flush=True
        )
        time.sleep(RETRY_DELAY)

    return outcomes


def maybe_cleanup():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        with open(CLEANUP_STATE_FILE) as f:
            last = f.read().strip()
        if last == today:
            return
    except FileNotFoundError:
        pass

    print(
        f"[monitor] Очистка: история {RETAIN_DAYS} дней, "
        f"службы и процессы {SNAPSHOT_RETAIN_DAYS}...",
        flush=True
    )
    (
        deleted_metrics, deleted_status, deleted_services, deleted_processes,
        deleted_backups, deleted_db_sizes, deleted_onec_logs
    ) = cleanup_old_data(RETAIN_DAYS, SNAPSHOT_RETAIN_DAYS)
    print(
        f"[monitor] Удалено: {deleted_metrics} метрик, "
        f"{deleted_status} статусов, {deleted_services} сервисов, "
        f"{deleted_processes} процессов, {deleted_backups} backup-записей, "
        f"{deleted_db_sizes} database_sizes, {deleted_onec_logs} onec_log_metrics",
        flush=True
    )

    with open(CLEANUP_STATE_FILE, "w") as f:
        f.write(today)


def run_ping_cycle():
    try:
        servers = load_servers()
    except Exception as e:
        print(f"[ping] Не могу прочитать {SERVERS_FILE}: {e}", flush=True)
        return

    if not servers:
        return

    # Сначала пингуем все хосты разом, потом разбираем результаты по очереди:
    # решения об алертах остаются в одном потоке, как и раньше.
    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_PINGS, len(servers))) as pool:
        alive_flags = list(pool.map(lambda s: ping_host(s["host"]), servers))

    now = time.monotonic()

    for server, is_alive in zip(servers, alive_flags):
        name = server["name"]
        host = server["host"]

        # Решение принимаем под блокировкой, медленный I/O (БД, Telegram) — вне её
        with _ping_lock:
            if is_alive:
                action = "recovered" if name in _ping_down else None
                _ping_fail_since.pop(name, None)
                _ping_down.discard(name)
                silent_for = 0
            else:
                since = _ping_fail_since.setdefault(name, now)
                silent_for = now - since
                if name in _ping_down:
                    action = "still_down"
                elif silent_for >= PING_FAIL_SECONDS:
                    _ping_down.add(name)
                    action = "down"
                else:
                    action = "failing"

        if action == "recovered":
            print(f"[ping] ВОССТАНОВЛЕН {name} ({host})", flush=True)
            save_server_status(name, "online", error="Ping восстановлен")
            alert_server_online(server)
        elif action == "down":
            print(f"[ping] DOWN {name} ({host}) — молчит {round(silent_for)} сек",
                  flush=True)
            save_server_status(name, "ping_down", error="Ping не отвечает")
            alert_server_down(server)
        elif action == "still_down":
            print(f"[ping] Всё ещё недоступен {name} ({host})", flush=True)
        elif action == "failing":
            print(
                f"[ping] НЕТ ОТВЕТА {name} ({host}) — "
                f"{round(silent_for)}/{PING_FAIL_SECONDS} сек",
                flush=True
            )


def ping_interval() -> int:
    """Пауза до следующего круга пингов.

    Пока хоть один хост молчит, круг идёт чаще: это одновременно ускоряет
    объявление падения и, главное, ловит момент, когда сервер поднялся, —
    ждать общие полминуты, когда человек стоит рядом с сервером и ждёт
    подтверждения, незачем.
    """
    with _ping_lock:
        troubled = bool(_ping_fail_since)
    return PING_DOWN_INTERVAL if troubled else PING_INTERVAL


def ping_loop():
    while True:
        try:
            run_ping_cycle()
        except Exception as e:
            print(f"[ping] Ошибка цикла: {e}", flush=True)
        time.sleep(ping_interval())


def process_server(server: dict, final: bool = True):
    """Полная проверка одного сервера (выполняется в пуле потоков).

    final=False — это не последняя попытка: неудача возвращается как "retry",
    без записи статуса и алерта, и сервер уходит в следующий проход.
    """
    name = server["name"]
    host = server["host"]
    print(f"[monitor] Проверяю: {name} ({host})", flush=True)

    if server_type(server) == "device":
        # Сетевое устройство: только ping. Алерты о падении/восстановлении
        # шлёт ping_loop, здесь лишь фиксируем свежий статус в БД.
        if ping_host(host):
            print(f"  📡 {name}: устройство отвечает на ping", flush=True)
            save_server_status(name, "online")
            alert_server_online(server)
            return "online"
        print(f"  📡 {name}: устройство не отвечает на ping", flush=True)
        return "offline"

    try:
        if not ping_host(host):
            # В основном цикле просто логируем — алерт идёт из ping_loop
            print(f"[monitor] Пинг не прошёл {name}, пропускаю WinRM", flush=True)
            return "offline"

        info = check_server(server)

        # Замеры пишем одной вставкой до проверок, а не по диску внутри цикла:
        # прогноз заполнения читает историю из БД и должен видеть текущий замер,
        # поэтому запись обязана идти раньше check_disk_forecast_alert.
        save_disk_metrics(name, [
            (disk["Name"], float(disk["FreeGB"]), float(disk["UsedGB"]))
            for disk in info["disks"]
        ])

        kind = server_type(server)
        for disk in info["disks"]:
            free = float(disk["FreeGB"])
            used = float(disk["UsedGB"])
            print(f"  💽 {name} {disk['Name']}: free={free}GB used={used}GB", flush=True)
            check_disk_alert(name, disk, kind)

            # Прогноз заполнения — по истории из БД, уже с учётом только что
            # сохранённого замера. Ошибку глушим: без прогноза мониторинг
            # диска работает как раньше.
            try:
                trend = free_space_trend(get_disk_free_history(name, disk["Name"]))
                if trend and trend.get("shrinking"):
                    print(
                        f"  📉 {name} {disk['Name']}: "
                        f"{trend['slope_gb_per_day']:+.2f} ГБ/сут, "
                        f"хватит на {round(trend['days_left'])} дн",
                        flush=True
                    )
                check_disk_forecast_alert(name, disk["Name"], trend, kind)
            except Exception as e:
                print(f"  ⚠️ {name} {disk['Name']}: прогноз не построен: {e}", flush=True)

        uptime_hours = round(info["uptime_seconds"] / 3600, 1) if info["uptime_seconds"] else 0
        print(
            f"  🖥 {name}: CPU={info['cpu_load']}% RAM free={info['ram_free']}GB "
            f"uptime={uptime_hours}h",
            flush=True
        )

        save_server_status(
            name, "online",
            cpu_load=info["cpu_load"],
            ram_total=info["ram_total"],
            ram_free=info["ram_free"],
            uptime_seconds=info["uptime_seconds"]
        )
        alert_server_online(server)
        check_cpu_alert(name, info["cpu_load"])
        check_ram_alert(name, info["ram_total"], info["ram_free"])
        save_process_metrics(name, "cpu", info.get("top_cpu", []))
        save_process_metrics(name, "memory", info.get("top_memory", []))

        # Детали сервисов (контейнеры Docker, сайты веб-серверов) — для бота
        save_details_from_info(name, info)

        check_smart_alert(name, info.get("unhealthy_disks") or [])
        check_disk_temp_alert(name, info.get("disk_temps") or [])

        raid_arrays = info.get("raid_arrays") or []
        for array in raid_arrays:
            if array.get("degraded"):
                print(
                    f"  🚨 {name} RAID {array['name']}: деградирован "
                    f"({array.get('active')}/{array.get('total')})",
                    flush=True
                )
        check_raid_alert(name, raid_arrays)

        # Почему SMART не собрался (нет sudo без пароля / нет smartctl) —
        # пишем в лог, но не алертим: это настройка, а не авария
        smart_note = info.get("smart_note")
        if smart_note:
            print(f"  ⚠️ {name}: {smart_note}", flush=True)

        # Состояние дисков — на общий том, чтобы бот показывал его в карточке
        # (алерты приходят только при поломке, а видеть текущее надо всегда)
        save_disk_health(
            name,
            raid=raid_arrays,
            temps=info.get("disk_temps") or [],
            smart_note=smart_note,
        )
        check_time_drift(name, info.get("server_time_utc"))
        if info.get("docker_containers") is not None:
            check_docker_alerts(name, info["docker_containers"])

        service_rows = []
        for service in info.get("services", []):
            service_name = service.get("Name")
            if not service_name:
                continue
            service_rows.append((
                service_name,
                service.get("Label") or service.get("DisplayName") or service_name,
                service.get("Status", "unknown"),
            ))
        save_service_statuses(name, service_rows)

        for service in info.get("services", []):
            service_name = service.get("Name")
            if not service_name:
                continue

            print(f"  ⚙️ {name} {service_name}: {service.get('Status', 'unknown')}", flush=True)
            check_service_alert(name, service)

        # Снапшоты приходят только от VMware — у остальных типов ключа нет
        if info.get("snapshots") is not None:
            print(
                f"  📸 {name}: ВМ {info.get('vm_count', 0)}, "
                f"хостов {info.get('host_count', 0)}, "
                f"снапшотов {len(info['snapshots'])}",
                flush=True
            )
            check_snapshot_alerts(
                name,
                info["snapshots"],
                max_age_days=server.get("snapshot_alert_days"),
                max_size_gb=server.get("snapshot_alert_gb"),
            )

        return "online"

    except Exception as e:
        error_str = str(e)
        if not final:
            print(f"  ⚠️ {name}: попытка не удалась: {error_str}", flush=True)
            return "retry"
        status = parse_status(error_str)
        print(f"[monitor] ОФЛАЙН {name}: {status}", flush=True)
        save_server_status(name, status, error=error_str)
        alert_server_offline(server, error_str)
        return "offline"


def _self_report_hour() -> int | None:
    """Час самоотчёта из SELF_REPORT_HOUR или None, если выключен/некорректен."""
    if not SELF_REPORT_HOUR:
        return None
    try:
        hour = int(SELF_REPORT_HOUR)
    except ValueError:
        return None
    return hour if 0 <= hour <= 23 else None


def maybe_send_self_report(now: datetime = None):
    """Раз в сутки, в час SELF_REPORT_HOUR (Алматы), шлёт «монитор жив» со
    сводкой по последнему циклу. Защита от повтора — дата в state-файле."""
    hour = _self_report_hour()
    if hour is None:
        return

    now = now or datetime.now(ALMATY)
    if now.hour != hour:
        return

    today = now.strftime("%Y-%m-%d")
    state = load_json(SELF_REPORT_STATE_FILE)
    if state.get("date") == today:
        return

    tally = _last_cycle_tally
    total = tally.get("total", 0)
    online = tally.get("online", 0)
    offline = tally.get("offline", 0)
    deferred = len(load_json(DEFERRED_FILE).get("items", []))

    lines = [
        "🩺 AgentMonitor жив",
        f"🖥 Серверов: {total}",
        f"🟢 Онлайн: {online}   🔴 Офлайн: {offline}",
    ]
    if deferred:
        lines.append(f"🌙 Отложенных алертов: {deferred}")
    if offline:
        lines.append("\n⚠️ Есть недоступные — загляни в 🚨 Проблемы")

    try:
        # через send_or_defer: если час самоотчёта попал в тихие часы,
        # он тоже дождётся утра — ночью бот молчит полностью
        send_or_defer("\n".join(lines))
    finally:
        save_json_safe(SELF_REPORT_STATE_FILE, {"date": today})


def save_json_safe(path: str, data: dict):
    """Та же атомарная запись, что и в alerts.save_json, но сбой записи только
    логируется: отметка о самоотчёте не стоит падения цикла мониторинга."""
    try:
        save_json(path, data)
    except OSError as e:
        print(f"[monitor] Не удалось записать {path}: {e}", flush=True)


def backup_scan_due(now: float, last: float) -> bool:
    """Пора ли обходить каталоги бэкапов. Вынесено отдельно ради теста:
    решение зависит только от времени, а не от состояния монитора."""
    if BACKUP_SCAN_MINUTES <= 0:
        return True
    if last is None:
        return True
    return now - last >= BACKUP_SCAN_MINUTES * 60


def maybe_run_backup_cycle():
    """Обход каталогов бэкапов — раз в BACKUP_SCAN_MINUTES, а не каждый цикл.

    Опрос серверов имеет смысл частым: диск заполняется, служба падает
    в любую минуту. Копия же появляется раз в сутки, а её поиск — это
    удалённая сессия и обход каталога с десятками тысяч файлов.
    """
    global _last_backup_scan
    now = time.monotonic()
    if not backup_scan_due(now, _last_backup_scan):
        left = round((BACKUP_SCAN_MINUTES * 60 - (now - _last_backup_scan)) / 60)
        print(f"[backup] Пропускаю обход: следующий через ~{left} мин", flush=True)
        return False

    _last_backup_scan = now
    run_backup_cycle(on_progress=touch_heartbeat)
    return True


def run_cycle():
    # Утро после тихих часов: отправляем накопленные некритичные алерты
    try:
        flush_deferred()
    except Exception as e:
        print(f"[monitor] Ошибка отправки отложенных алертов: {e}", flush=True)

    # Предупреждение за 15 минут до начала тихих часов
    try:
        notify_quiet_hours_start()
    except Exception as e:
        print(f"[monitor] Ошибка предупреждения о тихих часах: {e}", flush=True)

    try:
        servers = load_servers()
    except Exception as e:
        print(f"[monitor] Не могу прочитать {SERVERS_FILE}: {e}", flush=True)
        return

    current_names = [s["name"] for s in servers]
    removed = cleanup_removed_servers(current_names)
    for name in removed:
        print(f"[monitor] Удалён из БД: {name}", flush=True)
        try:
            purge_server_state(name)
            purge_disk_health(name)
            forget_log_events(name)
            forget_iis_data(name)
            forget_firewall_data(name)
            forget_mail_data(name)
        except Exception as e:
            print(f"[monitor] Не удалось очистить состояние {name}: {e}", flush=True)

    maybe_cleanup()

    # Серверы опрашиваются параллельно: один недоступный сервер
    # (таймауты + ретраи) не задерживает проверку остальных.
    outcomes = list(run_server_checks(servers).values())

    online = sum(1 for o in outcomes if o == "online")
    offline = sum(1 for o in outcomes if o == "offline")
    _last_cycle_tally.update({"online": online, "offline": offline, "total": len(servers)})
    print(f"[monitor] Цикл завершён: онлайн {online}, офлайн {offline}\n", flush=True)

    try:
        maybe_send_self_report()
    except Exception as e:
        print(f"[monitor] Ошибка самоотчёта: {e}", flush=True)

    # Сбор метрик бэкапов. Отдельный try: сбой внутри (недоступная БД,
    # битая запись в конфиге) раньше пробивался наружу через run_cycle()
    # и завершал процесс монитора целиком — вместе с ping-циклом.
    try:
        maybe_run_backup_cycle()
    except Exception as e:
        print(f"[monitor] Ошибка сбора метрик бэкапов: {e}", flush=True)

    # Сводка журналов Windows и SQL для дашборда — свой, более редкий шаг.
    # Тот же отдельный try: чтение Event Log по WinRM отваливается по правам
    # и таймаутам чаще остального, и ронять цикл из-за этого нельзя.
    try:
        maybe_run_log_cycle(servers, on_progress=touch_heartbeat)
    except Exception as e:
        print(f"[monitor] Ошибка сбора журналов: {e}", flush=True)

    # Сводка IIS: логи сайта читаются по смещению, поэтому шаг дешёвый —
    # полмиллиона строк за сутки перечитывать не приходится.
    try:
        maybe_run_iis_cycle(servers, on_progress=touch_heartbeat)
    except Exception as e:
        print(f"[monitor] Ошибка сбора IIS: {e}", flush=True)

    # Почта Zimbra: подбор пароля и вход из чужой страны идут ночью, и
    # ждать, пока кто-то откроет раздел, нельзя.
    try:
        maybe_run_zimbra_cycle(servers, on_progress=touch_heartbeat)
    except Exception as e:
        print(f"[monitor] Ошибка проверки почты: {e}", flush=True)

    # Почта Exchange: та же сводка для дашборда, что у Zimbra, но с
    # другой стороны — логи IIS и журнал Security. Свой try: WinRM
    # отваливается по правам чаще прочего.
    try:
        maybe_run_exchange_cycle(servers, on_progress=touch_heartbeat)
    except Exception as e:
        print(f"[monitor] Ошибка сбора почты Exchange: {e}", flush=True)

    # Снятие истёкших блокировок IP. Дешёвый шаг: без истёкших строк он не
    # ходит на серверы вовсе.
    try:
        run_firewall_expiry(servers)
    except Exception as e:
        print(f"[monitor] Ошибка снятия блокировок IP: {e}", flush=True)

    # Ретеншн и RESTORE VERIFYONLY — в своём потоке (maintenance_loop), не здесь:
    # VERIFY может идти до 2 часов, и раньше это останавливало весь цикл
    # мониторинга (ping/диски/сервисы всех серверов) на всё это время.


def maintenance_loop():
    """Ретеншн и RESTORE VERIFYONLY — отдельно от run_cycle(), чтобы долгий
    VERIFY (до 2 часов на больших базах) не блокировал обычный опрос серверов."""
    while True:
        try:
            run_backup_maintenance()
        except Exception as e:
            print(f"[maintenance] Ошибка: {e}", flush=True)
        time.sleep(INTERVAL)


def heartbeat_age_seconds():
    """Сколько секунд назад обновлялся пульс. None — файла нет или он битый."""
    try:
        with open(HEARTBEAT_FILE) as f:
            written = datetime.fromisoformat(f.read().strip())
    except (OSError, ValueError):
        return None
    return (datetime.now(timezone.utc) - written).total_seconds()


def watchdog_loop():
    """Сторож зависшего цикла.

    Пульс теперь обновляется по ходу цикла — после каждого сервера, — поэтому
    его застой означает не «долго работает», а «встало намертво»: обычно это
    сетевой вызов, повисший без таймаута. Лечится только перезапуском, и
    сделать его должен сам процесс: снаружи никто не следит.
    """
    if STALL_EXIT_MINUTES <= 0:
        return
    limit = STALL_EXIT_MINUTES * 60
    while True:
        time.sleep(60)
        age = heartbeat_age_seconds()
        if age is not None and age > limit:
            print(
                f"[monitor] Пульс не обновлялся {round(age / 60)} мин — "
                f"цикл завис, выхожу для перезапуска контейнера",
                flush=True
            )
            traceback.print_stack()
            os._exit(1)


def main():
    print("[monitor] AgentMonitor запущен", flush=True)
    print(f"[monitor] Интервал: {INTERVAL} сек, retry: {RETRY_COUNT}x{RETRY_DELAY}сек", flush=True)
    print(
        f"[monitor] Ping-мониторинг: каждые {PING_INTERVAL} сек "
        f"(упавшие — каждые {PING_DOWN_INTERVAL}), "
        f"падение при молчании {PING_FAIL_SECONDS} сек",
        flush=True
    )
    print(
        f"[monitor] Хранение данных: {RETAIN_DAYS} дней "
        f"(службы и процессы — {SNAPSHOT_RETAIN_DAYS})",
        flush=True
    )

    os.makedirs("/app/data", exist_ok=True)
    for path in [
        DISK_STATE_FILE,
        SERVER_STATE_FILE,
        ALERTS_DISABLED_FILE,
        CPU_STATE_FILE,
        RAM_STATE_FILE,
        "/app/data/service_alert_state.json",
        "/app/data/backup_alert_state.json"
    ]:
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("{}")
            print(f"[monitor] Создан файл состояния: {path}", flush=True)

    try:
        ensure_time_indexes()
    except Exception as e:
        print(f"[monitor] Проверка индексов не удалась: {e}", flush=True)

    touch_heartbeat()
    threading.Thread(target=ping_loop, daemon=True).start()
    threading.Thread(target=maintenance_loop, daemon=True).start()
    threading.Thread(target=watchdog_loop, daemon=True).start()

    while True:
        # Последний рубеж: любая неучтённая ошибка в цикле не должна
        # останавливать мониторинг. Молчащий монитор хуже шумного —
        # heartbeat при этом не обновляется, и healthcheck это увидит.
        try:
            run_cycle()
        except Exception as e:
            print(f"[monitor] Непредвиденная ошибка цикла: {e}", flush=True)
            traceback.print_exc()
        touch_heartbeat()
        print(f"[monitor] Следующая проверка через {INTERVAL} сек...", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
