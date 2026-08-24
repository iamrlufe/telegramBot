import json
import time
import os
import subprocess
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from server_check import check_server, server_type
from service_details import save_service_details
from winrm_errors import parse_status
from backup_collector import run_backup_cycle
from backup_maintenance import run_backup_maintenance
from db import (
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
from alerts import (
    check_disk_alert,
    check_disk_forecast_alert,
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

INTERVAL = 300
PING_INTERVAL = 30
RETRY_DELAY = 30       # пауза перед повторной попыткой WinRM (сек)
RETRY_COUNT = 2        # количество попыток WinRM перед алертом офлайн
PING_FAIL_THRESHOLD = 15  # сколько подряд неудачных пингов = сервер упал
MAX_PARALLEL_CHECKS = 5   # сколько серверов опрашиваем одновременно
SERVERS_FILE = "/app/config/servers.json"

DISK_STATE_FILE = "/app/data/disk_alert_state.json"
SERVER_STATE_FILE = "/app/data/server_alert_state.json"
ALERTS_DISABLED_FILE = "/app/data/alerts_disabled.json"
CLEANUP_STATE_FILE = "/app/data/last_cleanup.txt"
CPU_STATE_FILE = "/app/data/cpu_alert_state.json"
RAM_STATE_FILE = "/app/data/ram_alert_state.json"
HEARTBEAT_FILE = "/app/data/heartbeat"
SELF_REPORT_STATE_FILE = "/app/data/self_report_state.json"

RETAIN_DAYS = 30

# Ежедневный отчёт «монитор жив»: час по Алматы. Пусто в .env — выключено.
SELF_REPORT_HOUR = os.getenv("SELF_REPORT_HOUR", "9").strip()

# Итог последнего цикла для самоотчёта: {"online", "offline", "total"}
_last_cycle_tally: dict = {}

# Счётчики неудачных пингов — хранятся в памяти
# { server_name: int }
_ping_fail_counts: dict = {}
_ping_lock = threading.Lock()


def touch_heartbeat():
    """Обновляет файл-пульс: docker healthcheck проверяет его свежесть."""
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())
    except OSError as e:
        print(f"[monitor] Не удалось обновить heartbeat: {e}", flush=True)


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


def try_check_server(server: dict) -> dict:
    name = server["name"]
    last_error = None

    for attempt in range(1, RETRY_COUNT + 1):
        try:
            return check_server(server)
        except Exception as e:
            last_error = e
            if attempt < RETRY_COUNT:
                print(f"  ⚠️ {name}: попытка {attempt}/{RETRY_COUNT} не удалась: {e}", flush=True)
                print(f"  ⏳ {name}: повтор через {RETRY_DELAY} сек...", flush=True)
                time.sleep(RETRY_DELAY)
            else:
                print(f"  ❌ Все {RETRY_COUNT} попытки исчерпаны для {name}", flush=True)

    raise last_error


def maybe_cleanup():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        with open(CLEANUP_STATE_FILE) as f:
            last = f.read().strip()
        if last == today:
            return
    except FileNotFoundError:
        pass

    print(f"[monitor] Очистка данных старше {RETAIN_DAYS} дней...", flush=True)
    (
        deleted_metrics, deleted_status, deleted_services, deleted_processes,
        deleted_backups, deleted_db_sizes, deleted_onec_logs
    ) = cleanup_old_data(RETAIN_DAYS)
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

    for server in servers:
        name = server["name"]
        host = server["host"]
        is_alive = ping_host(host)

        # Решение принимаем под блокировкой, медленный I/O (БД, Telegram) — вне её
        action = None
        with _ping_lock:
            if is_alive:
                was_down = _ping_fail_counts.get(name, 0) >= PING_FAIL_THRESHOLD
                _ping_fail_counts[name] = 0
                if was_down:
                    action = "recovered"
            else:
                count = _ping_fail_counts.get(name, 0) + 1
                _ping_fail_counts[name] = count
                if count == PING_FAIL_THRESHOLD:
                    action = "down"
                elif count > PING_FAIL_THRESHOLD:
                    action = "still_down"
                else:
                    action = f"fail_{count}"

        if action == "recovered":
            print(f"[ping] ВОССТАНОВЛЕН {name} ({host})", flush=True)
            save_server_status(name, "online", error="Ping восстановлен")
            alert_server_online(server)
        elif action == "down":
            print(f"[ping] DOWN {name} ({host}) — порог достигнут", flush=True)
            save_server_status(name, "ping_down", error="Ping не отвечает")
            alert_server_down(server)
        elif action == "still_down":
            print(f"[ping] Всё ещё недоступен {name} ({host})", flush=True)
        elif action:
            count = action.split("_", 1)[1]
            print(
                f"[ping] НЕТ ОТВЕТА {name} ({host}) — {count}/{PING_FAIL_THRESHOLD}",
                flush=True
            )


def ping_loop():
    while True:
        try:
            run_ping_cycle()
        except Exception as e:
            print(f"[ping] Ошибка цикла: {e}", flush=True)
        time.sleep(PING_INTERVAL)


def process_server(server: dict):
    """Полная проверка одного сервера (выполняется в пуле потоков)."""
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

        info = try_check_server(server)

        # Замеры пишем одной вставкой до проверок, а не по диску внутри цикла:
        # прогноз заполнения читает историю из БД и должен видеть текущий замер,
        # поэтому запись обязана идти раньше check_disk_forecast_alert.
        save_disk_metrics(name, [
            (disk["Name"], float(disk["FreeGB"]), float(disk["UsedGB"]))
            for disk in info["disks"]
        ])

        for disk in info["disks"]:
            free = float(disk["FreeGB"])
            used = float(disk["UsedGB"])
            print(f"  💽 {name} {disk['Name']}: free={free}GB used={used}GB", flush=True)
            check_disk_alert(name, disk)

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
                check_disk_forecast_alert(name, disk["Name"], trend)
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
        save_service_details(name, info.get("service_details") or {})

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

        return "online"

    except Exception as e:
        error_str = str(e)
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
        except Exception as e:
            print(f"[monitor] Не удалось очистить состояние {name}: {e}", flush=True)

    maybe_cleanup()

    # Серверы опрашиваются параллельно: один недоступный сервер
    # (таймауты + ретраи) не задерживает проверку остальных.
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_CHECKS) as pool:
        outcomes = list(pool.map(process_server, servers))

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
        run_backup_cycle()
    except Exception as e:
        print(f"[monitor] Ошибка сбора метрик бэкапов: {e}", flush=True)

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


def main():
    print("[monitor] AgentMonitor запущен", flush=True)
    print(f"[monitor] Интервал: {INTERVAL} сек, retry: {RETRY_COUNT}x{RETRY_DELAY}сек", flush=True)
    print(f"[monitor] Ping-мониторинг: каждые {PING_INTERVAL} сек, порог: {PING_FAIL_THRESHOLD} неудач", flush=True)
    print(f"[monitor] Хранение данных: {RETAIN_DAYS} дней", flush=True)

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

    touch_heartbeat()
    threading.Thread(target=ping_loop, daemon=True).start()
    threading.Thread(target=maintenance_loop, daemon=True).start()

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
