import json
import os
import threading
import time

import psycopg2
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from telegram import InlineKeyboardButton

from pgconn import get_conn
from service_details import load_service_details, load_platform_details
from disk_health import format_disk_health, load_disk_health
from backup_files import disk_of_path
from backup_verify import path_str
from backup_schedule import load_schedule_map, schedule_for, weekly_backup_missed
from linux_check import PSEUDO_MOUNT_PREFIXES
from alerts_ack import ack_hash, ack_key_forever, active_ack_digests

ALMATY = ZoneInfo("Asia/Almaty")
STALE_MINUTES = 15
DISK_WARN_FREE = 20
DISK_CRIT_FREE = 10
BACKUP_WARN_HOURS = 24


def is_pseudo_disk(name: str) -> bool:
    """Псевдо-ФС ядра, попавшая в базу до того, как её начали отсеивать при
    сборе: `/sys/firmware/efi/efivars` — хранилище переменных UEFI, всегда
    заполненное, и в отчёте оно значилось критическим диском с 0%."""
    return name != "/" and name.startswith(PSEUDO_MOUNT_PREFIXES)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


# Копия недельной давности и вчерашняя лежали в одной жёлтой куче: порог
# делит «отстал» и «бэкапа фактически нет».
BACKUP_CRIT_HOURS = _int_env("BACKUP_CRIT_HOURS", 72)
BACKUP_STALE_MINUTES = 30

# Метрика диска, которая перестала обновляться, остаётся в базе навсегда:
# DISTINCT ON выдаёт последнюю запись, даже если ей неделя. Так в отчёте
# держались тома, которых больше нет, — отключённые диски, переименованные
# буквы и отсеянные псевдо-ФС вроде efivarfs.
DISK_METRIC_FRESH_HOURS = 2
ONEC_LOG_WARN_GB = 5
ONEC_LOG_CRIT_GB = 10
ONEC_LOG_STALE_MINUTES = 30
SERVER_BUTTONS_PER_PAGE = 8

# Записи старше недели в сводке проблем ничего не значат: свежесть каждой
# категории проверяется своими порогами в минутах и часах. Ограничение нужно
# запросам: DISTINCT ON без него читает таблицу целиком, а это вся история
# за месяц на каждое нажатие 🚨 Проблемы.
PROBLEM_HISTORY_DAYS = 7

# Сводка пересчитывалась на каждое нажатие кнопки — пять тяжёлых запросов
# ради данных, которые обновляются раз в пять минут. Ходьба «сводка →
# сервер → назад» стоила пятнадцати.
PROBLEMS_CACHE_SECONDS = _int_env("PROBLEMS_CACHE_SECONDS", 45)
SERVERS_FILE = "/app/config/servers.json"


def _make_bar(used_pct: float, width: int = 10) -> str:
    filled = round(used_pct / 100 * width)
    empty = width - filled
    return f"[{'█' * filled}{'░' * empty}] {used_pct}%"


def _format_duration(seconds) -> str:
    if seconds is None:
        return "нет данных"
    seconds = int(seconds)
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days:
        return f"{days} д {hours} ч"
    if hours:
        return f"{hours} ч {minutes} мин"
    return f"{minutes} мин"


def _format_local_time(dt) -> str:
    return dt.replace(tzinfo=timezone.utc).astimezone(ALMATY).strftime("%d.%m %H:%M")


def _fetch_optional(cur, query: str, params: tuple = ()) -> list:
    try:
        cur.execute(query, params)
        return cur.fetchall()
    except psycopg2.Error as e:
        cur.connection.rollback()
        print(f"[bot] Optional problem query skipped: {e}", flush=True)
        return []


def _load_backup_targets() -> tuple[dict[str, set[tuple[str, str]]], set[str]]:
    targets: dict[str, set[tuple[str, str]]] = {}
    config_server_names: set[str] = set()
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
        for server in servers:
            name = server.get("name")
            if not name:
                continue
            config_server_names.add(name)
            entries: set[tuple[str, str]] = set()
            backups = server.get("backups", {})
            if isinstance(backups, dict):
                for backup_type, paths in backups.items():
                    if not isinstance(paths, list):
                        paths = [paths]
                    for raw_path in paths:
                        # Путь бывает объектом {path, alert_hours, schedule_*} —
                        # без path_str() в набор попадала строка вида "{'path': …}",
                        # она не совпадала с БД, и такие пути молча выпадали
                        # из сводки проблем целиком.
                        backup_path = path_str(raw_path)
                        if backup_path:
                            entries.add((str(backup_type), str(backup_path)))
            targets[name] = entries
    except Exception as e:
        print(f"[bot] Не удалось прочитать {SERVERS_FILE}: {e}", flush=True)
    return targets, config_server_names


def _paginate_buttons(buttons: list, page: int, per_page: int, callback_prefix: str,
                      back_callback: str = None, columns: int = 2) -> list:
    total_pages = max(1, (len(buttons) + per_page - 1) // per_page)
    page = max(0, min(page, total_pages - 1))
    start = page * per_page
    end = start + per_page
    page_buttons = buttons[start:end]

    keyboard = [page_buttons[i:i+columns] for i in range(0, len(page_buttons), columns)]
    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton("◀️", callback_data=f"{callback_prefix}:{page - 1}"))
    nav_row.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton("▶️", callback_data=f"{callback_prefix}:{page + 1}"))
    keyboard.append(nav_row)

    if back_callback:
        keyboard.append([InlineKeyboardButton("◀️ Назад", callback_data=back_callback)])

    return keyboard


# ─── Состояние серверов со списком кнопок ────────────────────

def get_servers_status(page: int = 0) -> tuple:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (server_name)
                   server_name, status, checked_at
            FROM server_status
            ORDER BY server_name, checked_at DESC
        """)
        rows = cur.fetchall()

    if not rows:
        return "⚠️ Нет данных — мониторинг ещё не запускался", []

    now_utc = datetime.now(timezone.utc)
    online = 0
    offline = 0
    buttons = []

    msg = "🖥 СОСТОЯНИЕ СЕРВЕРОВ\n\n"
    msg += "━━━━━━━━━━━━━━━━━━━━\n\n"

    for server_name, status, checked_at in sorted(rows):
        checked_utc = checked_at.replace(tzinfo=timezone.utc)
        age_min = (now_utc - checked_utc).total_seconds() / 60
        stale = " ⚠️" if age_min > STALE_MINUTES else ""
        time_str = checked_utc.astimezone(ALMATY).strftime("%H:%M")

        if status == "online":
            icon = "🟢"
            msg += f"🟢 {server_name}{stale} ({time_str})\n"
            online += 1
        else:
            icon = "🔴"
            msg += f"🔴 {server_name} — {status}{stale} ({time_str})\n"
            offline += 1

        buttons.append(
            InlineKeyboardButton(f"{icon} {server_name}", callback_data=f"server:{server_name}")
        )

    keyboard = _paginate_buttons(
        buttons,
        page=page,
        per_page=SERVER_BUTTONS_PER_PAGE,
        callback_prefix="servers_list",
        columns=2
    )

    total = online + offline
    availability = round((online / total) * 100, 1) if total > 0 else 0

    msg += "\n━━━━━━━━━━━━━━━━━━━━\n\n"
    msg += (
        f"📊 ИТОГО\n\n"
        f"🟢 Онлайн: {online}\n"
        f"🔴 Оффлайн: {offline}\n"
        f"📈 Доступность: {availability}%\n\n"
        f"🕒 Обновляется каждые 5 минут"
    )

    return msg, keyboard


# ─── Детали конкретного сервера ──────────────────────────────

def get_disk_usage(server_name: str, disk_name: str):
    """(free_gb, used_gb) последнего замера диска или None.
    Имя диска сопоставляется без учёта «:», «\\» и регистра ('E' == 'E:')."""
    norm = str(disk_name or "").rstrip(":\\/").upper()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (disk_name) disk_name, free_gb, used_gb
            FROM disk_metrics
            WHERE server_name = %s
            ORDER BY disk_name, created_at DESC
        """, (server_name,))
        for dn, free, used in cur.fetchall():
            if str(dn).rstrip(":\\/").upper() == norm:
                return float(free), float(used)
    return None


def get_server_disks(server_name: str) -> list:
    """[(disk_name, free_gb, used_gb), ...] по последнему замеру каждого диска.
    Нужен для меню «какой диск разобрать» под карточкой сервера."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (disk_name) disk_name, free_gb, used_gb
            FROM disk_metrics
            WHERE server_name = %s
            ORDER BY disk_name, created_at DESC
        """, (server_name,))
        return [(dn, float(free or 0), float(used or 0))
                for dn, free, used in cur.fetchall() if not is_pseudo_disk(dn)]


def _top_line(row, by: str) -> str:
    """Строка топа процессов/ВМ: иконка по нагрузке, без пустого PID.

    У виртуальных машин идентификатора процесса нет, и в колонке лежит 0 —
    выводить «(0)» бессмысленно. Иконка та же, что в разделе ВМ: 🔥 от 80%.
    """
    process_name, process_id, cpu_percent, _cpu_seconds, memory_mb = row
    cpu_percent = cpu_percent if cpu_percent is not None else 0
    memory_mb = memory_mb if memory_mb is not None else 0

    icon = "🔥" if float(cpu_percent) >= 80 else "🟢"
    name = str(process_name)
    if process_id:
        name += f" ({process_id})"

    if by == "cpu":
        return f"{icon} {name} — {cpu_percent}% CPU · {memory_mb} MB"
    return f"{icon} {name} — {memory_mb} MB · {cpu_percent}% CPU"


def get_server_detail(server_name: str) -> str:
    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute("""
            SELECT DISTINCT ON (server_name)
                   status, error, checked_at, cpu_load, ram_total, ram_free, uptime_seconds
            FROM server_status
            WHERE server_name = %s
            ORDER BY server_name, checked_at DESC
        """, (server_name,))
        status_row = cur.fetchone()

        cur.execute("""
            SELECT DISTINCT ON (disk_name)
                   disk_name, free_gb, used_gb
            FROM disk_metrics
            WHERE server_name = %s
            ORDER BY disk_name, created_at DESC
        """, (server_name,))
        disk_rows = [row for row in cur.fetchall() if not is_pseudo_disk(row[0])]

        cur.execute("""
            SELECT DISTINCT ON (service_name)
                   service_name, display_name, status, checked_at
            FROM service_status
            WHERE server_name = %s
              AND checked_at >= NOW() - INTERVAL '15 minutes'
            ORDER BY service_name, checked_at DESC
        """, (server_name,))
        service_rows = cur.fetchall()

        cur.execute("""
            SELECT process_name, process_id, cpu_percent, cpu_seconds, memory_mb
            FROM process_metrics
            WHERE server_name = %s
              AND metric_type = 'cpu'
              AND created_at = (
                  SELECT MAX(created_at)
                  FROM process_metrics
                  WHERE server_name = %s
                    AND metric_type = 'cpu'
              )
            ORDER BY cpu_percent DESC NULLS LAST
            LIMIT 5
        """, (server_name, server_name))
        top_cpu_rows = cur.fetchall()

        cur.execute("""
            SELECT process_name, process_id, cpu_percent, cpu_seconds, memory_mb
            FROM process_metrics
            WHERE server_name = %s
              AND metric_type = 'memory'
              AND created_at = (
                  SELECT MAX(created_at)
                  FROM process_metrics
                  WHERE server_name = %s
                    AND metric_type = 'memory'
              )
            ORDER BY memory_mb DESC NULLS LAST
            LIMIT 5
        """, (server_name, server_name))
        top_memory_rows = cur.fetchall()

        cur.execute("""
            SELECT
                MIN(cpu_load),
                ROUND(AVG(cpu_load)::numeric, 1),
                MAX(cpu_load),
                MIN(ROUND(((ram_total - ram_free) / NULLIF(ram_total, 0) * 100)::numeric, 1)),
                ROUND(AVG((ram_total - ram_free) / NULLIF(ram_total, 0) * 100)::numeric, 1),
                MAX(ROUND(((ram_total - ram_free) / NULLIF(ram_total, 0) * 100)::numeric, 1))
            FROM server_status
            WHERE server_name = %s
              AND checked_at >= NOW() - INTERVAL '24 hours'
              AND status = 'online'
        """, (server_name,))
        resource_history = cur.fetchone()

        cur.execute("""
            SELECT
                disk_name,
                MIN(ROUND((free_gb / NULLIF(free_gb + used_gb, 0) * 100)::numeric, 1)),
                ROUND(AVG(free_gb / NULLIF(free_gb + used_gb, 0) * 100)::numeric, 1),
                MAX(ROUND((free_gb / NULLIF(free_gb + used_gb, 0) * 100)::numeric, 1))
            FROM disk_metrics
            WHERE server_name = %s
              AND created_at >= NOW() - INTERVAL '24 hours'
            GROUP BY disk_name
            ORDER BY disk_name
        """, (server_name,))
        disk_history = cur.fetchall()

        # Где лежат бэкапы этого сервера: путь, диск и размер каталога
        try:
            cur.execute("""
                SELECT DISTINCT ON (backup_type, backup_path)
                       backup_type, backup_path, file_count,
                       total_size_gb, newest_file
                FROM backup_metrics
                WHERE server_name = %s
                ORDER BY backup_type, backup_path, created_at DESC
            """, (server_name,))
            backup_rows = cur.fetchall()
        except Exception:
            conn.rollback()
            backup_rows = []

    # Путь, убранный из конфига, остаётся в БД навсегда — monitor его больше
    # не опрашивает, но и не удаляет. Особенно опасны родительские каталоги
    # (был "G:\Backups", стали "G:\Backups\elev22" и "G:\Backups\sh"):
    # родитель суммирует дочерние, поэтому мёртвая копия в одном подкаталоге
    # маскируется свежими файлами соседнего. Показываем только то, что есть
    # в конфиге — как это уже делают дайджест и Backup Health.
    # Сервер не из конфига (остался в БД) не фильтруем: иначе он опустеет.
    backup_targets, config_server_names = _load_backup_targets()
    if server_name in config_server_names:
        allowed = backup_targets.get(server_name, set())
        backup_rows = [
            row for row in backup_rows if (str(row[0]), str(row[1])) in allowed
        ]

    if not status_row:
        return f"❓ Нет данных по серверу {server_name}"

    status, error, checked_at, cpu_load, ram_total, ram_free, uptime_seconds = status_row
    checked_local = checked_at.replace(tzinfo=timezone.utc).astimezone(ALMATY)
    time_str = checked_local.strftime("%d.%m.%Y %H:%M")
    status_line = "🟢 Онлайн" if status == "online" else f"🔴 {status}"

    msg = f"🖥 {server_name}\n"
    msg += "━━━━━━━━━━━━━━━━━━━━\n\n"
    msg += f"Статус:   {status_line}\n"
    msg += f"Проверен: {time_str}\n"
    msg += f"Uptime:   {_format_duration(uptime_seconds)}\n"

    if error and status != "online":
        first_line = error.splitlines()[0][:100]
        msg += f"Ошибка:   {first_line}\n"

    # CPU
    if cpu_load is not None:
        cpu_load = float(cpu_load)
        cpu_icon = "🔴" if cpu_load >= 90 else "🟠" if cpu_load >= 70 else "🟢"
        msg += f"\n{cpu_icon} CPU\n"
        msg += f"   {_make_bar(cpu_load)}\n"
        msg += f"   Загрузка: {cpu_load}%\n"

    # RAM
    if ram_total is not None and ram_free is not None and float(ram_total) > 0:
        ram_total = float(ram_total)
        ram_free = float(ram_free)
        ram_used = ram_total - ram_free
        ram_used_pct = round((ram_used / ram_total) * 100, 1)
        ram_icon = "🔴" if ram_used_pct >= 90 else "🟠" if ram_used_pct >= 70 else "🟢"
        msg += f"\n{ram_icon} RAM\n"
        msg += f"   {_make_bar(ram_used_pct)}\n"
        msg += f"   Занято:  {round(ram_used, 1)} ГБ\n"
        msg += f"   Свободно: {round(ram_free, 1)} ГБ\n"
        msg += f"   Всего:   {round(ram_total, 1)} ГБ\n"

    # Диски
    if disk_rows:
        msg += "\n💽 ДИСКИ\n"
        for disk_name, free, used in disk_rows:
            free = float(free)
            used = float(used)
            total = free + used
            pct_used = round((used / total) * 100, 1) if total > 0 else 0
            pct_free = round(100 - pct_used, 1)
            disk_icon = "🔴" if pct_free < 10 else "🟠" if pct_free < 20 else "🟢"
            msg += f"\n{disk_icon} {disk_name}:\n"
            msg += f"   {_make_bar(pct_used)}\n"
            msg += f"   Свободно: {free} ГБ ({pct_free}%)\n"
            msg += f"   Занято:   {used} ГБ\n"
            msg += f"   Всего:    {round(total, 1)} ГБ\n"
    else:
        msg += "\n💽 Нет данных по дискам\n"

    # RAID, температура дисков, причина недоступности SMART (Linux/NAS).
    # Алерты приходят только при поломке — текущее состояние надо видеть всегда.
    msg += format_disk_health(load_disk_health(server_name))

    # Бэкапы: на каком диске и в каком каталоге лежат, сколько занимают
    if backup_rows:
        msg += "\n💾 БЭКАПЫ\n"
        for backup_type, backup_path, file_count, total_size_gb, newest_file in backup_rows:
            size_gb = float(total_size_gb or 0)
            msg += f"\n   📁 {disk_of_path(backup_path)} · {str(backup_type).upper()}\n"
            msg += f"      {backup_path}\n"
            msg += f"      Размер: {round(size_gb, 2)} ГБ · файлов: {file_count or 0}\n"
            if newest_file:
                fresh = newest_file.strftime("%d.%m.%Y %H:%M")
                msg += f"      Свежий: {fresh}\n"

    # Разбивка платформы по хостам (vCenter): агрегат выше показывает,
    # хватает ли ресурсов в целом, а здесь видно перекос между хостами
    platform = load_platform_details(server_name)
    host_lines = platform.get("hosts") or []
    if host_lines:
        msg += "\n🖥 ХОСТЫ\n"
        for line in host_lines[:15]:
            msg += f"   {str(line)[:90]}\n"

    vm_lines = platform.get("vms") or []
    if vm_lines:
        summary = (platform.get("summary") or [""])[0]
        msg += "\n🧩 ВИРТУАЛЬНЫЕ МАШИНЫ\n"
        if summary:
            msg += f"   {summary}\n\n"
        for line in vm_lines:
            msg += f"   {str(line)[:110]}\n"

    # Сервисы (Windows-службы или systemd-юниты)
    if service_rows:
        details = load_service_details(server_name)
        msg += "\n⚙️ СЕРВИСЫ\n"
        for service_name, display_name, service_status, service_checked_at in service_rows:
            icon = "🟢" if str(service_status).lower() == "running" else "🔴"
            label = display_name if display_name and display_name != service_name else service_name
            msg += f"   {icon} {label}: {service_status}\n"
            # Расширенная информация: контейнеры Docker, сайты веб-серверов
            for line in details.get(service_name, [])[:12]:
                msg += f"      {str(line)[:90]}\n"

    if top_cpu_rows or top_memory_rows:
        # Заголовок зависит от того, что в строках: у VMware это не процессы,
        # а виртуальные машины, и «топ процессов» там читается как ошибка
        header = "🖥 ТОП ВМ" if platform.get("vms") else "🔥 ТОП ПРОЦЕССОВ"
        msg += f"\n{header}\n"
        if top_cpu_rows:
            msg += "   CPU:\n"
            for row in top_cpu_rows:
                msg += f"      {_top_line(row, by='cpu')}\n"
        if top_memory_rows:
            msg += "   RAM:\n"
            for row in top_memory_rows:
                msg += f"      {_top_line(row, by='memory')}\n"

    # История за 24 часа
    msg += "\n📈 ИСТОРИЯ 24 ЧАСА\n"
    if resource_history and resource_history[0] is not None:
        cpu_min, cpu_avg, cpu_max, ram_min, ram_avg, ram_max = resource_history
        msg += f"   CPU: min {cpu_min}% / avg {cpu_avg}% / max {cpu_max}%\n"
        if ram_min is not None:
            msg += f"   RAM: min {ram_min}% / avg {ram_avg}% / max {ram_max}%\n"
    else:
        msg += "   CPU/RAM: нет данных\n"

    if disk_history:
        for disk_name, free_min, free_avg, free_max in disk_history:
            msg += (
                f"   {disk_name}: свободно min {free_min}% / "
                f"avg {free_avg}% / max {free_max}%\n"
            )
    else:
        msg += "   Диски: нет данных\n"

    return msg


# ─── Проблемы ────────────────────────────────────────────────

def collect_problems() -> list:
    backup_targets, config_server_names = _load_backup_targets()
    schedule_map = load_schedule_map(SERVERS_FILE)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (server_name)
                   server_name, status, error, checked_at,
                   cpu_load, ram_total, ram_free
            FROM server_status
            WHERE checked_at >= NOW() - make_interval(days => %s)
            ORDER BY server_name, checked_at DESC
        """, (PROBLEM_HISTORY_DAYS,))
        status_rows = cur.fetchall()

        cur.execute("""
            SELECT DISTINCT ON (server_name, disk_name)
                   server_name, disk_name, free_gb, used_gb, created_at
            FROM disk_metrics
            WHERE created_at >= NOW() - INTERVAL '1 hour' * %s
            ORDER BY server_name, disk_name, created_at DESC
        """, (DISK_METRIC_FRESH_HOURS,))
        disk_rows = cur.fetchall()

        service_rows = _fetch_optional(cur, """
            SELECT service_name, display_name, status, server_name, checked_at
            FROM (
                SELECT DISTINCT ON (server_name, service_name)
                       service_name, display_name, status, server_name, checked_at
                FROM service_status
                WHERE checked_at >= NOW() - make_interval(days => %s)
                ORDER BY server_name, service_name, checked_at DESC
            ) latest
            WHERE LOWER(status) != 'running'
              AND checked_at >= NOW() - INTERVAL '30 minutes'
            ORDER BY server_name, service_name
        """, (PROBLEM_HISTORY_DAYS,))

        backup_rows = _fetch_optional(cur, """
            SELECT server_name, backup_type, backup_path, file_count,
                   newest_file, disk_total_gb, disk_free_gb, created_at
            FROM (
                SELECT DISTINCT ON (server_name, backup_type, backup_path)
                       server_name, backup_type, backup_path, file_count,
                       newest_file, disk_total_gb, disk_free_gb, created_at
                FROM backup_metrics
                WHERE created_at >= NOW() - make_interval(days => %s)
                ORDER BY server_name, backup_type, backup_path, created_at DESC
            ) latest
            ORDER BY server_name, backup_type, backup_path
        """, (PROBLEM_HISTORY_DAYS,))

        onec_log_rows = _fetch_optional(cur, """
            SELECT server_name, log_name, log_path, total_size_gb,
                   file_count, status, error, created_at
            FROM (
                SELECT DISTINCT ON (server_name, log_path)
                       server_name, log_name, log_path, total_size_gb,
                       file_count, status, error, created_at
                FROM onec_log_metrics
                WHERE created_at >= NOW() - make_interval(days => %s)
                ORDER BY server_name, log_path, created_at DESC
            ) latest
            ORDER BY server_name, log_name, log_path
        """, (PROBLEM_HISTORY_DAYS,))

        verify_rows = _fetch_optional(cur, """
            SELECT server_name, backup_path, file_path, status, error, created_at
            FROM (
                SELECT DISTINCT ON (server_name, backup_path)
                       server_name, backup_path, file_path, status, error, created_at
                FROM backup_verifications
                WHERE created_at >= NOW() - INTERVAL '7 days'
                ORDER BY server_name, backup_path, created_at DESC
            ) latest
            WHERE status != 'ok'
            ORDER BY server_name, backup_path
        """)

    now_utc = datetime.now(timezone.utc)
    problems = []
    acked = active_ack_digests()

    def add(level, kind, server, text, weight=0.0, hint=None, key=None):
        """Проблема хранится разобранной, а не готовой строкой: из тех же
        записей собирается и сводка по категориям, и разбор по серверу.

        key — устойчивое имя проблемы (сервер + объект), по нему работает
        кнопка «Принял». В текст оно не годится: там проценты и дни, они
        меняются каждый час, и подавление слетало бы само собой."""
        if key and ack_hash(key) in acked:
            return
        problems.append({"level": level, "kind": kind, "server": server,
                         "text": text, "weight": weight, "hint": hint,
                         "key": key})

    icons = {
        "auth_failed":      "🔑",
        "access_denied":    "⛔",
        "timeout":          "⏱",
        "dns_error":        "🌐",
        "winrm_refused":    "⚠️",
        "host_unreachable": "🚨",
        "ping_down":        "🚨",
    }

    for server_name, status, error, checked_at, cpu_load, ram_total, ram_free in status_rows:
        checked_utc = checked_at.replace(tzinfo=timezone.utc)
        age_min = (now_utc - checked_utc).total_seconds() / 60
        time_str = _format_local_time(checked_at)

        if status != "online":
            icon = icons.get(status, "❓")
            line = f"{icon} {status} ({time_str})"
            if error:
                line += f"\n   {error.splitlines()[0][:90]}"
            add("crit", "status", server_name, line, weight=age_min,
                key=f"offline:{server_name}")
            continue

        if age_min > STALE_MINUTES:
            add("warn", "stale", server_name,
                f"⚠️ данные старше {round(age_min)} мин ({time_str})",
                weight=age_min, key=f"stale:{server_name}")

    for server_name, disk_name, free_gb, used_gb, created_at in disk_rows:
        if is_pseudo_disk(disk_name):
            continue
        free = float(free_gb)
        used = float(used_gb)
        total = free + used
        if total <= 0:
            continue
        free_pct = round(free / total * 100, 1)
        detail = f"{disk_name}: свободно {free_pct}% ({free} ГБ)"
        hint = f"минимум {free_pct}% свободно"
        disk_key = f"disk:{server_name}:{disk_name}"
        if free_pct < DISK_CRIT_FREE:
            add("crit", "disk", server_name, f"🔴 {detail}",
                weight=100 - free_pct, hint=hint, key=disk_key)
        elif free_pct < DISK_WARN_FREE:
            add("warn", "disk", server_name, f"🟠 {detail}",
                weight=100 - free_pct, hint=hint, key=disk_key)

    # RAID: развал массива не виден ни по свободному месту, ни по SMART
    # отдельного диска — в сводке проблем ему самое место
    for config_name in sorted(config_server_names):
        for array in load_disk_health(config_name).get("raid") or []:
            if not array.get("degraded"):
                continue
            counts = ""
            if array.get("total") is not None:
                counts = f" ({array.get('active')}/{array['total']})"
            if array.get("progress"):
                percent = array["progress"].get("percent")
                add("crit", "raid", config_name,
                    f"🔄 RAID {array.get('name')} восстанавливается{counts} — {percent}%",
                    key=f"raid:{config_name}:{array.get('name')}")
            else:
                add("crit", "raid", config_name,
                    f"🚨 RAID {array.get('name')} деградирован{counts}",
                    key=f"raid:{config_name}:{array.get('name')}")

    for service_name, display_name, service_status, server_name, checked_at in service_rows:
        label = display_name if display_name and display_name != service_name else service_name
        add("crit", "service", server_name, f"🚨 сервис {label} = {service_status}",
            key=f"service:{server_name}:{service_name}")

    for (
        server_name, backup_type, backup_path, file_count,
        newest_file, disk_total_gb, disk_free_gb, created_at
    ) in backup_rows:
        if server_name in config_server_names:
            server_targets = backup_targets.get(server_name, set())
            if not server_targets or (backup_type, backup_path) not in server_targets:
                continue

        created_utc = created_at.replace(tzinfo=timezone.utc)
        age_min = (now_utc - created_utc).total_seconds() / 60
        label = f"{backup_type.upper()} {backup_path}"
        backup_key = f"backup:{server_name}:{backup_type}:{backup_path}"

        if age_min > BACKUP_STALE_MINUTES:
            add("warn", "backup_stale", server_name,
                f"⚠️ {label}: метрики backup старше {round(age_min)} мин",
                weight=age_min,
                key=f"backup_stale:{server_name}:{backup_path}")

        if not file_count:
            add("crit", "backup", server_name, f"🚨 {label}: нет файлов backup",
                key=backup_key)
            continue

        schedule = schedule_for(schedule_map, server_name, backup_type, backup_path)
        if newest_file:
            newest = newest_file
            if getattr(newest, "tzinfo", None) is None:
                newest = newest.replace(tzinfo=timezone.utc)
            if schedule:
                # Недельная копия: между плановыми днями возраст растёт законно,
                # проблема — только пропущенный дедлайн (см. shared/backup_schedule.py)
                if weekly_backup_missed(newest, schedule[0], schedule[1]):
                    age_days = round((now_utc - newest).total_seconds() / 86400, 1)
                    add("crit", "backup", server_name,
                        f"🚨 {label}: пропущена недельная копия "
                        f"(последняя {age_days} дн назад)",
                        weight=age_days, hint=f"худший {age_days} дн",
                        key=backup_key)
            else:
                age_hours = (now_utc - newest).total_seconds() / 3600
                if age_hours > BACKUP_CRIT_HOURS:
                    age_days = round(age_hours / 24, 1)
                    add("crit", "backup", server_name,
                        f"🔴 {label}: последний backup {age_days} дн назад",
                        weight=age_days, hint=f"худший {age_days} дн",
                        key=backup_key)
                elif age_hours > BACKUP_WARN_HOURS:
                    age_days = round(age_hours / 24, 1)
                    add("warn", "backup", server_name,
                        f"🟠 {label}: последний backup {age_days} дн назад",
                        weight=age_days, hint=f"худший {age_days} дн",
                        key=backup_key)
        elif schedule:
            add("crit", "backup", server_name,
                f"🚨 {label}: пропущена недельная копия (нет даты последнего backup)",
                key=backup_key)
        else:
            add("warn", "backup", server_name, f"🟠 {label}: нет даты последнего backup",
                key=backup_key)

        total = float(disk_total_gb or 0)
        free = float(disk_free_gb or 0)
        if total > 0:
            free_pct = round(free / total * 100, 1)
            hint = f"минимум {free_pct}% свободно"
            disk_key = f"disk:{server_name}:backup:{backup_path}"
            if free_pct < DISK_CRIT_FREE:
                add("crit", "disk", server_name,
                    f"🔴 {label}: диск backup свободно {free_pct}% ({free} ГБ)",
                    weight=100 - free_pct, hint=hint, key=disk_key)
            elif free_pct < DISK_WARN_FREE:
                add("warn", "disk", server_name,
                    f"🟠 {label}: диск backup свободно {free_pct}% ({free} ГБ)",
                    weight=100 - free_pct, hint=hint, key=disk_key)

    for (
        server_name, log_name, log_path, total_size_gb,
        file_count, status, error, created_at
    ) in onec_log_rows:
        created_utc = created_at.replace(tzinfo=timezone.utc)
        age_min = (now_utc - created_utc).total_seconds() / 60
        label = f"1C log {log_name}: {log_path}"

        if age_min > ONEC_LOG_STALE_MINUTES:
            add("warn", "stale", server_name,
                f"⚠️ {label}: метрики старше {round(age_min)} мин", weight=age_min,
                key=f"onec_stale:{server_name}:{log_path}")

        if status != "ok":
            detail = error.splitlines()[0][:90] if error else status
            add("crit", "onec", server_name, f"🚨 {label}: {detail}",
                key=f"onec_log:{server_name}:{log_name}")
            continue

        size_gb = float(total_size_gb or 0)
        hint = f"крупнейший {size_gb} ГБ"
        onec_key = f"onec_log:{server_name}:{log_name}"
        if size_gb >= ONEC_LOG_CRIT_GB:
            add("crit", "onec", server_name, f"🚨 {label}: размер {size_gb} ГБ",
                weight=size_gb, hint=hint, key=onec_key)
        elif size_gb >= ONEC_LOG_WARN_GB:
            add("warn", "onec", server_name, f"🟠 {label}: размер {size_gb} ГБ",
                weight=size_gb, hint=hint, key=onec_key)

    for server_name, backup_path, file_path, status, error, created_at in verify_rows:
        detail = (error or status or "").splitlines()[0][:90]
        add("crit", "verify", server_name,
            f"🚨 backup не прошёл RESTORE VERIFYONLY\n   {backup_path}: {detail}",
            key=f"verify:{server_name}:{backup_path}")

    return problems


KIND_TITLES = {
    "status":       ("🖥", "Серверы не на связи"),
    "service":      ("🚨", "Службы"),
    "raid":         ("🧱", "RAID"),
    "disk":         ("💽", "Диски"),
    "backup":       ("💾", "Бэкапы"),
    "verify":       ("🧪", "Проверка бэкапов"),
    "onec":         ("📋", "Журналы 1С"),
    "backup_stale": ("⏱", "Метрики бэкапов устарели"),
    "stale":        ("⏱", "Данные устарели"),
}

NO_PROBLEMS = "✅ Проблем не обнаружено"


def short_server_name(name: str, limit: int = 18) -> str:
    """Кнопка узкая: домен обрезается, длинное имя усекается."""
    short = name.split(".", 1)[0]
    return short if len(short) <= limit else short[:limit - 1] + "…"


def problems_by_server(problems: list) -> list:
    """Серверы для кнопок: сначала с критичным, дальше по числу замечаний."""
    grouped = defaultdict(list)
    for item in problems:
        grouped[item["server"]].append(item)

    servers = []
    for name, items in grouped.items():
        crit = sum(1 for i in items if i["level"] == "crit")
        servers.append({"name": name, "items": items, "crit": crit,
                        "total": len(items)})
    servers.sort(key=lambda s: (-s["crit"], -s["total"], s["name"]))
    return servers


def format_problems_summary(problems: list) -> str:
    if not problems:
        return NO_PROBLEMS

    crit = [i for i in problems if i["level"] == "crit"]
    warn = [i for i in problems if i["level"] == "warn"]

    lines = [
        "🚨 ТРЕБУЕТ ВНИМАНИЯ",
        f"🔴 Критично: {len(crit)} · 🟠 Предупреждений: {len(warn)}",
        "",
    ]

    grouped = defaultdict(list)
    for item in problems:
        grouped[item["kind"]].append(item)

    for kind, (icon, title) in KIND_TITLES.items():
        items = grouped.get(kind)
        if not items:
            continue
        servers = len({i["server"] for i in items})
        line = f"{icon} {title}: {len(items)}"
        if servers > 1:
            line += f" на {servers} серверах"
        worst = max(items, key=lambda i: i["weight"])
        if worst.get("hint"):
            line += f" · {worst['hint']}"
        lines.append(line)

    lines.append("")
    lines.append("Разбор по серверу — кнопки ниже.")
    return "\n".join(lines)


def format_problems_for_server(server: dict) -> str:
    """Все замечания одного сервера, сгруппированные по разделам."""
    lines = [
        f"🖥 {server['name']}",
        f"🔴 Критично: {server['crit']} · "
        f"🟠 Предупреждений: {server['total'] - server['crit']}",
    ]

    grouped = defaultdict(list)
    for item in server["items"]:
        grouped[item["kind"]].append(item)

    for kind, (icon, title) in KIND_TITLES.items():
        items = grouped.get(kind)
        if not items:
            continue
        lines.append("")
        lines.append(f"{icon} {title.upper()} ({len(items)})")
        items.sort(key=lambda i: (i["level"] != "crit", -i["weight"], i["text"]))
        lines += [item["text"] for item in items]

    return "\n".join(lines)


def ack_server_problems(server: dict) -> int:
    """Принять все замечания сервера навсегда — кнопка «Принял».

    Подавляются именно эти замечания (диск C:, эта база, эта служба), а не
    сервер целиком: новая проблема на том же сервере придёт как обычно.
    Возвращает, сколько замечаний заглушено — их же и показываем в ответе.
    Снимается в ⚙️ Настройка → ✅ Принятые алерты.
    """
    keys = {item["key"] for item in server["items"] if item.get("key")}
    for key in sorted(keys):
        ack_key_forever(key)
    # Иначе следующий экран показал бы только что принятые замечания из кеша
    invalidate_problems_cache()
    return len(keys)


# Готовая сводка и момент её сборки (monotonic). Общая на процесс: у бота
# один и тот же ответ для всех, кто нажал 🚨 Проблемы.
_problems_cache = {"at": 0.0, "value": None}
_problems_lock = threading.Lock()


def invalidate_problems_cache():
    """Сбрасывает кеш — после «Принял», когда ответ обязан измениться сразу."""
    with _problems_lock:
        _problems_cache["value"] = None


def get_problems(force: bool = False) -> tuple:
    """Сводка по категориям и серверы для кнопок. Плоский список строк
    разрастался до трёх десятков почти одинаковых строк — по пути на каждую
    базу, — и главное в нём терялось.

    Результат живёт PROBLEMS_CACHE_SECONDS: данные обновляются раз в пять
    минут, а ходьба «сводка → сервер → назад» пересчитывала их каждый раз
    заново — пять запросов на нажатие.
    """
    now = time.monotonic()
    if not force and PROBLEMS_CACHE_SECONDS > 0:
        with _problems_lock:
            cached = _problems_cache["value"]
            if cached and now - _problems_cache["at"] < PROBLEMS_CACHE_SECONDS:
                return cached

    problems = collect_problems()
    value = (format_problems_summary(problems), problems_by_server(problems))
    with _problems_lock:
        _problems_cache.update(at=time.monotonic(), value=value)
    return value


# ─── Отчёт ───────────────────────────────────────────────────

CPU_WARN, CPU_CRIT = 70, 90
RAM_WARN, RAM_CRIT = 70, 90
# Для дисков считается свободное место, поэтому пороги «меньше чем».
DISK_WARN, DISK_CRIT = 20, 10

REPORT_MODES = ("short", "compact", "full")


def _load_icon(value: float, warn: float, crit: float) -> str:
    return "🔴" if value >= crit else "🟠" if value >= warn else "🟢"


def _free_icon(pct_free: float) -> str:
    return "🔴" if pct_free < DISK_CRIT else "🟠" if pct_free < DISK_WARN else "🟢"


def collect_report_data() -> tuple:
    """Данные отчёта одним запросом на всех, чтобы три режима вывода
    отличались только вёрсткой."""
    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute("SELECT MAX(created_at) FROM disk_metrics")
        last_update = cur.fetchone()[0]

        cur.execute("""
            SELECT DISTINCT ON (server_name, disk_name)
                   server_name, disk_name, free_gb, used_gb
            FROM disk_metrics
            WHERE created_at >= NOW() - INTERVAL '1 hour' * %s
            ORDER BY server_name, disk_name, created_at DESC
        """, (DISK_METRIC_FRESH_HOURS,))
        disk_rows = cur.fetchall()

        cur.execute("""
            SELECT DISTINCT ON (server_name)
                   server_name, status, cpu_load, ram_total, ram_free, uptime_seconds
            FROM server_status
            ORDER BY server_name, checked_at DESC
        """)
        status_rows = cur.fetchall()

    server_statuses = {row[0]: row[1:] for row in status_rows}
    disks_by_server = defaultdict(list)
    for server, disk, free, used in disk_rows:
        if is_pseudo_disk(disk):
            continue
        disks_by_server[server].append((disk, float(free), float(used)))

    servers = []
    for name in sorted(set(disks_by_server) | set(server_statuses)):
        status_row = server_statuses.get(name)
        status = status_row[0] if status_row else "unknown"
        item = {"name": name, "status": status, "cpu": None, "ram_pct": None,
                "ram_free": None, "uptime": None, "disks": []}

        if status_row:
            cpu_load, ram_total, ram_free, uptime_seconds = status_row[1:]
            if cpu_load is not None:
                item["cpu"] = float(cpu_load)
            if ram_total is not None and ram_free is not None and float(ram_total) > 0:
                item["ram_free"] = float(ram_free)
                item["ram_pct"] = round(
                    (float(ram_total) - float(ram_free)) / float(ram_total) * 100, 1
                )
            item["uptime"] = uptime_seconds

        for disk, free, used in disks_by_server.get(name, []):
            total = free + used
            item["disks"].append({
                "name": disk,
                "free_gb": free,
                "pct_free": round((free / total) * 100, 1) if total > 0 else 0,
            })
        servers.append(item)

    return servers, last_update


def _server_alerts(server: dict) -> list:
    """Что именно не в порядке — этим строки отчёта и отличаются от
    сплошного перечисления всех метрик подряд."""
    alerts = []
    if server["cpu"] is not None and server["cpu"] >= CPU_WARN:
        alerts.append((server["cpu"] >= CPU_CRIT, f"CPU {server['cpu']}%"))
    if server["ram_pct"] is not None and server["ram_pct"] >= RAM_WARN:
        alerts.append((server["ram_pct"] >= RAM_CRIT, f"RAM {server['ram_pct']}%"))
    for disk in sorted(server["disks"], key=lambda d: d["pct_free"]):
        if disk["pct_free"] < DISK_WARN:
            alerts.append((disk["pct_free"] < DISK_CRIT,
                           f"{disk['name']} {disk['pct_free']}%"))
    return alerts


def _report_header(title: str, servers: list) -> str:
    return f"{title}\n{len(servers)} серверов\n"


def _report_footer(last_update) -> str:
    if not last_update:
        return ""
    t = last_update.replace(tzinfo=timezone.utc).astimezone(ALMATY)
    return f"\n📅 Данные актуальны на: {t.strftime('%d.%m.%Y %H:%M')}"


def _render_short(title: str, servers: list, last_update) -> str:
    offline = [s for s in servers if s["status"] != "online"]
    online = [s for s in servers if s["status"] == "online"]
    troubled = [(s, _server_alerts(s)) for s in online]
    troubled = [(s, a) for s, a in troubled if a]
    healthy = [s for s in online if not _server_alerts(s)]

    # Критичное выше предупреждений, дальше — по числу замечаний.
    troubled.sort(key=lambda pair: (not any(crit for crit, _ in pair[1]),
                                    -len(pair[1]), pair[0]["name"]))

    lines = [_report_header(title, servers)]
    if offline:
        lines.append(f"🔴 НЕ НА СВЯЗИ ({len(offline)})")
        lines += [f"🔴 {s['name']} ({s['status']})" for s in offline]
        lines.append("")

    if troubled:
        lines.append(f"⚠️ ТРЕБУЮТ ВНИМАНИЯ ({len(troubled)})")
        for server, alerts in troubled:
            icon = "🔴" if any(crit for crit, _ in alerts) else "🟠"
            detail = " · ".join(text for _, text in alerts[:4])
            if len(alerts) > 4:
                detail += f" · +{len(alerts) - 4}"
            lines.append(f"{icon} {server['name']} · {detail}")
        lines.append("")

    if healthy:
        lines.append(f"✅ В НОРМЕ ({len(healthy)})")
        lines.append(" · ".join(s["name"] for s in healthy))
        lines.append("")

    if not troubled and not offline:
        lines.append("Замечаний нет: CPU, память и диски в пределах порогов.")
        lines.append("")

    lines.append("Подробности по любому серверу — 🖥 Серверы")
    return "\n".join(lines) + _report_footer(last_update)


def _render_compact(title: str, servers: list, last_update) -> str:
    """Каждый сервер одной строкой: CPU, память и худший диск."""
    lines = [_report_header(title, servers)]
    ordered = sorted(
        servers,
        key=lambda s: (s["status"] == "online", not _server_alerts(s), s["name"])
    )
    for server in ordered:
        if server["status"] != "online":
            lines.append(f"🔴 {server['name']} ({server['status']})")
            continue

        alerts = _server_alerts(server)
        icon = "🟢"
        if alerts:
            icon = "🔴" if any(crit for crit, _ in alerts) else "🟠"

        parts = []
        if server["cpu"] is not None:
            parts.append(f"CPU {server['cpu']}%")
        if server["ram_pct"] is not None:
            parts.append(f"RAM {server['ram_pct']}%")

        disks = server["disks"]
        if disks:
            worst = min(disks, key=lambda d: d["pct_free"])
            tail = f" (из {len(disks)})" if len(disks) > 1 else ""
            if worst["pct_free"] < DISK_WARN:
                parts.append(f"{worst['name']} {worst['pct_free']}%{tail}")
            else:
                parts.append(f"диски ок ({len(disks)})")

        lines.append(f"{icon} {server['name']} · " + " · ".join(parts))

    return "\n".join(lines) + "\n" + _report_footer(last_update)


def _render_full(title: str, servers: list, last_update) -> str:
    critical, warning = [], []
    lines = [_report_header(title, servers)]

    for server in servers:
        if server["status"] != "online":
            lines.append(f"🔴 {server['name']} ({server['status']})\n")
            continue

        lines.append(f"🖥 {server['name']}")
        if server["cpu"] is not None:
            icon = _load_icon(server["cpu"], CPU_WARN, CPU_CRIT)
            lines.append(f"   {icon} CPU: {server['cpu']}%")
            if server["cpu"] >= CPU_CRIT:
                critical.append(f"🔴 {server['name']} → CPU {server['cpu']}%")
            elif server["cpu"] >= CPU_WARN:
                warning.append(f"🟠 {server['name']} → CPU {server['cpu']}%")
        if server["ram_pct"] is not None:
            icon = _load_icon(server["ram_pct"], RAM_WARN, RAM_CRIT)
            lines.append(
                f"   {icon} RAM: {server['ram_pct']}% занято "
                f"({server['ram_free']} ГБ свободно)"
            )
            if server["ram_pct"] >= RAM_CRIT:
                critical.append(f"🔴 {server['name']} → RAM {server['ram_pct']}%")
            elif server["ram_pct"] >= RAM_WARN:
                warning.append(f"🟠 {server['name']} → RAM {server['ram_pct']}%")
        if server["uptime"] is not None:
            lines.append(f"   ⏱ Uptime: {_format_duration(server['uptime'])}")

        for disk in server["disks"]:
            pct = disk["pct_free"]
            icon = _free_icon(pct)
            entry = f"{server['name']} → {disk['name']} ({pct}%)"
            if pct < DISK_CRIT:
                critical.append(f"🔴 {entry}")
            elif pct < DISK_WARN:
                warning.append(f"🟠 {entry}")
            lines.append(
                f"   {icon} {disk['name']}: {pct}% свободно ({disk['free_gb']} ГБ)"
            )
        lines.append("")

    lines.append("━" * 20)
    if critical:
        lines.append("\n🚨 КРИТИЧНО\n")
        lines += critical
    if warning:
        lines.append("\n🟠 ПРЕДУПРЕЖДЕНИЕ\n")
        lines += warning

    return "\n".join(lines) + "\n" + _report_footer(last_update)


def build_report(title: str = "📊 ОТЧЁТ ПО ИНФРАСТРУКТУРЕ",
                 mode: str = "short") -> str:
    """Три вида одного отчёта. По умолчанию короткий: полный перечень всех
    метрик всех серверов занимал под сотню строк и два сообщения Telegram,
    а читали в нём ровно то, что вышло за пороги."""
    servers, last_update = collect_report_data()
    if mode == "full":
        return _render_full(title, servers, last_update)
    if mode == "compact":
        return _render_compact(title, servers, last_update)
    return _render_short(title, servers, last_update)
