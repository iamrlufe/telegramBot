"""
bot/backup_bot_db.py

Запросы к PostgreSQL для модуля бэкапов.
"""
import json
import os
from datetime import datetime, timedelta, timezone

from psycopg2 import errors

from pgconn import get_conn
from backup_files import (
    list_backup_files,
    deletable_backup_targets,
    DELETABLE_EXTENSIONS,
    NO_DELETE_TYPES,
)
from backup_verify import path_str
from backup_schedule import load_schedule_map, schedule_for, weekly_backup_missed
from settings import SERVERS_FILE

SYSTEM_DATABASES = {"master", "model", "msdb", "tempdb"}
COPY_DATABASE_MARKERS = ("copy", "коп", "backup", "bak", "old")


def load_server_config(server_name: str) -> dict | None:
    """Конфиг сервера из servers.json (host, учётные данные, backups)."""
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
    except Exception as e:
        print(f"[backup_db] Ошибка чтения {SERVERS_FILE}: {e}")
        return None
    return next((s for s in servers if s.get("name") == server_name), None)


def get_backup_servers() -> list:
    """Список серверов для раздела backup report."""
    config_servers = []
    config_server_names = set()
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
        for server in servers:
            config_server_names.add(server["name"])
            backups = server.get("backups", {})
            has_backup_paths = isinstance(backups, dict) and any(backups.values())
            if has_backup_paths:
                config_servers.append(server["name"])
    except Exception as e:
        print(f"[backup_db] Ошибка чтения {SERVERS_FILE}: {e}")

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT server_name
            FROM backup_metrics
            ORDER BY server_name
        """)
        db_servers = [row[0] for row in cur.fetchall()]

    orphan_db_servers = [name for name in db_servers if name not in config_server_names]
    return sorted(set(config_servers) | set(orphan_db_servers))


def get_config_backup_targets(server_name: str | None = None) -> dict[str, list[dict]]:
    targets: dict[str, list[dict]] = {}
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
        for server in servers:
            name = server["name"]
            if server_name and name != server_name:
                continue
            backups = server.get("backups", {})
            items = []
            if isinstance(backups, dict):
                for backup_type, paths in backups.items():
                    if not isinstance(paths, list):
                        paths = [paths]
                    for raw_path in paths:
                        backup_path = path_str(raw_path)
                        if backup_path:
                            items.append({
                                "backup_type": backup_type,
                                "backup_path": backup_path,
                            })
            targets[name] = items
    except Exception as e:
        print(f"[backup_db] Ошибка чтения {SERVERS_FILE}: {e}")

    if server_name:
        return {server_name: targets.get(server_name, [])}
    return targets


def has_config_server(server_name: str) -> bool:
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
        return any(server.get("name") == server_name for server in servers)
    except Exception as e:
        print(f"[backup_db] Ошибка чтения {SERVERS_FILE}: {e}")
        return False


def get_cleanup_servers() -> list:
    """Список серверов для cleanup только с реальными удаляемыми backup-путями."""
    config_servers = []
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
        for server in servers:
            backups = server.get("backups", {})
            if not isinstance(backups, dict):
                continue
            # Windows чистится по WinRM, Linux и NAS — по SSH.
            # Сетевым устройствам чистить нечего.
            if (server.get("type") or "windows").strip().lower() == "device":
                continue
            for backup_type, paths in backups.items():
                if backup_type in NO_DELETE_TYPES:
                    continue
                if paths:
                    config_servers.append(server["name"])
                    break
    except Exception as e:
        print(f"[backup_db] Ошибка чтения {SERVERS_FILE}: {e}")

    return sorted(set(config_servers))


BACKUP_STATUS_MISSING = "missing"


def get_latest_backup_metrics(include_missing: bool = False) -> list:
    """Последние метрики по каждому серверу/типу/пути.

    include_missing=True добавляет пути, которые есть в конфиге, но по
    которым метрик нет вовсе (status=BACKUP_STATUS_MISSING). Без них сервер,
    у которого сбор ни разу не отработал, выглядел в дайджесте ровно как
    сервер без настроенных бэкапов — то есть самая опасная ситуация была
    невидима. По умолчанию выключено, чтобы не менять остальных вызывающих.
    """
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT DISTINCT ON (server_name, backup_type, backup_path)
                    server_name, backup_type, backup_path,
                    file_count, oldest_file, newest_file,
                    total_size_gb, disk_total_gb, disk_free_gb,
                    status, error,
                    created_at
                FROM backup_metrics
                ORDER BY server_name, backup_type, backup_path, created_at DESC
            """)
        except errors.UndefinedColumn:
            conn.rollback()
            cur = conn.cursor()
            cur.execute("""
                SELECT DISTINCT ON (server_name, backup_type, backup_path)
                    server_name, backup_type, backup_path,
                    file_count, oldest_file, newest_file,
                    total_size_gb, disk_total_gb, disk_free_gb,
                    NULL::TEXT AS status,
                    NULL::TEXT AS error,
                    created_at
                FROM backup_metrics
                ORDER BY server_name, backup_type, backup_path, created_at DESC
            """)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]

    # Пути, переименованные/удалённые в servers.json, оставляют в БД старые
    # строки навечно (monitor их больше не опрашивает, но и не удаляет) —
    # без этого фильтра они годами висят в дайджесте как "устарел"/"пусто".
    # Источник истины — текущий конфиг: путь показываем, только если он
    # там всё ещё есть.
    valid_paths = {
        (server, item["backup_type"], item["backup_path"])
        for server, items in get_config_backup_targets().items()
        for item in items
    }
    rows = [
        row for row in rows
        if (row["server_name"], row["backup_type"], row["backup_path"]) in valid_paths
    ]

    if include_missing:
        collected = {
            (row["server_name"], row["backup_type"], row["backup_path"])
            for row in rows
        }
        for server, backup_type, backup_path in sorted(valid_paths - collected):
            rows.append({
                "server_name": server,
                "backup_type": backup_type,
                "backup_path": backup_path,
                "file_count": None,
                "oldest_file": None,
                "newest_file": None,
                "total_size_gb": None,
                "disk_total_gb": None,
                "disk_free_gb": None,
                "status": BACKUP_STATUS_MISSING,
                "error": None,
                "created_at": None,
            })

    return rows


def get_backup_report(server_name: str) -> list:
    """Последние метрики конкретного сервера."""
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT DISTINCT ON (backup_type, backup_path)
                    backup_type, backup_path,
                    file_count, oldest_file, newest_file,
                    total_size_gb, disk_total_gb, disk_free_gb,
                    status, error
                FROM backup_metrics
                WHERE server_name = %s
                ORDER BY backup_type, backup_path, created_at DESC
            """, (server_name,))
        except errors.UndefinedColumn:
            conn.rollback()
            cur = conn.cursor()
            cur.execute("""
                SELECT DISTINCT ON (backup_type, backup_path)
                    backup_type, backup_path,
                    file_count, oldest_file, newest_file,
                    total_size_gb, disk_total_gb, disk_free_gb,
                    NULL::TEXT AS status,
                    NULL::TEXT AS error
                FROM backup_metrics
                WHERE server_name = %s
                ORDER BY backup_type, backup_path, created_at DESC
            """, (server_name,))
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]

    # См. get_latest_backup_metrics — те же старые пути после переименования в конфиге.
    valid_paths = {
        (item["backup_type"], item["backup_path"])
        for item in get_config_backup_targets(server_name).get(server_name, [])
    }
    return [row for row in rows if (row["backup_type"], row["backup_path"]) in valid_paths]


def get_db_sizes() -> list:
    """Последние данные о размерах БД по всем серверам."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (server_name, database_name)
                server_name, database_name, size_gb
            FROM database_sizes
            ORDER BY server_name, database_name, collected_at DESC
        """)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        return [
            row for row in rows
            if is_visible_database_name(row["database_name"])
        ]


def is_visible_database_name(database_name: str) -> bool:
    name = str(database_name or "").lower()
    if name in SYSTEM_DATABASES:
        return False
    return not any(marker in name for marker in COPY_DATABASE_MARKERS)


def get_growth_servers() -> list:
    """Серверы у которых есть история размеров (для графика роста)."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT server_name FROM database_sizes
            UNION
            SELECT DISTINCT server_name FROM backup_metrics
            ORDER BY server_name
        """)
        return [row[0] for row in cur.fetchall()]


def get_latest_verifications(days: int = 7) -> list[dict]:
    """Последний результат RESTORE VERIFYONLY по каждому server+path за N дней."""
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT DISTINCT ON (server_name, backup_path)
                    server_name, backup_path, file_path, file_size_gb,
                    status, error, duration_sec, created_at
                FROM backup_verifications
                WHERE created_at >= NOW() - make_interval(days => %s)
                ORDER BY server_name, backup_path, created_at DESC
            """, (days,))
        except errors.UndefinedTable:
            conn.rollback()
            return []
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def get_verify_backup_servers() -> list[str]:
    """Серверы с "verify_backup": true и хотя бы одним путём в backups.sql —
    для них имеет смысл предлагать ручной запуск RESTORE VERIFYONLY."""
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
    except Exception as e:
        print(f"[backup_db] Ошибка чтения {SERVERS_FILE}: {e}")
        return []
    names = []
    for s in servers:
        if not s.get("verify_backup"):
            continue
        sql_paths = s.get("backups", {}).get("sql", [])
        if sql_paths:
            names.append(s["name"])
    return names


def run_verify_now(server_name: str) -> list[dict]:
    """Ручной запуск RESTORE VERIFYONLY для сервера — вне суточного
    расписания (VERIFY_HOUR), по кнопке 🧪 Verify статус в боте.
    Возвращает список {path, status, error, size_gb, duration_sec} по каждому
    пути backups.sql. Блокирующая операция (WinRM + SQL) — вызывать через
    asyncio.to_thread."""
    from backup_verify import verify_newest_bak, save_verification, path_str

    server = load_server_config(server_name)
    if not server:
        raise ValueError(f"Сервер {server_name} не найден в конфиге")

    sql_paths = server.get("backups", {}).get("sql", [])
    if not isinstance(sql_paths, list):
        sql_paths = [sql_paths]

    results = []
    for path_spec in sql_paths:
        backup_path = path_str(path_spec)
        if not backup_path:
            continue
        try:
            res = verify_newest_bak(
                server["host"], backup_path,
                server.get("username"), server.get("password")
            )
        except Exception as e:
            res = {"status": "error", "error": str(e), "file": None,
                   "size_gb": None, "modified": None, "duration_sec": None}

        try:
            save_verification(server_name, backup_path, res)
        except Exception as e:
            print(f"[verify] {server_name}: не удалось сохранить результат: {e}")

        results.append({
            "path": backup_path,
            "status": res.get("status"),
            "error": res.get("error"),
            "size_gb": res.get("size_gb"),
            "duration_sec": res.get("duration_sec"),
        })
    return results


# ─── Еженедельный дайджест ───────────────────────────────────

def _week_ago_backup_sizes(days: int) -> dict:
    """{(server, type, path): total_size_gb} — самая ранняя запись за окно."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (server_name, backup_type, backup_path)
                server_name, backup_type, backup_path, total_size_gb
            FROM backup_metrics
            WHERE created_at >= NOW() - make_interval(days => %s)
              AND total_size_gb IS NOT NULL
            ORDER BY server_name, backup_type, backup_path, created_at ASC
        """, (days,))
        return {(r[0], r[1], r[2]): float(r[3]) for r in cur.fetchall()}


def _db_size_totals(days: int) -> tuple[dict, dict]:
    """({server: сумма ГБ сейчас}, {server: сумма ГБ N дней назад}) по видимым базам."""
    now_totals: dict[str, float] = {}
    old_totals: dict[str, float] = {}
    with get_conn() as conn:
        cur = conn.cursor()
        for target, order in ((now_totals, "DESC"), (old_totals, "ASC")):
            cur.execute(f"""
                SELECT DISTINCT ON (server_name, database_name)
                    server_name, database_name, size_gb
                FROM database_sizes
                WHERE collected_at >= NOW() - make_interval(days => %s)
                  AND size_gb IS NOT NULL
                ORDER BY server_name, database_name, collected_at {order}
            """, (days,))
            for server, db_name, size_gb in cur.fetchall():
                if not is_visible_database_name(db_name):
                    continue
                target[server] = target.get(server, 0.0) + float(size_gb)
    return now_totals, old_totals


def _fmt_delta(delta: float) -> str:
    sign = "+" if delta >= 0 else ""
    return f"{sign}{round(delta, 1)} ГБ/нед"


def classify_backup_row(row: dict, now_utc: datetime, schedule_map: dict = None) -> str:
    """Статус одного пути бэкапа: "crit" / "warn" / "ok" — та же логика,
    что и в тексте дайджеста (build_backup_digest), вынесена сюда, чтобы
    графики (тепловая карта свежести) не расходились с текстом.

    schedule_map (из shared/backup_schedule.py) — пути с недельным расписанием
    оцениваются по пропуску дедлайна, а не по возрасту файла."""
    if row.get("status") in ("error", BACKUP_STATUS_MISSING):
        return "crit"
    if not (row["file_count"] or 0):
        return "crit"
    schedule = schedule_for(
        schedule_map, row["server_name"], row["backup_type"], row["backup_path"]
    )
    if row["newest_file"]:
        newest = row["newest_file"]
        if getattr(newest, "tzinfo", None):
            newest = newest.astimezone(timezone.utc).replace(tzinfo=None)
        if schedule:
            return "crit" if weekly_backup_missed(newest, schedule[0], schedule[1]) else "ok"
        age_h = (now_utc - newest).total_seconds() / 3600
        return "warn" if age_h > 24 else "ok"
    return "crit" if schedule else "warn"


def get_backup_volume_history(days: int = 30) -> list[dict]:
    """Суммарный объём бэкапов по серверам, по дням — для графика общего
    объёма по инфраструктуре. Берётся последний снимок каждого пути за
    день, чтобы не завышать сумму частыми опросами monitor."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            WITH ranked AS (
                SELECT
                    server_name, backup_type, backup_path, total_size_gb,
                    DATE(created_at) AS day,
                    ROW_NUMBER() OVER (
                        PARTITION BY server_name, backup_type, backup_path, DATE(created_at)
                        ORDER BY created_at DESC
                    ) AS rn
                FROM backup_metrics
                WHERE created_at >= NOW() - make_interval(days => %s)
                  AND total_size_gb IS NOT NULL
            )
            SELECT day, server_name, SUM(total_size_gb) AS total_gb
            FROM ranked
            WHERE rn = 1
            GROUP BY day, server_name
            ORDER BY day
        """, (days,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def build_backup_digest(days: int = 7) -> str:
    """Еженедельная сводка: свежесть бэкапов, рост размеров, verify-статус."""
    from datetime import timezone as _tz

    latest = get_latest_backup_metrics(include_missing=True)
    old_sizes = _week_ago_backup_sizes(days)
    db_now, db_old = _db_size_totals(days)
    verifications = get_latest_verifications(days)
    verify_by_server: dict[str, list[dict]] = {}
    for v in verifications:
        verify_by_server.setdefault(v["server_name"], []).append(v)

    servers = sorted(
        {row["server_name"] for row in latest} | set(db_now) | set(verify_by_server)
    )
    if not servers:
        return "💾 ЕЖЕНЕДЕЛЬНЫЙ ДАЙДЖЕСТ БЭКАПОВ\n\nНет данных по бэкапам."

    now_utc = datetime.now(_tz.utc).replace(tzinfo=None)
    schedule_map = load_schedule_map(SERVERS_FILE)
    ok = warn = crit = 0
    blocks = []

    for server in servers:
        lines = [f"🖥 {server}"]

        for row in [r for r in latest if r["server_name"] == server]:
            btype, path = row["backup_type"], row["backup_path"]
            label = f"{btype.upper()} {path}"
            size = float(row["total_size_gb"] or 0)
            key = (server, btype, path)
            delta_txt = ""
            if key in old_sizes:
                delta_txt = f" ({_fmt_delta(size - old_sizes[key])})"

            if row.get("status") == BACKUP_STATUS_MISSING:
                # Путь настроен, но сбор по нему ни разу не отработал —
                # раньше такой сервер просто исчезал из дайджеста
                crit += 1
                lines.append(f"   🔴 {label}: нет данных сбора")
            elif row.get("status") == "error":
                crit += 1
                lines.append(f"   🔴 {label}: путь недоступен")
            elif not (row["file_count"] or 0):
                crit += 1
                lines.append(f"   🔴 {label}: каталог пуст")
            elif row["newest_file"]:
                newest = row["newest_file"]
                if getattr(newest, "tzinfo", None):
                    newest = newest.astimezone(_tz.utc).replace(tzinfo=None)
                age_h = (now_utc - newest).total_seconds() / 3600
                schedule = schedule_for(schedule_map, server, btype, path)
                if schedule and weekly_backup_missed(newest, schedule[0], schedule[1]):
                    crit += 1
                    lines.append(
                        f"   🔴 {label}: пропущена недельная копия "
                        f"(последняя {round(age_h / 24, 1)} дн назад)"
                    )
                elif schedule:
                    # Плановая недельная копия на месте — возраст ни при чём
                    ok += 1
                    lines.append(
                        f"   ✅ {label}: недельная копия в срок, "
                        f"{round(size, 1)} ГБ{delta_txt}"
                    )
                elif age_h > 24:
                    warn += 1
                    lines.append(
                        f"   🟠 {label}: последний {round(age_h / 24, 1)} дн назад, "
                        f"{round(size, 1)} ГБ{delta_txt}"
                    )
                else:
                    ok += 1
                    lines.append(
                        f"   ✅ {label}: свежий ({round(age_h)} ч назад), "
                        f"{round(size, 1)} ГБ{delta_txt}"
                    )
            else:
                warn += 1
                lines.append(f"   🟠 {label}: нет даты последнего бэкапа")

        for v in verify_by_server.get(server, []):
            when = v["created_at"].strftime("%d.%m") if v.get("created_at") else "?"
            if v["status"] == "ok":
                lines.append(f"   🧪 Verify: ✅ ok ({when})")
            else:
                crit += 1
                detail = (v.get("error") or v["status"] or "")[:60]
                lines.append(f"   🧪 Verify: ❌ {v['status']} ({when}) {detail}")

        if server in db_now:
            delta_txt = ""
            if server in db_old:
                delta_txt = f" ({_fmt_delta(db_now[server] - db_old[server])})"
            lines.append(f"   🗄 Базы: {round(db_now[server], 1)} ГБ{delta_txt}")

        blocks.append("\n".join(lines))

    header = (
        f"💾 ЕЖЕНЕДЕЛЬНЫЙ ДАЙДЖЕСТ БЭКАПОВ\n\n"
        f"✅ Норма: {ok}   🟠 Предупреждение: {warn}   🔴 Критично: {crit}\n\n"
        f"{'━' * 20}\n\n"
    )
    return header + "\n\n".join(blocks)


def get_files_for_cleanup(server_name: str, age_days: int,
                          only_path: str = None) -> list:
    """
    Возвращает список файлов старше age_days для данного сервера.
    Только не-veeam типы, только разрешённые расширения.

    only_path — чистить лишь один каталог бэкапов (у сервера их может быть
    несколько на разных дисках, и заполняются они по-разному).
    Учётные данные в результат не попадают.
    """
    server = load_server_config(server_name)
    if not server:
        return []

    targets = deletable_backup_targets(server)
    if only_path:
        targets = [t for t in targets if t["path"] == only_path]

    # naive UTC — сравнивается с LastWriteTime.ToUniversalTime() из PowerShell
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=age_days)

    result = []
    for target in targets:
        backup_path = target["path"]
        try:
            files = list_backup_files(
                server,
                backup_path,
                older_than=cutoff.strftime("%Y-%m-%d %H:%M:%S"),
                extensions=DELETABLE_EXTENSIONS,
            )
            for f in files:
                ext = os.path.splitext(f["file_name"])[1].lower()
                if ext not in DELETABLE_EXTENSIONS:
                    continue
                mod = f["modified"]
                if isinstance(mod, str):
                    mod = datetime.strptime(mod, "%Y-%m-%d %H:%M:%S")
                if mod < cutoff:
                    result.append(dict(f))
        except Exception as e:
            print(f"[backup_db] Ошибка listing {server_name} {backup_path}: {e}")

    # Сортируем от старых к новым
    result.sort(key=lambda x: x["modified"])
    return result
