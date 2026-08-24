from psycopg2 import errors
from psycopg2.extras import execute_values

from pgconn import get_conn


def save_disk_metric(server_name: str, disk_name: str, free_gb: float, used_gb: float):
    save_disk_metrics(server_name, [(disk_name, free_gb, used_gb)])


def save_disk_metrics(server_name: str, rows: list):
    """rows — [(disk_name, free_gb, used_gb), ...]. Одна вставка на сервер:
    у машины бывает пять-шесть дисков, и раньше каждый стоил отдельного
    запроса в цикле опроса."""
    if not rows:
        return
    values = [(server_name, disk_name, free_gb, used_gb)
              for disk_name, free_gb, used_gb in rows]
    with get_conn() as conn:
        cur = conn.cursor()
        execute_values(
            cur,
            "INSERT INTO disk_metrics (server_name, disk_name, free_gb, used_gb) VALUES %s",
            values
        )


def get_disk_free_history(server_name: str, disk_name: str, days: int = 14) -> list:
    """[(created_at, free_gb), ...] за последние N суток — основа прогноза
    заполнения диска (shared/disk_forecast.py). Берём по одному замеру в час:
    опрос идёт каждые 5 минут, и все точки часа лежат почти в одной,
    только утяжеляя выборку.

    Есть индекс (server_name, disk_name, created_at DESC)."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT MIN(created_at) AS at, AVG(free_gb) AS free_gb
            FROM disk_metrics
            WHERE server_name = %s AND disk_name = %s
              AND created_at >= NOW() - make_interval(days => %s)
            GROUP BY date_trunc('hour', created_at)
            ORDER BY at
            """,
            (server_name, disk_name, days)
        )
        return [(row[0], float(row[1])) for row in cur.fetchall()]


def save_server_status(server_name: str, status: str, error: str = None,
                       cpu_load: float = None, ram_total: float = None, ram_free: float = None,
                       uptime_seconds: int = None):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO server_status
                (server_name, status, error, cpu_load, ram_total, ram_free, uptime_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (server_name, status, error, cpu_load, ram_total, ram_free, uptime_seconds)
        )


def save_service_status(server_name: str, service_name: str, display_name: str, status: str):
    save_service_statuses(server_name, [(service_name, display_name, status)])


def save_service_statuses(server_name: str, rows: list):
    """rows — [(service_name, display_name, status), ...]. Одна вставка вместо
    запроса на каждую службу: на серверах 1С их до десятка."""
    if not rows:
        return
    values = [(server_name, service_name, display_name, status)
              for service_name, display_name, status in rows]
    with get_conn() as conn:
        cur = conn.cursor()
        execute_values(
            cur,
            "INSERT INTO service_status (server_name, service_name, display_name, status) VALUES %s",
            values
        )


def save_process_metrics(server_name: str, metric_type: str, processes: list):
    """Топ процессов приходит списком по 5-10 штук на каждый тип метрики —
    пишем одной вставкой, а не циклом execute."""
    if not processes:
        return
    values = [
        (
            server_name,
            metric_type,
            process.get("Name"),
            process.get("Id"),
            process.get("CpuPercent"),
            process.get("CpuSeconds"),
            process.get("MemoryMB")
        )
        for process in processes
    ]
    with get_conn() as conn:
        cur = conn.cursor()
        execute_values(
            cur,
            """
            INSERT INTO process_metrics
                (server_name, metric_type, process_name, process_id,
                 cpu_percent, cpu_seconds, memory_mb)
            VALUES %s
            """,
            values
        )


def get_latest_server_status(server_name: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT status
            FROM server_status
            WHERE server_name = %s
            ORDER BY checked_at DESC
            LIMIT 1
            """,
            (server_name,)
        )
        row = cur.fetchone()
    return row[0] if row else None


def cleanup_removed_servers(current_names: list) -> list:
    """
    Удаляет из БД серверы которых нет в servers.json.
    Возвращает список удалённых имён.
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT server_name FROM server_status")
        db_names = {row[0] for row in cur.fetchall()}
        removed = db_names - set(current_names)
        for name in removed:
            cur.execute("DELETE FROM server_status WHERE server_name = %s", (name,))
            cur.execute("DELETE FROM disk_metrics WHERE server_name = %s", (name,))
            cur.execute("DELETE FROM service_status WHERE server_name = %s", (name,))
            cur.execute("DELETE FROM process_metrics WHERE server_name = %s", (name,))
            cur.execute("DELETE FROM backup_metrics WHERE server_name = %s", (name,))
            cur.execute("DELETE FROM database_sizes WHERE server_name = %s", (name,))
            cur.execute("DELETE FROM onec_log_metrics WHERE server_name = %s", (name,))

    # Отдельная транзакция: таблицы может не быть на старой БД,
    # ошибка не должна откатить остальные удаления
    if removed:
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                for name in removed:
                    cur.execute("DELETE FROM backup_verifications WHERE server_name = %s", (name,))
        except errors.UndefinedTable:
            pass
    return list(removed)


def cleanup_old_data(retain_days: int) -> tuple:
    """
    Удаляет записи старше retain_days дней.
    Возвращает (удалено метрик, удалено статусов, удалено сервисов, удалено процессов,
    удалено backup, удалено database_sizes, удалено onec_log).
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM disk_metrics WHERE created_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_metrics = cur.rowcount
        cur.execute(
            "DELETE FROM server_status WHERE checked_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_status = cur.rowcount
        cur.execute(
            "DELETE FROM service_status WHERE checked_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_services = cur.rowcount
        cur.execute(
            "DELETE FROM process_metrics WHERE created_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_processes = cur.rowcount
        cur.execute(
            "DELETE FROM backup_metrics WHERE created_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_backups = cur.rowcount
        cur.execute(
            "DELETE FROM database_sizes WHERE collected_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_db_sizes = cur.rowcount
        cur.execute(
            "DELETE FROM onec_log_metrics WHERE created_at < NOW() - make_interval(days => %s)",
            (retain_days,)
        )
        deleted_onec_logs = cur.rowcount

    # Отдельная транзакция: таблицы может не быть на старой БД
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM backup_verifications WHERE created_at < NOW() - make_interval(days => %s)",
                (retain_days,)
            )
    except errors.UndefinedTable:
        pass

    return (
        deleted_metrics, deleted_status, deleted_services, deleted_processes,
        deleted_backups, deleted_db_sizes, deleted_onec_logs
    )
