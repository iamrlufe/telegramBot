from psycopg2 import errors

from pgconn import get_conn

# Запись замеров опроса переехала в shared/metrics_store.py: тем же кодом
# пользуется кнопка «Обновить» в боте. Здесь осталось то, что нужно только
# монитору, — чтение истории, уборка и индексы.


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


def cleanup_old_data(retain_days: int, snapshot_days: int = None) -> tuple:
    """
    Удаляет записи старше retain_days дней.

    snapshot_days — свой, более короткий срок для таблиц, из которых читается
    только последняя запись: список служб и топ процессов. История там не
    используется нигде (ни в графиках, ни в прогнозе), а объём даёт больше
    половины базы — на десяти серверах это под полтора миллиона строк за
    месяц ради данных, которые живут пять минут.

    Возвращает (удалено метрик, удалено статусов, удалено сервисов, удалено процессов,
    удалено backup, удалено database_sizes, удалено onec_log).
    """
    snapshot_days = snapshot_days or retain_days
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
            (snapshot_days,)
        )
        deleted_services = cur.rowcount
        cur.execute(
            "DELETE FROM process_metrics WHERE created_at < NOW() - make_interval(days => %s)",
            (snapshot_days,)
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


# Индексы, которых нет в init.sql у давно живущих установок: init.sql
# накатывается только при первом старте базы, поэтому добавляем их здесь.
# Все существующие индексы начинаются с server_name и для выборки «всё
# старше даты» бесполезны — ежедневная очистка читала таблицы целиком.
TIME_INDEXES = [
    ("idx_disk_metrics_created", "disk_metrics", "created_at"),
    ("idx_server_status_checked", "server_status", "checked_at"),
    ("idx_service_status_checked", "service_status", "checked_at"),
    ("idx_process_metrics_created", "process_metrics", "created_at"),
    ("idx_backup_metrics_created", "backup_metrics", "created_at"),
    ("idx_database_sizes_collected", "database_sizes", "collected_at"),
    ("idx_onec_log_metrics_created", "onec_log_metrics", "created_at"),
]


def ensure_time_indexes():
    """Создаёт недостающие индексы по времени. Идемпотентна, вызывается
    при старте монитора: на пустой базе индексы уже есть из init.sql,
    на живой — появятся здесь."""
    for index, table, column in TIME_INDEXES:
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS {index} ON {table} ({column} DESC)"
                )
        except errors.UndefinedTable:
            continue
        except Exception as e:
            print(f"[monitor] Индекс {index} не создан: {e}", flush=True)
