"""
shared/metrics_store.py

Запись замеров опроса в PostgreSQL: статус сервера, диски, службы, топ
процессов. Одно место на оба процесса.

Раньше этот код жил в monitor/db.py, а bot/refresh.py — кнопка «Обновить» —
держал собственную копию: те же четыре таблицы, но INSERT на каждый диск,
службу и процесс в цикле, тогда как монитор давно писал их пачкой через
execute_values. Расхождение было не только в скорости: колонку пришлось бы
добавлять в двух местах, и второе забылось бы.

Импортировать monitor/db.py из бота нельзя — это разные образы, в /app бота
каталога monitor нет вовсе. Поэтому общий код лежит в shared/, который
копируется в оба.
"""
from psycopg2.extras import execute_values

from pgconn import get_conn


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
