"""
shared/pgconn.py

Единое подключение к PostgreSQL для bot и monitor.
Коммитит транзакцию при успешном выходе из контекста (для SELECT это no-op).

Соединения берутся из пула, а не открываются заново на каждый запрос: один
отчёт или график — это десятки обращений к базе подряд, и раньше каждое
платило за TCP-рукопожатие и аутентификацию. Пул общий на процесс и
потокобезопасный: монитор опрашивает серверы в ThreadPoolExecutor, бот
уводит запросы в asyncio.to_thread.

POSTGRES_POOL_SIZE ограничивает число одновременных соединений от одного
процесса (по умолчанию 10).
"""
import os
import threading
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool as _pg_pool

_pool = None
_pool_lock = threading.Lock()


def _pool_size() -> int:
    raw = os.getenv("POSTGRES_POOL_SIZE", "10").strip()
    try:
        size = int(raw)
    except ValueError:
        print(f"[pgconn] Некорректный POSTGRES_POOL_SIZE={raw!r}, беру 10", flush=True)
        return 10
    return max(1, size)


def _get_pool():
    """Ленивая инициализация: пул создаётся при первом запросе, а не на импорте,
    чтобы модуль можно было импортировать до того, как поднялась база."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = _pg_pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=_pool_size(),
                    host=os.getenv("POSTGRES_HOST"),
                    dbname=os.getenv("POSTGRES_DB"),
                    user=os.getenv("POSTGRES_USER"),
                    password=os.getenv("POSTGRES_PASSWORD"),
                )
    return _pool


@contextmanager
def get_conn():
    pool = _get_pool()
    conn = pool.getconn()

    # Соединение могло умереть, пока лежало в пуле (перезапуск Postgres,
    # обрыв сети). Мёртвое выбрасываем и берём следующее — иначе первый же
    # запрос после рестарта базы падал бы у случайного вызывающего.
    if conn.closed:
        pool.putconn(conn, close=True)
        conn = pool.getconn()

    broken = False
    try:
        yield conn
        conn.commit()
    except Exception:
        # Без отката в пул вернулась бы соединение с оборванной транзакцией,
        # и следующий, кто его возьмёт, получил бы InFailedSqlTransaction
        # на ровном месте.
        try:
            conn.rollback()
        except psycopg2.Error:
            broken = True
        raise
    finally:
        pool.putconn(conn, close=broken or conn.closed)


def close_pool():
    """Закрывает все соединения. Нужен только при остановке процесса."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            try:
                _pool.closeall()
            finally:
                _pool = None
