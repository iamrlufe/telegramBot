"""
shared/pgconn.py

Единое подключение к PostgreSQL для bot и monitor.
Коммитит транзакцию при успешном выходе из контекста (для SELECT это no-op).
"""
import os
from contextlib import contextmanager

import psycopg2


@contextmanager
def get_conn():
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST"),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD")
    )
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
