"""
Пул соединений с PostgreSQL (shared/pgconn.py).

Проверяем не сам psycopg2, а договорённости, на которые опирается остальной
код: транзакция коммитится при успехе, откатывается при исключении, и
соединение всегда возвращается в пул — иначе пул исчерпается за несколько
запросов и бот встанет.
"""
import psycopg2
import pytest

import pgconn


class FakeConn:
    def __init__(self, closed=False, rollback_error=False):
        self.closed = closed
        self.rollback_error = rollback_error
        self.commits = 0
        self.rollbacks = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1
        if self.rollback_error:
            raise psycopg2.Error("соединение потеряно")


class FakePool:
    def __init__(self, *conns):
        self.available = list(conns)
        self.returned = []

    def getconn(self):
        return self.available.pop(0)

    def putconn(self, conn, close=False):
        self.returned.append((conn, close))


@pytest.fixture
def use_pool(monkeypatch):
    """Подставляет фальшивый пул вместо настоящего."""
    def install(*conns):
        pool = FakePool(*conns)
        monkeypatch.setattr(pgconn, "_get_pool", lambda: pool)
        return pool
    return install


def test_commit_on_success(use_pool):
    conn = FakeConn()
    pool = use_pool(conn)

    with pgconn.get_conn() as got:
        assert got is conn

    assert conn.commits == 1
    assert conn.rollbacks == 0
    assert pool.returned == [(conn, False)]


def test_rollback_and_reraise_on_error(use_pool):
    conn = FakeConn()
    pool = use_pool(conn)

    with pytest.raises(ValueError):
        with pgconn.get_conn():
            raise ValueError("запрос упал")

    # Без отката соединение вернулось бы в пул с оборванной транзакцией,
    # и следующий вызывающий получил бы ошибку на ровном месте.
    assert conn.rollbacks == 1
    assert conn.commits == 0
    assert pool.returned == [(conn, False)]


def test_dead_connection_is_replaced(use_pool):
    dead, alive = FakeConn(closed=True), FakeConn()
    pool = use_pool(dead, alive)

    with pgconn.get_conn() as got:
        assert got is alive

    # Мёртвое соединение выброшено (close=True), рабочее возвращено в пул
    assert pool.returned[0] == (dead, True)
    assert pool.returned[-1] == (alive, False)


def test_connection_dropped_when_rollback_fails(use_pool):
    conn = FakeConn(rollback_error=True)
    pool = use_pool(conn)

    with pytest.raises(ValueError):
        with pgconn.get_conn():
            raise ValueError("запрос упал")

    # Откатить не удалось — состояние соединения неизвестно, в пул не возвращаем
    assert pool.returned == [(conn, True)]


@pytest.mark.parametrize("env,expected", [
    (None, 10),
    ("3", 3),
    ("0", 1),
    ("-5", 1),
    ("много", 10),
])
def test_pool_size(monkeypatch, env, expected):
    if env is None:
        monkeypatch.delenv("POSTGRES_POOL_SIZE", raising=False)
    else:
        monkeypatch.setenv("POSTGRES_POOL_SIZE", env)
    assert pgconn._pool_size() == expected
