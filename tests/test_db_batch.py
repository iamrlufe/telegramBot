"""
Пакетная запись метрик (monitor/db.py).

Цикл опроса пишет метрики по всем серверам каждые 5 минут. Раньше каждый диск,
служба и процесс стоили отдельного INSERT; здесь проверяем, что теперь на набор
приходится один запрос и что пустой набор не открывает соединение вовсе.
"""
from contextlib import contextmanager

import pytest

import db


class FakeCursor:
    pass


class FakeConn:
    def __init__(self):
        self.cursors = 0

    def cursor(self):
        self.cursors += 1
        return FakeCursor()


@pytest.fixture
def calls(monkeypatch):
    """Записывает обращения к БД: (открытых соединений, [(sql, values), ...])."""
    log = {"conns": 0, "inserts": []}

    @contextmanager
    def fake_get_conn():
        log["conns"] += 1
        yield FakeConn()

    def fake_execute_values(cur, sql, values):
        log["inserts"].append((" ".join(sql.split()), values))

    monkeypatch.setattr(db, "get_conn", fake_get_conn)
    monkeypatch.setattr(db, "execute_values", fake_execute_values)
    return log


def test_disks_written_in_one_insert(calls):
    db.save_disk_metrics("srv-01", [("C:", 10.5, 90.0), ("D:", 200.0, 50.0), ("E:", 1.0, 999.0)])

    assert calls["conns"] == 1
    assert len(calls["inserts"]) == 1
    sql, values = calls["inserts"][0]
    assert "INSERT INTO disk_metrics" in sql
    assert values == [
        ("srv-01", "C:", 10.5, 90.0),
        ("srv-01", "D:", 200.0, 50.0),
        ("srv-01", "E:", 1.0, 999.0),
    ]


def test_single_disk_helper_still_works(calls):
    db.save_disk_metric("srv-01", "C:", 10.5, 90.0)

    sql, values = calls["inserts"][0]
    assert "INSERT INTO disk_metrics" in sql
    assert values == [("srv-01", "C:", 10.5, 90.0)]


def test_services_written_in_one_insert(calls):
    db.save_service_statuses("srv-01", [
        ("MSSQLSERVER", "SQL Server", "running"),
        ("W3SVC", "IIS", "stopped"),
    ])

    assert len(calls["inserts"]) == 1
    sql, values = calls["inserts"][0]
    assert "INSERT INTO service_status" in sql
    assert values == [
        ("srv-01", "MSSQLSERVER", "SQL Server", "running"),
        ("srv-01", "W3SVC", "IIS", "stopped"),
    ]


def test_processes_written_in_one_insert(calls):
    db.save_process_metrics("srv-01", "cpu", [
        {"Name": "sqlservr", "Id": 100, "CpuPercent": 40.5, "CpuSeconds": 12, "MemoryMB": 2048},
        {"Name": "w3wp", "Id": 200, "CpuPercent": 5.0, "CpuSeconds": 3, "MemoryMB": 512},
    ])

    assert len(calls["inserts"]) == 1
    sql, values = calls["inserts"][0]
    assert "INSERT INTO process_metrics" in sql
    assert values == [
        ("srv-01", "cpu", "sqlservr", 100, 40.5, 12, 2048),
        ("srv-01", "cpu", "w3wp", 200, 5.0, 3, 512),
    ]


def test_missing_process_fields_become_none(calls):
    db.save_process_metrics("srv-01", "memory", [{"Name": "idle"}])

    _, values = calls["inserts"][0]
    assert values == [("srv-01", "memory", "idle", None, None, None, None)]


@pytest.mark.parametrize("call", [
    lambda: db.save_disk_metrics("srv-01", []),
    lambda: db.save_service_statuses("srv-01", []),
    lambda: db.save_process_metrics("srv-01", "cpu", []),
])
def test_empty_batch_does_not_touch_db(calls, call):
    call()

    # Сервер без дисков или без служб — обычное дело; лишнее соединение
    # на каждый такой сервер в каждом цикле не нужно.
    assert calls["conns"] == 0
    assert calls["inserts"] == []
