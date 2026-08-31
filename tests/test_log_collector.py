"""Фоновый сбор журналов: кого опрашиваем, как часто и что делаем при отказе.

Живьём журналы читать нельзя — на десятке серверов это под сотню удалённых
вызовов на каждый отчёт. Поэтому монитор собирает сводку раз в час, и цена
ошибки здесь — либо лишняя нагрузка, либо пустой дашборд.
"""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lc = _load("log_collector", ROOT / "monitor" / "log_collector.py")

WINDOWS = {"name": "app-01.example.local", "host": "192.0.2.11"}
WINDOWS_SQL = {"name": "sql-01.example.local", "host": "192.0.2.10", "dbsize": True}
LINUX = {"name": "nas-01.example.local", "host": "192.0.2.20", "type": "linux"}
DEVICE = {"name": "sw-01.example.local", "host": "192.0.2.1", "type": "device"}


@pytest.fixture
def readers(monkeypatch):
    """Настоящие ходят по WinRM и в SQL — подменяем оба."""
    calls = {"win": [], "sql": []}

    def win(server, hours=24):
        calls["win"].append(server["name"])
        return [{"category": "disk", "level": "crit", "event_at": "", "event_id": "7",
                 "title": "Ошибка диска", "detail": "", "count": 1}], ""

    def sql(server, hours=24):
        calls["sql"].append(server["name"])
        return [], ""

    monkeypatch.setattr(lc, "windows_events", win)
    monkeypatch.setattr(lc, "sql_events", sql)
    return calls


def test_windows_server_gives_only_event_log(readers):
    assert [source for _n, source, _e, _err in lc.collect_server(WINDOWS)] == ["win"]
    assert readers["sql"] == []


def test_mssql_server_gives_both_sources(readers):
    """dbsize и означает «здесь MSSQL» — тот же признак, по которому кнопка
    SQL-логов появляется в карточке."""
    assert [source for _n, source, _e, _err in lc.collect_server(WINDOWS_SQL)] == ["win", "sql"]


def test_linux_and_devices_are_skipped(readers):
    assert lc.collect_server(LINUX) == []
    assert lc.collect_server(DEVICE) == []
    assert readers["win"] == []


def test_unreachable_source_reports_failure_without_events(monkeypatch):
    """Сервер не ответил — снимок трогать нельзя, иначе вместо вчерашних
    записей будет пустой экран."""
    def boom(server, hours=24):
        raise Exception("WinRM timeout")

    monkeypatch.setattr(lc, "windows_events", boom)
    monkeypatch.setattr(lc, "sql_events", lambda *a, **k: ([], ""))

    results = lc.collect_server(WINDOWS)

    assert results == [(WINDOWS["name"], "win", None, "WinRM timeout")]


def test_scan_runs_at_once_after_start():
    assert lc.log_scan_due(now=1000.0, last=None) is True


def test_scan_waits_out_the_interval(monkeypatch):
    monkeypatch.setattr(lc, "LOG_SCAN_MINUTES", 60)

    assert lc.log_scan_due(now=1000.0, last=1000.0 - 59 * 60) is False
    assert lc.log_scan_due(now=1000.0, last=1000.0 - 61 * 60) is True


def test_zero_interval_means_every_cycle(monkeypatch):
    monkeypatch.setattr(lc, "LOG_SCAN_MINUTES", 0)

    assert lc.log_scan_due(now=1000.0, last=999.0) is True


def test_cycle_writes_snapshot_and_marks_failures(monkeypatch, readers):
    """Успех заменяет снимок, отказ — только отметку о попытке."""
    saved, failed = [], []
    monkeypatch.setattr(lc, "save_snapshot",
                        lambda name, source, events, error: saved.append((name, source)))
    monkeypatch.setattr(lc, "save_failure",
                        lambda name, source, error: failed.append((name, source, error)))

    def sql_boom(server, hours=24):
        raise Exception("нет прав на msdb")

    monkeypatch.setattr(lc, "sql_events", sql_boom)

    lc.run_log_cycle([WINDOWS_SQL, LINUX])

    assert saved == [(WINDOWS_SQL["name"], "win")]
    assert failed == [(WINDOWS_SQL["name"], "sql", "нет прав на msdb")]
