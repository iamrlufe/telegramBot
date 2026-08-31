"""Приведение журналов Windows и SQL к общему виду для дашборда.

Сводку собирает монитор в фоне и кладёт в базу; здесь проверяется разбор,
из-за которого сводка может соврать: уровень события, схлопывание повторов
и то, что недоступный раздел журнала не уносит с собой остальные.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ls = _load("log_summary", ROOT / "shared" / "log_summary.py")

SERVER = {"name": "sql-01.example.local", "host": "192.0.2.10"}


def _win(monkeypatch, **readers):
    """Подменяет чтение журналов: настоящие ходят по WinRM."""
    for name in ("read_reboots", "read_service_failures", "read_disk_errors",
                 "read_app_errors", "read_failed_logons"):
        monkeypatch.setattr(ls, name, readers.get(name, lambda *a, **k: []))


def _row(when, event_id, msg, src="Service Control Manager"):
    return {"d": when, "id": event_id, "src": src, "msg": msg}


# ─── Уровень события ─────────────────────────────────────────

@pytest.mark.parametrize("event_id,expected", [
    (6008, "crit"),   # неожиданное завершение
    (41, "crit"),     # Kernel-Power
    (1074, "warn"),   # штатная перезагрузка по команде
    (6005, "warn"),   # система загрузилась
])
def test_reboot_level_separates_crash_from_planned(event_id, expected):
    """Плановая перезагрузка не должна красить сервер в красный."""
    assert ls._win_level("reboot", event_id) == expected


def test_disk_errors_are_always_critical():
    """Сыплющийся диск критичен при любом коде: чинить надо сразу."""
    assert ls._win_level("disk", 51) == "crit"


def test_service_restarted_by_itself_is_only_warning():
    assert ls._win_level("service", 7031) == "warn"
    assert ls._win_level("service", 7000) == "crit"


# ─── Схлопывание повторов ────────────────────────────────────

def test_repeated_event_collapses_into_one_row(monkeypatch):
    """Падающая по кругу служба — одна строка со счётчиком, а не двадцать."""
    rows = [_row(f"2026-09-01 0{i}:00:00", 7000, "Служба TermService не запустилась")
            for i in range(1, 6)]
    _win(monkeypatch, read_service_failures=lambda *a, **k: rows)

    events, error = ls.windows_events(SERVER)

    assert not error
    assert len(events) == 1
    assert events[0]["count"] == 5
    assert "5 раз" in events[0]["title"]
    assert events[0]["event_at"] == "2026-09-01 05:00:00"


def test_brute_force_logons_are_critical(monkeypatch):
    """Единичная опечатка в пароле — предупреждение, серия — уже перебор."""
    def logons(*a, **k):
        return [{"d": f"2026-09-01 01:{i:02d}:00", "user": "administrator",
                 "ip": "192.0.2.77", "eid": "4625", "code": "0xC000006A",
                 "reason": "неверный пароль", "how": "RDP"} for i in range(25)]
    _win(monkeypatch, read_failed_logons=logons)

    events, _ = ls.windows_events(SERVER)

    assert len(events) == 1
    assert events[0]["level"] == "crit"
    assert events[0]["count"] == 25
    assert "administrator" in events[0]["detail"]
    assert "192.0.2.77" in events[0]["detail"]


def test_single_failed_logon_stays_warning(monkeypatch):
    _win(monkeypatch, read_failed_logons=lambda *a, **k: [
        {"d": "2026-09-01 01:00:00", "user": "petrov", "ip": "192.0.2.30",
         "eid": "4625", "code": "0xC000006A", "reason": "неверный пароль", "how": ""}
    ])

    events, _ = ls.windows_events(SERVER)

    assert events[0]["level"] == "warn"


# ─── Отказ одного раздела ────────────────────────────────────

def test_broken_reader_does_not_lose_the_others(monkeypatch):
    """Security обычно недоступен по правам. Это не повод терять System:
    раньше такой отказ означал бы пустую сводку по всему серверу."""
    def denied(*a, **k):
        raise Exception("Access is denied")

    _win(monkeypatch,
         read_disk_errors=lambda *a, **k: [_row("2026-09-01 02:00:00", 7, "плохой блок", "disk")],
         read_failed_logons=denied)

    events, error = ls.windows_events(SERVER)

    assert [e["category"] for e in events] == ["disk"]
    assert "Event Log Readers" in error


def test_empty_journal_is_not_an_error(monkeypatch):
    """«Событий не найдено» Get-WinEvent возвращает как ошибку — это штатный
    ответ, и подписывать им сводку нельзя."""
    def no_events(*a, **k):
        raise Exception("No events were found that match the specified selection criteria")

    _win(monkeypatch, read_reboots=no_events)

    events, error = ls.windows_events(SERVER)

    assert events == []
    assert error == ""


# ─── Счётчики по категориям ──────────────────────────────────

def test_counters_keep_fixed_category_order():
    """Колонки не должны прыгать от сервера к серверу."""
    events = [
        {"category": "logon", "level": "crit", "count": 41},
        {"category": "disk", "level": "crit", "count": 4},
    ]

    counters = ls.count_by_category(events, "win")

    assert [c["key"] for c in counters] == ["reboot", "service", "disk", "app", "logon"]
    assert [c["count"] for c in counters] == [0, 0, 4, 0, 41]
    assert counters[2]["level"] == "crit"
    assert counters[0]["level"] == ""


def test_counters_sum_collapsed_events():
    """В счётчике — число событий, а не число строк после схлопывания."""
    events = [
        {"category": "service", "level": "warn", "count": 5},
        {"category": "service", "level": "crit", "count": 2},
    ]

    counters = {c["key"]: c for c in ls.count_by_category(events, "win")}

    assert counters["service"]["count"] == 7
    assert counters["service"]["level"] == "crit"
