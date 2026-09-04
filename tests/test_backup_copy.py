"""Запуск копирования по готовности копии (вместо планировщика Windows).

Проверяется главное: бот везёт копию тогда, когда SQL её закончил, и ровно
один раз; не везёт вчерашнюю после перезапуска монитора; ждёт окончания
столько, сколько копирование реально идёт, а не сколько угадали.
"""
from datetime import datetime, timedelta

import pytest

from backup_copy import (
    copy_settings,
    launch_script_ps,
    pick_ready_backup,
    run_verdict,
    should_start,
    type_label,
)

NOW = datetime(2026, 9, 5, 4, 0, 0)


def _server(**over):
    server = {"name": "sql-region", "host": "h",
              "copy_script": "C:\\Scripts\\copy.ps1"}
    server.update(over)
    return server


def _rows():
    return [
        {"db": "base", "btype": "L", "finished": "2026-09-05 03:50:00", "size_gb": 0.2},
        {"db": "base", "btype": "I", "finished": "2026-09-05 03:30:00", "size_gb": 70.4},
        {"db": "base", "btype": "D", "finished": "2026-09-04 03:10:00", "size_gb": 210.0},
    ]


# ─── Настройки ───────────────────────────────────────────────

def test_settings_none_without_script():
    assert copy_settings({"name": "a", "host": "h"}) is None


def test_settings_defaults():
    s = copy_settings(_server())
    assert s["types"] == ("D", "I")     # журналы по умолчанию не возим
    assert s["auto"] is True
    assert s["timeout_minutes"] > 0


def test_settings_read_types_from_string():
    assert copy_settings(_server(copy_types="d, l"))["types"] == ("D", "L")


def test_auto_can_be_turned_off():
    assert copy_settings(_server(copy_after_backup=False))["auto"] is False


# ─── Выбор копии из msdb ─────────────────────────────────────

def test_journal_is_ignored_by_default():
    """Журналы делают каждые 15–60 минут: гонять на них скрипт — значит
    копировать непрерывно."""
    ready = pick_ready_backup(_rows(), copy_settings(_server()))
    assert ready["type"] == "I"
    assert ready["finished"] == datetime(2026, 9, 5, 3, 30)


def test_journal_taken_when_asked():
    ready = pick_ready_backup(_rows(), copy_settings(_server(copy_types="L")))
    assert ready["type"] == "L"


def test_no_matching_backup():
    rows = [{"db": "b", "btype": "L", "finished": "2026-09-05 03:50:00"}]
    assert pick_ready_backup(rows, copy_settings(_server())) is None


# ─── Пора ли запускать ───────────────────────────────────────

def _ready(minutes_ago=30):
    return {"db": "base", "type": "I", "finished": NOW - timedelta(minutes=minutes_ago),
            "size_gb": 70.4}


def test_starts_when_backup_is_ready():
    ok, reason = should_start(_ready(), {}, copy_settings(_server()), NOW)
    assert ok and reason is None


def test_waits_out_the_delay():
    """SQL закрывает файл раньше, чем система дописывает его на диск."""
    ok, reason = should_start(_ready(1), {}, copy_settings(_server()), NOW)
    assert not ok and "ждём" in reason


def test_same_backup_is_sent_once():
    state = {"last_finished": "2026-09-05 03:30:00"}
    ok, _ = should_start(_ready(), state, copy_settings(_server()), NOW)
    assert not ok


def test_does_not_start_while_previous_copy_runs():
    state = {"run": {"pid": 1, "started": "2026-09-05 03:35:00"}}
    ok, reason = should_start(_ready(), state, copy_settings(_server()), NOW)
    assert not ok and "идёт" in reason


def test_stale_backup_is_not_shipped():
    """Монитор перезапустили, состояние потеряли — вчерашнюю копию везти
    некуда, она давно уехала."""
    ok, reason = should_start(_ready(minutes_ago=600), {},
                              copy_settings(_server()), NOW)
    assert not ok and "старая" in reason


def test_auto_off_blocks_start():
    ok, _ = should_start(_ready(), {}, copy_settings(_server(copy_after_backup=False)), NOW)
    assert not ok


# ─── Сколько ждать окончания ─────────────────────────────────

def test_long_copy_is_not_a_failure():
    """70 ГБ едут часами — при своём таймауте это норма, а не авария."""
    run = {"started": "2026-09-05 01:00:00"}
    settings = copy_settings(_server(copy_timeout_minutes=360))
    assert run_verdict(run, settings, NOW) == "running"


def test_timeout_is_counted_from_start():
    run = {"started": "2026-09-05 01:00:00"}
    settings = copy_settings(_server(copy_timeout_minutes=120))
    assert run_verdict(run, settings, NOW) == "timeout"


# ─── Запуск скрипта ──────────────────────────────────────────

def test_ps1_runs_through_powershell():
    script = launch_script_ps("C:\\Scripts\\copy.ps1")
    assert "powershell.exe" in script and "Bypass" in script


def test_launch_returns_pid_immediately():
    """Ждать окончания нельзя: сессия WinRM живёт минуты, копия — часы."""
    assert "-PassThru" in launch_script_ps("C:\\a.bat")
    assert "Pid" in launch_script_ps("C:\\a.bat")


def test_quotes_do_not_break_the_script():
    assert "''" in launch_script_ps("C:\\Scripts\\it's copy.bat")


def test_type_label_is_readable():
    assert type_label("I") == "разностная"
