"""Тесты недельного расписания бэкапов (shared/backup_schedule.py) и его
применения в monitor/backup_collector.py.

Ключевая регрессия: путь с schedule_weekday не должен давать «БЭКАП УСТАРЕЛ»
по возрасту — между плановыми копиями он законно стареет почти на неделю.
"""
import json
from datetime import datetime

import pytest

import backup_collector
from backup_schedule import (
    ALMATY,
    load_schedule_map,
    most_recent_weekly_deadline,
    path_schedule,
    schedule_for,
    weekly_backup_missed,
)


def _almaty(y, m, d, hh=0, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=ALMATY)


# ─── path_schedule ───────────────────────────────────────────

def test_path_schedule_reads_pair():
    assert path_schedule({
        "path": "F:\\ftp\\branch\\base_one\\FULL",
        "schedule_weekday": "mon",
        "schedule_by_hour": 9,
    }) == ("mon", 9)


def test_path_schedule_absent_for_plain_string():
    assert path_schedule("F:\\ftp\\Taraz") is None
    assert path_schedule({"path": "F:\\ftp\\Taraz"}) is None


@pytest.mark.parametrize("spec", [
    {"path": "p", "schedule_weekday": "mon"},               # без часа
    {"path": "p", "schedule_by_hour": 9},                   # без дня
    {"path": "p", "schedule_weekday": "monday", "schedule_by_hour": 9},
    {"path": "p", "schedule_weekday": "mon", "schedule_by_hour": 24},
    {"path": "p", "schedule_weekday": "mon", "schedule_by_hour": "утро"},
])
def test_path_schedule_rejects_broken_config(spec):
    """Битое расписание игнорируется — путь остаётся под обычным контролем."""
    assert path_schedule(spec) is None


def test_path_schedule_case_insensitive():
    assert path_schedule({"schedule_weekday": "MON", "schedule_by_hour": "9"}) == ("mon", 9)


# ─── most_recent_weekly_deadline ─────────────────────────────

def test_deadline_is_last_passed_weekday():
    # воскресенье 02.08.2026 → ближайший прошедший понедельник 27.07 09:00
    assert most_recent_weekly_deadline("mon", 9, _almaty(2026, 8, 2, 9, 45)) \
        == _almaty(2026, 7, 27, 9)


def test_deadline_steps_back_a_week_before_the_hour():
    # понедельник, но 08:00 — дедлайн 09:00 ещё не наступил
    assert most_recent_weekly_deadline("mon", 9, _almaty(2026, 8, 3, 8)) \
        == _almaty(2026, 7, 27, 9)


def test_deadline_today_after_the_hour():
    assert most_recent_weekly_deadline("mon", 9, _almaty(2026, 8, 3, 9, 1)) \
        == _almaty(2026, 8, 3, 9)


# ─── weekly_backup_missed ────────────────────────────────────

def test_weekly_not_missed_for_real_alert_case():
    """Ровно случай ложного алерта: FULL от 31.07 22:45 UTC, проверка 02.08.
    Копия за неделю есть — тревоги быть не должно, хотя файлу уже 35 часов."""
    newest = datetime(2026, 7, 31, 22, 45)          # naive UTC, как из PowerShell
    assert weekly_backup_missed(newest, "mon", 9, _almaty(2026, 8, 2, 9, 45)) is False


def test_weekly_missed_when_no_copy_for_over_a_week():
    newest = datetime(2026, 7, 15, 22, 45)
    assert weekly_backup_missed(newest, "mon", 9, _almaty(2026, 8, 2, 9, 45)) is True


def test_weekly_missed_when_never_seen():
    assert weekly_backup_missed(None, "mon", 9, _almaty(2026, 8, 2)) is True


# ─── load_schedule_map ───────────────────────────────────────

def test_load_schedule_map_keys_match_db_triple(tmp_path):
    config = tmp_path / "servers.json"
    config.write_text(json.dumps([{
        "name": "sql-01.example.local",
        "backups": {"sql": [
            {"path": "F:\\ftp\\branch\\base_one\\FULL",
             "schedule_weekday": "mon", "schedule_by_hour": 9},
            "F:\\ftp\\branch\\base_one\\DIFF",
        ]},
    }]), encoding="utf-8")

    schedules = load_schedule_map(str(config))
    assert schedules == {
        ("sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\FULL"): ("mon", 9)
    }
    assert schedule_for(schedules, "sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\FULL") \
        == ("mon", 9)
    assert schedule_for(schedules, "sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\DIFF") is None


def test_load_schedule_map_survives_missing_file(tmp_path):
    assert load_schedule_map(str(tmp_path / "нет.json")) == {}


# ─── _check_backup_alerts: возраст против расписания ─────────

@pytest.fixture
def collector_io(monkeypatch):
    """Ловит алерты backup_collector и держит состояние в памяти."""
    sent, state = [], {}
    monkeypatch.setattr(backup_collector, "is_muted", lambda name: False)
    monkeypatch.setattr(backup_collector, "send_or_defer", lambda text, **kw: sent.append(text))
    monkeypatch.setattr(backup_collector, "load_json", lambda path: dict(state))
    monkeypatch.setattr(backup_collector, "save_json",
                        lambda path, data: (state.clear(), state.update(data)))
    return sent, state


def _metrics(newest, file_count=3):
    return {
        "file_count": file_count,
        "newest_file": newest,
        "newest_file_gb": None,
        "total_size_gb": 100.0,
        "disk_total_gb": 500.0,
        "disk_free_gb": 200.0,
    }


def _long_ago():
    """Файл заведомо старше любого alert_hours, но моложе недельного дедлайна
    не бывает — берём «час назад минус 35 часов» от текущего момента."""
    from datetime import timedelta, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=35)


def test_weekly_path_does_not_alert_on_age(collector_io):
    """Регрессия: недельная копия не должна давать «БЭКАП УСТАРЕЛ»."""
    sent, _ = collector_io
    backup_collector._check_backup_alerts(
        "sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\FULL",
        _metrics(_long_ago()), alert_hours=30, weekly_scheduled=True
    )
    assert sent == []


def test_plain_path_still_alerts_on_age(collector_io):
    """Обычный (ежедневный) путь контроль по возрасту не теряет."""
    sent, _ = collector_io
    backup_collector._check_backup_alerts(
        "sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\DIFF",
        _metrics(_long_ago()), alert_hours=30, weekly_scheduled=False
    )
    assert len(sent) == 1
    assert "БЭКАП УСТАРЕЛ" in sent[0]


def test_weekly_path_clears_stale_old_state(collector_io):
    """Уже поднятый флаг «old» снимается, когда путь стал недельным —
    иначе после правки конфига состояние осталось бы залипшим."""
    sent, state = collector_io
    key = "sql-01.example.local:sql:F:\\ftp\\branch\\base_one\\FULL"
    state[key] = "old"

    backup_collector._check_backup_alerts(
        "sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\FULL",
        _metrics(_long_ago()), alert_hours=30, weekly_scheduled=True
    )
    assert sent == []
    assert key not in state


def test_empty_directory_alerts_even_when_weekly(collector_io):
    """Пустой каталог — проблема при любом расписании."""
    sent, _ = collector_io
    backup_collector._check_backup_alerts(
        "sql-01.example.local", "sql", "F:\\ftp\\branch\\base_one\\FULL",
        _metrics(None, file_count=0), alert_hours=30, weekly_scheduled=True
    )
    assert len(sent) == 1
    assert "БЭКАП НЕ СОЗДАЁТСЯ" in sent[0]
