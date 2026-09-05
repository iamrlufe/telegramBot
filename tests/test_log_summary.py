"""Приведение журналов Windows и SQL к общему виду для дашборда.

Сводку собирает монитор в фоне и кладёт в базу; здесь проверяется разбор,
из-за которого сводка может соврать: уровень события, схлопывание повторов
и то, что недоступный раздел журнала не уносит с собой остальные.
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


# ─── Запуски джоб SQL Agent ──────────────────────────────────

def _run(job, when, duration, status=1):
    return {"job": job, "when": when, "duration": duration, "status": status}


def test_successful_runs_are_listed_not_dropped():
    """Раньше успешные запуски выбрасывались целиком, и джоба, которая
    вообще не запускалась, была невидима: она не падает — её просто нет."""
    events = ls.job_runs([
        _run("Ночной FULL", "2026-09-01 01:00:00", 1530),
        _run("Ночной FULL", "2026-09-01 13:00:00", 1500),
        _run("syspolicy_purge_history", "2026-09-01 02:00:00", 2),
    ])

    names = {e["title"] for e in events}
    assert any("Ночной FULL" in n for n in names)
    assert any("syspolicy" in n for n in names)
    runs = {e["title"]: e["count"] for e in events}
    assert runs[next(n for n in names if "Ночной FULL" in n)] == 2


def test_long_job_flagged_even_when_successful():
    """Формально успех, а по существу съеденное ночное окно."""
    events = ls.job_runs([_run("Daily_Maintence_Plan", "2026-09-01 01:30:00", 130000)])

    assert events[0]["level"] == "warn"
    assert "слишком долго" in events[0]["title"]
    assert "13 ч 0 мин" in events[0]["detail"]


def test_long_but_expected_job_stays_green():
    """Порог 12 часов выбран так, чтобы ночной план обслуживания на 7 ч 29 мин
    не поднимал шум: на больших базах это нормальная длительность."""
    events = ls.job_runs([_run("Daily_Maintence_Plan", "2026-09-01 01:30:00", 72900)])

    assert events[0]["level"] == "ok"
    assert "7 ч 29 мин" in events[0]["detail"]


def test_short_job_stays_green():
    events = ls.job_runs([_run("syspolicy_purge_history", "2026-09-01 02:00:00", 2)])

    assert events[0]["level"] == "ok"
    assert "слишком долго" not in events[0]["title"]


def test_threshold_is_configurable(monkeypatch):
    """На больших базах перестроение индексов идёт часами — порог высокий
    и настраиваемый."""
    monkeypatch.setattr(ls, "JOB_LONG_HOURS", 2)

    events = ls.job_runs([_run("Плановое обслуживание", "2026-09-01 01:30:00", 30000)])

    assert events[0]["level"] == "warn"


def test_backup_jobs_marked():
    """Молчание бэкапной джобы значит, что копии сегодня не будет — это
    надо видеть, не читая имена глазами."""
    events = ls.job_runs([
        _run("Weekly backup FULL", "2026-09-01 09:00:00", 3000),
        _run("Обновление статистики", "2026-09-01 03:00:00", 600),
    ])
    marked = {e["title"]: "бэкапная" in e["detail"] for e in events}

    assert marked["Джоба «Weekly backup FULL»"] is True
    assert marked["Джоба «Обновление статистики»"] is False


def test_failures_counted_inside_the_run_row():
    events = ls.job_runs([
        _run("Ночной FULL", "2026-09-01 01:00:00", 1530, status=0),
        _run("Ночной FULL", "2026-09-01 13:00:00", 1500, status=1),
    ])

    assert "падений: 1" in events[0]["detail"]


def test_duration_decoded_from_msdb_format():
    """msdb хранит длительность целым HHMMSS: 72900 это 7 ч 29 мин."""
    assert ls.job_seconds(72900) == 7 * 3600 + 29 * 60
    assert ls.job_seconds(132) == 92
    assert ls.job_seconds(None) == 0


# ─── Расписания джоб: чего не было ───────────────────────────

from datetime import datetime

# 01.09.2026 — вторник.
TUESDAY = datetime(2026, 9, 1, 13, 20)

FREQ = {"daily": 4, "weekly": 8, "monthly": 16, "once": 1, "on_start": 64}


def _sched(job, ft="daily", fi=1, at=13000, jen=1, sen=1, rf=1, run=0):
    return {"job": job, "jen": jen, "sen": sen, "ft": FREQ.get(ft, ft),
            "fi": fi, "st": 1, "si": 0, "rf": rf, "ast": at, "run": run}


def test_missed_daily_job_is_named():
    """Не отработавшая джоба не падает и в истории не появляется вовсе —
    отличить «не была нужна» от «не запустилась» можно только по расписанию."""
    events = ls.job_schedule_events([_sched("Ночной FULL")], ran=set(), now=TUESDAY)

    assert len(events) == 1
    assert "не запускалась" in events[0]["title"]
    assert "ежедневно в 01:30" in events[0]["detail"]


def test_job_that_ran_is_silent():
    events = ls.job_schedule_events([_sched("Ночной FULL")],
                                    ran={"Ночной FULL"}, now=TUESDAY)

    assert events == []


def test_running_job_is_not_reported_missing():
    """Запись в sysjobhistory появляется только при завершении: в пять утра
    семичасовой ночной план ещё не отчитался, но идёт."""
    events = ls.job_schedule_events([_sched("Ночной FULL", run=1)],
                                    ran=set(), now=TUESDAY)

    assert events == []


def test_grace_before_calling_it_missed():
    """Джоба стартует не секунда в секунду, а очередь Agent бывает занята."""
    just_now = datetime(2026, 9, 1, 1, 40)

    assert ls.job_schedule_events([_sched("Ночной FULL")], set(), now=just_now) == []
    later = datetime(2026, 9, 1, 3, 0)
    assert ls.job_schedule_events([_sched("Ночной FULL")], set(), now=later)


def test_weekly_job_only_on_its_weekday():
    """Понедельничная копия во вторник не пропущена — её сегодня и не ждут."""
    monday_only = _sched("Weekly backup", ft="weekly", fi=2, at=90000)

    assert ls.job_schedule_events([monday_only], set(), now=TUESDAY) == []
    monday = datetime(2026, 8, 31, 13, 0)
    events = ls.job_schedule_events([monday_only], set(), now=monday)
    assert "по понедельникам в 09:00" in events[0]["detail"]


def test_monthly_job_only_on_its_day():
    first = _sched("Месячный отчёт", ft="monthly", fi=1, at=30000)
    fifth = _sched("Месячный отчёт", ft="monthly", fi=5, at=30000)

    assert ls.job_schedule_events([first], set(), now=TUESDAY)
    assert ls.job_schedule_events([fifth], set(), now=TUESDAY) == []


def test_unparsed_schedules_stay_quiet():
    """Однократные и «при старте Agent» не разбираем: угадывать по ним
    пропуск значит поднимать ложную тревогу."""
    for kind in ("once", "on_start"):
        assert ls.job_schedule_events([_sched("X", ft=kind)], set(), now=TUESDAY) == []


def test_disabled_schedule_is_not_a_miss():
    assert ls.job_schedule_events([_sched("X", sen=0)], set(), now=TUESDAY) == []


def test_disabled_job_reported_separately():
    """Самый тихий случай: не падает, не пропадает, не жалуется."""
    events = ls.job_schedule_events([_sched("Ночной FULL", jen=0)], set(), now=TUESDAY)

    assert "отключена" in events[0]["title"]


def test_backup_job_miss_is_critical():
    """Молчание бэкапной джобы значит, что копии сегодня не будет."""
    backup = ls.job_schedule_events([_sched("Weekly backup FULL")], set(), now=TUESDAY)
    other = ls.job_schedule_events([_sched("Обновление статистики")], set(), now=TUESDAY)

    assert backup[0]["level"] == "crit"
    assert other[0]["level"] == "warn"


def test_several_schedules_one_row():
    """У джобы бывает несколько расписаний — строка всё равно одна."""
    events = ls.job_schedule_events(
        [_sched("Ночной FULL"), _sched("Ночной FULL", ft="weekly", fi=4, at=90000)],
        set(), now=TUESDAY)

    assert len(events) == 1
