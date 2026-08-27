"""Тесты состояния баз MSSQL (shared/mssql_health.py + вывод в боте).

Сеть не нужна: run_query подменяется. Закреплены смысловые вещи, которые
легко потерять при правке SQL: log_reuse_wait_desc как причина роста LDF,
отличие «не проверялась ни разу» от «проверялась давно», и то, что файл с
выключенным автоприростом встаёт независимо от места на диске.
"""
import base64
import json

import pytest

import mssql_health
import sqllog_bot

SERVER = {"name": "sql-01.example.local", "host": "192.0.2.10",
          "username": "svc", "password": "x", "dbsize": True}


def _fake_sql(monkeypatch, payload):
    scripts = []

    def run_query(server, tsql, columns, timeout_sec=90):
        scripts.append(tsql)
        return json.loads(json.dumps(payload))

    monkeypatch.setattr(mssql_health, "run_query", run_query)
    return scripts


# ─── Журналы транзакций ──────────────────────────────────────

def test_log_backup_wait_explained():
    """LOG_BACKUP — самая частая причина раздувшегося LDF."""
    text = mssql_health.explain_log_wait("LOG_BACKUP")
    assert "BACKUP LOG" in text and "Full" in text


def test_nothing_wait_is_normal():
    assert "штатно" in mssql_health.explain_log_wait("NOTHING")


def test_active_transaction_points_at_application():
    assert "транзакц" in mssql_health.explain_log_wait("ACTIVE_TRANSACTION")


def test_log_files_carry_reason(monkeypatch):
    _fake_sql(monkeypatch, [{"db": "buh", "model": "FULL",
                             "waitfor": "LOG_BACKUP", "log_gb": 48.5,
                             "data_gb": 139.9}])
    rows = mssql_health.read_log_files(SERVER)
    assert "BACKUP LOG" in rows[0]["why"]


def test_log_output_warns_only_on_problem():
    """NOTHING — это норма, предупреждать не о чем."""
    ok = sqllog_bot.format_tlog([{"db": "d", "model": "SIMPLE",
                                  "waitfor": "NOTHING", "log_gb": 1,
                                  "data_gb": 10, "why": ""}], 24)
    assert "⚠️" not in ok
    bad = sqllog_bot.format_tlog([{"db": "buh", "model": "FULL",
                                   "waitfor": "LOG_BACKUP", "log_gb": 48,
                                   "data_gb": 139,
                                   "why": "нужен бэкап журнала"}], 24)
    assert "⚠️" in bad and "бэкап журнала" in bad


# ─── CHECKDB ─────────────────────────────────────────────────

def test_never_checked_database_flagged():
    """1900-01-01 — заглушка SQL: проверки не было ни разу."""
    text = sqllog_bot.format_checkdb(
        [{"db": "buh", "lastgood": "1900-01-01 00:00:00", "days": 46000}], 24)
    assert "не проверялась ни разу" in text


def test_recent_check_marked_ok():
    text = sqllog_bot.format_checkdb(
        [{"db": "buh", "lastgood": "2026-08-25 03:00:00", "days": 2}], 24)
    assert "✅" in text


def test_stale_check_marked_warning():
    text = sqllog_bot.format_checkdb(
        [{"db": "buh", "lastgood": "2026-01-01 03:00:00", "days": 238}], 24)
    assert "⚠️" in text


def test_checkdb_empty_mentions_required_rights():
    """DBCC DBINFO требует sysadmin — иначе раздел молча пуст."""
    assert "sysadmin" in sqllog_bot.format_checkdb([], 24)


# ─── Активность ──────────────────────────────────────────────

def test_activity_shows_blocker():
    """Ради этого раздел и нужен: кто именно держит блокировку."""
    text = sqllog_bot.format_activity([{
        "spid": 55, "state": "suspended", "blocker": 42, "waittype": "LCK_M_X",
        "sec": 120, "db": "buh", "login": "app", "hostname": "TERM-1",
        "app": "1CV8", "sqltext": "UPDATE ..."}], 24)
    assert "заблокирован сессией 42" in text
    assert "spid 55" in text and "1CV8" in text


def test_activity_ignores_zero_blocker():
    text = sqllog_bot.format_activity([{
        "spid": 55, "blocker": 0, "sec": 30, "db": "buh", "login": "app",
        "hostname": "", "app": "", "sqltext": "SELECT 1"}], 24)
    assert "заблокирован" not in text


def test_activity_query_excludes_itself(monkeypatch):
    """Собственная сессия всегда «выполняется дольше всех»."""
    scripts = _fake_sql(monkeypatch, [])
    mssql_health.read_activity(SERVER)
    assert "@@SPID" in scripts[0]
    assert "is_user_process = 1" in scripts[0]


# ─── Файлы БД ────────────────────────────────────────────────

def test_growth_disabled_is_capped():
    """growth = 0 — файл не вырастет, сколько бы места ни было на диске."""
    assert mssql_health._is_capped({"growth": 0, "maxsize": -1})


def test_max_size_zero_is_capped():
    assert mssql_health._is_capped({"growth": 1024, "maxsize": 0})


def test_normal_file_not_capped():
    assert not mssql_health._is_capped({"growth": 1024, "maxsize": -1})


def test_max_size_converted_to_gb():
    """max_size в страницах по 8 КБ; -1 и 0 — не пределы, а флаги."""
    assert mssql_health._max_size_gb(131072) == 1.0
    assert mssql_health._max_size_gb(-1) is None
    assert mssql_health._max_size_gb(0) is None


def test_files_query_avoids_msforeachdb(monkeypatch):
    """sp_MSforeachdb недокументирована и медленна на десятках баз."""
    scripts = _fake_sql(monkeypatch, [])
    mssql_health.read_file_space(SERVER)
    assert "sp_MSforeachdb" not in scripts[0]
    assert "sys.master_files" in scripts[0]


def test_capped_files_listed_first():
    rows = [
        {"db": "buh", "fname": "buh_dat", "kind": "ROWS", "size_gb": 100,
         "capped": False, "limit_gb": None},
        {"db": "zup", "fname": "zup_log", "kind": "LOG", "size_gb": 2,
         "capped": True, "limit_gb": 2.0},
    ]
    text = sqllog_bot.format_files(rows, 24)
    assert text.index("Не смогут вырасти") < text.index("Крупнейшие файлы")
    assert "zup_log" in text


def test_help_section_exists_and_fits():
    """Раздел SQL уже упирался в лимит Telegram — состояние вынесено отдельно."""
    from config_editor import HELP_SECTIONS
    from tg_utils import split_message
    text = HELP_SECTIONS["sqlhealth"][1]
    assert "LOG_BACKUP" in text and "sysadmin" in text
    assert len(split_message(text)) == 1
