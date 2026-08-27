"""Тесты чтения журналов MSSQL (shared/mssql_log.py, bot/sqllog_bot.py).

Сеть не нужна: run_ps подменяется, проверяется собранный T-SQL и разбор
ответа. Отдельно закреплены грабли, из-за которых раздел молча ломается:
русская локаль сервера, лимит длины PowerShell-скрипта и отказ в правах
на одном источнике при живых остальных.
"""
import base64
import json

import pytest

import mssql_log
import sqllog_bot
from winrm_client import MAX_PS_COMMAND_CHARS, compact_ps

SERVER = {"name": "sql-01.example.local", "host": "192.0.2.10",
          "username": "svc", "password": "x", "dbsize": True}


def _fake_ps(monkeypatch, payload):
    """Подменяет run_ps; возвращает список отправленных скриптов."""
    scripts = []

    def run_ps(host, script, username=None, password=None, **kwargs):
        scripts.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(mssql_log, "run_ps", run_ps)
    return scripts


# ─── Разбор отказов входа ────────────────────────────────────

def test_login_failure_english():
    row = mssql_log.parse_login_failure(
        "Login failed for user 'ДОМЕН\\ivanov'. Reason: Password did not match "
        "that for the login provided. [CLIENT: 192.0.2.15]"
    )
    assert row["user"] == "ДОМЕН\\ivanov"
    assert row["client"] == "192.0.2.15"


def test_login_failure_state_decoded():
    """Голая цифра state дежурному ничего не говорит — расшифровываем."""
    row = mssql_log.parse_login_failure(
        "Error: 18456, Severity: 14, State: 8. Login failed for user 'sa'. "
        "[CLIENT: 192.0.2.77]"
    )
    assert row["state"] == "8"
    assert row["reason"] == "неверный пароль"


def test_login_failure_russian_locale():
    """На русской локали SQL пишет кириллицей и другими кавычками."""
    row = mssql_log.parse_login_failure(
        'Ошибка входа пользователя "app_user". [CLIENT: 192.0.2.31]'
    )
    assert row["user"] == "app_user"
    assert row["client"] == "192.0.2.31"


def test_login_failure_database_extracted():
    """Главное в запросе — на какую базу шло подключение."""
    row = mssql_log.parse_login_failure(
        'Login failed for user \'app_user\'. Reason: Failed to open the '
        'explicitly specified database "TradeDB". [CLIENT: 192.0.2.31]'
    )
    assert row["database"] == "TradeDB"


def test_login_failure_local_client_without_brackets():
    """<local machine> ломает разметку Telegram — скобки снимаем."""
    row = mssql_log.parse_login_failure(
        "Login failed for user 'svc'. [CLIENT: <local machine>]"
    )
    assert row["client"] == "local machine"


def test_group_login_failures_collapses_series():
    """Сломанный сервис даёт сотни одинаковых отказов — схлопываем в одну строку."""
    rows = [
        {"d": "2026-08-27 11:00:00", "t": "Login failed for user 'app'. "
                                          "State: 8. [CLIENT: 192.0.2.31]"},
        {"d": "2026-08-27 11:05:00", "t": "Login failed for user 'app'. "
                                          "State: 8. [CLIENT: 192.0.2.31]"},
        {"d": "2026-08-27 12:00:00", "t": "Login failed for user 'sa'. "
                                          "State: 5. [CLIENT: 192.0.2.77]"},
    ]
    grouped = mssql_log.group_login_failures(rows)
    assert len(grouped) == 2
    # Свежие сверху
    assert grouped[0]["user"] == "sa"
    app = next(r for r in grouped if r["user"] == "app")
    assert app["count"] == 2
    assert app["last"] == "2026-08-27 11:05:00"


def test_group_login_failures_keeps_database_from_any_row():
    """Имя базы бывает лишь в части сообщений серии — не теряем его."""
    rows = [
        {"d": "2026-08-27 11:00:00",
         "t": "Login failed for user 'app'. State: 38. [CLIENT: 192.0.2.31]"},
        {"d": "2026-08-27 11:01:00",
         "t": 'Login failed for user \'app\'. State: 38. Failed to open the '
              'explicitly specified database "TradeDB". [CLIENT: 192.0.2.31]'},
    ]
    grouped = mssql_log.group_login_failures(rows)
    assert grouped[0]["database"] == "TradeDB"


# ─── Форматы msdb ────────────────────────────────────────────

def test_agent_datetime_decoded():
    """msdb хранит время целыми: 20260827 / 31500 → 03:15:00."""
    assert mssql_log.decode_agent_datetime(20260827, 31500) == "2026-08-27 03:15:00"


def test_agent_datetime_midnight():
    assert mssql_log.decode_agent_datetime(20260827, 0) == "2026-08-27 00:00:00"


def test_agent_datetime_empty_on_garbage():
    assert mssql_log.decode_agent_datetime(None, None) == ""


def test_agent_duration_decoded():
    assert mssql_log.decode_agent_duration(132) == "1 мин 32 с"
    assert mssql_log.decode_agent_duration(20500) == "2 ч 5 мин"


# ─── Сборка запросов ─────────────────────────────────────────

def test_errorlog_query_uses_only_current_file_for_24h():
    q = mssql_log._errorlog_query(24, "1=1", 40)
    assert "xp_readerrorlog 0," in q
    assert "xp_readerrorlog 1," not in q


def test_errorlog_query_reads_archives_for_week():
    """ERRORLOG обнуляется при рестарте — за неделю нужны архивы."""
    q = mssql_log._errorlog_query(24 * 7, "1=1", 40)
    for n in (0, 1, 2, 3):
        assert f"xp_readerrorlog {n}," in q
    # Архива может не быть — без TRY/CATCH упал бы весь батч
    assert q.count("BEGIN TRY") == 4


def test_errorlog_query_always_limited():
    """Без TOP и периода запрос не укладывается в таймаут WinRM."""
    q = mssql_log._errorlog_query(24, "1=1", 40)
    assert "TOP 40" in q
    assert "ORDER BY LogDate DESC" in q


def test_errorlog_script_fits_winrm_limit():
    """Худший случай (неделя, все архивы) должен пролезать в командную строку."""
    q = mssql_log._errorlog_query(24 * 7, "LogText LIKE '%Login failed%'", 60)
    script = mssql_log.PS_OUT_B64_HELPER + f"$q = @'\n{q}\n'@\n" + "Invoke-Sqlcmd"
    encoded = len(base64.b64encode(compact_ps(script).encode("utf_16_le")))
    assert encoded < MAX_PS_COMMAND_CHARS


def test_read_login_errors_selects_explicit_columns(monkeypatch):
    """Select-Object * утащил бы служебные поля DataRow и раздул ответ."""
    scripts = _fake_ps(monkeypatch, [])
    mssql_log.read_login_errors(SERVER, hours=24)
    assert "Select-Object d,t" in scripts[0]
    assert "Select-Object *" not in scripts[0]


def test_read_login_errors_groups_result(monkeypatch):
    _fake_ps(monkeypatch, [
        {"d": "2026-08-27 11:00:00",
         "t": "Login failed for user 'app'. State: 8. [CLIENT: 192.0.2.31]"},
        {"d": "2026-08-27 11:02:00",
         "t": "Login failed for user 'app'. State: 8. [CLIENT: 192.0.2.31]"},
    ])
    rows = mssql_log.read_login_errors(SERVER)
    assert len(rows) == 1 and rows[0]["count"] == 2


def test_read_agent_jobs_decodes_time(monkeypatch):
    _fake_ps(monkeypatch, [{"job": "Ежедневный бэкап", "step": 0,
                            "stepname": None, "status": 1, "rundate": 20260827,
                            "runtime": 31500, "duration": 132, "msg": "ok"}])
    rows = mssql_log.read_agent_jobs(SERVER)
    assert rows[0]["when"] == "2026-08-27 03:15:00"
    assert rows[0]["took"] == "1 мин 32 с"


def test_backup_errors_survive_missing_permission(monkeypatch):
    """Отказ в правах на ERRORLOG не должен прятать историю джоб."""
    def run_ps(host, script, username=None, password=None, **kwargs):
        if "xp_readerrorlog" in script:
            raise Exception("The EXECUTE permission was denied on the object "
                            "'xp_readerrorlog'")
        payload = [{"job": "Backup", "step": 2, "stepname": "Backup TradeDB",
                    "status": 0, "rundate": 20260827, "runtime": 31500,
                    "duration": 5, "msg": "failed with 1 errors"}]
        return base64.b64encode(json.dumps(payload).encode()).decode("ascii")

    monkeypatch.setattr(mssql_log, "run_ps", run_ps)
    data = mssql_log.read_backup_errors(SERVER)
    assert data["jobs"] and data["jobs"][0]["job"] == "Backup"
    assert any("securityadmin" in e for e in data["errors"])


def test_friendly_error_explains_missing_rights():
    msg = mssql_log.friendly_sql_error(
        "The EXECUTE permission was denied on the object 'xp_readerrorlog'")
    assert "securityadmin" in msg


def test_friendly_error_explains_missing_cmdlet():
    msg = mssql_log.friendly_sql_error(
        "Invoke-Sqlcmd : The term 'Invoke-Sqlcmd' is not recognized")
    assert "SqlServer" in msg


# ─── Кнопка и вывод ──────────────────────────────────────────

def test_button_only_for_mssql_servers():
    """Отдельного флага нет: признак MSSQL — тот же dbsize."""
    assert sqllog_bot.has_mssql({"dbsize": True})
    assert not sqllog_bot.has_mssql({"dbsize": False})
    assert not sqllog_bot.has_mssql({})


def test_button_hidden_for_linux():
    """Invoke-Sqlcmd — только Windows: на Linux кнопка бессмысленна."""
    assert not sqllog_bot.has_mssql({"dbsize": True, "type": "linux"})


def test_token_cache_is_bounded():
    """Кэш кнопок не должен расти бесконечно в долгоживущем процессе."""
    for _ in range(sqllog_bot.SQL_TOKENS_MAX + 50):
        sqllog_bot.sql_token("sql-01.example.local", 24)
    assert len(sqllog_bot.SQL_TOKENS) <= sqllog_bot.SQL_TOKENS_MAX


def test_login_output_shows_source_and_database():
    rows = mssql_log.group_login_failures([
        {"d": "2026-08-27 09:20:00",
         "t": 'Login failed for user \'app_user\'. State: 38. Failed to open '
              'the explicitly specified database "TradeDB". [CLIENT: 192.0.2.31]'},
    ])
    text = sqllog_bot.format_logins(rows, 24)
    assert "app_user" in text and "192.0.2.31" in text
    assert "TradeDB" in text and "нет доступа к базе" in text


def test_empty_login_output_mentions_log_reset():
    """Пустой лог — не то же самое, что «всё хорошо»: он мог обнулиться."""
    text = sqllog_bot.format_logins([], 24)
    assert "перезапуск" in text.lower()


def test_multiline_sql_message_flattened():
    """Сообщения SQL многострочные, в списке нужна одна строка."""
    flat = sqllog_bot._short("BACKUP failed\r\n  Operating system error 5", 300)
    assert "\n" not in flat and "  " not in flat


def test_history_warns_when_sql_has_no_backups():
    text = sqllog_bot.format_history([], 7)
    assert "не записал" in text


# ─── Справка в боте ──────────────────────────────────────────

def test_help_section_documents_required_rights():
    """Без указания роли пользователь не поймёт, почему раздел пуст."""
    from config_editor import HELP_SECTIONS
    text = HELP_SECTIONS["sqllog"][1]
    assert "securityadmin" in text
    assert "SQLAgentReaderRole" in text


def test_help_section_warns_about_log_reset():
    from config_editor import HELP_SECTIONS
    assert "sp_cycle_errorlog" in HELP_SECTIONS["sqllog"][1]
