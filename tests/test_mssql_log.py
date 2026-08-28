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
    """<local machine> ломает разметку Telegram и не читается как источник."""
    row = mssql_log.parse_login_failure(
        "Login failed for user 'svc'. [CLIENT: <local machine>]"
    )
    assert "<" not in row["client"]
    assert row["client"] == "локально, с самого сервера"


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
    data = mssql_log.read_login_errors(SERVER)
    assert len(data["rows"]) == 1 and data["rows"][0]["count"] == 2
    assert data["truncated"] is False


def test_read_agent_jobs_decodes_time(monkeypatch):
    _fake_ps(monkeypatch, [{"job": "Ежедневный бэкап", "step": 0,
                            "stepname": None, "status": 1, "rundate": 20260827,
                            "runtime": 31500, "duration": 132, "msg": "ok"}])
    rows = mssql_log.read_agent_jobs(SERVER)["rows"]
    assert rows[0]["when"] == "2026-08-27 03:15:00"
    assert rows[0]["took"] == "1 мин 32 с"


def test_agent_jobs_filter_avoids_agent_datetime(monkeypatch):
    """agent_datetime недокументирована и падает на мусорных значениях."""
    scripts = _fake_ps(monkeypatch, [])
    mssql_log._agent_job_rows(SERVER, hours=24)
    assert "agent_datetime" not in scripts[0]
    assert "h.run_date" in scripts[0]


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
    text = sqllog_bot.format_history([], 24)
    assert "не записал" in text


def test_history_period_matches_other_sections():
    """«за 1 дн.» рядом с «за 24 часа» в остальных разделах путало."""
    assert "24 часа" in sqllog_bot.format_history([], 24)
    assert "7 дней" in sqllog_bot.format_history([], 24 * 7)


# ─── Разбор: база, адрес, дата ───────────────────────────────

def test_same_login_different_databases_not_merged():
    """Один логин ломится в разные базы — это разные проблемы."""
    rows = [
        {"d": "2026-08-27 13:06:00",
         "t": 'Cannot open database "buh_copy_arc" requested by the login. '
              "The login failed. Login failed for user 'sa'."},
        {"d": "2026-08-27 13:07:00",
         "t": 'Cannot open database "other_db" requested by the login. '
              "The login failed. Login failed for user 'sa'."},
    ]
    grouped = mssql_log.group_login_failures(rows)
    assert len(grouped) == 2
    assert {r["database"] for r in grouped} == {"buh_copy_arc", "other_db"}


def test_state_taken_from_paired_error_line():
    """SQL пишет отказ двумя строками: код состояния — в первой."""
    rows = [
        {"d": "2026-08-27 13:06:00", "t": "Error: 18456, Severity: 14, State: 38."},
        {"d": "2026-08-27 13:06:00",
         "t": "Login failed for user 'intGisUser2'. [CLIENT: 192.0.2.44]"},
    ]
    grouped = mssql_log.group_login_failures(rows)
    assert len(grouped) == 1, "служебная строка не должна попадать в список"
    assert grouped[0]["state"] == "38"
    assert grouped[0]["reason"] == "нет доступа к базе"


def test_missing_client_is_stated_explicitly():
    """Ошибка 4060 пишется без [CLIENT] — молчание читалось бы как «локально»."""
    rows = mssql_log.group_login_failures([
        {"d": "2026-08-27 13:06:00",
         "t": 'Cannot open database "buh_copy_arc" requested by the login. '
              "The login failed. Login failed for user 'sa'."},
    ])
    text = sqllog_bot.format_logins(rows, 24)
    assert "адрес не записан" in text


def test_date_is_day_first():
    """'08-27' читалось как 8 июля — показываем 27.08."""
    assert sqllog_bot._when("2026-08-27 00:00:00") == "27.08 00:00"


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


def test_login_result_flags_truncation(monkeypatch):
    """Ровно limit строк — счётчик врал бы, выдавая предел за полное число."""
    _fake_ps(monkeypatch, [
        {"d": f"2026-08-27 13:{n:02d}:00",
         "t": f"Login failed for user 'u{n}'. State: 8. [CLIENT: 192.0.2.9]"}
        for n in range(5)
    ])
    data = mssql_log.read_login_errors(SERVER, limit=5)
    assert data["truncated"] is True
    assert "предел выборки" in sqllog_bot.format_logins(data, 24)


# ─── Расшифровка записей движка ──────────────────────────────

def test_engine_error_824_explained():
    """«Error: 824» само по себе дежурному ничего не говорит."""
    text = mssql_log.explain_engine_error(
        "Error: 824, Severity: 24, State: 2. SQL Server detected a "
        "logical consistency-based I/O error: incorrect checksum")
    assert "повреждени" in text and "CHECKDB" in text


def test_engine_error_825_marked_as_early_warning():
    """825 — предупреждение до 823/824, это важно различать."""
    text = mssql_log.explain_engine_error("Error: 825, Severity: 10, State: 2.")
    assert "повтор" in text


def test_engine_slow_io_explained():
    text = mssql_log.explain_engine_error(
        "SQL Server has encountered 1 occurrence(s) of I/O requests taking "
        "longer than 15 seconds to complete")
    assert "хранилище" in text


def test_engine_deadlock_points_at_application():
    """Взаимоблокировка — проблема запросов, а не сервера."""
    text = mssql_log.explain_engine_error("deadlock victim")
    assert "приложения" in text


def test_engine_specific_code_wins_over_severity():
    """Правила идут сверху вниз: код конкретнее, чем severity."""
    text = mssql_log.explain_engine_error("Error: 823, Severity: 24, State: 2.")
    assert "страницу" in text and "фатальная" not in text


def test_engine_output_carries_explanations():
    rows = [{"d": "2026-08-27 03:10:00",
             "t": "Error: 825, Severity: 10, State: 2. A read of the file "
                  "succeeded after failing 3 times"}]
    text = sqllog_bot.format_engine(rows, 24)
    assert "↳" in text and "сыпаться" in text


def test_engine_identical_records_collapsed():
    """Одна проблема повторяется десятками строк и занимает весь экран."""
    rows = [{"d": f"2026-08-27 03:{n:02d}:00",
             "t": "Error: 825, Severity: 10, State: 2."} for n in range(5)]
    text = sqllog_bot.format_engine(rows, 24)
    assert "5 раз" in text


def test_engine_empty_output_lists_what_was_checked():
    """«Ничего серьёзного» не объясняло, что именно проверялось."""
    text = sqllog_bot.format_engine([], 24)
    for expected in ("823", "15 секунд", "взаимоблокировк", "sp_cycle_errorlog"):
        assert expected in text


def test_help_section_matches_current_behaviour():
    """Справка в боте обязана описывать то, что раздел делает сейчас."""
    from config_editor import HELP_SECTIONS
    text = HELP_SECTIONS["sqllog"][1]
    for expected in ("адрес не записан", "823", "825", "UNC", "предел"):
        assert expected in text, f"в справке бота нет: {expected}"


# ─── Русская локаль сервера ──────────────────────────────────

def test_client_parsed_from_russian_log():
    """SQL на русской локали пишет [КЛИЕНТ: …] — адрес терялся целиком."""
    row = mssql_log.parse_login_failure(
        'Login failed for user \'sa\'. Причина: не удалось открыть явно '
        'указанную базу данных "copy_obn". [КЛИЕНТ: 192.0.2.55]'
    )
    assert row["client"] == "192.0.2.55"
    assert row["database"] == "copy_obn"


def test_local_machine_client_translated():
    """<local machine> не читается как ответ на вопрос «откуда»."""
    row = mssql_log.parse_login_failure(
        "Login failed for user 'sa'. [КЛИЕНТ: <local machine>]")
    assert row["client"] == "локально, с самого сервера"


def test_state_from_russian_error_line():
    """Служебная строка тоже русская: «Ошибка: 18456 … состояние: 38»."""
    rows = [
        {"d": "2026-08-27 13:26:42",
         "t": "Ошибка: 18456, серьезность: 14, состояние: 38."},
        {"d": "2026-08-27 13:26:42",
         "t": 'Login failed for user \'sa\'. Причина: не удалось открыть явно '
              'указанную базу данных "kuRoman". [КЛИЕНТ: <local machine>]'},
    ]
    grouped = mssql_log.group_login_failures(rows)
    assert len(grouped) == 1
    assert grouped[0]["state"] == "38"
    assert grouped[0]["reason"] == "нет доступа к базе"
    assert grouped[0]["database"] == "kuRoman"


def test_russian_error_line_included_in_query():
    q = mssql_log._errorlog_query(24, "1=1", 40)
    # сам фильтр строится в read_login_errors — проверяем его отдельно
    import inspect
    src = inspect.getsource(mssql_log.read_login_errors)
    assert "Ошибка: 18456" in src


# ─── Пустая история джоб ─────────────────────────────────────

def test_empty_jobs_blames_permissions_not_service(monkeypatch):
    """Без SQLAgentReaderRole чужие джобы не видны, и ошибки при этом нет."""
    data = {"rows": [], "jobs_total": 0}
    text = sqllog_bot.format_jobs(data, 24)
    assert "SQLAgentReaderRole" in text
    assert "Agent запущена" not in text


def test_empty_jobs_when_jobs_are_visible():
    """Джобы видны, но не запускались — совсем другой вывод."""
    text = sqllog_bot.format_jobs({"rows": [], "jobs_total": 7}, 24)
    assert "Джоб видно: 7" in text
    assert "расписание" in text


def test_jobs_total_requested_only_when_empty(monkeypatch):
    """Лишний запрос на каждый показ истории не нужен."""
    scripts = _fake_ps(monkeypatch, [{"job": "J", "step": 0, "stepname": None,
                                      "status": 1, "rundate": 20260827,
                                      "runtime": 31500, "duration": 1,
                                      "msg": ""}])
    mssql_log.read_agent_jobs(SERVER)
    assert not any("COUNT(*)" in s for s in scripts)


# ─── Суть сообщения джоба и причина сбоя ─────────────────────

# Реальный вывод шага плана обслуживания: полезное — в самом конце.
MAINT_PLAN_MSG = (
    "Executed as user: NT Service\\SQLSERVERAGENT. Microsoft (R) SQL Server "
    "Execute Package Utility Version 15.0.4200.1 for 64-bit Copyright (C) "
    "Microsoft Corporation. All rights reserved. Started: 0:10:00 "
    "Progress: 2026-08-27 00:10:01.07 Source: {FA1D6D23-35E0-493A} "
    "Executing query \"DECLARE @Guid UNIQUEIDENTIFIER\". : 100% complete "
    "End Progress Error: 2026-08-27 00:10:05.11 Code: 0xC002F210 "
    "Source: Back Up Database Task Execute SQL Task "
    "Description: Failed to open the backup device. "
    "Operating system error 3(The system cannot find the path specified.). "
    "End Error The package execution failed. The step failed."
)


def test_job_summary_drops_dtexec_header():
    """Обрезка по первым символам показывала только шапку dtexec."""
    summary = summarize_job_message_wrapper()
    assert "Execute Package Utility" not in summary
    assert "Failed to open the backup device" in summary


def summarize_job_message_wrapper():
    return mssql_log.summarize_job_message(MAINT_PLAN_MSG, limit=250)


def test_job_summary_respects_limit():
    assert len(mssql_log.summarize_job_message(MAINT_PLAN_MSG, limit=80)) <= 80


def test_job_summary_survives_plain_message():
    """У обычного шага (не плана обслуживания) описания нет."""
    summary = mssql_log.summarize_job_message(
        "Executed as user: DOMAIN\\svc. The step failed.")
    assert "The step failed" in summary


def test_job_summary_empty_input():
    assert mssql_log.summarize_job_message("") == ""
    assert mssql_log.summarize_job_message(None) == ""


def test_backup_error_path_not_found_explained():
    """Ошибка ОС 3 у бэкапа — почти всегда буква сетевого диска."""
    text = mssql_log.explain_backup_error(MAINT_PLAN_MSG)
    assert "путь не найден" in text and "UNC" in text


def test_backup_error_access_denied_explained():
    text = mssql_log.explain_backup_error(
        "Operating system error 5(Access is denied.)")
    assert "прав" in text


def test_backup_error_no_space_explained():
    text = mssql_log.explain_backup_error(
        "Operating system error 112(There is not enough space on the disk.)")
    assert "место" in text


def test_backup_error_russian_locale():
    text = mssql_log.explain_backup_error(
        "ошибка операционной системы 3(Системе не удается найти указанный путь.)")
    assert "путь не найден" in text


def test_unknown_backup_error_has_no_explanation():
    assert mssql_log.explain_backup_error("Something odd happened") == ""


def test_job_message_fetched_long_enough(monkeypatch):
    """При LEFT(...,400) описание ошибки не попадало в выборку вовсе."""
    scripts = _fake_ps(monkeypatch, [])
    mssql_log._agent_job_rows(SERVER)
    assert "LEFT(h.message, 1500)" in scripts[0]


def test_backup_section_shows_summary_and_reason():
    data = {"engine": [], "errors": [], "jobs": [{
        "when": "2026-08-27 00:10:00", "job": "backupdaily.Subplan_1",
        "step": 1, "stepname": "Subplan_1", "msg": MAINT_PLAN_MSG}]}
    text = sqllog_bot.format_backup_errors(data, 24)
    assert "Execute Package Utility" not in text
    assert "Failed to open the backup device" in text
    assert "↳" in text and "UNC" in text


# Реальный случай: план обслуживания длинный, и SQL Agent сохранил в истории
# только первые ~1024 символа — до самой ошибки текст не дошёл.
TRUNCATED_PLAN_MSG = (
    "Executed as user: NT Service\\SQLSERVERAGENT. Microsoft (R) SQL Server "
    "Execute Package Utility Version 15.0.4200.8 for 64-bit Copyright (C) "
    "Microsoft Corporation. All rights reserved. Started: 0:10:00 "
    "Progress: 2026-08-28 00:10:01.61 Source: {FA1D6D23-35E0-493A-975D-6A51856A34ED} "
    "Executing query \"DECLARE @Guid"
)


def test_job_summary_empty_when_only_dtexec_header():
    """Шапка dtexec — не причина сбоя, и выдавать её за причину нельзя."""
    assert mssql_log.summarize_job_message(TRUNCATED_PLAN_MSG) == ""


def test_job_summary_keeps_tail_when_no_description():
    """Без Description полезное в конце — обрезаем начало, а не хвост."""
    text = ("Executed as user: DOMAIN\\svc. " + "x" * 400
            + " The step failed.")
    summary = mssql_log.summarize_job_message(text, limit=100)
    assert summary.startswith("…")
    assert "The step failed" in summary
    assert len(summary) <= 100


def test_backup_section_explains_truncated_message():
    """Вместо шапки дежурный получает, где искать причину."""
    data = {"engine": [], "errors": [], "jobs": [{
        "when": "2026-08-28 00:10:00", "job": "backupdaily.Subplan_1",
        "step": 1, "stepname": "Subplan_1", "msg": TRUNCATED_PLAN_MSG}]}
    text = sqllog_bot.format_backup_errors(data, 24)
    assert "Execute Package Utility" not in text
    assert "Executing query" not in text
    assert mssql_log.JOB_MESSAGE_TRUNCATED in text


def test_jobs_section_notes_missing_step_text():
    """В списке джоб пустая строка выглядела как «упал молча»."""
    text = sqllog_bot.format_jobs({"rows": [{
        "when": "2026-08-28 00:10:00", "job": "backupdaily", "status": 0,
        "msg": TRUNCATED_PLAN_MSG}], "jobs_total": 5}, 24)
    assert "шапка dtexec" in text
