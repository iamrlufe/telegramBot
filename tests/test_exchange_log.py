"""Тесты раздела почты Exchange (shared/exchange_log.py, bot/exchange_bot.py).

Ключевое, что здесь закреплено: успешные входы читаются из логов IIS, а
неудачные — из журнала Security, потому что при форменной аутентификации
IIS не знает имени пользователя. Плюс агрегация на сервере: на живом
Exchange логи в сутки — сотни мегабайт.
"""
import base64
import json

import pytest

import exchange_log
import exchange_bot

SERVER = {"name": "mail-01.example.local", "host": "192.0.2.12",
          "username": "svc", "password": "x",
          "services": ["MSExchangeIS", "MSExchangeTransport", "W3SVC"]}


def _fake_ps(monkeypatch, payload, target=exchange_log):
    scripts = []

    def run_ps(host, script, username=None, password=None, **kwargs):
        scripts.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(target, "run_ps", run_ps)
    return scripts


# ─── Признак почтового сервера ───────────────────────────────

def test_button_shown_for_exchange_services():
    """Отдельного флага нет: признак — служба MSExchange*, как у nginx/docker."""
    assert exchange_bot.has_exchange(SERVER)


def test_button_hidden_without_exchange_services():
    assert not exchange_bot.has_exchange({"services": ["W3SVC", "MSSQLSERVER"]})
    assert not exchange_bot.has_exchange({})


def test_button_hidden_for_non_windows():
    assert not exchange_bot.has_exchange(
        {"type": "linux", "services": ["MSExchangeIS"]})


def test_service_name_case_insensitive():
    assert exchange_bot.has_exchange({"services": ["msexchangeis"]})


# ─── Чтение логов IIS ────────────────────────────────────────

def test_log_directory_taken_from_iis_config(monkeypatch):
    """Каталог логов настраивается — угадывать его нельзя."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    assert "WebAdministration" in scripts[0]
    assert "logFile.directory" in scripts[0]


def test_fields_parsed_by_name_not_position(monkeypatch):
    """Набор колонок в логе IIS настраивается: позиции дадут чужие значения."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    assert "#Fields:" in scripts[0]
    assert "$map[$names[$i]] = $i" in scripts[0]


def test_aggregation_happens_on_server(monkeypatch):
    """Сотни мегабайт логов не должны ехать в контейнер построчно."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    assert "$agg" in scripts[0] and "Sort-Object" in scripts[0]
    assert "Select-Object -First" in scripts[0]


def test_owa_and_activesync_use_different_paths(monkeypatch):
    owa = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    eas_scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_activesync(SERVER)
    assert "/owa/" in owa[0]
    assert "activesync" in eas_scripts[0].lower()


def test_missing_log_directory_reported(monkeypatch):
    """Отсутствие каталога — понятная ошибка, а не пустой список."""
    _fake_ps(monkeypatch, {"iis_error": "Каталог логов IIS не найден: C:\\x"})
    with pytest.raises(Exception, match="не найден"):
        exchange_log.read_owa_logins(SERVER)


def test_single_row_normalized(monkeypatch):
    """PowerShell сворачивает список из одного элемента в сам элемент."""
    _fake_ps(monkeypatch, {"rows": {"user": "ivanov", "ip": "192.0.2.55",
                                    "ua": "Chrome", "count": 3,
                                    "last": "2026-08-27 09:14:22"},
                           "scanned": 3})
    data = exchange_log.read_owa_logins(SERVER)
    assert isinstance(data["rows"], list) and len(data["rows"]) == 1


# ─── Неудачные входы: журнал Security ────────────────────────

def test_failures_read_from_security_not_iis(monkeypatch):
    """При форменной аутентификации IIS не знает имени: cs-username пуст."""
    import winlog
    scripts = _fake_ps(monkeypatch, [], target=winlog)
    exchange_log.read_owa_failures(SERVER)
    assert "LogName='Security'" in scripts[0]
    assert "Id=4625" in scripts[0]


def test_failures_filtered_to_web_logons(monkeypatch):
    """Вход по RDP не должен попадать в раздел почты."""
    import winlog
    _fake_ps(monkeypatch, [
        {"d": "2026-08-27 09:00:00", "user": "ivanov", "ip": "192.0.2.55",
         "ltype": "8", "proc": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
         "status": "0xC000006A", "status2": ""},
        {"d": "2026-08-27 09:05:00", "user": "petrov", "ip": "192.0.2.60",
         "ltype": "10", "proc": "C:\\Windows\\System32\\svchost.exe",
         "status": "0xC000006A", "status2": ""},
    ], target=winlog)
    rows = exchange_log.read_owa_failures(SERVER)
    assert len(rows) == 1 and rows[0]["user"] == "ivanov"


def test_failures_grouped_and_explained(monkeypatch):
    import winlog
    _fake_ps(monkeypatch, [
        {"d": f"2026-08-27 09:0{n}:00", "user": "ivanov", "ip": "192.0.2.55",
         "ltype": "8", "proc": "c:\\windows\\system32\\inetsrv\\w3wp.exe",
         "status": "0xC000006A", "status2": ""} for n in range(4)
    ], target=winlog)
    rows = exchange_log.read_owa_failures(SERVER)
    assert rows[0]["count"] == 4
    assert rows[0]["reason"] == "неверный пароль"


# ─── Вывод ───────────────────────────────────────────────────

def _render(result):
    return exchange_bot.render(*result, page=0)[0]


def test_owa_output_shows_user_ip_and_client():
    text = _render(exchange_bot.format_owa({"rows": [
        {"user": "ivanov", "ip": "192.0.2.55", "count": 12,
         "last": "2026-08-27 09:14:22",
         "ua": "Mozilla/5.0+(Windows+NT+10.0)+Chrome/128.0"}], "scanned": 12}, 24))
    assert "ivanov" in text and "192.0.2.55" in text
    assert "Chrome" in text and "Mozilla" not in text


def test_client_name_recognizes_phones():
    assert exchange_bot._client_name("Apple-iPhone14C2/2011.300") == "iPhone"
    assert exchange_bot._client_name("Android/12.0.0-EAS-2.0") == "Android"


def test_client_name_survives_unknown_agent():
    assert exchange_bot._client_name("") == "неизвестный клиент"


def test_empty_owa_points_at_iis_logging():
    """Пустой раздел чаще всего значит выключённые логи IIS."""
    text = _render(exchange_bot.format_owa({"rows": [], "scanned": 0}, 24))
    assert "журналов IIS" in text


def test_empty_failures_point_at_audit():
    text = _render(exchange_bot.format_failures([], 24))
    assert "4625" in text and "аудит" in text.lower()


def test_failures_output_notes_protocol_ambiguity():
    """OWA, ActiveSync и EWS в Security неразличимы — это надо сказать."""
    text = _render(exchange_bot.format_failures([{
        "user": "ivanov", "ip": "192.0.2.55", "code": "0xC000006A",
        "reason": "неверный пароль", "count": 5,
        "last": "2026-08-27 09:00:00"}], 24))
    assert "ActiveSync" in text and "неразличимы" in text


def test_token_cache_is_bounded():
    for _ in range(exchange_bot.EX_TOKENS_MAX + 50):
        exchange_bot.ex_token("mail-01.example.local", 24)
    assert len(exchange_bot.EX_TOKENS) <= exchange_bot.EX_TOKENS_MAX


def test_iis_script_fits_winrm_limit(monkeypatch):
    """Скрипт агрегации длинный — если не влезет, раздел мёртв целиком."""
    from winrm_client import MAX_PS_COMMAND_CHARS, compact_ps
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER, hours=168)
    encoded = len(base64.b64encode(compact_ps(scripts[0]).encode("utf_16_le")))
    assert encoded < MAX_PS_COMMAND_CHARS, f"{encoded} из {MAX_PS_COMMAND_CHARS}"


def test_help_section_explains_two_sources():
    """Разные источники для успехов и отказов — не очевидно, надо объяснить."""
    from config_editor import HELP_SECTIONS
    text = HELP_SECTIONS["exchange"][1]
    assert "IIS" in text and "4625" in text


# ─── Постраничный вывод ──────────────────────────────────────

def _many_rows(n):
    return {"rows": [{"user": f"user{i}@example.local", "ip": f"192.0.2.{i}",
                      "count": 100 - i, "last": "2026-08-27 09:00:00",
                      "ua": "Chrome/128"} for i in range(n)], "scanned": 5000}


def test_long_list_is_paginated():
    """Раньше остаток обрывался фразой «… ещё 25» и был недоступен."""
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    assert len(blocks) == 40
    text, page, total = exchange_bot.render(header, blocks, 0)
    assert total == 3, "40 записей по 15 на страницу — три страницы"
    assert "Показано 1–15 из 40" in text
    assert "… ещё" not in text


def test_second_page_shows_next_records():
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    text, page, total = exchange_bot.render(header, blocks, 1)
    assert "user15@example.local" in text
    assert "user0@example.local" not in text
    assert "Показано 16–30 из 40" in text


def test_last_page_is_partial():
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    text, page, total = exchange_bot.render(header, blocks, 2)
    assert "Показано 31–40 из 40" in text


def test_page_number_clamped():
    """Кнопка из старого сообщения может указывать на исчезнувшую страницу."""
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    _, page, total = exchange_bot.render(header, blocks, 99)
    assert page == total - 1


def test_short_list_has_no_pagination_line():
    header, blocks = exchange_bot.format_owa(_many_rows(5), 24)
    text, _, total = exchange_bot.render(header, blocks, 0)
    assert total == 1 and "Показано" not in text


def test_nav_buttons_only_when_needed():
    from tg_utils import nav_row
    assert nav_row("exlog_page:r1:", 0, 1) == []
    row = nav_row("exlog_page:r1:", 1, 3)
    assert len(row) == 3, "назад, счётчик, вперёд"


def test_result_cache_is_bounded():
    """Кэш сводок не должен расти бесконечно в долгоживущем процессе."""
    for n in range(exchange_bot.EX_RESULTS_MAX + 30):
        exchange_bot.result_token("mail-01.example.local", 24, "owa",
                                  [f"b{n}"], "h")
    assert len(exchange_bot.EX_RESULTS) <= exchange_bot.EX_RESULTS_MAX


def test_paginate_helper_boundaries():
    from tg_utils import paginate
    chunk, page, total = paginate(list(range(10)), 0, 4)
    assert chunk == [0, 1, 2, 3] and total == 3
    chunk, page, total = paginate(list(range(10)), 2, 4)
    assert chunk == [8, 9] and page == 2
    chunk, page, total = paginate([], 0, 4)
    assert chunk == [] and total == 1


# ─── Чтение занятого файла ───────────────────────────────────

def test_current_day_log_opened_with_shared_access(monkeypatch):
    """Текущие сутки IIS держит открытыми: монопольный ReadLines падает с
    «файл используется другим процессом», а при SilentlyContinue — падает
    молча, и раздел показывал пустоту вместо сегодняшних сеансов."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)

    assert "ReadLines" not in scripts[0]
    assert "'Open', 'Read', 'ReadWrite'" in scripts[0]
    assert "StreamReader" in scripts[0]


def test_unreadable_file_is_reported_not_swallowed(monkeypatch):
    """Файл, который всё же не открылся, попадает в $failed — неполная
    выборка обязана быть названа."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)

    assert "$failed" in scripts[0]
    assert "failed = $failed" in scripts[0]


def test_incomplete_read_is_visible_in_the_card():
    """Пользователь должен видеть, что выборка неполная, а не гадать."""
    data = {"rows": [{"user": "petrov", "ip": "192.0.2.30", "ua": "1CV8C",
                      "count": 3, "last": "2026-09-01 08:00:00"}],
            "scanned": 3, "failed": ["u_ex260901.log"]}

    header, _blocks = exchange_bot.format_owa(data, 24)

    assert "не удалось прочитать" in header.lower()


def test_complete_read_says_nothing_extra():
    data = {"rows": [{"user": "petrov", "ip": "192.0.2.30", "ua": "1CV8C",
                      "count": 3, "last": "2026-09-01 08:00:00"}],
            "scanned": 3, "failed": []}

    header, _blocks = exchange_bot.format_owa(data, 24)

    assert "не удалось" not in header.lower()
