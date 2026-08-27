"""Тесты журналов Windows (shared/winlog.py, bot/winlog_bot.py).

Сеть не нужна: run_ps подменяется, проверяется собранный фильтр
Get-WinEvent и разбор ответа. Отдельно закреплены грабли: разбор 4625 по
именам полей, а не по индексам, и отличие «нет прав» от «нет событий».
"""
import base64
import json

import pytest

import winlog
import winlog_bot

SERVER = {"name": "app-01.example.local", "host": "192.0.2.11",
          "username": "svc", "password": "x"}


def _fake_ps(monkeypatch, payload):
    scripts = []

    def run_ps(host, script, username=None, password=None, **kwargs):
        scripts.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(winlog, "run_ps", run_ps)
    return scripts


# ─── Фильтры запроса ─────────────────────────────────────────

def test_reboot_filter_limits_ids_and_period(monkeypatch):
    """Без отбора по кодам журнал System даёт тысячи записей в сутки."""
    scripts = _fake_ps(monkeypatch, [])
    winlog.read_reboots(SERVER, hours=24)
    assert "Id=6008,41,1074,1076,6005,6006" in scripts[0]
    assert "StartTime=" in scripts[0]
    assert "LogName='System'" in scripts[0]


def test_uses_filterhashtable_not_get_eventlog(monkeypatch):
    """Get-EventLog тащит весь журнал в память и читает минутами."""
    scripts = _fake_ps(monkeypatch, [])
    winlog.read_disk_errors(SERVER)
    assert "Get-WinEvent -FilterHashtable" in scripts[0]
    assert "Get-EventLog" not in scripts[0]


def test_app_errors_take_only_error_levels(monkeypatch):
    scripts = _fake_ps(monkeypatch, [])
    winlog.read_app_errors(SERVER)
    assert "Level=1,2" in scripts[0]
    assert "LogName='Application'" in scripts[0]


def test_maxevents_always_set(monkeypatch):
    scripts = _fake_ps(monkeypatch, [])
    winlog.read_service_failures(SERVER, limit=25)
    assert "-MaxEvents 25" in scripts[0]


# ─── Расшифровка кодов ───────────────────────────────────────

def test_kernel_power_explained():
    """41 — самый частый и самый непонятный код при падении сервера."""
    assert "питание" in winlog.explain_event(41)


def test_6008_and_1074_differ():
    """Аварийное завершение и штатная перезагрузка — разные ситуации."""
    assert "неожиданным" in winlog.explain_event(6008)
    assert "штатное" in winlog.explain_event(1074)


def test_service_crash_codes_distinguish_restart():
    """7031 перезапускается автоматически, 7034 — нет."""
    assert "перезапущена" in winlog.explain_event(7031)
    assert "не была" in winlog.explain_event(7034)


def test_unknown_event_id_has_no_explanation():
    assert winlog.explain_event(99999) == ""
    assert winlog.explain_event(None) == ""


# ─── Неудачные входы (4625) ──────────────────────────────────

def test_failed_logon_parsed_by_field_names(monkeypatch):
    """Порядок полей 4625 менялся между версиями — читаем по именам."""
    scripts = _fake_ps(monkeypatch, [])
    winlog.read_failed_logons(SERVER)
    assert "TargetUserName" in scripts[0] and "IpAddress" in scripts[0]
    assert "Properties[" not in scripts[0]


def test_failed_logon_substatus_wins(monkeypatch):
    """Общий Status почти всегда 0xC000006D, причина — в SubStatus."""
    _fake_ps(monkeypatch, [{
        "d": "2026-08-27 13:00:00", "user": "admin", "domain": "DOM",
        "ip": "192.0.2.55", "host": "PC-1", "ltype": "10",
        "status": "0xC000006A", "status2": "0xC000006D",
    }])
    row = winlog.read_failed_logons(SERVER)[0]
    assert row["reason"] == "неверный пароль"
    assert row["how"] == "RDP (удалённый рабочий стол)"


def test_failed_logon_falls_back_to_status(monkeypatch):
    _fake_ps(monkeypatch, [{
        "d": "2026-08-27 13:00:00", "user": "guest", "domain": "",
        "ip": "192.0.2.56", "host": "", "ltype": "3",
        "status": "0x0", "status2": "0xC0000064",
    }])
    row = winlog.read_failed_logons(SERVER)[0]
    assert row["reason"] == "такой учётной записи не существует"


def test_failed_logons_grouped_by_source():
    """Перебор паролей — это одна проблема, а не сто строк."""
    rows = [{"d": f"2026-08-27 13:{n:02d}:00", "user": "admin", "domain": "DOM",
             "ip": "192.0.2.55", "host": "PC-1", "code": "0xC000006A"}
            for n in range(5)]
    grouped = winlog.group_failed_logons(rows)
    assert len(grouped) == 1 and grouped[0]["count"] == 5
    assert grouped[0]["last"] == "2026-08-27 13:04:00"


def test_logon_output_shows_source_and_reason():
    rows = winlog.group_failed_logons([{
        "d": "2026-08-27 13:00:00", "user": "admin", "domain": "DOM",
        "ip": "192.0.2.55", "host": "PC-1", "code": "0xC000006A",
        "reason": "неверный пароль", "how": "RDP (удалённый рабочий стол)",
    }])
    text = winlog_bot.format_logons(rows, 24)
    assert "DOM\\admin" in text and "192.0.2.55" in text
    assert "неверный пароль" in text and "RDP" in text


def test_empty_logons_mention_event_log_readers():
    """Пустой Security чаще означает нехватку прав, а не отсутствие атак."""
    assert "Event Log Readers" in winlog_bot.format_logons([], 24)


# ─── Вывод событий ───────────────────────────────────────────

def test_events_collapsed_with_counter():
    """Служба, падающая по кругу, иначе занимает весь экран."""
    rows = [{"d": f"2026-08-27 03:{n:02d}:00", "id": 7031,
             "src": "Service Control Manager",
             "msg": "Служба \"1C:Enterprise\" завершилась неожиданно"}
            for n in range(6)]
    text = winlog_bot.format_reboots(rows, 24)
    assert "6 раз" in text


def test_event_output_carries_explanation():
    rows = [{"d": "2026-08-27 03:00:00", "id": 41, "src": "Kernel-Power",
             "msg": "The system has rebooted without cleanly shutting down"}]
    text = winlog_bot.format_reboots(rows, 24)
    assert "↳" in text and "питание" in text


def test_empty_section_lists_what_was_checked():
    """«Записей нет» без списка кодов не говорит, о чём вообще речь."""
    text = winlog_bot.format_disks([], 24)
    for code in ("7/11/51", "55", "129"):
        assert code in text


def test_multiline_message_flattened():
    rows = [{"d": "2026-08-27 03:00:00", "id": 7034,
             "src": "SCM", "msg": "Служба упала\r\n   и не поднялась"}]
    text = winlog_bot.format_services(rows, 24)
    assert "\r" not in text and "   и не" not in text


# ─── Кнопка и права ──────────────────────────────────────────

def test_button_only_for_windows():
    assert winlog_bot.has_winlog({"host": "x"})
    assert winlog_bot.has_winlog({"host": "x", "type": "windows"})
    for kind in ("linux", "vmware", "device"):
        assert not winlog_bot.has_winlog({"host": "x", "type": kind})


def test_access_denied_explains_group():
    msg = winlog.friendly_winlog_error("Access is denied")
    assert "Event Log Readers" in msg


def test_no_events_is_not_an_error():
    """«No events were found» — пустой журнал, а не сбой."""
    assert winlog.friendly_winlog_error("No events were found matching") == ""


def test_token_cache_is_bounded():
    for _ in range(winlog_bot.WIN_TOKENS_MAX + 50):
        winlog_bot.win_token("app-01.example.local", 24)
    assert len(winlog_bot.WIN_TOKENS) <= winlog_bot.WIN_TOKENS_MAX


def test_help_section_documents_security_rights():
    """Пустой Security без объяснения читается как «атак не было»."""
    from config_editor import HELP_SECTIONS
    text = HELP_SECTIONS["winlog"][1]
    assert "Event Log Readers" in text
    assert "4625" in text and "41" in text


# ─── Состояние сервера ───────────────────────────────────────

def test_host_state_script_fits_winrm_limit(monkeypatch):
    """Скрипт длинный: если не влезет в командную строку, раздел мёртв."""
    import base64
    from winrm_client import MAX_PS_COMMAND_CHARS, compact_ps
    scripts = _fake_ps(monkeypatch, {})
    winlog.read_host_state(SERVER)
    encoded = len(base64.b64encode(compact_ps(scripts[0]).encode("utf_16_le")))
    assert encoded < MAX_PS_COMMAND_CHARS, f"{encoded} из {MAX_PS_COMMAND_CHARS}"


def test_host_state_normalizes_single_item(monkeypatch):
    """PowerShell сворачивает список из одного элемента в сам элемент."""
    _fake_ps(monkeypatch, {"reboot": "установленные обновления",
                           "certs": {"subject": "CN=srv", "until": "2026-09-01",
                                     "days": 5},
                           "hotfix": {"id": "KB5030219", "on": "2026-08-01"},
                           "boot": "2026-08-01 03:00:00"})
    data = winlog.read_host_state(SERVER)
    assert data["reboot"] == ["установленные обновления"]
    assert isinstance(data["certs"], list) and len(data["certs"]) == 1


def test_host_state_checks_all_reboot_sources(monkeypatch):
    """Признаков ожидания перезагрузки три, и они независимы."""
    scripts = _fake_ps(monkeypatch, {})
    winlog.read_host_state(SERVER)
    for key in ("Component Based Servicing", "RebootRequired",
                "PendingFileRenameOperations"):
        assert key in scripts[0]


def test_pending_reboot_explained():
    text = winlog_bot.format_host_state(
        {"reboot": ["установленные обновления"], "boot": "2026-08-01 03:00:00",
         "certs": [], "hotfix": []}, 24)
    assert "Ждёт перезагрузки" in text
    assert "не применена" in text


def test_no_pending_reboot_stated_positively():
    text = winlog_bot.format_host_state(
        {"reboot": [], "boot": "", "certs": [], "hotfix": []}, 24)
    assert "не требуется" in text


def test_expired_certificate_marked_differently():
    """Истёкший и истекающий — разные ситуации, метка должна различаться."""
    text = winlog_bot.format_host_state({
        "reboot": [], "boot": "", "hotfix": [],
        "certs": [{"subject": "CN=old.example.local", "until": "2026-08-01",
                   "days": -20}],
    }, 24)
    assert "❌" in text and "истёк" in text


def test_expiring_certificate_shows_days_left():
    text = winlog_bot.format_host_state({
        "reboot": [], "boot": "", "hotfix": [],
        "certs": [{"subject": "CN=rdp.example.local", "until": "2026-10-01",
                   "days": 30}],
    }, 24)
    assert "через 30 дн." in text
