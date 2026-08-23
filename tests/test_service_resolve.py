"""
Сопоставление служб из конфига со снимком SCM (Win32_Service).

Реальный случай: 1С регистрирует рядом две службы — 32-битную (остаётся
зарегистрированной, но не работает) и «(x86-64)». В конфиге записано базовое
имя, и оно точно совпадает именно с мёртвой 32-битной.
"""
import base64

from server_check import STATUS_SCRIPT, resolve_service
from winrm_client import MAX_PS_COMMAND_CHARS, PS_OUT_B64_HELPER, compact_ps


def svc(name, display, state, pid=0):
    return {"Name": name, "DisplayName": display, "State": state, "ProcessId": pid}


APP01 = [
    svc("1C:Enterprise 8.3 Server Agent", "Агент сервера 1С:Предприятия 8.3", "Stopped"),
    svc("1C:Enterprise 8.3 Server Agent (x86-64)",
        "Агент сервера 1С:Предприятия 8.3 (x86-64)", "Running", 4720),
    svc("MSSQLSERVER", "SQL Server (MSSQLSERVER)", "Running", 1000),
    svc("MsDtsServer130", "Службы SQL Server Integration Services 13.0", "Running", 4176),
    svc("SQLSERVERAGENT", "Агент SQL Server", "Stopped"),
]


def test_prefers_x64_over_exact_32bit_match():
    spec = {"name": "1C:Enterprise 8.3 Server Agent",
            "display_name": "1C:Enterprise 8.3 Server Agent", "label": "1С"}
    result = resolve_service(APP01, spec)
    assert result["Name"] == "1C:Enterprise 8.3 Server Agent (x86-64)"
    assert result["Status"] == "Running"
    assert result["MatchCount"] == 2
    assert result["Ambiguous"] is False


def test_matches_by_cyrillic_display_name():
    spec = {"name": None, "display_name": "Агент сервера 1С:Предприятия 8.3",
            "label": "1С"}
    result = resolve_service(APP01, spec)
    assert result["Name"] == "1C:Enterprise 8.3 Server Agent (x86-64)"
    assert result["Status"] == "Running"


def test_full_x64_name_in_config():
    spec = {"name": "1C:Enterprise 8.3 Server Agent (x86-64)",
            "display_name": "1C:Enterprise 8.3 Server Agent (x86-64)", "label": "1С"}
    result = resolve_service(APP01, spec)
    assert result["Name"] == "1C:Enterprise 8.3 Server Agent (x86-64)"
    assert result["MatchCount"] == 1


def test_plain_service_unaffected():
    spec = {"name": "MSSQLSERVER", "display_name": "MSSQLSERVER", "label": "SQL"}
    result = resolve_service(APP01, spec)
    assert result["Name"] == "MSSQLSERVER"
    assert result["Status"] == "Running"
    assert result["MatchCount"] == 1


def test_prefix_match_does_not_catch_unrelated_services():
    # "MsDtsServer130" не должен подтянуться к "MsDtsServer": вариантом
    # считается только суффикс в скобках.
    spec = {"name": "MsDtsServer", "display_name": "MsDtsServer", "label": "SSIS"}
    assert resolve_service(APP01, spec)["Status"] == "not_found"


def test_stopped_service_reported_as_problem():
    spec = {"name": "SQLSERVERAGENT", "display_name": "SQLSERVERAGENT", "label": "Агент"}
    result = resolve_service(APP01, spec)
    assert result["Status"] == "Stopped"
    assert result["Ambiguous"] is False


def test_live_process_beats_stale_stopped_state():
    services = [svc("Zombie", "Zombie", "Stopped", 777)]
    spec = {"name": "Zombie", "display_name": "Zombie", "label": "Z"}
    assert resolve_service(services, spec)["Status"] == "Running"


def test_ambiguous_when_duplicates_without_bitness():
    services = [
        svc("Agent 8.3 (1541)", "Агент 8.3 (1541)", "Stopped"),
        svc("Agent 8.3 (1741)", "Агент 8.3 (1741)", "Stopped"),
    ]
    spec = {"name": "Agent 8.3", "display_name": "Agent 8.3", "label": "A"}
    result = resolve_service(services, spec)
    assert result["MatchCount"] == 2
    assert result["Ambiguous"] is True


def test_missing_service_reports_config_name():
    spec = {"name": "НетТакой", "display_name": "НетТакой", "label": "X"}
    result = resolve_service([], spec)
    assert result["Status"] == "not_found"
    assert result["Name"] == "НетТакой"


def test_status_script_fits_winrm_command_line():
    # Скрипт больше не зависит от конфига, но лимит проверяем явно:
    # раньше он был превышен и все серверы падали с
    # «The command line is too long».
    script = compact_ps(PS_OUT_B64_HELPER + STATUS_SCRIPT)
    encoded = len(base64.b64encode(script.encode("utf_16_le")))
    assert encoded < MAX_PS_COMMAND_CHARS
