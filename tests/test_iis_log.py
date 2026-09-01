"""Чтение логов IIS по смещению.

Суточный файл на живой публикации 1С — десятки мегабайт и полмиллиона
строк. Полный проход занимает десятки секунд, поэтому читается только
дописанное с прошлого раза. Ошибка здесь стоит либо потерянных суток,
либо перечитывания 20 ГБ истории.
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


iis_log = _load("iis_log", ROOT / "shared" / "iis_log.py")
winrm_client = _load("winrm_client", ROOT / "shared" / "winrm_client.py")

SERVER = {"name": "web-01.example.local", "host": "192.0.2.11",
          "username": "svc", "password": "x"}


def _scripts(monkeypatch, payload):
    import base64
    import json

    seen = []

    def run_ps(host, script, username=None, password=None, **kwargs):
        seen.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(iis_log, "run_ps", run_ps)
    return seen


# ─── Лимит WinRM ─────────────────────────────────────────────

def test_script_fits_winrm_command_line():
    """Командная строка WinRM — 8192 символа, а UTF-16 и base64 раздувают
    текст втрое. Не влезший скрипт падает ещё до запуска."""
    state = {f"u_ex2609{i:02d}.log": 123456789 for i in range(4)}

    assert winrm_client.ps_fits(iis_log._script(state, 10000, 25))


def test_extra_script_fits_too():
    """HTTPERR и конфигурация вынесены во второй вызов именно потому, что
    один скрипт на всё в лимит не влезает."""
    assert winrm_client.ps_fits(iis_log._extra_script({"httperr1.log": 5}, 25))


# ─── Смещения ────────────────────────────────────────────────

def test_offset_passed_into_script(monkeypatch):
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {"u_ex260901.log": 4096})

    assert "u_ex260901.log" in scripts[0]
    assert "4096" in scripts[0]


def test_script_rereads_file_that_became_shorter(monkeypatch):
    """Файл короче запомненного смещения — его подменили; продолжать с
    середины чужого файла нельзя."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {"u_ex260901.log": 10})

    assert "if($off -gt $f.Length){$off=0}" in winrm_client.compact_ps(scripts[0])


def test_script_skips_history_on_first_run(monkeypatch):
    """Истории здесь на 20 ГБ: с нуля читается только самый свежий файл,
    остальные пропускаются установкой смещения в конец."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {})
    compact = winrm_client.compact_ps(scripts[0])

    assert "$off=$f.Length" in compact


def test_yesterdays_tail_is_not_lost(monkeypatch):
    """После полуночи у вчерашнего файла остаётся хвост: окно в 36 часов
    покрывает и его."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {})

    assert "AddHours(-36)" in scripts[0]


def test_state_returned_as_numbers(monkeypatch):
    _scripts(monkeypatch, {"total": 5, "state": {"u_ex260901.log": "8192"}})
    data = iis_log.read_site_logs(SERVER, {})

    assert data["state"] == {"u_ex260901.log": 8192}


# ─── Разбор ──────────────────────────────────────────────────

def test_fields_parsed_by_name(monkeypatch):
    """Набор колонок в логе IIS настраивается: позиции дадут чужие значения."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {})

    assert "#Fields:" in scripts[0]
    assert "$map[$n[$i]]=$i" in winrm_client.compact_ps(scripts[0])


def test_header_read_before_seek():
    """Строка #Fields лежит в начале файла, а читать надо с середины —
    заголовок вычитывается до перемотки."""
    script = iis_log._script({"u_ex260901.log": 100}, 10000, 25)
    compact = winrm_client.compact_ps(script)

    assert compact.index("#Fields:") < compact.index("$fs.Position=$off")


def test_log_file_opened_with_shared_access():
    """Текущие сутки IIS держит открытыми — монопольное чтение падает."""
    script = iis_log._script({}, 10000, 25)

    assert "'Open','Read','ReadWrite'" in winrm_client.compact_ps(script)


def test_publications_taken_from_iis_config():
    """Список баз нельзя зашивать: добавили публикацию — она мгновенно
    оказалась бы «посторонним путём»."""
    assert "Get-WebApplication" in iis_log._script({}, 10000, 25)


def test_redirect_from_port_80_is_not_a_finding():
    """На порту 80 стоит редирект на HTTPS: он отдаёт 301 на любой путь,
    включая несуществующий. Считать это находкой сканера нельзя."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "$p[$map['s-port']] -ne '80'" in compact


def test_idle_connections_excluded_from_httperr_details():
    """Timer_ConnectionIdle — 10 тысяч штатных записей в сутки; без отсева
    они похоронят десяток настоящих."""
    compact = winrm_client.compact_ps(iis_log._extra_script({}, 25))

    assert "-ne 'Timer_ConnectionIdle'" in compact


def test_slow_threshold_is_configurable(monkeypatch):
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {}, slow_ms=3000)

    assert "-gt 3000" in winrm_client.compact_ps(scripts[0])


def test_single_row_normalized(monkeypatch):
    """PowerShell отдаёт одиночный элемент объектом, а не массивом."""
    _scripts(monkeypatch, {"total": 1, "state": {},
                           "codes": {"k": "200.0", "n": 5}})
    data = iis_log.read_site_logs(SERVER, {})

    assert data["codes"] == [{"k": "200.0", "n": 5}]
