"""Фоновый сбор IIS: кого опрашиваем, как часто, что при отказе."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ic = _load("iis_collector", ROOT / "monitor" / "iis_collector.py")

IIS = {"name": "web-01.example.local", "host": "192.0.2.11",
       "services": ["W3SVC", "WAS"]}
SQL = {"name": "sql-01.example.local", "host": "192.0.2.10", "dbsize": True,
       "services": ["MSSQLSERVER"]}
LINUX = {"name": "nas-01.example.local", "host": "192.0.2.20", "type": "linux",
         "services": ["nginx"]}


# ─── Кого опрашиваем ─────────────────────────────────────────

def test_iis_detected_by_service():
    """Отдельного флага нет: признак — служба W3SVC, как dbsize для MSSQL."""
    assert ic.has_iis(IIS) is True
    assert ic.has_iis(SQL) is False


def test_service_name_case_insensitive():
    assert ic.has_iis({**IIS, "services": ["w3svc"]}) is True


def test_linux_is_not_iis():
    """nginx на Linux — тоже веб-сервер, но не IIS и читается иначе."""
    assert ic.has_iis(LINUX) is False


# ─── Расписание ──────────────────────────────────────────────

def test_first_run_happens_at_once():
    assert ic.iis_scan_due(now=1000.0, last=None) is True


def test_interval_respected(monkeypatch):
    monkeypatch.setattr(ic, "IIS_SCAN_MINUTES", 60)

    assert ic.iis_scan_due(now=1000.0, last=1000.0 - 59 * 60) is False
    assert ic.iis_scan_due(now=1000.0, last=1000.0 - 61 * 60) is True


# ─── Разбор ответа ───────────────────────────────────────────

def test_counters_mapped_to_categories():
    rows = ic._rows_from_site({
        "total": 476176, "alien": 889, "slow": 245,
        "alienuris": [{"k": "/index.php", "n": 743}],
        "logins": [{"k": "agro|192.0.2.30", "n": 26}],
        "hits": [{"k": "/x.php|192.0.2.99|curl", "n": 2}],
    })

    assert ("total", "requests", 476176) in rows
    assert ("alienuri", "/index.php", 743) in rows
    assert ("login", "agro|192.0.2.30", 26) in rows
    assert ("hit", "/x.php|192.0.2.99|curl", 2) in rows


def test_httperr_reasons_and_details_separated():
    rows = ic._rows_from_extra({
        "reasons": [{"k": "Timer_ConnectionIdle", "n": 10595}],
        "details": [{"k": "Verb|-|-|192.0.2.99", "n": 12}],
    })

    assert ("herr", "Timer_ConnectionIdle", 10595) in rows
    assert ("herrd", "Verb|-|-|192.0.2.99", 12) in rows


# ─── Отказы ──────────────────────────────────────────────────

def test_broken_site_logs_do_not_block_httperr(monkeypatch):
    """Логи сайта закрыты по правам — HTTPERR и конфигурация всё равно
    читаются: это разные вызовы и разные права."""
    monkeypatch.setattr(ic, "load_state", lambda *a: {})
    monkeypatch.setattr(ic, "save_state", lambda *a: None)

    def boom(*a, **k):
        raise Exception("Access is denied")

    monkeypatch.setattr(ic, "read_site_logs", boom)
    monkeypatch.setattr(ic, "read_httperr_and_config", lambda *a, **k: {
        "reasons": [{"k": "Verb", "n": 3}], "apps": [{"p": "/agro"}],
        "pools": [], "logs_mb": 100.0, "oldest": "2026-01-01", "state": {},
    })

    name, rows, facts, error = ic.collect_server(IIS)

    assert name == IIS["name"]
    assert ("herr", "Verb", 3) in rows
    assert facts["logs_mb"] == 100.0
    assert "логи сайта" in error


def test_state_saved_only_for_successful_read(monkeypatch):
    """Смещение обязано двигаться ровно на прочитанное: сохранить его после
    сбоя значит потерять сутки."""
    saved = []
    monkeypatch.setattr(ic, "load_state", lambda *a: {})
    monkeypatch.setattr(ic, "save_state",
                        lambda name, source, state: saved.append((source, state)))
    monkeypatch.setattr(ic, "read_site_logs", lambda *a, **k: {
        "total": 10, "state": {"u_ex260901.log": 900}})

    def boom(*a, **k):
        raise Exception("нет доступа к HTTPERR")

    monkeypatch.setattr(ic, "read_httperr_and_config", boom)

    _name, _rows, _facts, error = ic.collect_server(IIS)

    assert saved == [("site", {"u_ex260901.log": 900})]
    assert "HTTPERR" in error
