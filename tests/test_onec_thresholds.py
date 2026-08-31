"""Пороги журнала регистрации 1С: один источник для алертов и сводки.

Разбор onec_logs был продублирован в мониторе и в боте, и они разошлись.
У пути `C:\\Program Files\\1cv8\\srvinfo\\reg_1541` стояли свои 150/180 ГБ:
монитор молчал (правильно), а 🚨 Проблемы красили журнал на 12.54 ГБ
критичным по общим 5/10 — выглядело как «настройка не работает».
"""
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import onec_logs

ROOT = Path(__file__).resolve().parent.parent


def _load_bot_db():
    spec = importlib.util.spec_from_file_location("bot_db", ROOT / "bot" / "db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bot_db = _load_bot_db()


# ─── Разбор конфига ──────────────────────────────────────────

def test_path_thresholds_win_over_common():
    targets = onec_logs.onec_targets({"onec_logs": [
        {"path": r"C:\1cv8\srvinfo\reg_1541", "name": "ЛогиСервера1С",
         "warn_gb": 150, "crit_gb": 180},
    ]})
    assert targets == [{"name": "ЛогиСервера1С", "path": r"C:\1cv8\srvinfo\reg_1541",
                        "warn_gb": 150.0, "crit_gb": 180.0}]


def test_common_thresholds_when_path_has_none():
    targets = onec_logs.onec_targets({"onec_logs": [r"D:\logs"]})
    assert targets[0]["warn_gb"] == onec_logs.ONEC_LOG_WARN_GB
    assert targets[0]["crit_gb"] == onec_logs.ONEC_LOG_CRIT_GB
    assert targets[0]["name"] == "1C log"


def test_explicit_reset_does_not_break_collection():
    """Сброс к общим порогам бот пишет как warn_gb: null — float(None)
    ронял разбор, а вместе с ним весь сбор по этому серверу."""
    targets = onec_logs.onec_targets({"onec_logs": [
        {"path": r"D:\logs", "warn_gb": None, "crit_gb": None},
    ]})
    assert targets[0]["warn_gb"] == onec_logs.ONEC_LOG_WARN_GB


def test_single_object_and_garbage_entries():
    assert onec_logs.onec_targets({"onec_logs": {"path": r"D:\one"}})[0]["path"] == r"D:\one"
    assert onec_logs.onec_targets({"onec_logs": [{"name": "без пути"}, 42]}) == []
    assert onec_logs.onec_targets({}) == []


def test_thresholds_map_from_config_file(tmp_path):
    config = tmp_path / "servers.json"
    config.write_text(json.dumps([
        {"name": "srv-01", "onec_logs": [
            {"path": r"C:\reg_1541", "warn_gb": 150, "crit_gb": 180}]},
        {"name": "srv-02", "onec_logs": [r"D:\logs"]},
        {"name": "srv-03"},
    ]), encoding="utf-8")

    thresholds = onec_logs.load_onec_thresholds(str(config))
    assert thresholds[("srv-01", r"C:\reg_1541")] == (150.0, 180.0)
    assert thresholds[("srv-02", r"D:\logs")] == (
        onec_logs.ONEC_LOG_WARN_GB, onec_logs.ONEC_LOG_CRIT_GB)


def test_unreadable_config_is_not_fatal(tmp_path):
    assert onec_logs.load_onec_thresholds(str(tmp_path / "нет.json")) == {}


# ─── Сводка проблем считает по конфигу ───────────────────────

class _FakeCursor:
    def __init__(self, rows_by_table):
        self._rows_by_table = rows_by_table
        self._rows = []

    def execute(self, query, params=()):
        self._rows = []
        for table, rows in self._rows_by_table.items():
            if f"FROM {table}" in query:
                self._rows = rows
                break

    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def onec_log_of_12gb(monkeypatch):
    """Тот самый журнал сервера 1С: 12.54 ГБ при порогах 150/180."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = {
        "onec_log_metrics": [(
            "ast-kcmr-02", "ЛогиСервера1С", r"C:\Program Files\1cv8\srvinfo\reg_1541",
            12.54, 42, "ok", None, now,
        )],
    }
    cursor = _FakeCursor(rows)
    monkeypatch.setattr(bot_db, "get_conn", lambda: _FakeConn(cursor))
    monkeypatch.setattr(bot_db, "_load_backup_targets", lambda: ({}, set()))
    monkeypatch.setattr(bot_db, "load_schedule_map", lambda path: {})
    monkeypatch.setattr(bot_db, "load_disk_health", lambda name: {})
    monkeypatch.setattr(bot_db, "active_ack_digests", lambda: set())
    return rows


def _thresholds(monkeypatch, value):
    monkeypatch.setattr(bot_db, "load_onec_thresholds", lambda path: value)


def test_summary_respects_path_thresholds(onec_log_of_12gb, monkeypatch):
    _thresholds(monkeypatch, {
        ("ast-kcmr-02", r"C:\Program Files\1cv8\srvinfo\reg_1541"): (150.0, 180.0)
    })
    assert bot_db.collect_problems() == [], \
        "12.54 ГБ при пороге 150 — не проблема ни в каком виде"


def test_summary_still_warns_above_the_configured_limit(onec_log_of_12gb, monkeypatch):
    _thresholds(monkeypatch, {
        ("ast-kcmr-02", r"C:\Program Files\1cv8\srvinfo\reg_1541"): (10.0, 20.0)
    })
    problems = bot_db.collect_problems()
    assert [p["level"] for p in problems] == ["warn"]

    _thresholds(monkeypatch, {
        ("ast-kcmr-02", r"C:\Program Files\1cv8\srvinfo\reg_1541"): (5.0, 10.0)
    })
    assert [p["level"] for p in bot_db.collect_problems()] == ["crit"]


def test_path_missing_from_config_falls_back_to_common(onec_log_of_12gb, monkeypatch):
    """Путь убрали из конфига, метрики в базе остались — считаем по общим."""
    _thresholds(monkeypatch, {})
    assert [p["level"] for p in bot_db.collect_problems()] == ["crit"]
