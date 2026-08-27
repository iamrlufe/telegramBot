"""Тесты автоалерта о провалившемся бэкапе MSSQL.

Главное, что проверяется: алерт уходит один раз на событие. Монитор
опрашивает сервер каждые 5 минут и получает те же строки ERRORLOG —
без запоминания ключей группа получала бы одно и то же сообщение
288 раз в сутки.
"""
import json

import pytest

import alerts
import backup_collector
import mssql_log


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Изолированный файл состояния и перехват отправки."""
    path = tmp_path / "backup_fail_state.json"
    monkeypatch.setattr(alerts, "BACKUP_FAIL_STATE_FILE", str(path))
    monkeypatch.setattr(alerts, "is_muted", lambda name: False)
    sent = []
    monkeypatch.setattr(alerts, "send_or_defer",
                        lambda text, reply_markup=None, ack_key=None: sent.append(text))
    return sent


EVENT = {"key": "j|2026-08-27 00:00:00|Ежедневный бэкап|2",
         "when": "2026-08-27 00:00:00",
         "text": "джоб «Ежедневный бэкап», шаг 2: failed with 1 errors"}


def test_alert_sent_for_new_failure(state):
    alerts.check_backup_failure_alerts("sql-01.example.local", [EVENT])
    assert len(state) == 1
    assert "БЭКАП НЕ ВЫПОЛНЕН" in state[0]
    assert "Ежедневный бэкап" in state[0]


def test_same_failure_not_repeated(state):
    """Опрос каждые 5 минут возвращает те же строки — алерт один."""
    for _ in range(5):
        alerts.check_backup_failure_alerts("sql-01.example.local", [EVENT])
    assert len(state) == 1


def test_new_failure_next_night_alerts_again(state):
    """Ключ включает время: сбой следующей ночью — новое событие."""
    alerts.check_backup_failure_alerts("sql-01.example.local", [EVENT])
    later = dict(EVENT, key="j|2026-08-28 00:00:00|Ежедневный бэкап|2",
                 when="2026-08-28 00:00:00")
    alerts.check_backup_failure_alerts("sql-01.example.local", [later])
    assert len(state) == 2


def test_muted_server_stays_silent(state, monkeypatch):
    monkeypatch.setattr(alerts, "is_muted", lambda name: True)
    alerts.check_backup_failure_alerts("sql-01.example.local", [EVENT])
    assert state == []


def test_empty_events_do_nothing(state):
    alerts.check_backup_failure_alerts("sql-01.example.local", [])
    assert state == []


def test_long_series_trimmed_in_message(state):
    """Серия сбоев за ночь не должна упираться в лимит сообщения."""
    events = [dict(EVENT, key=f"j|2026-08-27 0{n}:00:00|Job|1") for n in range(9)]
    alerts.check_backup_failure_alerts("sql-01.example.local", events)
    assert "и ещё 4" in state[0]


def test_state_keeps_keys_within_window(state, tmp_path):
    """Ключи держатся по времени: ограничение числом приводило к тому,
    что вытесненные события снова считались новыми."""
    for n in range(200):
        alerts.check_backup_failure_alerts(
            "sql-01.example.local", [dict(EVENT, key=f"k{n}")])
    saved = json.loads((tmp_path / "backup_fail_state.json").read_text())
    assert len(saved["sql-01.example.local"]) == 200


# ─── Сбор событий из SQL ─────────────────────────────────────

def test_collector_builds_events_from_both_sources(monkeypatch):
    """ERRORLOG знает ошибку ОС и путь, история джоб — упавший шаг."""
    captured = {}

    def fake_read(server, hours=24):
        return {
            "engine": [{"d": "2026-08-27 00:00:00",
                        "t": "BackupDiskFile::CreateMedia: Backup device "
                             "'G:\\pro_bak\\x.bak' failed to create. "
                             "Operating system error 3(The system cannot "
                             "find the path specified.)."}],
            "jobs": [{"when": "2026-08-27 00:00:00", "job": "Ночной бэкап",
                      "step": 2, "stepname": "Backup zup_qb",
                      "msg": "failed with 1 errors"}],
            "errors": [],
        }

    # Подменяем только чтение: разбор сообщения и расшифровку причины
    # проверяем настоящие — ради них событие и собирается.
    monkeypatch.setattr(mssql_log, "read_backup_errors", fake_read)
    monkeypatch.setattr(backup_collector, "check_backup_failure_alerts",
                        lambda name, events: captured.update(name=name, events=events))

    backup_collector.check_mssql_backup_failures(
        {"name": "sql-01.example.local", "host": "192.0.2.10"})

    assert any("UNC" in (e.get("why") or "") for e in captured["events"]), \
        "причина сбоя не расшифрована"
    keys = [e["key"] for e in captured["events"]]
    assert any(k.startswith("e|") for k in keys), "нет события из ERRORLOG"
    assert any(k.startswith("j|") for k in keys), "нет события из истории джоб"
    assert any("Ночной бэкап" in e["text"] for e in captured["events"])


def test_collector_reports_unavailable_source(monkeypatch, capsys):
    """«Алертов нет» не должно означать «мы просто не смотрели»."""
    def fake_read(server, hours=24):
        return {"engine": [], "jobs": [],
                "errors": ["ERRORLOG: нет прав, нужна роль securityadmin"]}

    # Подменяем только чтение: разбор сообщения и расшифровку причины
    # проверяем настоящие — ради них событие и собирается.
    monkeypatch.setattr(mssql_log, "read_backup_errors", fake_read)
    monkeypatch.setattr(backup_collector, "check_backup_failure_alerts",
                        lambda name, events: None)

    backup_collector.check_mssql_backup_failures(
        {"name": "sql-01.example.local", "host": "192.0.2.10"})
    assert "securityadmin" in capsys.readouterr().out


def test_alert_carries_reason_line(state):
    """Причина отдельной строкой: длинное сообщение шага не читают целиком."""
    alerts.check_backup_failure_alerts("sql-01.example.local", [dict(
        EVENT, key="j|new", why="путь не найден: каталога нет")])
    assert "↳ путь не найден" in state[0]
