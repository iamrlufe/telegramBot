"""Тесты приёма алертов («Принято, не напоминать»).

Механика общая для всех алертов, поэтому проверяется на уровне
send_or_defer: если ack_key передан, алерт получает кнопку и уважает
подавление. Отдельно — исправление повторов сбоя бэкапа: ключи теперь
живут по времени, а не последними N штуками.
"""
import json

import pytest

import alerts
import alerts_ack


@pytest.fixture
def ack_file(tmp_path, monkeypatch):
    path = tmp_path / "alert_ack.json"
    monkeypatch.setattr(alerts_ack, "ACK_FILE", str(path))
    return path


@pytest.fixture
def sent(monkeypatch):
    """Перехват отправки, тихие часы выключены."""
    messages = []
    monkeypatch.setattr(alerts, "in_quiet_hours", lambda: False)
    monkeypatch.setattr(alerts, "send_telegram",
                        lambda text, markup=None: messages.append((text, markup)))
    return messages


# ─── Кнопка и подавление ─────────────────────────────────────

def test_ack_button_added_when_key_given(ack_file, sent):
    alerts.send_or_defer("🚨 Тест", ack_key="disk:srv-01:C")
    text, markup = sent[0]
    buttons = [b for row in markup["inline_keyboard"] for b in row]
    assert any(b["callback_data"].startswith("ack:") for b in buttons)


def test_no_button_without_key(ack_file, sent):
    alerts.send_or_defer("✅ Восстановлено")
    assert sent[0][1] is None


def test_existing_buttons_preserved(ack_file, sent):
    """Кнопка приёма добавляется к клавиатуре, а не заменяет её."""
    alerts.send_or_defer("🚨 Тест",
                         reply_markup={"inline_keyboard": [[{"text": "График",
                                                             "callback_data": "chart:x"}]]},
                         ack_key="disk:srv-01:C")
    keyboard = sent[0][1]["inline_keyboard"]
    assert len(keyboard) == 2
    assert keyboard[0][0]["text"] == "График"


def test_acked_alert_is_not_sent(ack_file, sent):
    alerts.send_or_defer("🚨 Первый", ack_key="disk:srv-01:C")
    digest = alerts_ack.ack_hash("disk:srv-01:C")
    alerts_ack.ack_alert(digest)
    alerts.send_or_defer("🚨 Второй", ack_key="disk:srv-01:C")
    assert len(sent) == 1, "после приёма алерт не должен приходить"


def test_ack_is_per_alert_not_per_server(ack_file, sent):
    """Приняли алерт по диску C — алерт по диску D обязан прийти."""
    alerts.send_or_defer("🚨 C", ack_key="disk:srv-01:C")
    alerts_ack.ack_alert(alerts_ack.ack_hash("disk:srv-01:C"))
    alerts.send_or_defer("🚨 D", ack_key="disk:srv-01:D")
    assert len(sent) == 2


def test_ack_expires(ack_file, sent, monkeypatch):
    """Подавление временное: через сутки алерт возвращается."""
    alerts.send_or_defer("🚨 Тест", ack_key="offline:srv-01")
    digest = alerts_ack.ack_hash("offline:srv-01")
    alerts_ack.ack_alert(digest, hours=-1)      # срок уже истёк
    alerts.send_or_defer("🚨 Тест", ack_key="offline:srv-01")
    assert len(sent) == 2


def test_unack_returns_alert(ack_file, sent):
    alerts.send_or_defer("🚨 Тест", ack_key="smart:srv-01")
    digest = alerts_ack.ack_hash("smart:srv-01")
    alerts_ack.ack_alert(digest)
    alerts_ack.unack_alert(digest)
    alerts.send_or_defer("🚨 Тест", ack_key="smart:srv-01")
    assert len(sent) == 2


def test_unknown_digest_handled(ack_file):
    key, until = alerts_ack.ack_alert("deadbeef1234")
    assert key is None and until is None


def test_callback_data_fits_telegram_limit(ack_file):
    """Ключ бывает длинным: сервер + путь к бэкапу."""
    key = "backup_stale:very-long-server-name.example.local:E:\\Backups\\base_one\\FULL"
    digest = alerts_ack.register_ack_key(key)
    assert len(f"ack:{digest}".encode("utf-8")) <= 64


def test_ack_list_shows_active_only(ack_file):
    alerts_ack.register_ack_key("disk:srv-01:C")
    alerts_ack.register_ack_key("disk:srv-01:D")
    alerts_ack.ack_alert(alerts_ack.ack_hash("disk:srv-01:C"))
    alerts_ack.ack_alert(alerts_ack.ack_hash("disk:srv-01:D"), hours=-1)
    keys = [item["key"] for item in alerts_ack.active_acks()]
    assert keys == ["disk:srv-01:C"]


def test_acks_purged_with_server(ack_file):
    """Удалили сервер — его подавления не должны достаться тёзке."""
    alerts_ack.register_ack_key("disk:srv-01:C")
    alerts_ack.ack_alert(alerts_ack.ack_hash("disk:srv-01:C"))
    alerts_ack.purge_acks_for_server("srv-01")
    assert alerts_ack.active_acks() == []


def test_broken_ack_file_does_not_crash(ack_file):
    ack_file.write_text("{ это не json")
    assert alerts_ack.is_acked("disk:srv-01:C") is False


# ─── Повторы сбоя бэкапа ─────────────────────────────────────

@pytest.fixture
def fail_state(tmp_path, monkeypatch):
    path = tmp_path / "backup_fail_state.json"
    monkeypatch.setattr(alerts, "BACKUP_FAIL_STATE_FILE", str(path))
    monkeypatch.setattr(alerts, "is_muted", lambda name: False)
    messages = []
    monkeypatch.setattr(alerts, "send_or_defer",
                        lambda text, reply_markup=None, ack_key=None: messages.append(text))
    return messages, path


def test_high_frequency_failures_do_not_loop(fail_state):
    """BACKUP LOG идёт каждые 5 минут: за сутки под три сотни сбоев.
    Прежний буфер на 60 ключей переполнялся, вытесненные события снова
    считались новыми, и алерт шёл по кругу."""
    messages, _ = fail_state
    events = [{"key": f"j|2026-08-27 {h:02d}:{m:02d}:00|Job|1",
               "when": f"2026-08-27 {h:02d}:{m:02d}:00", "text": "BACKUP LOG failed"}
              for h in range(24) for m in (0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55)]
    alerts.check_backup_failure_alerts("sql-01.example.local", events)
    assert len(messages) == 1
    # повторный цикл монитора с теми же событиями
    alerts.check_backup_failure_alerts("sql-01.example.local", events)
    assert len(messages) == 1, "те же сбои не должны прийти второй раз"


def test_old_keys_forgotten_after_window(fail_state, monkeypatch):
    """Ключи чистятся по возрасту, иначе файл состояния растёт вечно."""
    messages, path = fail_state
    alerts.check_backup_failure_alerts(
        "sql-01.example.local",
        [{"key": "j|old", "when": "2026-08-01 00:00:00", "text": "x"}])
    state = json.loads(path.read_text())
    assert isinstance(state["sql-01.example.local"], dict)


def test_legacy_list_state_migrated(fail_state):
    """Старый формат — список ключей: после обновления прошлые сбои
    не должны прилететь заново."""
    messages, path = fail_state
    path.write_text(json.dumps({"sql-01.example.local": ["j|known"]}))
    alerts.check_backup_failure_alerts(
        "sql-01.example.local",
        [{"key": "j|known", "when": "2026-08-27 00:00:00", "text": "x"}])
    assert messages == []
