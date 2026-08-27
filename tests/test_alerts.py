"""Тесты monitor/alerts.py: тихие часы, окно предупреждения, docker-статусы."""
import inspect
from datetime import datetime
from pathlib import Path

import alerts


# ─── in_quiet_hours ──────────────────────────────────────────

def _at(hh, mm=0):
    return datetime(2026, 7, 24, hh, mm)


def test_quiet_hours_disabled(monkeypatch):
    monkeypatch.delenv("QUIET_HOURS", raising=False)
    assert alerts.in_quiet_hours(_at(3)) is False


def test_quiet_hours_overnight_range(monkeypatch):
    monkeypatch.setenv("QUIET_HOURS", "23:00-07:00")
    assert alerts.in_quiet_hours(_at(23, 30)) is True
    assert alerts.in_quiet_hours(_at(3)) is True
    assert alerts.in_quiet_hours(_at(6, 59)) is True
    assert alerts.in_quiet_hours(_at(7, 0)) is False
    assert alerts.in_quiet_hours(_at(12)) is False


def test_quiet_hours_same_day_range(monkeypatch):
    monkeypatch.setenv("QUIET_HOURS", "01:00-05:00")
    assert alerts.in_quiet_hours(_at(2)) is True
    assert alerts.in_quiet_hours(_at(0, 30)) is False
    assert alerts.in_quiet_hours(_at(5)) is False


def test_quiet_hours_bad_value(monkeypatch):
    monkeypatch.setenv("QUIET_HOURS", "totally-broken")
    assert alerts.in_quiet_hours(_at(3)) is False


# ─── notify_quiet_hours_start (окно предупреждения) ──────────

def _wire_notify(monkeypatch, state):
    """Подменяет ввод/вывод alerts, копит отправленные сообщения в list."""
    sent = []
    monkeypatch.setattr(alerts, "load_json", lambda path: dict(state))
    monkeypatch.setattr(alerts, "save_json", lambda path, data: state.update(data))
    monkeypatch.setattr(alerts, "send_telegram", lambda *a, **k: sent.append(a[0] if a else ""))
    return sent


def test_notify_fires_once_in_window(monkeypatch):
    monkeypatch.setenv("QUIET_HOURS", "23:00-07:00")
    state = {}
    sent = _wire_notify(monkeypatch, state)

    alerts.notify_quiet_hours_start(_at(22, 47))   # за 13 мин — шлём
    assert len(sent) == 1
    assert "13 мин" in sent[0]

    alerts.notify_quiet_hours_start(_at(22, 52))   # тот же старт — не дублируем
    assert len(sent) == 1


def test_notify_outside_window(monkeypatch):
    monkeypatch.setenv("QUIET_HOURS", "23:00-07:00")
    sent = _wire_notify(monkeypatch, {})
    alerts.notify_quiet_hours_start(_at(22, 40))   # за 20 мин — рано
    alerts.notify_quiet_hours_start(_at(23, 0))    # уже начались
    assert sent == []


def test_notify_no_double_fire_across_midnight(monkeypatch):
    # тихие часы стартуют в 00:10 — окно 23:55..00:10 пересекает полночь
    monkeypatch.setenv("QUIET_HOURS", "00:10-08:00")
    state = {}
    sent = _wire_notify(monkeypatch, state)

    alerts.notify_quiet_hours_start(datetime(2026, 7, 24, 23, 59))
    alerts.notify_quiet_hours_start(datetime(2026, 7, 25, 0, 5))
    assert len(sent) == 1     # один и тот же старт — одно уведомление


def test_notify_disabled(monkeypatch):
    monkeypatch.delenv("QUIET_HOURS", raising=False)
    sent = _wire_notify(monkeypatch, {})
    alerts.notify_quiet_hours_start(_at(22, 50))
    assert sent == []


# ─── Тихий режим глушит ВСЁ (без исключений) ─────────────────

def test_send_or_defer_queues_everything_in_quiet_hours(monkeypatch):
    """В тихие часы ни один алерт не уходит сразу — всё в очередь."""
    monkeypatch.setenv("QUIET_HOURS", "23:00-07:00")
    monkeypatch.setattr(alerts, "in_quiet_hours", lambda *a, **k: True)

    sent, queue = [], {}
    monkeypatch.setattr(alerts, "send_telegram", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(alerts, "load_json", lambda path: dict(queue))
    monkeypatch.setattr(alerts, "save_json", lambda path, data: queue.update(data))

    alerts.send_or_defer("🚨 Сервер упал")
    alerts.send_or_defer("🚨 ПРОБЛЕМА С ФИЗИЧЕСКИМ ДИСКОМ")
    alerts.send_or_defer("🆘 БЭКАП УСТАРЕЛ")

    assert sent == []                      # ночью ничего не пробило
    assert len(queue.get("items", [])) == 3


def test_send_or_defer_sends_outside_quiet_hours(monkeypatch):
    monkeypatch.setattr(alerts, "in_quiet_hours", lambda *a, **k: False)
    sent = []
    monkeypatch.setattr(alerts, "send_telegram", lambda *a, **k: sent.append(a))
    alerts.send_or_defer("🚨 Сервер упал")
    assert len(sent) == 1


def test_no_quiet_hours_bypass_left_in_monitor():
    """Защита от регрессии: в monitor/ не должно быть critical-обхода тишины,
    а алерты не должны звать send_telegram напрямую."""
    monitor_dir = Path(alerts.__file__).parent
    for path in sorted(monitor_dir.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "critical=True" not in source, f"{path.name}: обход тишины вернулся"

    # send_telegram в alerts.py допустим только внутри send_or_defer,
    # flush_deferred и notify_quiet_hours_start (все — вне тихих часов)
    allowed = {"send_or_defer", "flush_deferred", "notify_quiet_hours_start"}
    for name, func in vars(alerts).items():
        if not callable(func) or not hasattr(func, "__code__"):
            continue
        if getattr(func, "__module__", None) != alerts.__name__:
            continue
        if name in allowed or name == "send_telegram":
            continue
        try:
            body = inspect.getsource(func)
        except OSError:
            continue
        assert "send_telegram(" not in body, f"{name}(): шлёт минуя тихие часы"


# ─── _docker_problem ─────────────────────────────────────────

def test_docker_problem_classification():
    assert alerts._docker_problem("Up 3 hours") == "ok"
    assert alerts._docker_problem("Up 2 minutes (healthy)") == "ok"
    assert alerts._docker_problem("Up (unhealthy)") == "unhealthy"
    assert alerts._docker_problem("Exited (1) 5 minutes ago") == "exited"
    assert alerts._docker_problem("Restarting (1) 2 seconds ago") == "restarting"
    assert alerts._docker_problem("Paused") == "paused"
    assert alerts._docker_problem("Created") == "created"
    assert alerts._docker_problem("") == "ok"


# ─── Повтор напоминаний (ALERT_REPEAT_HOURS) ─────────────────

def _now(hh=12, mm=0):
    return datetime(2026, 8, 29, hh, mm, tzinfo=alerts.ALMATY)


def test_new_problem_is_always_reported():
    assert alerts.alert_due({}, "srv:C", "crit", _now()) is True


def test_level_change_is_reported_immediately():
    state = {}
    alerts.mark_alert_sent(state, "srv:C", "warn", _now(12))
    assert alerts.alert_due(state, "srv:C", "crit", _now(12, 5)) is True


def test_same_level_is_repeated_after_the_interval(monkeypatch):
    """Раньше алерт приходил один раз и молчал, пока проблема висит."""
    monkeypatch.setattr(alerts, "ALERT_REPEAT_HOURS", 3)
    state = {}
    alerts.mark_alert_sent(state, "srv:C", "crit", _now(12))

    assert alerts.alert_due(state, "srv:C", "crit", _now(14, 59)) is False
    assert alerts.alert_due(state, "srv:C", "crit", _now(15, 0)) is True


def test_repeat_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(alerts, "ALERT_REPEAT_HOURS", 0)
    state = {}
    alerts.mark_alert_sent(state, "srv:C", "crit", _now(12))
    assert alerts.alert_due(state, "srv:C", "crit", _now(23, 0)) is False


def test_repeat_is_silent_during_quiet_hours(monkeypatch):
    """Иначе утренняя сводка состояла бы из одинаковых сообщений."""
    monkeypatch.setattr(alerts, "ALERT_REPEAT_HOURS", 3)
    monkeypatch.setenv("QUIET_HOURS", "23:00-07:00")
    state = {}
    alerts.mark_alert_sent(state, "srv:C", "crit", _now(20))

    assert alerts.alert_due(state, "srv:C", "crit", _now(23, 30)) is False

    morning = datetime(2026, 8, 30, 7, 5, tzinfo=alerts.ALMATY)
    assert alerts.alert_due(state, "srv:C", "crit", morning) is True


def test_old_state_format_is_read_and_not_re_alerted(monkeypatch):
    """В /app/data лежат записи прежнего формата — просто уровень, без
    времени. Обновление не должно поднимать тревогу задним числом."""
    monkeypatch.setattr(alerts, "ALERT_REPEAT_HOURS", 3)
    state = {"srv:C": "crit"}

    assert alerts.alert_level(state["srv:C"]) == "crit"
    assert alerts.alert_due(state, "srv:C", "crit", _now()) is False
    assert alerts.alert_due(state, "srv:C", "warn", _now()) is True


def test_mark_alert_sent_keeps_level_readable():
    state = {}
    alerts.mark_alert_sent(state, "srv:C", "crit", _now(12))
    assert alerts.alert_level(state["srv:C"]) == "crit"
    assert state["srv:C"]["sent"].startswith("2026-08-29T12:00")
