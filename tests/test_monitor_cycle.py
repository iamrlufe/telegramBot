"""Цикл монитора: пинг, повторы опроса, пульс, частота обхода бэкапов.

Всё это раньше держалось на последовательном коде: пинг по одному хосту,
сон RETRY_DELAY внутри воркера пула, heartbeat только в конце цикла.
Тесты фиксируют новое поведение — оно не про новые данные, а про то,
чтобы монитор не тормозил сам себя.
"""
import pytest

import monitor


SERVERS = [
    {"name": "srv-01.example.local", "host": "192.0.2.11", "type": "windows"},
    {"name": "srv-02.example.local", "host": "192.0.2.12", "type": "windows"},
    {"name": "srv-03.example.local", "host": "192.0.2.13", "type": "windows"},
]


@pytest.fixture
def quiet(monkeypatch):
    """Ни БД, ни Telegram, ни файлов: остаётся только логика цикла."""
    calls = {"status": [], "online": [], "offline": [], "down": [],
             "heartbeat": 0, "sleep": []}
    monkeypatch.setattr(monitor, "save_server_status",
                        lambda *a, **kw: calls["status"].append(a))
    monkeypatch.setattr(monitor, "alert_server_online",
                        lambda s: calls["online"].append(s["name"]))
    monkeypatch.setattr(monitor, "alert_server_offline",
                        lambda s, e: calls["offline"].append(s["name"]))
    monkeypatch.setattr(monitor, "alert_server_down",
                        lambda s: calls["down"].append(s["name"]))
    monkeypatch.setattr(monitor, "load_servers", lambda: SERVERS)
    monkeypatch.setattr(monitor, "touch_heartbeat",
                        lambda: calls.__setitem__("heartbeat", calls["heartbeat"] + 1))
    monkeypatch.setattr(monitor.time, "sleep",
                        lambda sec: calls["sleep"].append(sec))
    monitor._ping_fail_counts.clear()
    return calls


# ─── Пинг ────────────────────────────────────────────────────

def test_all_hosts_are_pinged_in_one_cycle(quiet, monkeypatch):
    pinged = []
    monkeypatch.setattr(monitor, "ping_host",
                        lambda host: pinged.append(host) or True)

    monitor.run_ping_cycle()

    assert sorted(pinged) == sorted(s["host"] for s in SERVERS)


def test_ping_cycle_does_not_wait_hosts_one_by_one(quiet, monkeypatch):
    """Недоступный хост стоит несколько секунд. Пока пинг шёл по очереди,
    цикл из десятка серверов переставал укладываться в PING_INTERVAL, и
    порог PING_FAIL_THRESHOLD переставал означать обещанные минуты."""
    import threading
    started = threading.Barrier(len(SERVERS), timeout=5)

    def slow_ping(host):
        # Барьер разойдётся только если все пинги идут одновременно
        started.wait()
        return True

    monkeypatch.setattr(monitor, "ping_host", slow_ping)
    monitor.run_ping_cycle()  # threading.BrokenBarrierError, если последовательно


def test_down_alert_after_threshold(quiet, monkeypatch):
    monkeypatch.setattr(monitor, "ping_host", lambda host: False)

    for _ in range(monitor.PING_FAIL_THRESHOLD):
        monitor.run_ping_cycle()

    assert quiet["down"] == [s["name"] for s in SERVERS]

    # дальше молчим, а не шлём алерт каждые полминуты
    monitor.run_ping_cycle()
    assert len(quiet["down"]) == len(SERVERS)


def test_recovery_alert_after_down(quiet, monkeypatch):
    monkeypatch.setattr(monitor, "ping_host", lambda host: False)
    for _ in range(monitor.PING_FAIL_THRESHOLD):
        monitor.run_ping_cycle()

    monkeypatch.setattr(monitor, "ping_host", lambda host: True)
    monitor.run_ping_cycle()

    assert quiet["online"] == [s["name"] for s in SERVERS]


def test_empty_server_list_is_not_an_error(quiet, monkeypatch):
    monkeypatch.setattr(monitor, "load_servers", lambda: [])
    monitor.run_ping_cycle()


# ─── Повтор опроса ───────────────────────────────────────────

@pytest.fixture
def checks(monkeypatch, quiet):
    """process_server подменяется целиком: интересен порядок проходов."""
    events = []

    def fake_process(server, final=True):
        events.append(server["name"])
        if server["name"] == "srv-02.example.local" and not final:
            return "retry"
        return "online"

    monkeypatch.setattr(monitor, "process_server", fake_process)
    monkeypatch.setattr(monitor.time, "sleep",
                        lambda sec: events.append(f"sleep:{sec}"))
    return events


def test_retry_happens_after_everyone_else(checks):
    """Раньше повтор спал внутри воркера и держал слот пула: один сервер
    с живым ping и сломанным WinRM тормозил очередь остальных."""
    outcomes = monitor.run_server_checks(SERVERS)

    first_pass = checks[:len(SERVERS)]
    assert sorted(first_pass) == sorted(s["name"] for s in SERVERS), \
        "первый проход должен охватить все серверы до всякого ожидания"
    assert checks[len(SERVERS)] == f"sleep:{monitor.RETRY_DELAY}"
    assert checks[-1] == "srv-02.example.local"
    assert outcomes["srv-02.example.local"] == "online"


def test_no_waiting_when_everything_answers(checks, monkeypatch):
    monkeypatch.setattr(monitor, "process_server",
                        lambda server, final=True: "online")
    monitor.run_server_checks(SERVERS)
    assert not [e for e in checks if str(e).startswith("sleep")]


def test_heartbeat_touched_for_every_server(quiet, monkeypatch):
    """Долгий, но живой цикл не должен выглядеть зависшим для healthcheck."""
    monkeypatch.setattr(monitor, "process_server",
                        lambda server, final=True: "online")
    monitor.run_server_checks(SERVERS)
    assert quiet["heartbeat"] == len(SERVERS)


def test_failed_server_reports_offline_on_last_attempt(quiet, monkeypatch):
    def always_broken(server):
        raise Exception("WinRM: таймаут")

    monkeypatch.setattr(monitor, "ping_host", lambda host: True)
    monkeypatch.setattr(monitor, "check_server", always_broken)
    monkeypatch.setattr(monitor, "server_type", lambda s: "windows")

    outcomes = monitor.run_server_checks([SERVERS[0]])

    assert outcomes[SERVERS[0]["name"]] == "offline"
    assert quiet["offline"] == [SERVERS[0]["name"]]
    # алерт ровно один: промежуточная неудача молчит
    assert len(quiet["offline"]) == 1


def test_intermediate_failure_stays_silent(quiet, monkeypatch):
    monkeypatch.setattr(monitor, "ping_host", lambda host: True)
    monkeypatch.setattr(monitor, "server_type", lambda s: "windows")
    monkeypatch.setattr(monitor, "check_server",
                        lambda s: (_ for _ in ()).throw(Exception("таймаут")))

    assert monitor.process_server(SERVERS[0], final=False) == "retry"
    assert quiet["offline"] == []
    assert quiet["status"] == [], "статус пишется только после последней попытки"


# ─── Частота обхода бэкапов ──────────────────────────────────

def test_backup_scan_runs_on_first_cycle():
    assert monitor.backup_scan_due(now=1000.0, last=None)


def test_backup_scan_waits_its_interval(monkeypatch):
    monkeypatch.setattr(monitor, "BACKUP_SCAN_MINUTES", 30)
    assert not monitor.backup_scan_due(now=1000.0, last=1000.0)
    assert not monitor.backup_scan_due(now=1000.0 + 29 * 60, last=1000.0)
    assert monitor.backup_scan_due(now=1000.0 + 30 * 60, last=1000.0)


def test_zero_means_every_cycle(monkeypatch):
    """Прежнее поведение остаётся доступным одной строкой в .env."""
    monkeypatch.setattr(monitor, "BACKUP_SCAN_MINUTES", 0)
    assert monitor.backup_scan_due(now=1000.0, last=999.0)


def test_backup_cycle_is_skipped_between_scans(monkeypatch):
    runs = []
    monkeypatch.setattr(monitor, "BACKUP_SCAN_MINUTES", 30)
    monkeypatch.setattr(monitor, "run_backup_cycle",
                        lambda on_progress=None: runs.append(1))
    monkeypatch.setattr(monitor, "_last_backup_scan", None)

    assert monitor.maybe_run_backup_cycle() is True
    assert monitor.maybe_run_backup_cycle() is False
    assert len(runs) == 1
