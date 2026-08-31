"""Обход каталогов бэкапов: пакетный опрос и параллельность по серверам.

Раньше цикл был полностью последовательным, и на каждый путь открывалась
своя сессия WinRM/SSH. На боевом контуре это полсотни рукопожатий подряд
каждые пять минут — дольше, чем сам обход каталогов.

Разделение на два шага (сбор по сети — параллельно, разбор с алертами —
в один поток) не косметика: состояние алертов лежит в общем JSON, который
читается и переписывается целиком, и параллельная запись теряла бы чужие
ключи.
"""
import threading

import pytest

import backup_collector as bc


WIN_SERVER = {
    "name": "sql-01.example.local", "host": "192.0.2.10", "type": "windows",
    "username": "monitor", "password": "secret",
    "backups": {"sql": ["D:\\Backups\\base1", "D:\\Backups\\base2",
                        {"path": "D:\\Backups\\diff", "alert_hours": 8}]},
}

NAS_SERVER = {
    "name": "nas-01.example.local", "host": "192.0.2.20", "type": "linux",
    "backups": {"sql": ["/volume1/db1", "/volume1/db2"]},
}


# ─── Разбор настроек путей ───────────────────────────────────

def test_targets_carry_their_own_settings():
    targets = bc._backup_targets(WIN_SERVER)

    assert [t["path"] for t in targets] == [
        "D:\\Backups\\base1", "D:\\Backups\\base2", "D:\\Backups\\diff"]
    assert targets[0]["alert_hours"] == bc.BACKUP_ALERT_HOURS
    assert targets[2]["alert_hours"] == 8, "своё время пути важнее серверного"


def test_diff_paths_never_check_size():
    """DIFF растёт неравномерно всю неделю — сравнение с историей даёт
    ложные срабатывания независимо от настройки."""
    server = dict(WIN_SERVER, backup_size_check=True)
    targets = {t["path"]: t for t in bc._backup_targets(server)}

    assert targets["D:\\Backups\\base1"]["size_check"] is True
    assert targets["D:\\Backups\\diff"]["size_check"] is False


def test_path_without_path_key_does_not_break_the_cycle():
    server = dict(WIN_SERVER, backups={"sql": [{"alert_hours": 5}]})
    targets = bc._backup_targets(server)
    assert targets[0]["path"] is None


def test_devices_and_datastores_have_nothing_to_scan():
    assert not bc._has_backup_work({"type": "device", "backups": {"sql": ["x"]}})
    assert not bc._has_backup_work({"type": "vmware", "dbsize": True})
    assert not bc._has_backup_work({"type": "windows"})
    assert bc._has_backup_work(WIN_SERVER)


# ─── Один вызов вместо сессии на каталог ─────────────────────

def test_windows_paths_are_scanned_in_one_call(monkeypatch):
    calls = []

    def fake_paths(host, targets, username=None, password=None):
        calls.append(list(targets))
        return {t: dict(FAKE_METRICS) for t in targets}

    monkeypatch.setattr(bc, "collect_backup_paths", fake_paths)
    collected = bc.collect_server_backups(WIN_SERVER)

    assert len(calls) == 1, "три каталога — один вызов, а не три сессии"
    assert len(calls[0]) == 3
    assert len(collected["metrics"]) == 3


def test_linux_paths_are_scanned_in_one_session(monkeypatch):
    calls = []
    monkeypatch.setattr(bc, "collect_backup_paths_ssh",
                        lambda server, targets: calls.append(list(targets)) or
                        {t: dict(FAKE_METRICS) for t in targets})

    bc.collect_server_backups(NAS_SERVER)
    assert len(calls) == 1


def test_unreachable_server_marks_every_path(monkeypatch):
    """Сервер не ответил вовсе — ошибку должен получить каждый его каталог,
    иначе путь молча остался бы без записи и без алерта."""
    def boom(host, targets, username=None, password=None):
        raise Exception("WinRM: таймаут")

    monkeypatch.setattr(bc, "collect_backup_paths", boom)
    collected = bc.collect_server_backups(WIN_SERVER)

    assert len(collected["metrics"]) == 3
    assert all(isinstance(v, Exception) for v in collected["metrics"].values())


# ─── Параллельность и разбор ─────────────────────────────────

FAKE_METRICS = {
    "file_count": 3, "total_size_gb": 12.0, "oldest_file": None,
    "newest_file": None, "newest_file_gb": 4.0, "log_count": 0,
    "log_newest": None, "full_count": 3, "full_newest": None,
    "full_newest_gb": 4.0, "disk_total_gb": 100.0, "disk_free_gb": 40.0,
}


@pytest.fixture
def cycle(monkeypatch):
    """Ни сети, ни БД, ни алертов — только порядок шагов цикла."""
    box = {"saved": [], "alerts": [], "progress": 0}
    monkeypatch.setattr(bc, "_prune_legacy_disk_keys", lambda: None)
    monkeypatch.setattr(bc, "save_backup_metric",
                        lambda name, t, p, m, **kw: box["saved"].append((name, p, kw.get("status", "ok"))))
    monkeypatch.setattr(bc, "_check_backup_alerts",
                        lambda *a, **kw: box["alerts"].append(a[:3]))
    monkeypatch.setattr(bc, "_check_weekly_schedule_alert", lambda *a, **kw: None)
    monkeypatch.setattr(bc, "collect_backup_paths",
                        lambda host, targets, username=None, password=None:
                        {t: dict(FAKE_METRICS) for t in targets})
    monkeypatch.setattr(bc, "collect_backup_paths_ssh",
                        lambda server, targets: {t: dict(FAKE_METRICS) for t in targets})
    return box


def test_servers_are_scanned_in_parallel(cycle, monkeypatch):
    """Барьер разойдётся, только если сбор идёт одновременно."""
    servers = [dict(WIN_SERVER, name=f"srv-{i}") for i in range(3)]
    monkeypatch.setattr(bc, "load_servers", lambda: servers)
    barrier = threading.Barrier(len(servers), timeout=5)

    def slow(host, targets, username=None, password=None):
        barrier.wait()
        return {t: dict(FAKE_METRICS) for t in targets}

    monkeypatch.setattr(bc, "collect_backup_paths", slow)
    bc.run_backup_cycle()

    assert len(cycle["saved"]) == 3 * 3


def test_every_server_is_applied_and_reported(cycle, monkeypatch):
    monkeypatch.setattr(bc, "load_servers", lambda: [WIN_SERVER, NAS_SERVER])
    progress = []

    bc.run_backup_cycle(on_progress=lambda: progress.append(1))

    names = {name for name, _path, _status in cycle["saved"]}
    assert names == {WIN_SERVER["name"], NAS_SERVER["name"]}
    assert len(progress) == 2, "пульс обновляется после каждого сервера"


def test_broken_server_does_not_stop_the_others(cycle, monkeypatch):
    monkeypatch.setattr(bc, "load_servers", lambda: [WIN_SERVER, NAS_SERVER])

    def boom(server, targets):
        raise Exception("SSH: сеть недоступна")

    monkeypatch.setattr(bc, "collect_backup_paths_ssh", boom)
    bc.run_backup_cycle()

    statuses = {name: status for name, _path, status in cycle["saved"]}
    assert statuses[WIN_SERVER["name"]] == "ok"
    assert statuses[NAS_SERVER["name"]] == "error"


def test_failed_path_is_saved_as_error(cycle, monkeypatch):
    monkeypatch.setattr(bc, "load_servers", lambda: [WIN_SERVER])

    def partial(host, targets, username=None, password=None):
        result = {t: dict(FAKE_METRICS) for t in targets}
        result[targets[0]] = RuntimeError("Path not found")
        return result

    monkeypatch.setattr(bc, "collect_backup_paths", partial)
    bc.run_backup_cycle()

    statuses = [status for _name, _path, status in cycle["saved"]]
    assert statuses.count("error") == 1 and statuses.count("ok") == 2
    assert len(cycle["alerts"]) == 2, "по сломанному пути алерт не считается"


def test_weekly_schedule_is_checked_even_when_server_is_down(cycle, monkeypatch):
    """Пропуск недельной копии виден по истории в БД — от успеха опроса
    он не зависит, иначе упавший сервер молчал бы и об этом."""
    server = dict(WIN_SERVER, backups={"sql": [
        {"path": "D:\\Backups\\weekly",
         "schedule_weekday": "sun", "schedule_by_hour": 23}]})
    monkeypatch.setattr(bc, "load_servers", lambda: [server])
    monkeypatch.setattr(bc, "collect_backup_paths",
                        lambda *a, **kw: (_ for _ in ()).throw(Exception("нет связи")))
    checked = []
    monkeypatch.setattr(bc, "_check_weekly_schedule_alert",
                        lambda *a, **kw: checked.append(a[2]))

    bc.run_backup_cycle()
    assert checked == ["D:\\Backups\\weekly"]


# ─── Пакетный ответ сервера ──────────────────────────────────

def _ps_row(index, **over):
    row = {
        "Index": index, "FileCount": 2, "TotalGB": 5.0,
        "OldestFile": "2026-08-20 01:00:00", "NewestFile": "2026-08-30 01:00:00",
        "NewestFileGB": 2.5, "LogCount": 0, "LogNewest": None,
        "FullCount": 2, "FullNewest": "2026-08-30 01:00:00", "FullNewestGB": 2.5,
        "DiskTotalGB": 100.0, "DiskFreeGB": 30.0,
    }
    row.update(over)
    return row


def test_batched_windows_answer_is_split_by_index(monkeypatch):
    import json
    targets = [("sql", "D:\\a"), ("sql", "D:\\b")]
    monkeypatch.setattr(bc, "run_ps",
                        lambda host, script, u=None, p=None:
                        json.dumps([_ps_row(0), _ps_row(1, FileCount=7)]))

    result = bc.collect_backup_paths("192.0.2.10", targets)
    assert result[targets[0]]["file_count"] == 2
    assert result[targets[1]]["file_count"] == 7


def test_single_path_answer_is_not_an_array(monkeypatch):
    """ConvertTo-Json разворачивает массив из одного элемента в объект —
    на этом ломался бы обход сервера с единственным каталогом."""
    import json
    monkeypatch.setattr(bc, "run_ps",
                        lambda host, script, u=None, p=None: json.dumps(_ps_row(0)))

    metrics = bc.collect_backup_path("192.0.2.10", "D:\\a", "sql")
    assert metrics["file_count"] == 2


def test_missing_path_does_not_spoil_the_batch(monkeypatch):
    import json
    targets = [("sql", "D:\\нет"), ("sql", "D:\\b")]
    monkeypatch.setattr(bc, "run_ps",
                        lambda host, script, u=None, p=None:
                        json.dumps([{"Index": 0, "Error": "Path not found"},
                                    _ps_row(1)]))

    result = bc.collect_backup_paths("192.0.2.10", targets)
    assert isinstance(result[targets[0]], Exception)
    assert result[targets[1]]["file_count"] == 2


def test_long_path_list_is_split_into_fitting_scripts(monkeypatch):
    """Командная строка WinRM ограничена 8000 символами после кодирования:
    пакет режется заранее, а не падает уже на сервере."""
    import json
    from winrm_client import ps_fits

    targets = [("sql", f"D:\\Backups\\очень_длинное_имя_базы_{i:03d}")
               for i in range(60)]
    scripts = []

    def fake_run_ps(host, script, u=None, p=None):
        scripts.append(script)
        assert ps_fits(script), "скрипт не влезает в командную строку WinRM"
        # Индексы внутри своей пачки — как их и нумерует сборщик
        count = script.count('"Path"')
        return json.dumps([_ps_row(i) for i in range(count)])

    monkeypatch.setattr(bc, "run_ps", fake_run_ps)
    result = bc.collect_backup_paths("192.0.2.10", targets)

    assert len(scripts) > 1, "такой список обязан разбиться на части"
    assert len(result) == len(targets)
    assert all(not isinstance(v, Exception) for v in result.values())


def test_batched_ssh_answer_is_split_by_marker(monkeypatch):
    targets = [("sql", "/volume1/db1"), ("sql", "/volume1/db2")]
    reply = (
        f'{bc.SSH_BATCH_MARKER} 0\n'
        '{"FileCount":2,"TotalBytes":1073741824,"Oldest":1753000000,'
        '"Newest":1754000000,"NewestBytes":1073741824,"DiskTotalKB":1,"DiskFreeKB":1}\n'
        f'{bc.SSH_BATCH_MARKER} 1\n'
        '{"Error":"Path not found"}\n'
    )
    monkeypatch.setattr(bc, "run_ssh",
                        lambda host, script, u=None, p=None, **kw: reply)

    result = bc.collect_backup_paths_ssh(NAS_SERVER, targets)
    assert result[targets[0]]["file_count"] == 2
    assert isinstance(result[targets[1]], Exception)


def test_ssh_batch_asks_for_every_path(monkeypatch):
    box = {}
    monkeypatch.setattr(bc, "run_ssh",
                        lambda host, script, u=None, p=None, **kw:
                        box.update(script=script) or "")

    bc.collect_backup_paths_ssh(NAS_SERVER, [("sql", "/volume1/db1"),
                                             ("veeam", "/volume1/veeam")])
    script = box["script"]
    assert "'/volume1/db1'" in script and "'/volume1/veeam'" in script
    assert script.count(bc.SSH_BATCH_MARKER) == 2
    # у veeam расширения не фильтруются, у sql — да
    assert "-iname '*.bak'" in script
