"""Автозапуск копирования: когда бот жмёт на курок, а когда ждёт.

Главный риск автоматики — увезти файл, который сервер ещё дописывает:
в msdb запись о копии появляется, как только закончилась ПЕРВАЯ база,
а следом сервер может писать вторую и третью.
"""
from datetime import datetime, timedelta

import backup_transfer as bt


SERVER = {"name": "sql-region", "host": "h",
          "copy_script": {"D": "C:\\full.cmd", "I": "C:\\diff.cmd"}}


def _finished(minutes_ago: int) -> str:
    return (bt._now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")


def _wire(monkeypatch, running, rows, launched):
    monkeypatch.setattr(bt, "read_running_backups", lambda server: running)
    monkeypatch.setattr(bt, "read_backup_history",
                        lambda server, days=1, limit=20: rows)

    def _launch(server, settings, ready=None, by="монитор"):
        launched.append(ready)
        return {"pid": 1, "started": "2026-09-05 04:00:00",
                "source_finished": bt._marker(ready["finished"]),
                "type": ready["type"]}

    monkeypatch.setattr(bt, "launch_copy", _launch)


def test_waits_while_a_backup_is_still_running(monkeypatch):
    """Копия второй базы ещё пишется — каталог трогать нельзя."""
    launched = []
    _wire(monkeypatch,
          running=[{"db": "base2", "pct": 43.0, "seconds": 120}],
          rows=[{"db": "base1", "btype": "I", "finished": _finished(30)}],
          launched=launched)

    changed = bt.process_server_copy(dict(SERVER), {})

    assert launched == []
    assert changed is False


def test_starts_when_the_server_is_quiet(monkeypatch):
    launched = []
    _wire(monkeypatch, running=[],
          rows=[{"db": "base1", "btype": "I", "finished": _finished(30)}],
          launched=launched)

    state = {}
    changed = bt.process_server_copy(dict(SERVER), state)

    assert [r["type"] for r in launched] == ["I"]
    assert changed is True


def test_unreadable_running_check_does_not_block(monkeypatch):
    """Не смогли спросить — не повод стоять: от полуготового файла
    защищает пауза перед запуском."""
    launched = []
    _wire(monkeypatch, running=[],
          rows=[{"db": "base1", "btype": "D", "finished": _finished(30)}],
          launched=launched)

    def _boom(server):
        raise RuntimeError("нет доступа к sys.dm_exec_requests")

    monkeypatch.setattr(bt, "read_running_backups", _boom)

    bt.process_server_copy(dict(SERVER), {})

    assert [r["type"] for r in launched] == ["D"]


def test_other_jobs_do_not_trigger_anything(monkeypatch):
    """Сигнал берётся из msdb.backupset, а не из джоб SQL Agent: сколько
    бы заданий ни стояло на сервере, реиндекс и checkdb записи о копии не
    создают — и копирование от них не запускается."""
    launched = []
    _wire(monkeypatch, running=[], rows=[], launched=launched)

    changed = bt.process_server_copy(dict(SERVER), {})

    assert launched == []
    assert changed is False


def test_journal_backup_does_not_trigger_full_script(monkeypatch):
    """Журналы делают каждые 15–60 минут. Скрипта для них не задано —
    значит и рейса быть не должно."""
    launched = []
    _wire(monkeypatch, running=[],
          rows=[{"db": "base1", "btype": "L", "finished": _finished(30)}],
          launched=launched)

    bt.process_server_copy(dict(SERVER), {})

    assert launched == []
