"""Тесты monitor/backup_maintenance.retention_for_server (безопасные ветки)."""
from backup_maintenance import (
    retention_for_server,
    _newest_per_directory,
    MIN_RETENTION_DAYS,
)


def test_no_retention_configured():
    assert retention_for_server({"name": "a", "host": "h"}) is None


def test_retention_below_minimum():
    server = {"name": "a", "host": "h", "retention_days": MIN_RETENTION_DAYS - 1}
    assert retention_for_server(server) is None


def test_retention_non_numeric():
    server = {"name": "a", "host": "h", "retention_days": "часто"}
    assert retention_for_server(server) is None


def test_retention_no_backups_returns_empty_summary():
    # retention_days валиден, но backups нет — WinRM не вызывается,
    # возвращается пустая сводка
    server = {"name": "a", "host": "h", "retention_days": MIN_RETENTION_DAYS + 5}
    summary = retention_for_server(server)
    assert summary == {"deleted": 0, "freed_gb": 0.0, "failed": 0, "errors": []}


# ─── «Последний экземпляр остаётся» — в каждом подкаталоге ───
# Листинг рекурсивный. При типовой раскладке «каталог на базу» защита,
# сохранявшая один-единственный новейший файл на весь путь, оставляла копию
# только одной базы — у остальных последний экземпляр удалялся.

def _f(path, modified):
    return {"full_path": path, "modified": modified, "size_gb": 1.0}


def test_newest_per_directory_keeps_one_file_in_each_subdir():
    files = [
        _f("E:\\B\\db1\\old.bak", "2026-01-01 00:00:00"),
        _f("E:\\B\\db1\\new.bak", "2026-02-01 00:00:00"),
        _f("E:\\B\\db2\\only.bak", "2025-01-01 00:00:00"),
    ]
    keep = _newest_per_directory(files)
    assert keep == {"E:\\B\\db1\\new.bak", "E:\\B\\db2\\only.bak"}


def test_newest_per_directory_handles_posix_paths():
    files = [
        _f("/volume1/backup/buh/a.bak", "2026-01-01 00:00:00"),
        _f("/volume1/backup/buh/b.bak", "2026-03-01 00:00:00"),
        _f("/volume1/backup/base1/c.bak", "2024-01-01 00:00:00"),
    ]
    assert _newest_per_directory(files) == {
        "/volume1/backup/buh/b.bak",
        "/volume1/backup/base1/c.bak",
    }


def test_newest_per_directory_flat_directory():
    files = [
        _f("E:\\B\\a.bak", "2026-01-01 00:00:00"),
        _f("E:\\B\\b.bak", "2026-01-02 00:00:00"),
    ]
    assert _newest_per_directory(files) == {"E:\\B\\b.bak"}
