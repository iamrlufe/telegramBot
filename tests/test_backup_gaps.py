"""Пути, настроенные в конфиге, но без данных сбора.

Раньше такой путь просто отсутствовал в дайджесте и на тепловой карте —
вместе с ним пропадал и весь сервер, если других путей у него не было.
То есть «сбор не работает» выглядело как «бэкапы не настроены»: самая
опасная ситуация была невидима.
"""
import backup_bot_db
from backup_bot_db import BACKUP_STATUS_MISSING, classify_backup_row

CONFIG = {
    "srv1": [
        {"backup_type": "sql", "backup_path": "E:\\Backups\\a"},
        {"backup_type": "sql", "backup_path": "E:\\Backups\\b"},
    ],
    "srv2": [
        {"backup_type": "sql", "backup_path": "G:\\Backups"},
    ],
}


def _row(server, path, **extra):
    row = {
        "server_name": server, "backup_type": "sql", "backup_path": path,
        "file_count": 5, "oldest_file": None, "newest_file": None,
        "total_size_gb": 10.0, "disk_total_gb": 100.0, "disk_free_gb": 50.0,
        "status": "ok", "error": None, "created_at": None,
    }
    row.update(extra)
    return row


def _wire(monkeypatch, db_rows):
    """Подменяет БД и конфиг, оставляя фильтрацию и добивку настоящими."""
    monkeypatch.setattr(backup_bot_db, "get_config_backup_targets",
                        lambda *a, **kw: CONFIG)

    class _Cur:
        description = [(k,) for k in db_rows[0]] if db_rows else [
            ("server_name",), ("backup_type",), ("backup_path",),
            ("file_count",), ("oldest_file",), ("newest_file",),
            ("total_size_gb",), ("disk_total_gb",), ("disk_free_gb",),
            ("status",), ("error",), ("created_at",),
        ]

        def execute(self, *a, **kw):
            pass

        def fetchall(self):
            return [tuple(r.values()) for r in db_rows]

    class _Conn:
        def cursor(self):
            return _Cur()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(backup_bot_db, "get_conn", lambda: _Conn())


# ─── Поведение по умолчанию не изменилось ────────────────────

def test_default_call_returns_only_collected(monkeypatch):
    """Старые вызывающие не должны увидеть синтетических строк."""
    _wire(monkeypatch, [_row("srv1", "E:\\Backups\\a")])
    rows = backup_bot_db.get_latest_backup_metrics()
    assert [r["backup_path"] for r in rows] == ["E:\\Backups\\a"]


def test_paths_removed_from_config_are_still_hidden(monkeypatch):
    """Фильтр по конфигу продолжает прятать удалённые пути."""
    _wire(monkeypatch, [
        _row("srv1", "E:\\Backups\\a"),
        _row("srv1", "E:\\Backups\\СТАРЫЙ"),
    ])
    rows = backup_bot_db.get_latest_backup_metrics(include_missing=True)
    assert "E:\\Backups\\СТАРЫЙ" not in [r["backup_path"] for r in rows]


# ─── Добивка пропусков ───────────────────────────────────────

def test_missing_paths_are_added(monkeypatch):
    _wire(monkeypatch, [_row("srv1", "E:\\Backups\\a")])
    rows = backup_bot_db.get_latest_backup_metrics(include_missing=True)

    by_path = {r["backup_path"]: r for r in rows}
    assert set(by_path) == {"E:\\Backups\\a", "E:\\Backups\\b", "G:\\Backups"}
    assert by_path["E:\\Backups\\b"]["status"] == BACKUP_STATUS_MISSING
    assert by_path["G:\\Backups"]["status"] == BACKUP_STATUS_MISSING


def test_server_without_any_metrics_appears(monkeypatch):
    """Именно этот случай раньше приводил к исчезновению сервера целиком."""
    _wire(monkeypatch, [_row("srv1", "E:\\Backups\\a")])
    rows = backup_bot_db.get_latest_backup_metrics(include_missing=True)
    assert "srv2" in {r["server_name"] for r in rows}


def test_collected_paths_are_not_duplicated(monkeypatch):
    _wire(monkeypatch, [
        _row("srv1", "E:\\Backups\\a"),
        _row("srv1", "E:\\Backups\\b"),
        _row("srv2", "G:\\Backups"),
    ])
    rows = backup_bot_db.get_latest_backup_metrics(include_missing=True)
    assert len(rows) == 3
    assert all(r["status"] == "ok" for r in rows)


# ─── Классификация ───────────────────────────────────────────

def test_missing_is_critical():
    row = _row("srv1", "E:\\Backups\\b", status=BACKUP_STATUS_MISSING,
               file_count=None)
    assert classify_backup_row(row, None) == "crit"


def test_error_still_critical():
    assert classify_backup_row(_row("s", "p", status="error"), None) == "crit"


def test_empty_directory_still_critical():
    assert classify_backup_row(_row("s", "p", file_count=0), None) == "crit"
