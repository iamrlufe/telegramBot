"""Листинг и удаление backup-файлов на Linux/NAS по SSH.

Цена ошибки здесь высокая — команда собирается в shell и удаляет чужие
бэкапы. Поэтому проверяются не только успешные сценарии, но и все защиты:
расширение, вхождение в backup-каталоги конфига, экранирование путей.
"""
import backup_files
from backup_files import (
    DELETABLE_EXTENSIONS,
    delete_backup_files,
    list_backup_files,
)

NAS = {
    "name": "nas",
    "host": "10.0.0.5",
    "type": "linux",
    "backups": {"sql": ["/volume1/backups/db1", "/volume1/backups/db2"],
                "veeam": ["/volume1/veeam"]},
}

WIN = {"name": "srv", "host": "10.0.0.6", "backups": {"sql": ["E:\\Backups"]}}


class _SSH:
    """Ловит скрипт и отдаёт заранее заданный ответ."""

    def __init__(self, reply=""):
        self.reply = reply
        self.script = None

    def __call__(self, host, script, *a, **kw):
        self.script = script
        return self.reply


# ─── Листинг ─────────────────────────────────────────────────

def test_list_parses_stat_output(monkeypatch):
    ssh = _SSH("1785500000 3221225472 /volume1/backups/db1/full.bak\n"
               "1785400000 1073741824 /volume1/backups/db1/log.trn\n")
    monkeypatch.setattr(backup_files, "run_ssh", ssh, raising=False)
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    files = list_backup_files(NAS, "/volume1/backups/db1")
    assert [f["file_name"] for f in files] == ["full.bak", "log.trn"]
    assert files[0]["size_gb"] == 3.0
    assert files[0]["full_path"] == "/volume1/backups/db1/full.bak"
    assert files[0]["modified"][:4] == "2026"


def test_list_excludes_synology_service_dirs(monkeypatch):
    """#recycle — корзина шары: удалённые копии не должны попасть
    в предпросмотр очистки как живые файлы."""
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))
    list_backup_files(NAS, "/volume1/backups/db1")

    assert "#recycle" in ssh.script
    assert "@eaDir" in ssh.script
    assert "-prune" in ssh.script


def test_list_quotes_path_with_spaces(monkeypatch):
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))
    list_backup_files(NAS, "/volume1/my backups/db 1")
    assert "'/volume1/my backups/db 1'" in ssh.script


def test_list_filters_by_age(monkeypatch):
    """older_than отсекает свежие файлы — их удалять не собираются."""
    ssh = _SSH("1785500000 1073741824 /volume1/backups/db1/new.bak\n"
               "1000000000 1073741824 /volume1/backups/db1/old.bak\n")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    files = list_backup_files(NAS, "/volume1/backups/db1",
                              older_than="2020-01-01 00:00:00")
    assert [f["file_name"] for f in files] == ["old.bak"]


def test_list_survives_broken_lines(monkeypatch):
    ssh = _SSH("мусор\n\n1785500000 1073741824 /volume1/backups/db1/ok.bak\n")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))
    files = list_backup_files(NAS, "/volume1/backups/db1")
    assert [f["file_name"] for f in files] == ["ok.bak"]


# ─── Удаление: защиты ────────────────────────────────────────

def test_delete_rejects_foreign_extension(monkeypatch):
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    results = delete_backup_files(NAS, ["/volume1/backups/db1/notes.txt"])
    assert results == [("/volume1/backups/db1/notes.txt", False,
                        "Запрещённое расширение")]
    assert ssh.script is None, "до сервера дело дойти не должно"


def test_delete_rejects_path_outside_config(monkeypatch):
    """Главная защита: удалять только внутри backup-каталогов конфига."""
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    results = delete_backup_files(NAS, ["/etc/important.bak",
                                        "/volume1/backups/other/x.bak"])
    assert all(not ok for _p, ok, _e in results)
    assert all("вне backup-каталогов" in err for _p, _ok, err in results)
    assert ssh.script is None


def test_delete_does_not_touch_veeam(monkeypatch):
    """Veeam в NO_DELETE_TYPES — его пути не считаются разрешёнными."""
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    results = delete_backup_files(NAS, ["/volume1/veeam/backup.bak"])
    assert results[0][1] is False
    assert "вне backup-каталогов" in results[0][2]


def test_delete_allows_configured_path(monkeypatch):
    ssh = _SSH("OK\t/volume1/backups/db1/old.bak\n")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    results = delete_backup_files(NAS, ["/volume1/backups/db1/old.bak"])
    assert results == [("/volume1/backups/db1/old.bak", True, "")]
    assert "'/volume1/backups/db1/old.bak'" in ssh.script


def test_delete_reports_failure(monkeypatch):
    ssh = _SSH("ERR\t/volume1/backups/db1/x.bak\tPermission denied\n")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    results = delete_backup_files(NAS, ["/volume1/backups/db1/x.bak"])
    assert results[0][1] is False
    assert "Permission denied" in results[0][2]


def test_delete_marks_silent_files_as_failed(monkeypatch):
    """Сервер не отчитался по файлу — считаем неудачей, а не успехом."""
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    results = delete_backup_files(NAS, ["/volume1/backups/db1/x.bak"])
    assert results[0][1] is False
    assert results[0][2] == "Нет ответа"


def test_delete_quotes_paths(monkeypatch):
    """Апостроф в имени не должен разорвать команду."""
    ssh = _SSH("")
    monkeypatch.setitem(__import__("sys").modules, "linux_check",
                        type("M", (), {"run_ssh": ssh}))

    delete_backup_files(NAS, ["/volume1/backups/db1/it's old.bak"])
    assert "'/volume1/backups/db1/it'\\''s old.bak'" in ssh.script


def test_extensions_whitelist_unchanged():
    assert DELETABLE_EXTENSIONS == {".bak", ".trn", ".dt", ".zip"}


# ─── Windows-ветка не задета ─────────────────────────────────

def test_windows_still_uses_powershell(monkeypatch):
    calls = {}

    def fake_run_ps(host, script, username=None, password=None, **kw):
        calls["host"] = host
        return "[]"

    monkeypatch.setattr(backup_files, "run_ps", fake_run_ps)
    files = list_backup_files(WIN, "E:\\Backups")
    assert files == []
    assert calls["host"] == "10.0.0.6"
