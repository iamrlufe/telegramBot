"""Тесты shared/backup_files.py: разбор путей и список каталогов для очистки."""
from backup_files import inside_backup_roots, disk_of_path, deletable_backup_targets, NO_DELETE_TYPES


def test_disk_of_path_windows_letter():
    assert disk_of_path("E:\\Backups\\SQL") == "E:"
    assert disk_of_path("f:\\sql") == "F:"


def test_disk_of_path_unc():
    assert disk_of_path(r"\\nas01\backups\sql") == r"\\nas01\backups"


def test_disk_of_path_weird_input():
    assert disk_of_path("") == ""
    assert disk_of_path(None) == ""
    assert disk_of_path("relative\\path") == "relative\\path"


def test_deletable_targets_excludes_veeam():
    server = {"backups": {
        "sql": ["E:\\Backups", "F:\\SQL\\Daily"],
        "veeam": ["G:\\Veeam"],
        "1c": "D:\\1C\\bk",
    }}
    targets = deletable_backup_targets(server)
    assert all(t["type"] != "veeam" for t in targets)
    assert "veeam" in NO_DELETE_TYPES
    # порядок стабилен, строка-путь превращается в один target
    paths = [t["path"] for t in targets]
    assert paths == ["E:\\Backups", "F:\\SQL\\Daily", "D:\\1C\\bk"]
    assert targets[0]["disk"] == "E:"
    assert targets[1]["disk"] == "F:"


def test_deletable_targets_no_backups():
    assert deletable_backup_targets({}) == []
    assert deletable_backup_targets({"backups": {}}) == []


def test_deletable_targets_skips_empty_paths():
    server = {"backups": {"sql": ["E:\\Backups", "", None]}}
    targets = deletable_backup_targets(server)
    assert [t["path"] for t in targets] == ["E:\\Backups"]


def test_disk_of_path_posix():
    """Linux/NAS: «диск» — это том Synology, а не весь путь целиком."""
    assert disk_of_path("/volume1/1ast/Buh") == "/volume1"
    assert disk_of_path("/volume4/1base1/branch_a") == "/volume4"
    assert disk_of_path("/volume1") == "/volume1"
    assert disk_of_path("/") == "/"


# ─── Проверка вхождения пути в backup-каталоги конфига ───────
# Раньше её выполняла только SSH-ветка, хотя справка и readme обещают
# ограничение для всех серверов. Без неё любой .bak на Windows-сервере
# мог быть удалён, если попадал в список на удаление.

WIN_SERVER = {
    "name": "SQL01",
    "host": "h",
    "backups": {
        "sql": ["E:\\Backups", {"path": "D:\\1C\\Backup"}],
        "veeam": ["F:\\Veeam"],
    },
}

LINUX_SERVER = {
    "name": "NAS",
    "host": "h",
    "type": "linux",
    "backups": {"sql": ["/volume1/backup/buh"]},
}


def test_inside_backup_roots_windows_allows_configured_path():
    assert inside_backup_roots(WIN_SERVER, "E:\\Backups\\db1\\full.bak")
    assert inside_backup_roots(WIN_SERVER, "D:\\1C\\Backup\\base.dt")


def test_inside_backup_roots_windows_is_case_and_separator_insensitive():
    assert inside_backup_roots(WIN_SERVER, "e:/backups/db1/full.bak")


def test_inside_backup_roots_windows_rejects_outside_path():
    assert not inside_backup_roots(WIN_SERVER, "C:\\Windows\\System32\\x.bak")
    # Похожий префикс — не то же самое, что вложенность
    assert not inside_backup_roots(WIN_SERVER, "E:\\BackupsOld\\full.bak")


def test_inside_backup_roots_windows_rejects_veeam_path():
    # veeam исключён из deletable_backup_targets, значит и из разрешённых корней
    assert not inside_backup_roots(WIN_SERVER, "F:\\Veeam\\job.bak")


def test_inside_backup_roots_linux():
    assert inside_backup_roots(LINUX_SERVER, "/volume1/backup/buh/a.bak")
    assert not inside_backup_roots(LINUX_SERVER, "/volume1/backup/buh2/a.bak")
    assert not inside_backup_roots(LINUX_SERVER, "/etc/passwd.bak")
