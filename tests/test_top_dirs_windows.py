"""Тесты Windows-ветки разбора занятого места (shared/remote_ops.py).

На Windows размеры считает robocopy /L, а не du. Отдельные грабли:
имена папок с '$' (C:\\$Recycle.Bin) и проваливание в файл вместо каталога.
"""
import base64
import json

import pytest

import remote_ops

SERVER = {"host": "srv-01", "username": "svc", "password": "x"}


def _fake_ps(monkeypatch, payload: dict):
    """Подменяет run_ps; возвращает список отправленных скриптов."""
    scripts = []

    def run_ps(host, script, **kwargs):
        scripts.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(remote_ops, "run_ps", run_ps)
    monkeypatch.setattr(remote_ops, "server_type", lambda s: "windows")
    return scripts


GB = 1024 ** 3


def test_bare_letter_becomes_root(monkeypatch):
    scripts = _fake_ps(monkeypatch, {"Items": [], "DirCount": 1, "FileCount": 0})
    remote_ops.get_top_dirs(SERVER, "E")
    assert r"$root = 'E:\'" in scripts[0]


def test_dollar_in_path_is_not_expanded(monkeypatch):
    r"""C:\$Recycle.Bin в двойных кавычках PowerShell схлопывался в C:\.Bin —
    путь должен уезжать на сервер литералом, в одинарных кавычках."""
    scripts = _fake_ps(monkeypatch, {"Items": [], "DirCount": 1, "FileCount": 0})
    remote_ops.get_top_dirs(SERVER, r"C:\$Recycle.Bin")
    assert r"$root = 'C:\$Recycle.Bin'" in scripts[0]
    assert '"C:\\$Recycle.Bin"' not in scripts[0]


def test_quote_in_path_is_escaped(monkeypatch):
    """Одинарная кавычка в имени папки не должна рвать скрипт."""
    scripts = _fake_ps(monkeypatch, {"Items": [], "DirCount": 1, "FileCount": 0})
    remote_ops.get_top_dirs(SERVER, r"D:\Ivan's Backup")
    assert r"$root = 'D:\Ivan''s Backup'" in scripts[0]


def test_subdir_path_used_as_is(monkeypatch):
    """Спуск: путь с бэкслешами уходит целиком, а не превращается в 'X:\\'."""
    scripts = _fake_ps(monkeypatch, {"Items": [], "DirCount": 1, "FileCount": 0})
    remote_ops.get_top_dirs(SERVER, r"E:\Backups\2026")
    assert r"$root = 'E:\Backups\2026'" in scripts[0]


def test_parses_items(monkeypatch):
    _fake_ps(monkeypatch, {
        "Items": [
            {"Path": r"E:\Backups\Full", "Bytes": 500 * GB},
            {"Path": r"E:\Backups\vm.vhdx", "Bytes": 120 * GB},
        ],
        "DirCount": 1, "FileCount": 1,
    })
    assert remote_ops.get_top_dirs(SERVER, r"E:\Backups") == [
        (r"E:\Backups\Full", 500.0),
        (r"E:\Backups\vm.vhdx", 120.0),
    ]


def test_dig_into_file_returns_empty(monkeypatch):
    """Get-ChildItem по файлу отдаёт сам файл — это не «содержимое»."""
    _fake_ps(monkeypatch, {
        "Items": [{"Path": r"E:\Backups\vm.vhdx", "Bytes": 120 * GB}],
        "DirCount": 0, "FileCount": 1,
    })
    assert remote_ops.get_top_dirs(SERVER, r"E:\Backups\vm.vhdx") == []


def test_trailing_slash_still_matches_root(monkeypatch):
    """Сравнение с корнем не должно спотыкаться на хвостовом слеше и регистре."""
    _fake_ps(monkeypatch, {
        "Items": [{"Path": r"E:\BACKUPS", "Bytes": 10 * GB}],
        "DirCount": 0, "FileCount": 1,
    })
    assert remote_ops.get_top_dirs(SERVER, "E:\\Backups\\") == []


def test_empty_listing_reports_permissions(monkeypatch):
    """Ноль объектов — это диагноз про права, а не пустой ответ."""
    _fake_ps(monkeypatch, {"Items": [], "DirCount": 0, "FileCount": 0})
    with pytest.raises(RuntimeError, match="нет прав"):
        remote_ops.get_top_dirs(SERVER, "E")


def test_powershell_error_surfaces(monkeypatch):
    _fake_ps(monkeypatch, {"Items": [], "DirCount": 0, "FileCount": 0,
                           "FirstError": "Access to the path is denied"})
    with pytest.raises(RuntimeError, match="Access to the path is denied"):
        remote_ops.get_top_dirs(SERVER, "E")
