"""Тесты shared/remote_ops.py: разбор занятого места на Linux («кто съел место»).

Повод: на почтовом сервере бот показал ~181 ГБ при 1.4 ТБ занятых по df.
Причина — du работал без sudo и молча не читал чужие каталоги.
Тесты фиксируют, что sudo в команде есть и что разбор вывода не ломается.
"""
import sys
import types

import remote_ops

SERVER = {"host": "nas.example.local", "username": "monitoring", "password": "x"}


def _fake_ssh(monkeypatch, output):
    """Подменяет linux_check.run_ssh; возвращает список выполненных команд."""
    calls = []

    def run_ssh(host, script, **kwargs):
        calls.append(script)
        return output

    stub = types.ModuleType("linux_check")
    stub.run_ssh = run_ssh
    monkeypatch.setitem(sys.modules, "linux_check", stub)
    monkeypatch.setattr(remote_ops, "server_type", lambda s: "linux")
    return calls


DU_OUTPUT = "\n".join([
    "1503238553600\t/",
    "182872793088\t/opt",
    "6227702579\t/var",
    "4123168604\t/swap.img",
])


def test_du_runs_under_sudo(monkeypatch):
    """Без sudo du не читает чужие каталоги — команда обязана его пробовать."""
    calls = _fake_ssh(monkeypatch, DU_OUTPUT)
    remote_ops.get_top_dirs(SERVER, "/")
    assert len(calls) == 1
    assert "$SUDO du -x -a -B1 -d1" in calls[0]


def test_sudo_probed_with_du_not_true(monkeypatch):
    """Право выдают узко (NOPASSWD: /usr/bin/du): проверка через `sudo -n true`
    требует пароль, проваливается и оставляет du без root — сумма занижена."""
    calls = _fake_ssh(monkeypatch, DU_OUTPUT)
    remote_ops.get_top_dirs(SERVER, "/")
    assert "sudo -n du --version" in calls[0]
    assert "sudo -n true" not in calls[0]


def test_du_falls_back_without_sudo(monkeypatch):
    """Если sudo без пароля не настроен, SUDO пустой — du всё равно выполнится."""
    calls = _fake_ssh(monkeypatch, DU_OUTPUT)
    remote_ops.get_top_dirs(SERVER, "/")
    assert "SUDO=''" in calls[0]


def test_parses_sizes_and_drops_mountpoint(monkeypatch):
    """Строка самого диска — итог, а не каталог: в список попадать не должна."""
    _fake_ssh(monkeypatch, DU_OUTPUT)
    result = remote_ops.get_top_dirs(SERVER, "/")
    assert [path for path, _ in result] == ["/opt", "/var", "/swap.img"]
    assert result[0][1] == 170.31


def test_mountpoint_is_quoted(monkeypatch):
    """Точка монтирования подставляется в шелл — экранирование обязательно."""
    calls = _fake_ssh(monkeypatch, "")
    remote_ops.get_top_dirs(SERVER, "/mnt/backup disk; rm -rf /")
    assert "'/mnt/backup disk; rm -rf /'" in calls[0]


def test_limit_respected(monkeypatch):
    """Топ обрезается по limit даже если сервер вернул больше строк."""
    _fake_ssh(monkeypatch, DU_OUTPUT)
    assert len(remote_ops.get_top_dirs(SERVER, "/", limit=2)) == 2


def test_garbage_lines_ignored(monkeypatch):
    """Мусор в выводе (баннеры sudo, пустые строки) не должен ронять разбор."""
    _fake_ssh(monkeypatch, "нет строки с табом\n\nabc\t/opt\n182872793088\t/opt")
    result = remote_ops.get_top_dirs(SERVER, "/")
    assert result == [("/opt", 170.31)]
