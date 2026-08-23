"""Тесты сбора метрик бэкапов по SSH (Linux / Synology NAS).

Зачем вообще SSH-ветка: сетевую папку, подключённую на Windows как диск
(Y:, Z:), через WinRM увидеть нельзя — подключённые диски живут только в
сессии того пользователя, который их подключил. Поэтому такие каталоги
опрашиваем на самом хранилище.

Тесты герметичные: настоящий SSH не нужен, run_ssh подменяется.
"""
from datetime import datetime

import pytest

import backup_collector as bc


@pytest.fixture
def ssh(monkeypatch):
    """Подменяет run_ssh: отдаёт заготовленный ответ, запоминает скрипт."""
    box = {"script": None, "reply": "", "kwargs": None}

    def fake_run_ssh(host, script, username=None, password=None, **kw):
        box["script"] = script
        box["host"] = host
        box["username"] = username
        box["kwargs"] = kw
        reply = box["reply"]
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(bc, "run_ssh", fake_run_ssh)
    return box


SERVER = {
    "name": "synology", "host": "10.0.0.5", "type": "linux",
    "username": "monitor", "password": "secret",
    "ssh_port": 2222, "ssh_key": "/app/config/ssh_key",
}


def _reply(file_count=2, total=3_221_225_472, oldest=1_753_000_000,
           newest=1_754_000_000, newest_bytes=2_147_483_648,
           total_kb=20_971_520, free_kb=10_485_760):
    return (
        f'{{"FileCount":{file_count},"TotalBytes":{total},'
        f'"Oldest":{oldest},"Newest":{newest},"NewestBytes":{newest_bytes},'
        f'"DiskTotalKB":{total_kb},"DiskFreeKB":{free_kb}}}'
    )


# ─── Разбор ответа ───────────────────────────────────────────

def test_metrics_shape_matches_windows_branch(ssh):
    """Ключи обязаны совпадать с WinRM-веткой: дальше их читает общий код
    (_check_backup_alerts, save_backup_metric)."""
    ssh["reply"] = _reply()
    metrics = bc.collect_backup_path_ssh(SERVER, "/volume1/backup/base1", "sql")

    assert set(metrics) == {
        "file_count", "total_size_gb", "oldest_file", "newest_file",
        "newest_file_gb", "disk_total_gb", "disk_free_gb",
        # отдельный учёт полных копий: журналы .trn можно исключить
        "full_count", "full_newest", "full_newest_gb", "log_count", "log_newest",
    }
    assert metrics["file_count"] == 2
    assert metrics["total_size_gb"] == 3.0          # 3 ГиБ
    assert metrics["newest_file_gb"] == 2.0
    assert metrics["disk_total_gb"] == 20.0
    assert metrics["disk_free_gb"] == 10.0


def test_timestamps_are_naive_utc(ssh):
    """PowerShell отдаёт naive UTC — SSH-ветка обязана делать так же,
    иначе возраст бэкапа посчитается со сдвигом на часовой пояс."""
    ssh["reply"] = _reply(oldest=1_753_000_000, newest=1_754_000_000)
    metrics = bc.collect_backup_path_ssh(SERVER, "/volume1/backup", "sql")

    assert metrics["newest_file"].tzinfo is None
    # epoch 1754000000 = 31.07.2025 22:13:20 UTC
    assert metrics["newest_file"] == datetime(2025, 7, 31, 22, 13, 20)
    assert metrics["oldest_file"] < metrics["newest_file"]


def test_empty_directory_reports_zero_files(ssh):
    """Пустой каталог — не ошибка, а 0 файлов: тогда сработает
    «БЭКАП НЕ СОЗДАЁТСЯ», как и на Windows."""
    ssh["reply"] = _reply(file_count=0, total=0, oldest=0, newest=0, newest_bytes=0)
    metrics = bc.collect_backup_path_ssh(SERVER, "/volume1/backup", "sql")

    assert metrics["file_count"] == 0
    assert metrics["oldest_file"] is None
    assert metrics["newest_file"] is None
    assert metrics["newest_file_gb"] is None


def test_missing_path_raises(ssh):
    ssh["reply"] = '{"Error":"Path not found"}'
    with pytest.raises(RuntimeError, match="Path not found"):
        bc.collect_backup_path_ssh(SERVER, "/volume1/нет", "sql")


def test_empty_output_raises(ssh):
    ssh["reply"] = "   "
    with pytest.raises(RuntimeError):
        bc.collect_backup_path_ssh(SERVER, "/volume1/backup", "sql")


# ─── Формирование команды ────────────────────────────────────

def test_ssh_params_are_passed(ssh):
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume1/backup", "sql")

    assert ssh["host"] == "10.0.0.5"
    assert ssh["username"] == "monitor"
    assert ssh["kwargs"]["port"] == 2222
    assert ssh["kwargs"]["key_path"] == "/app/config/ssh_key"


def test_default_ssh_port_when_not_set(ssh):
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh({"host": "h"}, "/volume1/backup", "sql")
    assert ssh["kwargs"]["port"] == 22


def test_sql_filters_extensions(ssh):
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume1/backup", "sql")

    script = ssh["script"]
    assert "-iname '*.bak'" in script
    assert "-iname '*.trn'" in script
    assert "-iname '*.dt'" not in script


def test_veeam_does_not_filter(ssh):
    """У veeam список расширений пуст — фильтра быть не должно."""
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume1/veeam", "veeam")
    assert "-iname" not in ssh["script"]


def test_path_is_quoted_for_shell(ssh):
    """Пробелы и апострофы в пути не должны ломать команду."""
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume1/it's backup/base1", "sql")
    assert "'/volume1/it'\\''s backup/base1'" in ssh["script"]


def test_synology_service_dirs_are_pruned(ssh):
    """@eaDir (метаданные) и #recycle (корзина шары) обязаны исключаться:
    иначе удалённый бэкап из корзины считается живым — объём завышен,
    а newest_file делает протухшую копию «свежей»."""
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume4/1base1/branch_b", "sql")

    script = ssh["script"]
    assert "-name '@eaDir'" in script
    assert "-name '#recycle'" in script
    assert "-prune" in script


@pytest.mark.parametrize("raw,expected", [
    ("/volume1/backup", "'/volume1/backup'"),
    ("/volume1/с пробелом", "'/volume1/с пробелом'"),
    ("/tmp/it's", "'/tmp/it'\\''s'"),
    ("/tmp/$(rm -rf /)", "'/tmp/$(rm -rf /)'"),
])
def test_sh_quote(raw, expected):
    assert bc._sh_quote(raw) == expected


# ─── Разделение .bak и .trn в одном каталоге ─────────────────

def test_ssh_script_requests_file_names(ssh):
    """Без %n в stat в строке нет имени файла, и .trn от .bak не отличить."""
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume1/db1", "sql")
    assert "stat -c '%Y %s %n'" in ssh["script"]


def test_ssh_script_classifies_by_line_end(ssh):
    """Путь может содержать пробелы, поэтому расширение берётся
    по концу всей строки, а не по номеру поля."""
    ssh["reply"] = _reply()
    bc.collect_backup_path_ssh(SERVER, "/volume1/db1", "sql")
    assert "[Tt][Rr][Nn]$" in ssh["script"]
    assert "LogCount" in ssh["script"] and "FullNewest" in ssh["script"]
