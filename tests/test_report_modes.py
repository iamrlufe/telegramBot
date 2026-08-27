"""Три режима отчёта: краткий, построчный и полный.

`import db` в тестах достаётся из monitor/ — одноимённый модуль бота
приходится грузить по пути.
"""
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_bot_db():
    spec = importlib.util.spec_from_file_location("bot_db", ROOT / "bot" / "db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bot_db = _load_bot_db()

LAST_UPDATE = datetime(2026, 8, 27, 13, 35, tzinfo=timezone.utc)


def _server(name, status="online", cpu=1.0, ram=10.0, disks=()):
    return {
        "name": name,
        "status": status,
        "cpu": cpu,
        "ram_pct": ram,
        "ram_free": 8.0,
        "uptime": 3600,
        "disks": [{"name": d, "free_gb": 10.0, "pct_free": pct} for d, pct in disks],
    }


SERVERS = [
    _server("app-01", disks=[("/", 61.3), ("/boot", 88.8)]),
    _server("file-01", cpu=15.0, ram=55.6, disks=[("C", 26.0), ("E", 18.9)]),
    _server("offline-01", status="timeout", cpu=None, ram=None),
    _server("vc-01", cpu=4.0, ram=83.7, disks=[("datastore2", 15.8)]),
    _server("full-01", cpu=95.0, ram=30.0, disks=[("C", 4.2)]),
]


def test_short_report_lists_only_problems():
    msg = bot_db._render_short("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)

    assert "⚠️ ТРЕБУЮТ ВНИМАНИЯ (3)" in msg
    assert "🔴 full-01 · CPU 95.0% · C 4.2%" in msg
    assert "🟠 vc-01 · RAM 83.7% · datastore2 15.8%" in msg
    assert "🟠 file-01 · E 18.9%" in msg
    # здоровый сервер — одной строкой в общем списке, без метрик
    assert "✅ В НОРМЕ (1)" in msg
    assert "app-01" in msg
    assert "88.8" not in msg
    # офлайн выносится отдельно
    assert "🔴 НЕ НА СВЯЗИ (1)" in msg
    assert "🔴 offline-01 (timeout)" in msg
    assert "📅 Данные актуальны на: 27.08.2026 18:35" in msg


def test_short_report_puts_critical_first():
    msg = bot_db._render_short("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)
    body = msg.split("ТРЕБУЮТ ВНИМАНИЯ", 1)[1]
    assert body.index("full-01") < body.index("vc-01")


def test_short_report_when_all_is_well():
    msg = bot_db._render_short("📊 ОТЧЁТ", [_server("app-01", disks=[("/", 50)])],
                               LAST_UPDATE)
    assert "Замечаний нет" in msg
    assert "ТРЕБУЮТ ВНИМАНИЯ" not in msg


def test_compact_report_one_line_per_server():
    msg = bot_db._render_compact("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)

    assert "🟢 app-01 · CPU 1.0% · RAM 10.0% · диски ок (2)" in msg
    assert "🟠 file-01 · CPU 15.0% · RAM 55.6% · E 18.9% (из 2)" in msg
    assert "🔴 offline-01 (timeout)" in msg
    # строка на сервер: заголовок, подпись и пустые строки сверх этого
    assert len([l for l in msg.splitlines() if l.startswith(("🟢", "🟠", "🔴"))]) == 5


def test_compact_report_orders_problems_first():
    msg = bot_db._render_compact("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)
    assert msg.index("offline-01") < msg.index("full-01") < msg.index("app-01")


def test_full_report_keeps_every_metric():
    msg = bot_db._render_full("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)

    assert "🖥 app-01" in msg
    assert "🟢 /boot: 88.8% свободно (10.0 ГБ)" in msg
    assert "⏱ Uptime:" in msg


def test_full_report_summary_includes_cpu_and_ram():
    """Раньше в сводку внизу попадали только диски, и RAM 83.7% в ней
    не значился."""
    msg = bot_db._render_full("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)
    summary = msg.split("━", 1)[1]

    assert "🔴 full-01 → CPU 95.0%" in summary
    assert "🟠 vc-01 → RAM 83.7%" in summary
    assert "🔴 full-01 → C (4.2%)" in summary
    assert "🟠 file-01 → E (18.9%)" in summary


def test_short_report_is_much_shorter():
    short = bot_db._render_short("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)
    full = bot_db._render_full("📊 ОТЧЁТ", SERVERS, LAST_UPDATE)
    assert len(short.splitlines()) < len(full.splitlines()) / 2


@pytest.mark.parametrize("mode,marker", [
    ("short", "ТРЕБУЮТ ВНИМАНИЯ"),
    ("compact", "диски ок"),
    ("full", "🖥 app-01"),
    ("невнятное", "ТРЕБУЮТ ВНИМАНИЯ"),
])
def test_build_report_dispatches_modes(monkeypatch, mode, marker):
    monkeypatch.setattr(bot_db, "collect_report_data",
                        lambda: (SERVERS, LAST_UPDATE))
    assert marker in bot_db.build_report(mode=mode)


def test_pseudo_filesystems_are_not_disks():
    """efivarfs пролезал в отчёт как «🔴 /sys/firmware/efi/efivars 0%»:
    это хранилище переменных UEFI, а не диск."""
    from linux_check import _parse_df

    lines = [
        "Filesystem 1024-blocks Used Available Capacity Mounted on",
        "/dev/sda2 32000000000 12000000000 20000000000 38% /",
        "efivarfs 262144 262144 0 100% /sys/firmware/efi/efivars",
        "/dev/sda1 1000000000 100000000 900000000 10% /boot",
        "/dev/loop0 100000000 100000000 0 100% /snap/core",
    ]
    names = [disk["Name"] for disk in _parse_df(lines)]

    assert "/sys/firmware/efi/efivars" not in names
    assert "/snap/core" not in names
    assert names == ["/"]  # /boot меньше гигабайта — тоже отсеян


def test_backup_older_than_crit_threshold_is_critical():
    """Копия десятидневной давности лежала в жёлтых наравне со вчерашней."""
    assert bot_db.BACKUP_CRIT_HOURS > bot_db.BACKUP_WARN_HOURS

    source = (ROOT / "bot" / "db.py").read_text(encoding="utf-8")
    crit_branch = source.split("age_hours > BACKUP_CRIT_HOURS", 1)[1][:220]
    assert 'add("crit", "backup"' in crit_branch
