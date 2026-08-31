"""Кнопка «Принял» в карточке сервера: замечания уходят навсегда.

Суточного подавления не хватало для того, что известно и оставлено
осознанно: диск списанной ВМ, база без бэкапа по решению. Через сутки
всё это возвращалось в сводку и в алерты.

Ключ подавления — сервер + объект, а не текст замечания: в тексте
проценты и дни, они меняются каждый час, и подавление по тексту
слетало бы само собой. Это и проверяется ниже.
"""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import alerts_ack

ROOT = Path(__file__).resolve().parent.parent


def _load_bot_db():
    spec = importlib.util.spec_from_file_location("bot_db", ROOT / "bot" / "db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bot_db = _load_bot_db()


@pytest.fixture
def ack_file(tmp_path, monkeypatch):
    path = tmp_path / "alert_ack.json"
    monkeypatch.setattr(alerts_ack, "ACK_FILE", str(path))
    return path


# ─── Бессрочное подавление ───────────────────────────────────

def test_forever_ack_survives_the_ack_period(ack_file):
    alerts_ack.ack_key_forever("disk:srv-01:C")
    assert alerts_ack.is_acked("disk:srv-01:C")

    # через год после суточного срока — всё ещё тихо
    far_future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    until = alerts_ack._load()["acks"][alerts_ack.ack_hash("disk:srv-01:C")]
    assert until == alerts_ack.ACK_FOREVER
    assert alerts_ack._is_active(until, far_future)


def test_hourly_ack_still_expires(ack_file):
    digest = alerts_ack.register_ack_key("disk:srv-01:D")
    alerts_ack.ack_alert(digest, hours=1)
    until = alerts_ack._load()["acks"][digest]
    later = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    assert not alerts_ack._is_active(until, later)


def test_forever_ack_is_listed_and_can_be_returned(ack_file):
    digest = alerts_ack.ack_key_forever("service:srv-01:W3SVC")
    item = alerts_ack.active_acks()[0]
    assert item["key"] == "service:srv-01:W3SVC"
    assert item["forever"] is True

    assert alerts_ack.unack_alert(digest) == "service:srv-01:W3SVC"
    assert not alerts_ack.is_acked("service:srv-01:W3SVC")


def test_active_digests_read_the_file_once(ack_file, monkeypatch):
    """Сводка проверяет десятки ключей — по чтению файла на каждый было бы
    расточительно."""
    alerts_ack.ack_key_forever("disk:srv-01:C")
    reads = []
    original = alerts_ack._load
    monkeypatch.setattr(alerts_ack, "_load",
                        lambda: (reads.append(1), original())[1])

    digests = alerts_ack.active_ack_digests()
    assert alerts_ack.ack_hash("disk:srv-01:C") in digests
    assert len(reads) == 1


# ─── Кнопка «Принял» ─────────────────────────────────────────

def _problem(kind, server, text, key):
    return {"level": "crit", "kind": kind, "server": server, "text": text,
            "weight": 0.0, "hint": None, "key": key}


def test_ack_button_silences_every_problem_of_the_server(ack_file):
    server = {
        "name": "srv-01.example.local",
        "crit": 2,
        "total": 2,
        "items": [
            _problem("disk", "srv-01.example.local", "🔴 C: свободно 4.2%",
                     "disk:srv-01.example.local:C"),
            _problem("service", "srv-01.example.local", "🚨 сервис W3SVC = stopped",
                     "service:srv-01.example.local:W3SVC"),
        ],
    }

    assert bot_db.ack_server_problems(server) == 2
    assert alerts_ack.is_acked("disk:srv-01.example.local:C")
    assert alerts_ack.is_acked("service:srv-01.example.local:W3SVC")
    # чужой сервер молчать не начинает
    assert not alerts_ack.is_acked("disk:srv-02.example.local:C")


def test_repeated_keys_counted_once(ack_file):
    """У одной цели бэкапа несколько замечаний с общим ключом — в ответе
    пользователю должно стоять число заглушённых проблем, а не строк."""
    key = "backup:srv-01:sql:D:\\Backups"
    server = {"name": "srv-01", "crit": 2, "total": 2, "items": [
        _problem("backup", "srv-01", "🚨 нет файлов backup", key),
        _problem("backup", "srv-01", "🔴 последний backup 9 дн назад", key),
    ]}
    assert bot_db.ack_server_problems(server) == 1


# ─── Сводка после «Принял» ───────────────────────────────────

class _FakeCursor:
    """Отдаёт строки по таблице из запроса: сводка проблем читает пять
    выборок подряд одним курсором."""

    def __init__(self, rows_by_table):
        self._rows_by_table = rows_by_table
        self._rows = []

    def execute(self, query, params=()):
        self._rows = []
        for table, rows in self._rows_by_table.items():
            if f"FROM {table}" in query:
                self._rows = rows
                break

    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def two_disks(monkeypatch):
    """Один сервер, два диска почти без места."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = {
        "server_status": [("srv-01", "online", None, now, 10.0, 8.0, 4.0)],
        "disk_metrics": [
            ("srv-01", "C", 2.0, 98.0, now),
            ("srv-01", "D", 3.0, 97.0, now),
        ],
    }
    cursor = _FakeCursor(rows)
    monkeypatch.setattr(bot_db, "get_conn", lambda: _FakeConn(cursor))
    monkeypatch.setattr(bot_db, "_load_backup_targets", lambda: ({}, set()))
    monkeypatch.setattr(bot_db, "load_schedule_map", lambda path: {})
    monkeypatch.setattr(bot_db, "load_disk_health", lambda name: {})
    return rows


def test_acked_problem_disappears_from_summary(ack_file, two_disks):
    problems = bot_db.collect_problems()
    assert {p["key"] for p in problems} == {"disk:srv-01:C", "disk:srv-01:D"}

    alerts_ack.ack_key_forever("disk:srv-01:C")
    problems = bot_db.collect_problems()
    assert [p["key"] for p in problems] == ["disk:srv-01:D"]


def test_ack_holds_when_the_number_in_the_text_changes(ack_file, two_disks):
    """Ключ не зависит от процентов: место на диске меняется каждый час, а
    подавление по тексту слетало бы с первым же изменением."""
    alerts_ack.ack_key_forever("disk:srv-01:C")
    two_disks["disk_metrics"][0] = ("srv-01", "C", 0.5, 99.5,
                                    datetime.now(timezone.utc).replace(tzinfo=None))

    assert [p["key"] for p in bot_db.collect_problems()] == ["disk:srv-01:D"]


def test_new_problem_on_acked_server_still_shows(ack_file, two_disks):
    alerts_ack.ack_key_forever("disk:srv-01:C")
    two_disks["disk_metrics"].append(
        ("srv-01", "E", 1.0, 99.0, datetime.now(timezone.utc).replace(tzinfo=None))
    )

    keys = {p["key"] for p in bot_db.collect_problems()}
    assert keys == {"disk:srv-01:D", "disk:srv-01:E"}
