"""Сверка приёмника с источником.

Смысл проверки — узнать о непривезённой копии через минуты, а не через
сутки: порог по возрасту (alert_hours) ставят с запасом, и до него авария
не видна. Отдельно проверяется огрызок: по SFTP обрыв загрузки выглядит
для сервера как успех, поймать его можно только сравнением с оригиналом.
"""
from datetime import datetime, timedelta

import pytest

from backup_mirror import mirror_findings, mirror_spec

NOW = datetime(2026, 9, 5, 6, 0, 0)


def _spec(**over):
    spec = {"server": "sql-region", "path": "E:\\Backups\\DIFF", "type": "sql",
            "lag_minutes": 45, "size_ratio": 0.98}
    spec.update(over)
    return spec


def _metrics(minutes_ago=None, gb=None, collected_minutes_ago=5):
    return {
        "newest_file": NOW - timedelta(minutes=minutes_ago) if minutes_ago is not None else None,
        "newest_file_gb": gb,
        "collected_at": NOW - timedelta(minutes=collected_minutes_ago),
    }


# ─── mirror_spec ─────────────────────────────────────────────

def test_spec_none_without_mirror_of():
    assert mirror_spec({"path": "E:\\B"}, "sql") is None
    assert mirror_spec("E:\\B", "sql") is None


def test_spec_defaults_type_from_path():
    spec = mirror_spec(
        {"path": "E:\\B", "mirror_of": {"server": "s", "path": "D:\\B"}}, "sql")
    assert spec["type"] == "sql"
    assert spec["lag_minutes"] > 0


def test_spec_ignores_incomplete_source():
    """Половина настройки — та же опечатка: сверять не с чем."""
    assert mirror_spec({"path": "E:\\B", "mirror_of": {"server": "s"}}, "sql") is None


# ─── не доехал ───────────────────────────────────────────────

def test_late_when_source_newer_and_grace_passed():
    findings = mirror_findings(_metrics(60, 7.0), _metrics(600, 7.0), _spec(), NOW)
    assert [f["kind"] for f in findings] == ["late"]
    assert findings[0]["lag_minutes"] == 60


def test_no_alert_while_copy_may_still_run():
    """Файл создан 10 минут назад — копирование законно ещё идёт."""
    assert mirror_findings(_metrics(10, 7.0), _metrics(600, 7.0), _spec(), NOW) == []


def test_late_when_dest_empty():
    findings = mirror_findings(_metrics(60, 7.0), _metrics(None), _spec(), NOW)
    assert findings[0]["kind"] == "late"
    assert findings[0]["dest_newest"] is None


def test_silent_when_source_metrics_stale():
    """Регион недоступен: «на источнике новее» ничего не значит — копия
    могла приехать, а данные протухли."""
    source = _metrics(60, 7.0, collected_minutes_ago=180)
    assert mirror_findings(source, _metrics(600, 7.0), _spec(), NOW) == []


def test_silent_when_source_has_no_backups():
    """Пустой источник — его собственная авария, её ловит проверка
    возраста самого источника. Дважды об одном не звеним."""
    assert mirror_findings(_metrics(None), _metrics(600, 7.0), _spec(), NOW) == []


def test_clock_skew_is_not_a_miss():
    """Пара минут расхождения часов не должна выглядеть как пропажа."""
    source = _metrics(60, 7.0)
    dest = dict(_metrics(60, 7.0))
    dest["newest_file"] = source["newest_file"] - timedelta(minutes=2)
    assert mirror_findings(source, dest, _spec(), NOW) == []


# ─── приехал огрызком ────────────────────────────────────────

def test_small_when_copy_is_shorter_than_original():
    findings = mirror_findings(_metrics(60, 7.0), _metrics(60, 3.5), _spec(), NOW)
    assert findings[0]["kind"] == "small"
    assert findings[0]["percent"] == 50


def test_full_copy_is_silent():
    assert mirror_findings(_metrics(60, 7.0), _metrics(60, 7.0), _spec(), NOW) == []


def test_size_not_compared_before_arrival():
    """Пока файла нет, говорим только «не доехал»: размер огрызка от
    отсутствующего файла — бессмыслица."""
    findings = mirror_findings(_metrics(60, 7.0), _metrics(600, 0.1), _spec(), NOW)
    assert [f["kind"] for f in findings] == ["late"]


def test_unknown_sizes_do_not_alert():
    assert mirror_findings(_metrics(60, None), _metrics(60, None), _spec(), NOW) == []
