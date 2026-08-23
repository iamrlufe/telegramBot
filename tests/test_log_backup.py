"""Каталог, где рядом с полными копиями лежат журналы транзакций (.trn).

Журналы делают каждые 15–60 минут, полную копию — раз в сутки. Общий
newest_file берёт максимум по всем файлам, поэтому свежий .trn МАСКИРУЕТ
пропавшую полную копию, и алерт «БЭКАП УСТАРЕЛ» не срабатывает.

С "ignore_logs": true журналы из учёта исключаются: считается только .bak.
Отсутствие журналов при этом не тревожит — они не контролируются вовсе.
"""
from datetime import datetime, timedelta, timezone

import pytest

import backup_collector as bc


def _ago(hours):
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)


def _metrics(full_age=None, log_age=None, full_count=1, log_count=1,
             full_gb=100.0):
    """Каталог со смесью .bak и .trn."""
    ages = [a for a in (full_age, log_age) if a is not None]
    newest = min(ages) if ages else None
    return {
        "file_count": full_count + log_count,
        "newest_file": _ago(newest) if newest is not None else None,
        "newest_file_gb": 0.01 if log_age is not None else full_gb,
        "total_size_gb": 100.0,
        "disk_total_gb": 500.0,
        "disk_free_gb": 200.0,
        "full_count": full_count,
        "full_newest": _ago(full_age) if full_age is not None else None,
        "full_newest_gb": full_gb if full_count else None,
        "log_count": log_count,
        "log_newest": _ago(log_age) if log_age is not None else None,
    }


@pytest.fixture
def io(monkeypatch):
    sent, state = [], {}
    monkeypatch.setattr(bc, "is_muted", lambda name: False)
    monkeypatch.setattr(bc, "send_or_defer", lambda text, **kw: sent.append(text))
    monkeypatch.setattr(bc, "load_json", lambda path: dict(state))
    monkeypatch.setattr(bc, "save_json",
                        lambda path, data: (state.clear(), state.update(data)))
    return sent, state


def _check(metrics, **kw):
    kw.setdefault("ignore_logs", True)
    bc._check_backup_alerts(
        "srv", "sql", "E:\\Backups\\db1", metrics, alert_hours=25, **kw
    )


# ─── Главное: свежий журнал больше не прячет пропавший .bak ──

def test_fresh_log_no_longer_masks_stale_full_backup(io):
    """Журналы свежие (10 мин), полной копии нет трое суток."""
    sent, _ = io
    _check(_metrics(full_age=72, log_age=0.16))

    assert len(sent) == 1
    assert "БЭКАП УСТАРЕЛ" in sent[0]
    assert "72 ч" in sent[0]


def test_without_flag_the_masking_remains(io):
    """Контрольный: без ignore_logs тот же каталог молчит — это и чинится."""
    sent, _ = io
    _check(_metrics(full_age=72, log_age=0.16), ignore_logs=False)
    assert sent == []


def test_missing_full_backup_reported_even_with_logs_present(io):
    """Журналы есть, .bak нет ни одного — каталог считается пустым."""
    sent, _ = io
    _check(_metrics(full_age=None, log_age=0.5, full_count=0, log_count=20))

    assert len(sent) == 1
    assert "БЭКАП НЕ СОЗДАЁТСЯ" in sent[0]


# ─── Журналы не контролируются ───────────────────────────────

def test_missing_logs_do_not_alert(io):
    """Полная копия свежая, журналов нет вовсе — тишина."""
    sent, _ = io
    _check(_metrics(full_age=2, log_age=None, log_count=0))
    assert sent == []


def test_stale_logs_do_not_alert(io):
    """Журналы встали трое суток назад, полная копия свежая — тишина."""
    sent, _ = io
    _check(_metrics(full_age=2, log_age=72))
    assert sent == []


# ─── Обычное поведение сохраняется ───────────────────────────

def test_fresh_full_backup_is_silent(io):
    sent, _ = io
    _check(_metrics(full_age=2, log_age=0.5))
    assert sent == []


def test_alert_is_not_repeated(io):
    sent, _ = io
    metrics = _metrics(full_age=72, log_age=0.16)
    _check(metrics)
    _check(metrics)
    assert len(sent) == 1


def test_weekly_schedule_still_suppresses_age_check(io):
    """У недельной копии возраст не показатель — её контролирует дедлайн."""
    sent, _ = io
    _check(_metrics(full_age=100, log_age=0.16), weekly_scheduled=True)
    assert sent == []


def test_empty_directory_still_alerts(io):
    sent, _ = io
    metrics = _metrics(full_age=None, log_age=None, full_count=0, log_count=0)
    metrics["file_count"] = 0
    _check(metrics)

    assert len(sent) == 1
    assert "БЭКАП НЕ СОЗДАЁТСЯ" in sent[0]


def test_size_check_uses_full_backup_not_log(io, monkeypatch):
    """Проверка «подозрительно маленький» должна сравнивать полную копию.
    Иначе крошечный .trn сравнивался бы с медианой .bak и давал ложный алерт."""
    sent, _ = io
    monkeypatch.setattr(bc, "get_recent_newest_sizes", lambda *a, **k: [100.0])
    monkeypatch.setattr(bc, "BACKUP_SIZE_CHECK_MIN_AGE_HOURS", 0)

    # newest_file_gb = 0.01 (журнал), full_newest_gb = 100 (полная копия)
    _check(_metrics(full_age=3, log_age=0.16, full_gb=100.0),
           size_check_enabled=True)
    assert sent == [], "размер полной копии в норме — алерта быть не должно"
