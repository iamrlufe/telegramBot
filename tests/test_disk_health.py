"""Тесты shared/disk_health.py: хранение и вывод состояния дисков.

RAID, температура и причина недоступности SMART собираются монитором, но
раньше только уходили в алерты — посмотреть текущее состояние было негде.
Теперь они пишутся на общий том и показываются в карточке сервера.
"""
import disk_health
from disk_health import format_disk_health, load_disk_health, save_disk_health


def _redirect(tmp_path, monkeypatch):
    monkeypatch.setattr(disk_health, "DISK_HEALTH_FILE",
                        str(tmp_path / "disk_health.json"))


RAID_OK = [{"name": "md2", "level": "raid5", "total": 4, "active": 4,
            "flags": "UUUU", "degraded": False, "failed": [], "progress": None}]

RAID_BAD = [{"name": "md2", "level": "raid5", "total": 4, "active": 3,
             "flags": "UU_U", "degraded": True, "failed": ["sata3p3"],
             "progress": None}]

RAID_REBUILD = [{"name": "md2", "level": "raid5", "total": 4, "active": 3,
                 "flags": "UU_U", "degraded": True, "failed": [],
                 "progress": {"action": "recovery", "percent": 12.7,
                              "finish": "328.5min"}}]


# ─── Сохранение и чтение ─────────────────────────────────────

def test_roundtrip(tmp_path, monkeypatch):
    _redirect(tmp_path, monkeypatch)
    save_disk_health("nas", raid=RAID_OK, temps=[{"name": "sda", "temp_c": 41.0}])

    health = load_disk_health("nas")
    assert health["raid"] == RAID_OK
    assert health["temps"] == [{"name": "sda", "temp_c": 41.0}]
    assert health["updated"]


def test_missing_server_is_empty(tmp_path, monkeypatch):
    _redirect(tmp_path, monkeypatch)
    health = load_disk_health("нет-такого")
    assert health["raid"] == [] and health["temps"] == []
    assert health["smart_note"] is None


def test_missing_file_does_not_crash(tmp_path, monkeypatch):
    """Первый запуск: файла ещё нет."""
    _redirect(tmp_path, monkeypatch)
    assert load_disk_health("nas")["raid"] == []


def test_empty_data_removes_entry(tmp_path, monkeypatch):
    """Иначе карточка показывала бы протухшее «всё хорошо»."""
    _redirect(tmp_path, monkeypatch)
    save_disk_health("nas", raid=RAID_OK)
    save_disk_health("nas", raid=[], temps=[], smart_note=None)
    assert load_disk_health("nas")["raid"] == []


def test_servers_do_not_overwrite_each_other(tmp_path, monkeypatch):
    _redirect(tmp_path, monkeypatch)
    save_disk_health("nas", raid=RAID_OK)
    save_disk_health("other", raid=RAID_BAD)
    assert load_disk_health("nas")["raid"] == RAID_OK
    assert load_disk_health("other")["raid"] == RAID_BAD


def test_purge_removes_only_one_server(tmp_path, monkeypatch):
    _redirect(tmp_path, monkeypatch)
    save_disk_health("nas", raid=RAID_OK)
    save_disk_health("other", raid=RAID_OK)
    disk_health.purge_disk_health("nas")
    assert load_disk_health("nas")["raid"] == []
    assert load_disk_health("other")["raid"] == RAID_OK


def test_broken_file_is_survived(tmp_path, monkeypatch):
    _redirect(tmp_path, monkeypatch)
    (tmp_path / "disk_health.json").write_text("{не json", encoding="utf-8")
    assert load_disk_health("nas")["raid"] == []


# ─── Вывод в карточке ────────────────────────────────────────

def test_healthy_raid_shown_with_check():
    text = format_disk_health({"raid": RAID_OK})
    assert "md2 (raid5): 4/4 [UUUU]" in text
    assert "✅" in text


def test_degraded_raid_is_loud():
    text = format_disk_health({"raid": RAID_BAD})
    assert "🚨" in text
    assert "3/4" in text
    assert "sata3p3" in text


def test_rebuilding_raid_shows_progress():
    text = format_disk_health({"raid": RAID_REBUILD})
    assert "🔄" in text
    assert "12.7%" in text
    assert "328.5min" in text


def test_temperatures_marked_above_thresholds():
    text = format_disk_health({"temps": [
        {"name": "sda", "temp_c": 41.0},
        {"name": "sdb", "temp_c": 55.0},
        {"name": "sdc", "temp_c": 63.0},
    ]})
    assert "sda 41°C" in text
    assert "sdb 55°C🌡" in text
    assert "sdc 63°C🔥" in text


def test_smart_note_shown():
    text = format_disk_health({"smart_note": "SMART недоступен: нужен sudo"})
    assert "нужен sudo" in text


def test_nothing_to_show_gives_empty_string():
    """На Windows этих сведений нет — блок не должен появляться вовсе."""
    assert format_disk_health({}) == ""
    assert format_disk_health(None) == ""
    assert format_disk_health({"raid": [], "temps": [], "smart_note": None}) == ""
