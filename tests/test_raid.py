"""Тесты разбора /proc/mdstat и алерта по RAID.

Зачем: развалившийся массив не виден ни по свободному месту, ни по SMART
отдельного диска. Для хранилища бэкапов это самая дорогая авария — второй
выпавший диск означает потерю данных.
"""
import alerts as alerts_mod
from linux_check import _parse_mdstat


def _lines(text):
    return text.strip("\n").split("\n")


# Реальный вывод Synology: SHR собран на md, том + системный раздел + swap
HEALTHY = """
Personalities : [linear] [raid0] [raid1] [raid5] [raid6] [raid10]
md2 : active raid5 sata1p3[0] sata2p3[1] sata3p3[2] sata4p3[3]
      23413870080 blocks super 1.2 level 5, 64k chunk, algorithm 2 [4/4] [UUUU]

md1 : active raid1 sata1p2[0] sata2p2[1] sata3p2[2] sata4p2[3]
      2097088 blocks [4/4] [UUUU]

md0 : active raid1 sata1p1[0] sata2p1[1] sata3p1[2] sata4p1[3]
      2490176 blocks [4/4] [UUUU]

unused devices: <none>
"""

DEGRADED = """
Personalities : [raid1] [raid5]
md2 : active raid5 sata1p3[0] sata2p3[1] sata3p3[3](F) sata4p3[2]
      23413870080 blocks super 1.2 level 5, 64k chunk, algorithm 2 [4/3] [UU_U]

unused devices: <none>
"""

REBUILDING = """
Personalities : [raid1] [raid5]
md2 : active raid5 sata1p3[0] sata2p3[1] sata3p3[4] sata4p3[2]
      23413870080 blocks super 1.2 level 5, 64k chunk, algorithm 2 [4/3] [UU_U]
      [==>..................]  recovery = 12.7% (991232/7804623360) finish=328.5min speed=98745K/sec

unused devices: <none>
"""

WITH_SPARE = """
Personalities : [raid1]
md1 : active raid1 sda2[0] sdb2[1] sdc2[2](S)
      2097088 blocks [2/2] [UU]

unused devices: <none>
"""

INACTIVE = """
Personalities : [raid1]
md0 : inactive sda1[0](S)
      2490176 blocks

unused devices: <none>
"""


# ─── Здоровый массив ─────────────────────────────────────────

def test_healthy_arrays_are_not_degraded():
    arrays = _parse_mdstat(_lines(HEALTHY))
    assert [a["name"] for a in arrays] == ["md2", "md1", "md0"]
    assert all(a["degraded"] is False for a in arrays)
    assert all(a["failed"] == [] for a in arrays)


def test_healthy_array_details():
    md2 = _parse_mdstat(_lines(HEALTHY))[0]
    assert md2["level"] == "raid5"
    assert md2["state"] == "active"
    assert (md2["total"], md2["active"]) == (4, 4)
    assert md2["flags"] == "UUUU"
    assert md2["progress"] is None


def test_service_lines_are_ignored():
    """«Personalities» и «unused devices» не должны стать массивами."""
    assert len(_parse_mdstat(_lines(HEALTHY))) == 3


# ─── Деградация ──────────────────────────────────────────────

def test_degraded_array_detected():
    md2 = _parse_mdstat(_lines(DEGRADED))[0]
    assert md2["degraded"] is True
    assert (md2["total"], md2["active"]) == (4, 3)
    assert md2["flags"] == "UU_U"
    assert md2["failed"] == ["sata3p3"]
    assert md2["progress"] is None


def test_rebuilding_array_reports_progress():
    md2 = _parse_mdstat(_lines(REBUILDING))[0]
    assert md2["degraded"] is True
    assert md2["progress"]["action"] == "recovery"
    assert md2["progress"]["percent"] == 12.7
    assert md2["progress"]["finish"] == "328.5min"


def test_inactive_array_is_degraded():
    md0 = _parse_mdstat(_lines(INACTIVE))[0]
    assert md0["state"] == "inactive"
    assert md0["degraded"] is True


# ─── Горячий резерв не путаем со сбоем ───────────────────────

def test_spare_disk_is_not_a_failure():
    """(S) — это запасной диск, а не выпавший. (F) — выпавший."""
    md1 = _parse_mdstat(_lines(WITH_SPARE))[0]
    assert md1["degraded"] is False
    assert md1["failed"] == []
    assert (md1["total"], md1["active"]) == (2, 2)


# ─── Устойчивость ────────────────────────────────────────────

def test_empty_mdstat_gives_nothing():
    """На сервере без RAID /proc/mdstat пуст или отсутствует."""
    assert _parse_mdstat([]) == []
    assert _parse_mdstat(["Personalities : ", "unused devices: <none>"]) == []


def test_garbage_does_not_crash():
    assert _parse_mdstat(["мусор", "   ", "12345 blocks [4/4] [UUUU]"]) == []


def test_underscore_without_count_mismatch_still_degraded():
    """Подстраховка: карта дисков важнее счётчика."""
    arrays = _parse_mdstat(_lines("""
md3 : active raid1 sda1[0] sdb1[1]
      100 blocks [2/2] [U_]
"""))
    assert arrays[0]["degraded"] is True


# ─── Алерт: переходы состояний ───────────────────────────────


def _wire_alerts(monkeypatch):
    """Ловит сообщения alerts, состояние держит в памяти."""
    sent, state = [], {}
    monkeypatch.setattr(alerts_mod, "is_muted", lambda name: False)
    monkeypatch.setattr(alerts_mod, "send_or_defer",
                        lambda text, **kw: sent.append(text))
    monkeypatch.setattr(alerts_mod, "load_json", lambda path: dict(state))
    monkeypatch.setattr(alerts_mod, "save_json",
                        lambda path, data: (state.clear(), state.update(data)))
    return sent, state


def test_alert_fires_once_on_degradation(monkeypatch):
    sent, _ = _wire_alerts(monkeypatch)
    arrays = _parse_mdstat(_lines(DEGRADED))

    alerts_mod.check_raid_alert("nas", arrays)
    assert len(sent) == 1
    assert "RAID ДЕГРАДИРОВАН" in sent[0]
    assert "sata3p3" in sent[0]

    alerts_mod.check_raid_alert("nas", arrays)   # то же состояние
    assert len(sent) == 1, "повторов быть не должно"


def test_healthy_array_is_silent(monkeypatch):
    sent, _ = _wire_alerts(monkeypatch)
    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(HEALTHY)))
    assert sent == []


def test_rebuild_start_and_recovery_are_reported(monkeypatch):
    sent, _ = _wire_alerts(monkeypatch)

    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(DEGRADED)))
    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(REBUILDING)))
    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(HEALTHY)))

    assert len(sent) == 3
    assert "ДЕГРАДИРОВАН" in sent[0]
    assert "ВОССТАНАВЛИВАЕТСЯ" in sent[1] and "12.7%" in sent[1]
    assert "снова в норме" in sent[2]


def test_muted_server_stays_quiet(monkeypatch):
    sent, _ = _wire_alerts(monkeypatch)
    monkeypatch.setattr(alerts_mod, "is_muted", lambda name: True)
    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(DEGRADED)))
    assert sent == []


def test_state_is_dropped_when_array_disappears(monkeypatch):
    """Массив разобрали — залипшее состояние не должно мешать в будущем."""
    sent, state = _wire_alerts(monkeypatch)
    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(DEGRADED)))
    assert any(k.startswith("nas:") for k in state)

    alerts_mod.check_raid_alert("nas", _parse_mdstat(_lines(HEALTHY)))
    assert not [k for k in state if k.startswith("nas:")]


# Реальный вывод второго NAS (ARM-модель, RAID10 из 4 дисков)
SYNOLOGY_RAID10 = """
Personalities : [raid1] [raid10]
md2 : active raid10 sda3[4] sdb3[1] sdd3[3] sdc3[2]
      27323316224 blocks super 1.2 64K chunks 2 near-copies [4/4] [UUUU]

md1 : active raid1 sda2[0] sdb2[1] sdc2[3] sdd2[2]
      2097088 blocks [4/4] [UUUU]

md0 : active raid1 sda1[0] sdb1[1] sdd1[3] sdc1[2]
      8388544 blocks [4/4] [UUUU]

unused devices: <none>
"""


def test_real_synology_raid10_is_healthy():
    """Формат RAID10 отличается от raid5: «64K chunks 2 near-copies»
    перед счётчиком — счётчик всё равно должен разбираться."""
    arrays = _parse_mdstat(_lines(SYNOLOGY_RAID10))
    assert [a["name"] for a in arrays] == ["md2", "md1", "md0"]
    assert all(a["degraded"] is False for a in arrays)

    md2 = arrays[0]
    assert md2["level"] == "raid10"
    assert (md2["total"], md2["active"]) == (4, 4)
    assert md2["flags"] == "UUUU"
