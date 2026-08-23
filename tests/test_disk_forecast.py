"""Тесты прогноза заполнения диска и новых парсеров Linux (SMART, температура).

Прогноз отвечает на вопрос «когда станет плохо», а не «плохо ли сейчас»:
бэкап-хранилище может держать 20% свободного и упереться в потолок за неделю.
"""
from datetime import datetime, timedelta


from disk_forecast import MIN_POINTS, forecast_text, free_space_trend
from linux_check import _parse_disk_temps, _parse_smart, _parse_smart_note


def _series(start_free, per_day, days=10, step_hours=6, start=None):
    """Ряд замеров: свободно меняется на per_day ГБ в сутки."""
    start = start or datetime(2026, 7, 1)
    points = []
    steps = int(days * 24 / step_hours)
    for i in range(steps):
        when = start + timedelta(hours=i * step_hours)
        free = start_free + per_day * (i * step_hours / 24)
        points.append((when, free))
    return points


# ─── free_space_trend ────────────────────────────────────────

def test_shrinking_disk_predicts_days_left():
    # 500 ГБ свободно, уходит по 10 ГБ/сут → примерно 50 дней... но за 10 дней
    # уже съедено 100, на последнем замере остаётся ~400 → ~40 дней
    trend = free_space_trend(_series(500, -10, days=10))

    assert trend["shrinking"] is True
    assert abs(trend["slope_gb_per_day"] - (-10)) < 0.1
    assert abs(trend["days_left"] - 40) < 1.5


def test_growing_free_space_is_not_a_problem():
    """Место освобождается (сработал ретеншн) — прогнозировать нечего."""
    trend = free_space_trend(_series(200, +5))
    assert trend["shrinking"] is False
    assert trend["days_left"] is None


def test_flat_disk_is_not_shrinking():
    trend = free_space_trend(_series(300, 0))
    assert trend["shrinking"] is False


def test_tiny_drift_is_treated_as_noise():
    """Наклон в граммах не должен превращаться в «место кончится»."""
    trend = free_space_trend(_series(300, -0.001))
    assert trend["shrinking"] is False


def test_too_few_points_gives_no_forecast():
    """На паре замеров случайное удаление бэкапа даёт бессмысленный наклон."""
    points = _series(500, -10, days=10)[: MIN_POINTS - 1]
    assert free_space_trend(points) is None


def test_no_forecast_without_data():
    assert free_space_trend([]) is None
    assert free_space_trend(None) is None


def test_all_points_at_same_moment():
    same = [(datetime(2026, 7, 1), 100.0)] * 10
    assert free_space_trend(same) is None


def test_accepts_epoch_and_datetime():
    as_dt = free_space_trend(_series(500, -10))
    as_epoch = free_space_trend([(w.timestamp(), f) for w, f in _series(500, -10)])
    assert abs(as_epoch["slope_gb_per_day"] - as_dt["slope_gb_per_day"]) < 1e-6


def test_broken_points_are_skipped():
    points = _series(500, -10)
    points.append(("мусор", None))
    trend = free_space_trend(points)
    assert trend is not None and trend["shrinking"]


def test_days_left_never_negative():
    """Диск уже переполнен — отдаём 0, а не отрицательное число."""
    trend = free_space_trend(_series(0.5, -10))
    assert trend["days_left"] >= 0


# ─── forecast_text ───────────────────────────────────────────

def test_forecast_text_mentions_rate_and_deadline():
    text = forecast_text(free_space_trend(_series(500, -10)))
    assert "ГБ/сут" in text and "дн" in text


def test_forecast_text_none_when_nothing_to_say():
    assert forecast_text(free_space_trend(_series(300, +5))) is None
    assert forecast_text(None) is None


def test_forecast_text_switches_to_months():
    text = forecast_text(free_space_trend(_series(5000, -10)))
    assert "мес" in text


# ─── SMART: причина недоступности ────────────────────────────

def test_smart_note_explains_missing_sudo():
    """Раньше stderr глушился и «нужен пароль» выглядел как «дисков нет»."""
    note = _parse_smart_note(["sda\t__NOSUDO__", "sdb\t__NOSUDO__"])
    assert note and "sudo" in note


def test_smart_note_explains_missing_smartctl():
    note = _parse_smart_note(["sda\t__NOSMARTCTL__"])
    assert note and "smartctl" in note


def test_smart_note_absent_when_all_good():
    assert _parse_smart_note(["sda\tSMART overall-health self-assessment: PASSED"]) is None


def test_markers_are_not_counted_as_failed_disks():
    """Маркер недоступности не должен превращаться в алерт «диск умирает»."""
    assert _parse_smart(["sda\t__NOSUDO__", "sdb\t__NOSMARTCTL__"]) == []


def test_failed_disk_still_detected():
    assert _parse_smart(["sda\tSMART overall-health self-assessment: FAILED!"]) \
        == ["sda: SMART FAILED"]


# ─── Температура дисков ──────────────────────────────────────

def test_disk_temps_parsed():
    assert _parse_disk_temps(["sda\t41", "sdb\t38.5"]) == [
        {"name": "sda", "temp_c": 41.0},
        {"name": "sdb", "temp_c": 38.5},
    ]


def test_disk_temps_ignore_garbage():
    assert _parse_disk_temps(["sda\t", "sdb\tн/д", "нет табуляции"]) == []


def test_disk_temps_reject_impossible_values():
    """Нестандартный вывод smartctl иногда даёт мусорные числа."""
    assert _parse_disk_temps(["sda\t999", "sdb\t-500", "sdc\t45"]) == [
        {"name": "sdc", "temp_c": 45.0}
    ]
