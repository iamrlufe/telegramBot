"""
shared/disk_forecast.py

Прогноз заполнения диска: «при текущем росте место кончится через N дней».

Порог по проценту свободного места отвечает на вопрос «плохо ли сейчас»,
но не на «когда станет плохо». Бэкап-хранилище может месяцами держать
20% свободного и всё равно упереться в потолок за неделю, если объём
копий вырос. Здесь считается наклон по истории disk_metrics и
экстраполируется до нуля.

Метод — метод наименьших квадратов по (время, свободно_ГБ). Специально
без numpy: модуль общий для bot и monitor, а тянуть ради одной прямой
тяжёлую зависимость в оба образа незачем.
"""
from datetime import datetime

# Меньше этого числа замеров прогноз не строим: на двух точках любой
# случайный скачок (удалили старый бэкап) даёт бессмысленный наклон.
MIN_POINTS = 6

# Наклон меньше этого считаем шумом, а не ростом (ГБ в сутки)
MIN_SLOPE_GB_PER_DAY = 0.01


def _to_epoch(value) -> float:
    if isinstance(value, datetime):
        return value.timestamp()
    return float(value)


def free_space_trend(points: list) -> dict | None:
    """points: [(время, свободно_ГБ), ...] — время datetime или epoch.

    Возвращает {"slope_gb_per_day", "days_left", "free_gb", "shrinking"}
    или None, если данных мало.

    days_left — сколько суток до нуля при текущем наклоне; None, если
    место не убывает (тогда прогнозировать нечего)."""
    clean = []
    for item in points or []:
        try:
            when, free = item
            clean.append((_to_epoch(when), float(free)))
        except (TypeError, ValueError):
            continue

    if len(clean) < MIN_POINTS:
        return None

    clean.sort(key=lambda p: p[0])
    span_days = (clean[-1][0] - clean[0][0]) / 86400
    if span_days <= 0:
        return None

    # Время в сутках от первого замера — иначе epoch-числа огромные
    # и МНК теряет точность на float
    xs = [(t - clean[0][0]) / 86400 for t, _ in clean]
    ys = [free for _, free in clean]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n

    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return None
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denominator

    free_now = ys[-1]
    shrinking = slope < -MIN_SLOPE_GB_PER_DAY
    days_left = None
    if shrinking:
        days_left = max(free_now / -slope, 0.0)

    return {
        "slope_gb_per_day": slope,
        "days_left": days_left,
        "free_gb": free_now,
        "shrinking": shrinking,
        "span_days": span_days,
        "points": n,
    }


def forecast_text(trend: dict | None) -> str | None:
    """Короткая фраза для карточки сервера, либо None если сказать нечего."""
    if not trend or not trend.get("shrinking"):
        return None
    days = trend["days_left"]
    per_day = abs(trend["slope_gb_per_day"])
    if days < 1:
        when = "меньше суток"
    elif days < 60:
        when = f"~{round(days)} дн"
    else:
        when = f"~{round(days / 30)} мес"
    return f"−{per_day:.1f} ГБ/сут, места хватит на {when}"
