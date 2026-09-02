"""
shared/backup_schedule.py

Недельное расписание бэкапа — общая логика для monitor (алерты) и bot
(🚨 Проблемы, Backup Health, дайджест, тепловая карта).

Путь, у которого в config/servers.json заданы schedule_weekday +
schedule_by_hour, делается не каждый день (например, полная копия по
понедельникам). Для такого пути «возраст последнего файла» ничего не значит:
между двумя плановыми копиями бэкап законно стареет почти на неделю, и
плоский порог alert_hours дал бы ложную тревогу уже на вторые сутки.

Правило одно и то же везде: если расписание задано — путь оценивается ТОЛЬКО
по недельному дедлайну (появилась ли копия к очередному weekday+by_hour), а
порог по возрасту к нему не применяется вообще. Пустой каталог и недоступный
путь остаются проблемой при любом расписании.
"""
import json
from datetime import datetime, timedelta, timezone
from settings import SERVERS_FILE, ALMATY, int_env


DEFAULT_SERVERS_FILE = SERVERS_FILE


# Насколько раньше дедлайна копия ещё считается «за эту неделю». Нужно,
# потому что задание нередко отрабатывает накануне вечером или заканчивается
# незадолго до срока: без допуска такая копия выглядела бы пропущенной.
WEEKLY_GRACE_HOURS = int_env("BACKUP_WEEKLY_GRACE_HOURS", 24)

# mon..sun -> datetime.weekday() (Пн=0 .. Вс=6), как и weekly_report() в bot.py
WEEKDAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WEEKDAY_LABELS_RU = [
    "понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"
]


WEEKDAY_SHORT_RU = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]


def weekday_short(weekday: str) -> str:
    """Короткое название — для кнопок выбора дня: семь «понедельников»
    в ряд не помещаются."""
    try:
        return WEEKDAY_SHORT_RU[WEEKDAY_NAMES.index(weekday)]
    except ValueError:
        return weekday


def weekday_label(weekday: str) -> str:
    """Русское название дня недели для текста алерта."""
    try:
        return WEEKDAY_LABELS_RU[WEEKDAY_NAMES.index(weekday)]
    except ValueError:
        return weekday


def path_schedule(item) -> tuple[str, int] | None:
    """Расписание из элемента backups.<type>: (weekday, by_hour) или None.

    None — и когда расписания нет, и когда оно задано неверно: молча
    игнорируем битое значение, чтобы опечатка в конфиге не отключала
    контроль пути совсем (останется обычная проверка по возрасту)."""
    if not isinstance(item, dict):
        return None
    weekday = item.get("schedule_weekday")
    by_hour = item.get("schedule_by_hour")
    if weekday is None or by_hour is None:
        return None
    weekday = str(weekday).strip().lower()
    if weekday not in WEEKDAY_NAMES:
        return None
    try:
        by_hour = int(by_hour)
    except (TypeError, ValueError):
        return None
    if not 0 <= by_hour <= 23:
        return None
    return weekday, by_hour


def load_schedule_map(servers_file: str = DEFAULT_SERVERS_FILE) -> dict:
    """{(server_name, backup_type, backup_path): (weekday, by_hour)} по конфигу.

    Ключ совпадает с тройкой, которой метрики идентифицируются в БД, — бот
    сопоставляет строки backup_metrics с расписанием именно по ней."""
    schedules: dict[tuple[str, str, str], tuple[str, int]] = {}
    try:
        with open(servers_file) as f:
            servers = json.load(f)
    except Exception as e:
        print(f"[schedule] Не удалось прочитать {servers_file}: {e}", flush=True)
        return schedules

    for server in servers:
        name = server.get("name")
        backups = server.get("backups")
        if not name or not isinstance(backups, dict):
            continue
        for backup_type, paths in backups.items():
            if not isinstance(paths, list):
                paths = [paths]
            for item in paths:
                schedule = path_schedule(item)
                if not schedule:
                    continue
                backup_path = item.get("path")
                if backup_path:
                    schedules[(name, str(backup_type), str(backup_path))] = schedule
    return schedules


def schedule_for(schedule_map: dict, server_name: str,
                 backup_type: str, backup_path: str) -> tuple[str, int] | None:
    """Расписание конкретной строки метрик, если оно задано в конфиге."""
    if not schedule_map:
        return None
    return schedule_map.get((server_name, str(backup_type), str(backup_path)))


def _as_almaty(dt: datetime) -> datetime:
    """naive-время считаем UTC (так его отдаёт PowerShell и хранит БД)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ALMATY)


def most_recent_weekly_deadline(weekday: str, by_hour: int, now: datetime) -> datetime:
    """Ближайший прошедший момент weekday+by_hour (Алматы) не позже now."""
    target = WEEKDAY_NAMES.index(weekday)
    days_back = (now.weekday() - target) % 7
    deadline = now.replace(hour=by_hour, minute=0, second=0, microsecond=0) \
        - timedelta(days=days_back)
    if deadline > now:
        deadline -= timedelta(days=7)
    return deadline


def weekly_backup_missed(newest_file, weekday: str, by_hour: int,
                         now: datetime = None, grace_hours: int = None) -> bool:
    """True, если к прошедшему недельному дедлайну копии за эту неделю нет.

    Сравнение идёт с самим дедлайном (минус допуск WEEKLY_GRACE_HOURS), а не
    с предыдущим: раньше копия, сделанная неделю назад, засчитывалась как
    свежая, и пропуск субботнего задания замечался только через неделю —
    к следующей субботе. Теперь тревога приходит в тот же день.

    Допуск нужен для копии, законченной незадолго до срока или накануне
    вечером. Обратная сторона: дедлайн должен указывать время, к которому
    копия уже готова, а не момент старта задания, иначе долгий job поднимет
    тревогу за час до собственного завершения.

    newest_file — naive UTC (как из PowerShell) или aware; now — время Алматы."""
    if newest_file is None:
        return True
    now = now or datetime.now(ALMATY)
    grace = WEEKLY_GRACE_HOURS if grace_hours is None else grace_hours
    deadline = most_recent_weekly_deadline(weekday, by_hour, now)
    return _as_almaty(newest_file) < deadline - timedelta(hours=grace)


def weekly_age_text(newest_file, weekday: str, by_hour: int,
                    now: datetime = None) -> str:
    """Короткое пояснение для интерфейсов бота: когда ждём следующую копию."""
    now = now or datetime.now(ALMATY)
    deadline = most_recent_weekly_deadline(weekday, by_hour, now)
    next_deadline = deadline + timedelta(days=7)
    return (
        f"недельная копия ({weekday_label(weekday)} {by_hour:02d}:00), "
        f"следующая к {next_deadline.strftime('%d.%m %H:%M')}"
    )
