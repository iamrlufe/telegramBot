"""
shared/settings.py

Общие настройки и разбор переменных окружения.

Три вещи были скопированы почти в каждый модуль: чтение числа из .env
(одиннадцать копий `_int_env`, различавшихся только префиксом в логе),
часовой пояс (двенадцать раз `ZoneInfo("Asia/Almaty")`) и путь к
servers.json (девять литералов). Копии успели разойтись: часть вариантов
падала на пустой строке в .env, часть молча брала умолчание. Здесь один
разбор, поведение которого — объединение прежних: пустое значение
равнозначно отсутствующему, любой мусор даёт умолчание и строку в лог,
если вызывающий модуль назвал себя через tag.
"""
import os
from zoneinfo import ZoneInfo

# Весь парк в одном часовом поясе; вся отчётность и тихие часы считаются
# по нему, а в базе время хранится в UTC.
ALMATY = ZoneInfo("Asia/Almaty")

# Конфигурация серверов. Внутри контейнеров bot и monitor смонтирована
# одним и тем же путём — расхождение здесь означало бы, что бот правит
# один файл, а монитор читает другой.
SERVERS_FILE = "/app/config/servers.json"


def _parse_env(name: str, default, cast, tag: str = None):
    raw = os.getenv(name, "")
    raw = raw.strip() if isinstance(raw, str) else raw
    if not raw:
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        if tag:
            print(f"[{tag}] Некорректный {name}={raw!r}, беру {default}", flush=True)
        return default


def int_env(name: str, default: int, tag: str = None) -> int:
    """Целое из .env; при мусоре или пустом значении — default."""
    return _parse_env(name, default, int, tag)


def float_env(name: str, default: float, tag: str = None) -> float:
    """Дробное из .env; при мусоре или пустом значении — default."""
    return _parse_env(name, default, float, tag)
