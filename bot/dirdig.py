"""
bot/dirdig.py

Навигация по каталогам в разборе «кто съел место»: кнопки «провалиться внутрь».

Telegram ограничивает callback_data 64 байтами — путь вроде
/opt/zimbra/backup/sessions/full-20260806 туда не влезает. Поэтому путь
живёт в памяти процесса под коротким токеном, а в кнопку идёт только он.
Кэш ограничен по размеру: после рестарта бота старые кнопки становятся
недействительны, и обработчик просит открыть разбор заново.

Пути бывают и Windows ('E:\\Backups\\Old'), и Linux — разбираем каждый
своим модулем: posixpath на бэкслешах молча вернёт мусор.
"""
import itertools
import ntpath
import posixpath
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

DIG_MAX_DEPTH = 4          # глубже 4 уровней от корня диска не спускаемся
DIG_BUTTONS = 8            # кнопок под сообщением (в текстовом топе строк больше)
DIG_TOKENS_MAX = 2000

DIG_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
_DIG_SEQ = itertools.count(1)


def dig_token(server_name: str, disk_name: str, path: str, depth: int) -> str:
    """Кладёт (сервер, диск, путь, глубина) в кэш и возвращает ключ для кнопки."""
    token = f"d{next(_DIG_SEQ)}"
    DIG_TOKENS[token] = (server_name, disk_name, path, depth)
    while len(DIG_TOKENS) > DIG_TOKENS_MAX:
        DIG_TOKENS.popitem(last=False)
    return token


def parent_path(path: str) -> str:
    """Родительский каталог. Выше корня не поднимаемся."""
    if "\\" in path:
        return ntpath.dirname(path.rstrip("\\")) or path
    return posixpath.dirname(path.rstrip("/")) or "/"


def basename(path: str) -> str:
    """Короткое имя для подписи кнопки (у корня имени нет — отдаём путь)."""
    name = (ntpath.basename(path.rstrip("\\")) if "\\" in path
            else posixpath.basename(path.rstrip("/")))
    return name or path


def dig_kb(server_name: str, disk_name: str, path: str, depth: int,
           top_dirs: list) -> InlineKeyboardMarkup:
    """Кнопки «провалиться внутрь» + возврат к родителю и к карточке сервера."""
    rows = []
    if depth < DIG_MAX_DEPTH:
        for child, size_gb in top_dirs[:DIG_BUTTONS]:
            token = dig_token(server_name, disk_name, child, depth + 1)
            rows.append([InlineKeyboardButton(
                f"↳ {basename(child)} — {size_gb} ГБ", callback_data=f"dig:{token}")])
    if depth > 0:
        parent = parent_path(path)
        back = dig_token(server_name, disk_name, parent, depth - 1)
        rows.append([InlineKeyboardButton(
            f"◀️ Наверх ({basename(parent)})", callback_data=f"dig:{back}")])
    rows.append([InlineKeyboardButton("🖥 К серверу", callback_data=f"server:{server_name}")])
    return InlineKeyboardMarkup(rows)
