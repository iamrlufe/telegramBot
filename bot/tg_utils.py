"""
bot/tg_utils.py

Безопасные обёртки над Telegram API: подавляют ожидаемые BadRequest
("Message is not modified", протухший callback query).
Плюс общий доступ к файлу mute-алертов (bot.py и config_editor.py).
"""
import json
import os
import tempfile
from datetime import datetime, timezone

from telegram.error import BadRequest

ALERTS_DISABLED_FILE = "/app/data/alerts_disabled.json"
TELEGRAM_TEXT_LIMIT = 4000


def split_message(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> list[str]:
    if len(text) <= limit:
        return [text]

    chunks = []
    current = ""

    for block in text.split("\n\n"):
        candidate = block if not current else current + "\n\n" + block
        if len(candidate) <= limit:
            current = candidate
            continue

        if current:
            chunks.append(current)
            current = ""

        if len(block) <= limit:
            current = block
            continue

        lines = block.splitlines()
        part = ""
        for line in lines:
            candidate = line if not part else part + "\n" + line
            if len(candidate) <= limit:
                part = candidate
                continue

            if part:
                chunks.append(part)
                part = ""

            while len(line) > limit:
                chunks.append(line[:limit])
                line = line[limit:]
            part = line

        if part:
            current = part

    if current:
        chunks.append(current)

    return chunks or [text[:limit]]


def load_muted() -> dict:
    """{server: True | iso-метка истечения}. Формат читает монитор (is_muted)."""
    try:
        with open(ALERTS_DISABLED_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_muted(data: dict):
    """Атомарная запись: временный файл рядом, затем os.replace.

    Файл пишет бот, а читает монитор в соседнем контейнере. Прямая запись
    через open(..., "w") на мгновение оставляет файл усечённым, и монитор,
    попавший в это окно, получал пустой JSON — то есть считал, что не заглушен
    никто, и слал алерты по только что заглушенному серверу. Общей блокировки
    между контейнерами нет, os.replace внутри одной ФС атомарен и закрывает
    именно эту гонку: читатель видит либо старый файл целиком, либо новый.
    """
    directory = os.path.dirname(ALERTS_DISABLED_FILE)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, ALERTS_DISABLED_FILE)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def mute_expired(value, now: datetime = None) -> bool:
    """True, если временный mute уже истёк (постоянный True не истекает)."""
    if value is True:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(value)) <= now
    except ValueError:
        return False


async def safe_edit_message(query, text: str, reply_markup=None, parse_mode=None):
    """Длинный текст режется на части: Telegram отклоняет сообщения больше
    ~4096 символов, и карточка сервера с двумя десятками backup-путей
    упиралась в этот предел — пользователь видел «Произошла ошибка».
    Кнопки вешаются на последнюю часть, чтобы остались под текстом."""
    chunks = split_message(text)
    try:
        await query.edit_message_text(
            chunks[0],
            reply_markup=reply_markup if len(chunks) == 1 else None,
            parse_mode=parse_mode
        )
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            raise
        if len(chunks) == 1:
            return

    for i, chunk in enumerate(chunks[1:], start=2):
        await query.message.reply_text(
            chunk,
            reply_markup=reply_markup if i == len(chunks) else None,
            parse_mode=parse_mode
        )


async def safe_answer_query(query):
    try:
        await query.answer()
    except BadRequest as e:
        text = str(e)
        if "Query is too old" in text or "query id is invalid" in text:
            print(f"[bot] CallbackQuery answer skipped: {text}", flush=True)
            return
        raise


# ─── Постраничный вывод длинных списков ──────────────────────

def paginate(blocks: list, page: int, per_page: int) -> tuple:
    """Возвращает (срез, номер страницы, всего страниц).

    Номер страницы подрезается по границам: кнопка из старого сообщения
    может указывать на страницу, которой в новых данных уже нет.
    """
    total_pages = max(1, (len(blocks) + per_page - 1) // per_page)
    page = max(0, min(page, total_pages - 1))
    start = page * per_page
    return blocks[start:start + per_page], page, total_pages


def nav_row(callback_prefix: str, page: int, total_pages: int) -> list:
    """Ряд кнопок листания. Пустой, если страница всего одна."""
    from telegram import InlineKeyboardButton

    if total_pages <= 1:
        return []
    row = []
    if page > 0:
        row.append(InlineKeyboardButton(
            "◀️", callback_data=f"{callback_prefix}{page - 1}"))
    row.append(InlineKeyboardButton(f"{page + 1}/{total_pages}",
                                    callback_data="noop"))
    if page < total_pages - 1:
        row.append(InlineKeyboardButton(
            "▶️", callback_data=f"{callback_prefix}{page + 1}"))
    return row
