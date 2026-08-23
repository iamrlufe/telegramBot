"""
bot/tg_utils.py

Безопасные обёртки над Telegram API: подавляют ожидаемые BadRequest
("Message is not modified", протухший callback query).
Плюс общий доступ к файлу mute-алертов (bot.py и config_editor.py).
"""
import json
import os
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
    os.makedirs(os.path.dirname(ALERTS_DISABLED_FILE), exist_ok=True)
    with open(ALERTS_DISABLED_FILE, "w") as f:
        json.dump(data, f)


def mute_expired(value, now: datetime = None) -> bool:
    """True, если временный mute уже истёк (постоянный True не истекает)."""
    if value is True:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(value)) <= now
    except ValueError:
        return False


async def safe_edit_message(query, text: str, reply_markup=None):
    """Длинный текст режется на части: Telegram отклоняет сообщения больше
    ~4096 символов, и карточка сервера с двумя десятками backup-путей
    упиралась в этот предел — пользователь видел «Произошла ошибка».
    Кнопки вешаются на последнюю часть, чтобы остались под текстом."""
    chunks = split_message(text)
    try:
        await query.edit_message_text(
            chunks[0],
            reply_markup=reply_markup if len(chunks) == 1 else None
        )
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            raise
        if len(chunks) == 1:
            return

    for i, chunk in enumerate(chunks[1:], start=2):
        await query.message.reply_text(
            chunk,
            reply_markup=reply_markup if i == len(chunks) else None
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
