"""Тесты bot/tg_utils.py: отправка длинных сообщений.

Telegram отклоняет сообщения длиннее ~4096 символов. Карточка сервера с
двумя десятками backup-путей (NAS) в этот предел упиралась, и пользователь
видел «Произошла ошибка. Попробуйте ещё раз» вместо карточки.
"""
import asyncio

from telegram.error import BadRequest

import tg_utils
from tg_utils import TELEGRAM_TEXT_LIMIT, safe_edit_message, split_message


class FakeMessage:
    def __init__(self):
        self.replies = []

    async def reply_text(self, text, reply_markup=None):
        self.replies.append({"text": text, "markup": reply_markup})


class FakeQuery:
    def __init__(self, raise_error=None):
        self.message = FakeMessage()
        self.edited = None
        self._raise = raise_error

    async def edit_message_text(self, text, reply_markup=None):
        if self._raise:
            raise self._raise
        self.edited = {"text": text, "markup": reply_markup}


def _run(coro):
    return asyncio.run(coro)


def _long_text(chars):
    """Текст из абзацев — split_message режет именно по \\n\\n."""
    block = "строка " * 20
    out = []
    while sum(len(b) + 2 for b in out) < chars:
        out.append(block)
    return "\n\n".join(out)


# ─── Короткое сообщение ──────────────────────────────────────

def test_short_message_is_edited_once_with_markup():
    query = FakeQuery()
    _run(safe_edit_message(query, "коротко", reply_markup="КНОПКИ"))

    assert query.edited["text"] == "коротко"
    assert query.edited["markup"] == "КНОПКИ"
    assert query.message.replies == []


# ─── Длинное сообщение ───────────────────────────────────────

def test_long_message_is_split_and_not_rejected():
    text = _long_text(TELEGRAM_TEXT_LIMIT * 2)
    query = FakeQuery()
    _run(safe_edit_message(query, text, reply_markup="КНОПКИ"))

    parts = [query.edited["text"]] + [r["text"] for r in query.message.replies]
    assert len(parts) > 1, "длинный текст обязан разбиваться"
    assert all(len(p) <= TELEGRAM_TEXT_LIMIT for p in parts)


def test_markup_goes_to_the_last_part_only():
    """Иначе кнопки остались бы висеть посреди текста."""
    text = _long_text(TELEGRAM_TEXT_LIMIT * 2)
    query = FakeQuery()
    _run(safe_edit_message(query, text, reply_markup="КНОПКИ"))

    assert query.edited["markup"] is None
    markups = [r["markup"] for r in query.message.replies]
    assert markups[-1] == "КНОПКИ"
    assert all(m is None for m in markups[:-1])


def test_split_preserves_all_content():
    text = _long_text(TELEGRAM_TEXT_LIMIT * 2)
    joined = "".join(split_message(text))
    assert joined.replace("\n", "") == text.replace("\n", "")


# ─── Поведение при ошибках Telegram ──────────────────────────

def test_not_modified_is_swallowed():
    query = FakeQuery(raise_error=BadRequest("Message is not modified"))
    _run(safe_edit_message(query, "текст"))     # не должно бросить
    assert query.message.replies == []


def test_other_bad_request_is_reraised():
    query = FakeQuery(raise_error=BadRequest("Message is too long"))
    try:
        _run(safe_edit_message(query, "текст"))
    except BadRequest:
        return
    raise AssertionError("посторонний BadRequest нужно пробрасывать")


def test_not_modified_still_sends_remaining_parts():
    """Первая часть совпала с прежним текстом — остальные всё равно нужны."""
    text = _long_text(TELEGRAM_TEXT_LIMIT * 2)
    query = FakeQuery(raise_error=BadRequest("Message is not modified"))
    _run(safe_edit_message(query, text, reply_markup="КНОПКИ"))

    assert query.message.replies, "хвост сообщения потерялся"
    assert query.message.replies[-1]["markup"] == "КНОПКИ"
