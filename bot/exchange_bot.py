"""
bot/exchange_bot.py

Раздел «📧 Почта (Exchange)» в карточке сервера: кто заходил в OWA,
кто ошибался паролем, мобильные клиенты и сводка по адресам.

Кнопка показывается, если среди services сервера есть служба MSExchange* —
так же, как в проекте определяются nginx, apache и docker: отдельный флаг
конфига на тот же факт заводить незачем.

Входов в почту сотни в сутки, поэтому все разделы показывают сводку с
счётчиками, а не поток строк.
"""
import asyncio
import itertools
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

from exchange_log import (
    read_owa_logins, read_owa_failures, read_activesync, read_top_sources,
)
from winlog import friendly_winlog_error
from refresh import load_server
from server_check import server_type
from tg_utils import safe_edit_message

EX_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
EX_TOKENS_MAX = 500
_SEQ = itertools.count(1)

PERIOD_SHORT_HOURS = 24
PERIOD_LONG_HOURS = 24 * 7
SHOW_LIMIT = 15


def ex_token(server_name: str, hours: int) -> str:
    token = f"x{next(_SEQ)}"
    EX_TOKENS[token] = (server_name, hours)
    while len(EX_TOKENS) > EX_TOKENS_MAX:
        EX_TOKENS.popitem(last=False)
    return token


def has_exchange(server: dict) -> bool:
    """Признак почтового сервера — служба MSExchange* в списке сервисов."""
    if server_type(server) != "windows":
        return False
    services = server.get("services") or []
    if isinstance(services, str):
        services = [services]
    return any(str(name).lower().startswith("msexchange") for name in services)


def period_name(hours: int) -> str:
    return "24 часа" if hours <= PERIOD_SHORT_HOURS else "7 дней"


def exchange_menu_kb(server_name: str, hours: int) -> InlineKeyboardMarkup:
    def cb(section: str) -> str:
        return f"exlog_{section}:{ex_token(server_name, hours)}"

    other = PERIOD_LONG_HOURS if hours <= PERIOD_SHORT_HOURS else PERIOD_SHORT_HOURS
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔓 Входы в OWA", callback_data=cb("owa")),
            InlineKeyboardButton("🔒 Неверный пароль", callback_data=cb("fail")),
        ],
        [
            InlineKeyboardButton("📱 Мобильные", callback_data=cb("eas")),
            InlineKeyboardButton("🌍 Адреса", callback_data=cb("ip")),
        ],
        [
            InlineKeyboardButton(f"⏱ {period_name(other)}",
                                 callback_data=f"exlog_menu:{ex_token(server_name, other)}"),
            InlineKeyboardButton("◀️ К серверу", callback_data=f"server:{server_name}"),
        ],
    ])


def section_kb(server_name: str, hours: int, section: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("◀️ К почте",
                             callback_data=f"exlog_menu:{ex_token(server_name, hours)}"),
        InlineKeyboardButton("🔄 Обновить",
                             callback_data=f"exlog_{section}:{ex_token(server_name, hours)}"),
    ]])


def _when(value) -> str:
    if not isinstance(value, str) or len(value) < 16:
        return value or ""
    return f"{value[8:10]}.{value[5:7]} {value[11:16]}"


def _short(text, limit: int) -> str:
    if not isinstance(text, str):
        return ""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def _client_name(agent: str) -> str:
    """Из User-Agent достаём узнаваемое: браузер или модель телефона.

    В логе IIS пробелы заменены плюсами, а полная строка занимает три
    экрана и в сводке бесполезна.
    """
    ua = (agent or "").replace("+", " ")
    for needle, label in (
        ("Edg/", "Edge"), ("YaBrowser", "Яндекс"), ("Chrome/", "Chrome"),
        ("Firefox/", "Firefox"), ("Safari/", "Safari"), ("Outlook", "Outlook"),
        ("Apple-iPhone", "iPhone"), ("Apple-iPad", "iPad"),
        ("Android", "Android"), ("SAMSUNG", "Samsung"),
    ):
        if needle.lower() in ua.lower():
            return label
    return _short(ua, 30) or "неизвестный клиент"


def format_owa(data: dict, hours: int) -> str:
    rows = data.get("rows") or []
    if not rows:
        return (f"🔓 Входы в OWA за {period_name(hours)}\n\n"
                "Записей нет. Проверьте, что на сервере включено ведение "
                "журналов IIS для сайта Default Web Site — раздел читает "
                "именно их.")
    lines = [f"🔓 Входы в OWA за {period_name(hours)}\n"
             f"Пользователей и адресов: {len(rows)} · "
             f"запросов: {data.get('scanned', 0)}\n"]
    for row in rows[:SHOW_LIMIT]:
        lines.append(f"{row.get('user')}  ← {row.get('ip')}")
        lines.append(f"   {_client_name(row.get('ua'))} · "
                     f"{row.get('count')} обращений · "
                     f"последнее {_when(row.get('last'))}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} пар «пользователь — адрес»")
    return "\n".join(lines)


def format_failures(rows: list, hours: int) -> str:
    if not rows:
        return (f"🔒 Неверный пароль за {period_name(hours)}\n\n"
                "Неудачных попыток нет.\n\n"
                "Раздел читает событие 4625 журнала Security — если аудит "
                "входа выключен, здесь будет пусто независимо от того, "
                "ошибался кто-то паролем или нет.")
    total = sum(row.get("count", 1) for row in rows)
    lines = [f"🔒 Неверный пароль за {period_name(hours)} — {total} попыток\n"]
    for row in rows[:SHOW_LIMIT]:
        source = row.get("ip") or "адрес не записан"
        lines.append(f"{row.get('user') or 'неизвестный логин'}  ← {source}")
        detail = row.get("reason") or f"код {row.get('code') or '?'}"
        lines.append(f"   {detail} · {row.get('count')} попыток · "
                     f"последняя {_when(row.get('last'))}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT}")
    lines.append("\nЭто веб-вход Exchange: OWA, ActiveSync и EWS здесь "
                 "неразличимы — все они проверяют пароль одинаково.")
    return "\n".join(lines)


def format_eas(data: dict, hours: int) -> str:
    rows = data.get("rows") or []
    if not rows:
        return (f"📱 Мобильные клиенты за {period_name(hours)}\n\n"
                "Обращений ActiveSync нет.")
    lines = [f"📱 Мобильные клиенты за {period_name(hours)}\n"
             f"Устройств: {len(rows)} · запросов: {data.get('scanned', 0)}\n"]
    for row in rows[:SHOW_LIMIT]:
        lines.append(f"{row.get('user')}  ·  {_client_name(row.get('ua'))}")
        lines.append(f"   {row.get('count')} обращений · "
                     f"последнее {_when(row.get('last'))}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} устройств")
    return "\n".join(lines)


def format_sources(data: dict, hours: int) -> str:
    rows = data.get("rows") or []
    if not rows:
        return f"🌍 Адреса за {period_name(hours)}\n\nОбращений нет."
    lines = [f"🌍 Откуда ходят в почту за {period_name(hours)}\n"
             f"Адресов: {len(rows)}\n"]
    for row in rows[:SHOW_LIMIT]:
        lines.append(f"{row.get('ip')}  —  {row.get('count')} обращений")
        lines.append(f"   последний: {row.get('user')} · "
                     f"{_when(row.get('last'))}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} адресов")
    return "\n".join(lines)


SECTIONS = {
    "owa": (read_owa_logins, format_owa),
    "fail": (read_owa_failures, format_failures),
    "eas": (read_activesync, format_eas),
    "ip": (read_top_sources, format_sources),
}


async def exchange_callback(query, context):
    section, _, token = query.data[len("exlog_"):].partition(":")

    state = EX_TOKENS.get(token)
    if state is None:
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку сервера заново."
        )
        return
    server_name, hours = state

    if section == "menu":
        await safe_edit_message(
            query,
            f"📧 Почта — {server_name}\nПериод: {period_name(hours)}",
            reply_markup=exchange_menu_kb(server_name, hours),
        )
        return

    handler = SECTIONS.get(section)
    if handler is None:
        return
    reader, formatter = handler

    # Логи IIS большие: чтение занимает десятки секунд, и молчащая кнопка
    # выглядит как зависший бот.
    await safe_edit_message(query, f"⏳ Читаю журналы почты: {server_name}…\n"
                                   f"На больших логах это занимает до минуты.")
    try:
        server = await asyncio.to_thread(load_server, server_name)
        rows = await asyncio.to_thread(reader, server, hours)
        text = formatter(rows, hours)
    except Exception as e:
        text = f"⚠️ Не удалось прочитать журналы {server_name}:\n{friendly_winlog_error(e)}"

    await safe_edit_message(query, text,
                            reply_markup=section_kb(server_name, hours, section))
