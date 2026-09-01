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
from geoip import resolve as geo_resolve, tag as geo_tag
from tg_utils import safe_edit_message, paginate, nav_row

EX_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
EX_TOKENS_MAX = 500
_SEQ = itertools.count(1)

# Прочитанные сводки живут под своим токеном: чтение логов IIS занимает до
# минуты, и перелистывание страниц не должно запускать его заново.
EX_RESULTS: "OrderedDict[str, dict]" = OrderedDict()
EX_RESULTS_MAX = 100

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
    """Почтовый сервер: явный флаг exchange или служба MSExchange* в сервисах.

    Автоопределение по службам покрывает типовой случай, но следить за
    службами Exchange в конфиге никто не обязан — поэтому есть и флаг.
    """
    if server_type(server) != "windows":
        return False
    if server.get("exchange"):
        return True
    services = server.get("services") or []
    if isinstance(services, str):
        services = [services]
    return any(str(name).lower().startswith("msexchange") for name in services)


def result_token(server_name: str, hours: int, section: str,
                 blocks: list, header: str) -> str:
    token = f"r{next(_SEQ)}"
    EX_RESULTS[token] = {"server": server_name, "hours": hours,
                         "section": section, "blocks": blocks, "header": header}
    while len(EX_RESULTS) > EX_RESULTS_MAX:
        EX_RESULTS.popitem(last=False)
    return token


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


def section_kb(server_name: str, hours: int, section: str,
               rtoken: str = None, page: int = 0,
               total_pages: int = 1) -> InlineKeyboardMarkup:
    rows = []
    if rtoken and total_pages > 1:
        rows.append(nav_row(f"exlog_page:{rtoken}:", page, total_pages))
    rows.append([
        InlineKeyboardButton("◀️ К почте",
                             callback_data=f"exlog_menu:{ex_token(server_name, hours)}"),
        InlineKeyboardButton("🔄 Обновить",
                             callback_data=f"exlog_{section}:{ex_token(server_name, hours)}"),
    ])
    return InlineKeyboardMarkup(rows)


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


def render(header: str, blocks: list, page: int = 0) -> tuple:
    """Собирает страницу: заголовок, срез блоков и строка «показано столько-то».

    Форматтеры возвращают список блоков, а не готовый текст, именно ради
    этого: раньше остаток списка обрывался фразой «… ещё 25», и добраться
    до него было нельзя.
    """
    if not blocks:
        return header, 0, 1
    chunk, page, total_pages = paginate(blocks, page, SHOW_LIMIT)
    first = page * SHOW_LIMIT + 1
    last = first + len(chunk) - 1
    text = header + "\n" + "\n".join(chunk)
    if total_pages > 1:
        text += f"\n\nПоказано {first}–{last} из {len(blocks)} · " \
                f"страница {page + 1} из {total_pages}"
    return text, page, total_pages


def _unread_note(data: dict) -> str:
    """Файл, который не удалось прочитать, обязан быть назван: иначе неполная
    выборка выглядит как «сегодня никто не заходил»."""
    failed = data.get("failed") or []
    if isinstance(failed, str):
        failed = [failed]
    if not failed:
        return ""
    return f"\n⚠️ Не удалось прочитать файлов журнала: {len(failed)} — данные неполные."


def format_owa(data: dict, hours: int, geo: dict = None) -> tuple:
    rows = data.get("rows") or []
    if not rows:
        return (f"🔓 Активность в OWA за {period_name(hours)}\n\n"
                "Записей нет. Проверьте, что на сервере включено ведение "
                "журналов IIS для сайта Default Web Site — раздел читает "
                f"именно их.{_unread_note(data)}", [])
    header = (f"🔓 Активность в OWA за {period_name(hours)}\n"
              f"Пользователей и адресов: {len(rows)} · "
              f"запросов: {data.get('scanned', 0)}"
              f"{_unread_note(data)}\n"
              "Считаются запросы к /owa/, а не входы: одна открытая вкладка "
              "шлёт их десятками в минуту.\n")
    blocks = [
        f"{row.get('user')}  ← {row.get('ip')}{geo_tag(row.get('ip'), geo)}\n"
        f"   {_client_name(row.get('ua'))} · {row.get('count')} обращений · "
        f"последнее {_when(row.get('last'))}"
        for row in rows
    ]
    return header, blocks


def format_failures(rows: list, hours: int, geo: dict = None) -> tuple:
    if not rows:
        return (f"🔒 Неверный пароль за {period_name(hours)}\n\n"
                "Неудачных попыток нет.\n\n"
                "Раздел читает событие 4625 журнала Security — если аудит "
                "входа выключен, здесь будет пусто независимо от того, "
                "ошибался кто-то паролем или нет.", [])
    total = sum(row.get("count", 1) for row in rows)
    header = (f"🔒 Неверный пароль за {period_name(hours)} — {total} попыток\n"
              f"Это веб-вход Exchange: OWA, ActiveSync и EWS здесь "
              f"неразличимы.\n")
    blocks = []
    for row in rows:
        source = ((row.get("ip") or "") + geo_tag(row.get("ip"), geo)
                  or "адрес не записан")
        detail = row.get("reason") or f"код {row.get('code') or '?'}"
        blocks.append(
            f"{row.get('user') or 'неизвестный логин'}  ← {source}\n"
            f"   {detail} · {row.get('count')} попыток · "
            f"последняя {_when(row.get('last'))}")
    return header, blocks


def format_eas(data: dict, hours: int, geo: dict = None) -> tuple:
    rows = data.get("rows") or []
    if not rows:
        return (f"📱 Мобильные клиенты за {period_name(hours)}\n\n"
                "Обращений ActiveSync нет.", [])
    header = (f"📱 Мобильные клиенты за {period_name(hours)}\n"
              f"Устройств: {len(rows)} · запросов: {data.get('scanned', 0)}"
              f"{_unread_note(data)}\n")
    blocks = [
        f"{row.get('user')}  ·  {_client_name(row.get('ua'))}\n"
        f"   {row.get('count')} обращений · последнее {_when(row.get('last'))}"
        for row in rows
    ]
    return header, blocks


def format_sources(data: dict, hours: int, geo: dict = None) -> tuple:
    rows = data.get("rows") or []
    if not rows:
        return f"🌍 Адреса за {period_name(hours)}\n\nОбращений нет.", []
    header = (f"🌍 Откуда ходят в почту за {period_name(hours)}\n"
              f"Адресов: {len(rows)}\n")
    blocks = [
        f"{row.get('ip')}{geo_tag(row.get('ip'), geo)}"
        f"  —  {row.get('count')} обращений\n"
        f"   последний: {row.get('user')} · {_when(row.get('last'))}"
        for row in rows
    ]
    return header, blocks


def addresses_of(payload) -> list:
    """Все адреса ответа: у разделов разная форма — словарь со `rows` у
    логов IIS и просто список у отказов из Security."""
    rows = payload.get("rows") if isinstance(payload, dict) else payload
    return [row.get("ip") for row in (rows or []) if isinstance(row, dict)]


SECTIONS = {
    "owa": (read_owa_logins, format_owa),
    "fail": (read_owa_failures, format_failures),
    "eas": (read_activesync, format_eas),
    "ip": (read_top_sources, format_sources),
}


async def exchange_callback(query, context):
    section, _, token = query.data[len("exlog_"):].partition(":")

    if section == "page":
        # Токен страницы: «<токен результата>:<номер>» — данные берём из
        # кэша, чтобы листание не перечитывало логи заново.
        rtoken, _, page_str = token.partition(":")
        saved = EX_RESULTS.get(rtoken)
        if saved is None:
            await query.message.reply_text(
                "Список устарел — откройте раздел заново."
            )
            return
        try:
            page = int(page_str)
        except ValueError:
            page = 0
        text, page, total_pages = render(saved["header"], saved["blocks"], page)
        await safe_edit_message(query, text, reply_markup=section_kb(
            saved["server"], saved["hours"], saved["section"],
            rtoken, page, total_pages))
        return

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
        # Страна и город — одним запросом на весь экран, а не построчно:
        # сорок адресов иначе означали бы сорок обращений к сервису.
        geo = await asyncio.to_thread(geo_resolve, addresses_of(rows))
        header, blocks = formatter(rows, hours, geo)
    except Exception as e:
        header, blocks = (f"⚠️ Не удалось прочитать журналы {server_name}:\n"
                          f"{friendly_winlog_error(e)}"), []

    text, page, total_pages = render(header, blocks, 0)
    rtoken = result_token(server_name, hours, section, blocks, header)
    await safe_edit_message(query, text, reply_markup=section_kb(
        server_name, hours, section, rtoken, page, total_pages))
