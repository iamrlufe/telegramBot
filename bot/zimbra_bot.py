"""
bot/zimbra_bot.py

Раздел «📬 Почта (Zimbra)» в карточке Linux-сервера: кто отправляет,
кто заходит, что не доставлено, что отбито на входе.

Кнопка показывается, если у сервера есть флаг `zimbra` либо среди services
есть `zimbra`/`postfix` — так же, как определяются nginx, apache и docker.

Данные читаются по нажатию: суточный mail.log это 25 МБ, но считает его
сам сервер одним проходом awk, и ответ приходит за секунды. Хранить нечего,
поэтому базы у раздела нет — в отличие от IIS, где логи на порядок больше.
"""
import asyncio
import itertools
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

from geoip import resolve as geo_resolve, tag as geo_tag
from refresh import load_server
from tg_utils import safe_edit_message, paginate, nav_row
from zimbra_log import (
    HOME_COUNTRY, QUEUE_ALERT, brute_force, foreign_logins, has_zimbra,
    heavy_senders, origin_kind, outside_senders, read_audit, read_mail,
)

ZM_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
ZM_TOKENS_MAX = 500
_SEQ = itertools.count(1)

# Прочитанная сводка живёт под своим токеном: перелистывание страниц не
# должно ходить на сервер заново.
ZM_RESULTS: "OrderedDict[str, dict]" = OrderedDict()
ZM_RESULTS_MAX = 100

PERIOD_SHORT_HOURS = 24
PERIOD_LONG_HOURS = 24 * 7
SHOW_LIMIT = 15


def zm_token(server_name: str, hours: int) -> str:
    token = f"z{next(_SEQ)}"
    ZM_TOKENS[token] = (server_name, hours)
    while len(ZM_TOKENS) > ZM_TOKENS_MAX:
        ZM_TOKENS.popitem(last=False)
    return token


def result_token(server_name: str, hours: int, section: str,
                 blocks: list, header: str) -> str:
    token = f"y{next(_SEQ)}"
    ZM_RESULTS[token] = {"server": server_name, "hours": hours,
                         "section": section, "blocks": blocks, "header": header}
    while len(ZM_RESULTS) > ZM_RESULTS_MAX:
        ZM_RESULTS.popitem(last=False)
    return token


def period_name(hours: int) -> str:
    return "24 часа" if hours <= PERIOD_SHORT_HOURS else "7 дней"


def menu_kb(server_name: str, hours: int) -> InlineKeyboardMarkup:
    def cb(section: str) -> str:
        return f"zm_{section}:{zm_token(server_name, hours)}"

    other = PERIOD_LONG_HOURS if hours <= PERIOD_SHORT_HOURS else PERIOD_SHORT_HOURS
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📤 Отправители", callback_data=cb("send")),
            InlineKeyboardButton("🔑 Входы", callback_data=cb("auth")),
        ],
        [
            InlineKeyboardButton("📦 Очередь", callback_data=cb("queue")),
            InlineKeyboardButton("🚫 Отбитые", callback_data=cb("reject")),
        ],
        [
            InlineKeyboardButton(f"⏱ {period_name(other)}",
                                 callback_data=f"zm_menu:{zm_token(server_name, other)}"),
            InlineKeyboardButton("◀️ К серверу",
                                 callback_data=f"server:{server_name}"),
        ],
    ])


def section_kb(server_name: str, hours: int, section: str,
               rtoken: str = None, page: int = 0,
               total_pages: int = 1) -> InlineKeyboardMarkup:
    rows = []
    if rtoken and total_pages > 1:
        rows.append(nav_row(f"zm_page:{rtoken}:", page, total_pages))
    rows.append([
        InlineKeyboardButton("◀️ К почте",
                             callback_data=f"zm_menu:{zm_token(server_name, hours)}"),
        InlineKeyboardButton("🔄 Обновить",
                             callback_data=f"zm_{section}:{zm_token(server_name, hours)}"),
    ])
    return InlineKeyboardMarkup(rows)


def render(header: str, blocks: list, page: int = 0) -> tuple:
    if not blocks:
        return header, 0, 1
    chunk, page, total_pages = paginate(blocks, page, SHOW_LIMIT)
    first = page * SHOW_LIMIT + 1
    last = first + len(chunk) - 1
    text = header + "\n" + "\n".join(chunk)
    if total_pages > 1:
        text += (f"\n\nПоказано {first}–{last} из {len(blocks)} · "
                 f"страница {page + 1} из {total_pages}")
    return text, page, total_pages


# ─── Экраны ──────────────────────────────────────────────────

ORIGIN_NAMES = {"web": "через веб", "inside": "напрямую изнутри",
                "outside": "🔴 снаружи"}


def format_send(data: dict, hours: int, geo: dict = None) -> tuple:
    senders = data.get("senders") or []
    if not senders:
        return (f"📤 Отправители за {period_name(hours)}\n\n"
                "Отправленных писем нет.", [])

    outside = outside_senders(data.get("origins"), data.get("local_domains"))
    heavy = {item["sender"] for item in heavy_senders(senders)}
    by_origin = _origins_by_sender(data.get("origins"))

    header = (f"📤 Отправители за {period_name(hours)}\n"
              f"Писем: {data['messages']} · отправителей: {len(senders)} · "
              f"получателей: {data['recipients']}\n"
              "Считаются письма, а не строки лога: одно письмо проходит "
              "через амавис двумя очередями и даёт 2-3 записи.\n")

    blocks = []
    for item in outside:
        blocks.append(
            f"🔴 {item['sender']} ← {item['ip']}{geo_tag(item['ip'], geo)}\n"
            f"   {item['count']} писем сдано С БЕЛОГО АДРЕСА, а не через веб\n"
            f"   так выглядит угнанная учётка: почта от своего адреса, "
            f"а отправлена снаружи")

    for item in senders:
        mark = "⚠️ " if item["sender"] in heavy else ""
        kinds = by_origin.get(item["sender"]) or set()
        how = " · ".join(ORIGIN_NAMES[k] for k in ("web", "inside", "outside")
                         if k in kinds)
        blocks.append(f"{mark}{item['messages']:>6}  {item['sender']}\n"
                      f"        {item['recipients']} получателей"
                      + (f" · {how}" if how else ""))
    return header, blocks


def _origins_by_sender(origins) -> dict:
    """Отправитель → как именно от него уходила почта. Учётка, которая
    обычно пишет через веб, а сегодня сдала пачку напрямую, видна сразу."""
    out = {}
    for (sender, ip), _count in origins or []:
        out.setdefault(sender, set()).add(origin_kind(ip))
    return out


def format_auth(data: dict, hours: int, geo: dict = None,
                codes: dict = None) -> tuple:
    events = data.get("events") or []
    if not events:
        return (f"🔑 Входы в почту за {period_name(hours)}\n\n"
                "Записей нет. Раздел читает /opt/zimbra/log/audit.log — "
                "если файла нет или он пуст, входы видно не будет.", [])

    accounts = {e["account"] for e in events}
    addresses = {e["ip"] for e in events}
    header = (f"🔑 Входы в почту за {period_name(hours)}\n"
              f"Учёток: {len(accounts)} · адресов: {len(addresses)} · "
              f"неудачных попыток: {data.get('failed', 0)}\n")

    blocks = []
    for item in brute_force(events):
        where = " админ-консоль" if item["admin"] else ""
        blocks.append(
            f"🔴 ПОДБОР ПАРОЛЯ{where}\n"
            f"   {item['account']} ← {item['ip']}{geo_tag(item['ip'], geo)}\n"
            f"   {item['count']} неудачных · протокол {item['protocol']}\n"
            + ("   🔴 с этого же адреса вход УДАЛСЯ — пароль подобран"
               if item["guessed"] else
               "   ни одного успешного входа — пароль пока не подобран"))

    for item in foreign_logins(events, codes):
        blocks.append(
            f"🔴 ВХОД НЕ ИЗ {HOME_COUNTRY}\n"
            f"   {item['account']} ← {item['ip']}{geo_tag(item['ip'], geo)}\n"
            f"   вход УДАЛСЯ · {item['count']} раз · последний {item['last']}")

    for event in events:
        if not event["ok"]:
            continue
        blocks.append(f"{event['count']:>5}  {event['account']}\n"
                      f"       ← {event['ip']}{geo_tag(event['ip'], geo)} · "
                      f"{event['protocol']}")
    return header, blocks


def format_queue(data: dict, hours: int) -> tuple:
    queue = data.get("queue")
    queue_line = ("не удалось прочитать очередь"
                  if queue is None else f"{queue} писем")
    mark = "🔴 " if queue is not None and queue > QUEUE_ALERT else ""

    header = (f"📦 Очередь и недоставленные за {period_name(hours)}\n"
              f"{mark}В очереди сейчас: {queue_line}\n"
              f"отложено: {data.get('deferred', 0)} попыток · "
              f"отказано: {data.get('bounced', 0)}\n")

    blocks = []
    reasons = data.get("defer_reasons") or []
    if reasons:
        blocks.append("Почему откладывается:")
        for parts, count in reasons[:10]:
            blocks.append(f"{count:>6}  {parts[0].strip()}")
    to = data.get("defer_to") or []
    if to:
        blocks.append("\nКому не доставляется:")
        for parts, count in to[:10]:
            blocks.append(f"{count:>6}  {parts[0]}")
    bounce = data.get("bounce_to") or []
    if bounce:
        blocks.append("\nКуда улетают отказы:")
        for parts, count in bounce[:10]:
            blocks.append(f"{count:>6}  {parts[0]}")
    if not blocks:
        blocks.append("Недоставленных писем нет.")
    return header, blocks


def format_reject(data: dict, hours: int, geo: dict = None) -> tuple:
    total = data.get("rejected", 0)
    header = (f"🚫 Отбито на входе за {period_name(hours)} — {total}\n"
              "Это письма, которые сервер не принял. Большое число здесь "
              "нормально: атака отбивается ДО приёма письма, а не после.\n")
    blocks = []
    reasons = data.get("reject_reasons") or []
    if reasons:
        blocks.append("Почему отбито:")
        for parts, count in reasons[:10]:
            blocks.append(f"{count:>6}  {parts[0].strip()}")
    ips = data.get("reject_ips") or []
    if ips:
        blocks.append("\nКто долбится:")
        for parts, count in ips[:15]:
            blocks.append(f"{count:>6}  {parts[0]}{geo_tag(parts[0], geo)}")
    if not blocks:
        blocks.append("Отбитых писем нет.")
    return header, blocks


# ─── Обработчик ──────────────────────────────────────────────

def _addresses(section: str, data: dict) -> list:
    """Адреса экрана — чтобы спросить страну один раз, а не построчно."""
    if section == "auth":
        return [e["ip"] for e in data.get("events") or []]
    if section == "reject":
        return [parts[0] for parts, _ in data.get("reject_ips") or []]
    if section == "send":
        return [ip for (_sender, ip), _ in data.get("origins") or []]
    return []


def _codes(geo: dict) -> dict:
    """Пометки geoip → коды стран.

    `foreign_logins` сравнивает страну, а geoip отдаёт готовую подпись с
    флагом. Флаг собран из двух regional indicator symbols, поэтому код
    восстанавливается обратно однозначно — отдельного запроса не нужно.
    """
    out = {}
    for address, label in (geo or {}).items():
        text = (label or "").strip()
        if len(text) >= 2 and all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in text[:2]):
            out[address] = "".join(
                chr(ord(c) - 0x1F1E6 + ord("A")) for c in text[:2])
    return out


READERS = {"send": read_mail, "queue": read_mail, "reject": read_mail,
           "auth": read_audit}


async def zimbra_callback(query, context):
    section, _, token = query.data[len("zm_"):].partition(":")

    if section == "page":
        rtoken, _, page_str = token.partition(":")
        saved = ZM_RESULTS.get(rtoken)
        if saved is None:
            await query.message.reply_text("Список устарел — откройте раздел заново.")
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

    state = ZM_TOKENS.get(token)
    if state is None:
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку сервера заново."
        )
        return
    server_name, hours = state

    if section == "menu":
        await safe_edit_message(
            query, f"📬 Почта (Zimbra) — {server_name}\n"
                   f"Период: {period_name(hours)}",
            reply_markup=menu_kb(server_name, hours))
        return

    reader = READERS.get(section)
    if reader is None:
        return

    await safe_edit_message(
        query, f"⏳ Читаю журналы почты: {server_name}…\n"
               "Считает сам сервер, обычно это несколько секунд.")
    try:
        server = await asyncio.to_thread(load_server, server_name)
        data = await asyncio.to_thread(reader, server, hours)
        geo = await asyncio.to_thread(geo_resolve, _addresses(section, data))
        if section == "send":
            header, blocks = format_send(data, hours, geo)
        elif section == "auth":
            header, blocks = format_auth(data, hours, geo, _codes(geo))
        elif section == "queue":
            header, blocks = format_queue(data, hours)
        else:
            header, blocks = format_reject(data, hours, geo)
    except Exception as e:
        header, blocks = (f"⚠️ Не удалось прочитать журналы {server_name}:\n"
                          f"{str(e).splitlines()[0][:250]}"), []

    text, page, total_pages = render(header, blocks, 0)
    rtoken = result_token(server_name, hours, section, blocks, header)
    await safe_edit_message(query, text, reply_markup=section_kb(
        server_name, hours, section, rtoken, page, total_pages))
