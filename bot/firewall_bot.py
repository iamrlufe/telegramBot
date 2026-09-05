"""
bot/firewall_bot.py

Раздел «🛡 Блокировка IP» в карточке сервера: список заблокированных,
блокировка адреса или подсети, снятие, белый список и сверка с сервером.

Бот сам не блокирует никого. Адрес называет человек — и делает это,
посмотрев на 🌐 IIS → 🔎 Сканирование или на алерт о подборе пароля.
Автоматика тут была бы дороже пользы: на публикации Exchange один неверно
опознанный адрес — это отрезанный офис, а если сайт стоит за обратным
прокси, в логе у всех посетителей один и тот же адрес прокси, и первая же
автоблокировка выключает сайт целиком.

Правило на сервере всегда собирается из списка целиком (shared/firewall.py),
поэтому любая операция здесь заодно чинит правило, если его правили руками.
"""
import asyncio
import itertools
from collections import OrderedDict
from datetime import datetime, timezone

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

import audit
import firewall_store as store
from geoip import resolve as geo_resolve
from iis_log import detect_brute_force, parse_hit
from iis_store import read_events
from config_editor import can_configure
# has_firewall здесь не вызывается: её реэкспортируют bot.py и iis_bot.py
# (`from firewall_bot import ...`). Убрать как «неиспользуемый импорт» —
# уронить бота на старте, поэтому noqa.
from firewall import (
    MAX_ADDRESSES, apply_blocks,
    has_firewall,  # noqa: F401  — реэкспорт для bot.py и iis_bot.py
    is_inside, normalize_target,
    read_blocks, refuse_reason, warn_reason,
)
from refresh import load_server
from tg_utils import safe_edit_message
from settings import ALMATY


FW_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
FW_TOKENS_MAX = 500
_SEQ = itertools.count(1)

# Строк на экран: список блокировок бывает длинным, а Telegram режет
# сообщение по длине.
SHOW_LIMIT = 30

AWAIT_KEY = "awaiting_fw"


def fw_token(*payload) -> str:
    token = f"f{next(_SEQ)}"
    FW_TOKENS[token] = payload
    while len(FW_TOKENS) > FW_TOKENS_MAX:
        FW_TOKENS.popitem(last=False)
    return token


def _when(moment) -> str:
    if not moment:
        return "бессрочно"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(ALMATY).strftime("%d.%m %H:%M")


def _left(moment) -> str:
    """Сколько осталось. Дата снятия сама по себе мало что говорит —
    «ещё 2 дня» читается быстрее, чем разница двух дат в уме."""
    if not moment:
        return "бессрочно"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    left = moment - datetime.now(timezone.utc)
    hours = int(left.total_seconds() // 3600)
    if hours <= 0:
        return "снимается"
    if hours < 48:
        return f"ещё {hours} ч"
    return f"ещё {hours // 24} дн"


# ─── Экраны ──────────────────────────────────────────────────

def menu_kb(server_name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "🚫 Заблокировать",
                callback_data=f"fw_ask:{fw_token(server_name)}"),
            InlineKeyboardButton(
                "✅ Снять",
                callback_data=f"fw_list:{fw_token(server_name)}"),
        ],
        [InlineKeyboardButton(
            "🔎 Кандидаты на блокировку",
            callback_data=f"fw_pick:{fw_token(server_name)}")],
        [
            InlineKeyboardButton(
                "⚪ Белый список",
                callback_data=f"fw_white:{fw_token(server_name)}"),
            InlineKeyboardButton(
                "🔍 Сверить с сервером",
                callback_data=f"fw_sync:{fw_token(server_name)}"),
        ],
        [InlineKeyboardButton("⬅️ Назад", callback_data=f"server:{server_name}")],
    ])


def format_menu(server_name: str, blocks: list, whitelist: list) -> str:
    lines = [f"🛡 Блокировка IP — {server_name}", ""]
    if not blocks:
        lines.append("Сейчас никто не заблокирован.")
        lines.append("")
        lines.append("Кого блокировать, видно в 🌐 IIS → 🔎 Сканирование: "
                     "адреса, с которых идут запросы к посторонним путям. "
                     "Бот сам не блокирует — адрес называете вы.")
    else:
        lines.append(f"Заблокировано адресов: {len(blocks)}")
        lines.append("")
        for item in blocks[:SHOW_LIMIT]:
            lines.append(f"🚫 {item['address']} — {_left(item['expires_at'])} "
                         f"(до {_when(item['expires_at'])})")
            if item.get("reason"):
                lines.append(f"      {item['reason']}")
        if len(blocks) > SHOW_LIMIT:
            lines.append(f"… и ещё {len(blocks) - SHOW_LIMIT}")
    if whitelist:
        lines.append("")
        lines.append(f"⚪ В белом списке: {len(whitelist)}")
    lines.append("")
    lines.append("Все адреса лежат в одном правиле Windows Firewall — в "
                 "оснастке wf.msc оно называется «AgroTNKbot: блокировка "
                 "сканеров».")
    return "\n".join(lines)


def format_ask(server_name: str) -> str:
    return (f"🚫 Блокировка на {server_name}\n\n"
            "Пришли адрес одним сообщением:\n"
            f"  192.0.2.10 — на {store.DEFAULT_DAYS} дня\n"
            "  192.0.2.10 7 — на 7 дней\n"
            "  192.0.2.0/24 — подсеть целиком\n"
            "  192.0.2.10 навсегда — без срока\n\n"
            "Блокируется весь входящий трафик с адреса, а не только "
            "веб-запросы.")


def format_sync(server_name: str, on_server: list, in_bot: list) -> str:
    """Сверка правила на сервере со списком бота.

    Нужна ровно затем, чтобы отличить «бот считает адрес заблокированным»
    от «адрес заблокирован»: правило могли снести в оснастке, а сервер —
    пересоздать из образа.
    """
    server_set, bot_set = set(on_server), set(in_bot)
    lines = [f"🔍 Сверка с сервером — {server_name}", "",
             f"В правиле на сервере: {len(server_set)}",
             f"В списке бота: {len(bot_set)}", ""]
    if server_set == bot_set:
        lines.append("✅ Совпадает.")
        return "\n".join(lines)

    missing = sorted(bot_set - server_set)
    extra = sorted(server_set - bot_set)
    if missing:
        lines.append(f"🔴 Есть в боте, но не блокируются на сервере: "
                     f"{len(missing)}")
        lines.append(", ".join(missing[:SHOW_LIMIT]))
        lines.append("")
    if extra:
        lines.append(f"🟠 Блокируются на сервере, но не в списке бота: "
                     f"{len(extra)}")
        lines.append(", ".join(extra[:SHOW_LIMIT]))
        lines.append("Скорее всего, правило правили руками в оснастке.")
        lines.append("")
    lines.append("Кнопка ниже перезапишет правило списком бота.")
    return "\n".join(lines)


# ─── Разбор ввода ────────────────────────────────────────────

FOREVER_WORDS = {"навсегда", "бессрочно", "forever", "0"}


def parse_block_input(text: str):
    """«192.0.2.10 7» → (адрес, дней, ошибка). days=None — бессрочно."""
    parts = (text or "").split()
    if not parts:
        return "", store.DEFAULT_DAYS, "Пустое сообщение."

    address = normalize_target(parts[0])
    if not address:
        return "", store.DEFAULT_DAYS, f"«{parts[0]}» — это не IP и не подсеть."

    if len(parts) == 1:
        return address, store.DEFAULT_DAYS, ""

    tail = parts[1].lower()
    if tail in FOREVER_WORDS:
        return address, None, ""
    if not tail.isdigit() or int(tail) < 1 or int(tail) > 365:
        return address, store.DEFAULT_DAYS, (
            "Срок — это число дней от 1 до 365 либо слово «навсегда».")
    return address, int(tail), ""


# ─── Кандидаты на блокировку ─────────────────────────────────

PICK_KEY = "fw_pick"

# Сколько адресов показывать списком. Больше — это уже не выбор, а
# пролистывание: кнопки не влезают на экран.
PICK_LIMIT = 15

# Ниже этого числа посторонних запросов адрес в кандидаты не идёт.
# Порог грубый намеренно: одиночные запросы к /.env шлёт кто угодно, а
# блокировка за это стоит дороже пользы.
SCAN_MIN_REQUESTS = 100


def _sum_by_ip(events: dict, category: str, index: int) -> dict:
    totals = {}
    for row in events.get(category) or []:
        parts = str(row["item"]).split("|")
        if len(parts) > index:
            totals[parts[index]] = totals.get(parts[index], 0) + row["count"]
    return totals


def candidates(events: dict, hour_events: dict, server: dict,
               blocked: list, white: list) -> list:
    """Адреса, которые стоит предложить к блокировке, от худших к прочим.

    Три повода, ровно те же, по которым приходят алерты: сервер отдал
    содержимое постороннему пути, идёт подбор пароля 1С, с адреса пришло
    много посторонних запросов.

    Отсеивается то, что блокировать нельзя или незачем: уже
    заблокированные, белый список, узлы прокси, свои и внутренние адреса
    (см. `refuse_reason`). Кандидат, которого бот откажется блокировать,
    в списке только раздражает.
    """
    volume = _sum_by_ip(events, "scan", 0)
    found, seen = [], set()

    def add(address, level, reason):
        address = (address or "").strip()
        if not address or address in seen:
            return
        if address in blocked:
            return
        target = normalize_target(address)
        # Отказ и «свой адрес» — разные причины не предлагать, но итог один:
        # кандидат, которого бот блокировать откажется или не должен, в
        # списке только раздражает.
        if not target or refuse_reason(target, server, white) or is_inside(target):
            return
        seen.add(address)
        found.append({"address": address, "level": level, "reason": reason,
                      "count": volume.get(address, 0)})

    for row in events.get("hit") or []:
        parsed = parse_hit(row["item"])
        if parsed:
            add(parsed[1], 0, f"сервер отдал {parsed[0]}")

    logins = [{"parts": (str(r["item"]).split("|") + ["", ""])[:2],
               "count": r["count"]} for r in hour_events.get("login") or []]
    requests = [{"parts": [str(r["item"])], "count": r["count"]}
                for r in hour_events.get("ip") or []]
    for item in detect_brute_force(logins, requests):
        if not item["working"]:
            add(item["ip"], 0,
                f"подбор пароля: {item['count']} входов за час")

    for address, count in sorted(volume.items(), key=lambda i: -i[1]):
        if count >= SCAN_MIN_REQUESTS:
            add(address, 1, f"{count} посторонних запросов")

    found.sort(key=lambda i: (i["level"], -i["count"]))
    return found[:PICK_LIMIT]


def pick_text(server_name: str, items: list, chosen: set, geo: dict) -> str:
    if not items:
        return (f"🔎 Кандидаты на блокировку — {server_name}\n\n"
                "Некого предлагать.\n\n"
                "В список идут адреса, которым сервер отдал содержимое по "
                "постороннему пути, адреса с подбором пароля 1С и те, с "
                f"которых пришло больше {SCAN_MIN_REQUESTS} посторонних "
                "запросов за сутки. Уже заблокированные, белый список, узлы "
                "Cloudflare и внутренние адреса сюда не попадают.")
    lines = [f"🔎 Кандидаты на блокировку — {server_name}", "",
             "Отметь адреса кнопками и нажми «Заблокировать». Данные — из "
             "сводки IIS за сутки.", ""]
    for index, item in enumerate(items):
        mark = "☑️" if index in chosen else "▫️"
        place = geo.get(item["address"]) or ""
        lines.append(f"{mark} {item['address']}"
                     + (f" · {place}" if place else ""))
        lines.append(f"      {item['reason']}")
    lines.append("")
    lines.append(f"Выбрано: {len(chosen)} из {len(items)}")
    return "\n".join(lines)


def pick_kb(items: list, chosen: set, geo: dict, server_name: str,
            days: int) -> InlineKeyboardMarkup:
    rows = []
    for index, item in enumerate(items):
        mark = "☑️" if index in chosen else "▫️"
        place = geo.get(item["address"]) or ""
        label = f"{mark} {item['address']}" + (f" · {place}" if place else "")
        rows.append([InlineKeyboardButton(label[:60],
                                          callback_data=f"fw_tog:{index}")])
    if items:
        rows.append([
            InlineKeyboardButton("☑️ Все", callback_data="fw_pickall"),
            InlineKeyboardButton("▫️ Снять", callback_data="fw_picknone"),
        ])
        rows.append([InlineKeyboardButton(
            f"🕒 Срок: {_days_name(days)}", callback_data="fw_pickdays")])
        rows.append([InlineKeyboardButton(
            f"🚫 Заблокировать ({len(chosen)})", callback_data="fw_pickgo")])
    rows.append([InlineKeyboardButton(
        "⬅️ Назад", callback_data=f"fw_menu:{fw_token(server_name)}")])
    return InlineKeyboardMarkup(rows)


# Сроки, по которым ходит кнопка «Срок». Больше месяца вручную не
# выбирают: если адрес нужен в бане навсегда, это отдельное решение.
DAY_CHOICES = (3, 7, 30, None)


def _days_name(days) -> str:
    return "бессрочно" if days is None else f"{days} дн."


def next_days(days):
    """Кнопка срока перебирает варианты по кругу: отдельный экран ради
    четырёх значений не нужен."""
    try:
        index = DAY_CHOICES.index(days)
    except ValueError:
        return DAY_CHOICES[0]
    return DAY_CHOICES[(index + 1) % len(DAY_CHOICES)]


# ─── Применение ──────────────────────────────────────────────

def _apply(server_name: str, addresses: list) -> list:
    """Приводит правило к списку. Отдельной функцией, чтобы уводить в
    поток одним вызовом: WinRM ходит на сервер секунды."""
    server = load_server(server_name)
    return apply_blocks(server, addresses)


def _addresses(server_name: str) -> list:
    return [b["address"] for b in store.list_blocks(server_name)]


def do_block(server_name: str, address: str, days, reason: str, author: str) -> str:
    """Блокирует адрес. Правило пишется первым: если WinRM не ответил,
    в базе не должно остаться записи о блокировке, которой нет."""
    current = _addresses(server_name)
    if address not in current:
        current = current + [address]
    _apply(server_name, current)
    store.add_block(server_name, address, reason=reason, author=author, days=days)
    return address


def do_block_many(server_name: str, addresses: list, days, author: str) -> int:
    """Все выбранные адреса — одной перезаписью правила.

    По вызову на адрес было бы N походов на сервер по WinRM: на пятнадцати
    адресах это полминуты ожидания вместо секунды, и половина могла бы
    примениться, а половина нет.
    """
    current = _addresses(server_name)
    fresh = [a for a in addresses if a not in current]
    _apply(server_name, current + fresh)
    for address in addresses:
        store.add_block(server_name, address,
                        reason="выбран в кандидатах", author=author, days=days)
    return len(fresh)


def do_unblock(server_name: str, address: str) -> bool:
    current = [a for a in _addresses(server_name) if a != address]
    _apply(server_name, current)
    return store.remove_block(server_name, address)


def do_whitelist(server_name: str, address: str, note: str) -> bool:
    """В белый список — значит и снять блокировку, если она была: иначе
    «больше не блокируем» оставит адрес отрезанным."""
    was_blocked = address in _addresses(server_name)
    if was_blocked:
        do_unblock(server_name, address)
    store.add_white(server_name, address, note)
    return was_blocked


# ─── Обработчик кнопок ───────────────────────────────────────

DENY = ("⛔ Блокировка адресов доступна только пользователям из "
        "TELEGRAM_DELETE_USERS: правило firewall отрезает трафик, "
        "и ошибка стоит дороже прочих настроек.")


async def show_pick(query, context, server_name: str):
    """Экран выбора. Состояние живёт в user_data, а не в callback_data:
    отмеченные адреса в 64 байта кнопки не поместятся."""
    state = context.user_data.get(PICK_KEY) or {}
    if state.get("server") != server_name:
        state = {"server": server_name, "items": [], "chosen": set(),
                 "days": store.DEFAULT_DAYS, "geo": {}}
        context.user_data[PICK_KEY] = state

    if not state["items"]:
        try:
            server = await asyncio.to_thread(load_server, server_name)
            events = await asyncio.to_thread(
                lambda: (read_events(24) or {}).get(server_name, {}))
            hour = await asyncio.to_thread(
                lambda: (read_events(1) or {}).get(server_name, {}))
            blocked = await asyncio.to_thread(_addresses, server_name)
            white = [i["address"] for i in
                     await asyncio.to_thread(store.list_whitelist, server_name)]
        except Exception as e:
            await safe_edit_message(
                query, f"⚠️ Сводка IIS недоступна: {str(e).splitlines()[0][:150]}",
                reply_markup=menu_kb(server_name))
            return
        state["items"] = candidates(events, hour, server, blocked, white)
        try:
            state["geo"] = await asyncio.to_thread(
                geo_resolve, [i["address"] for i in state["items"]])
        except Exception:
            state["geo"] = {}

    await safe_edit_message(
        query, pick_text(server_name, state["items"], state["chosen"],
                         state["geo"]),
        reply_markup=pick_kb(state["items"], state["chosen"], state["geo"],
                             server_name, state["days"]))


async def firewall_callback(query, context):
    section, _, token = query.data[len("fw_"):].partition(":")

    # Экран выбора держит состояние в user_data, токен ему не нужен.
    if section in ("tog", "pickall", "picknone", "pickdays", "pickgo"):
        await pick_callback(query, context, section, token)
        return

    payload = FW_TOKENS.get(token)
    if payload is None:
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку сервера заново."
        )
        return
    server_name = payload[0]

    if section != "menu" and not can_configure(query.from_user):
        await query.message.reply_text(DENY)
        return

    if section == "menu":
        blocks = await asyncio.to_thread(store.list_blocks, server_name)
        white = await asyncio.to_thread(store.list_whitelist, server_name)
        await safe_edit_message(query, format_menu(server_name, blocks, white),
                                reply_markup=menu_kb(server_name))

    elif section == "ask":
        context.user_data[AWAIT_KEY] = {"server": server_name, "mode": "block"}
        await safe_edit_message(query, format_ask(server_name),
                                reply_markup=menu_kb(server_name))

    elif section == "askwhite":
        context.user_data[AWAIT_KEY] = {"server": server_name, "mode": "white"}
        await safe_edit_message(
            query,
            f"⚪ Белый список на {server_name}\n\n"
            "Пришли адрес или подсеть одним сообщением — например адрес "
            "офиса или узла обратного прокси.\n\n"
            "Адрес из белого списка бот заблокировать откажется. Если он "
            "заблокирован сейчас — блокировка снимется.",
            reply_markup=menu_kb(server_name))

    elif section == "blockgo":
        _name, address, days = payload
        await safe_edit_message(query, f"⏳ Блокирую {address} на {server_name}…")
        user = query.from_user
        author = f"{user.id}" if user else ""
        try:
            await asyncio.to_thread(do_block, server_name, address, days,
                                    "заблокирован вручную из бота", author)
        except Exception as e:
            await query.message.reply_text(
                f"❌ Не удалось заблокировать {address}:\n{str(e).splitlines()[0][:200]}")
            return
        audit.log_config_change(user, "fwblock", server_name,
                                f"{address}, срок: "
                                f"{'бессрочно' if days is None else f'{days} дн.'}")
        blocks = await asyncio.to_thread(store.list_blocks, server_name)
        white = await asyncio.to_thread(store.list_whitelist, server_name)
        await query.message.reply_text(
            f"🚫 {address} заблокирован на {server_name}.\n\n"
            + format_menu(server_name, blocks, white),
            reply_markup=menu_kb(server_name))

    elif section == "pick":
        context.user_data.pop(PICK_KEY, None)
        await show_pick(query, context, server_name)

    elif section == "list":
        blocks = await asyncio.to_thread(store.list_blocks, server_name)
        if not blocks:
            await safe_edit_message(query, "Сейчас никто не заблокирован.",
                                    reply_markup=menu_kb(server_name))
            return
        rows = [[InlineKeyboardButton(
            f"✅ Снять {item['address']}",
            callback_data=f"fw_unblockgo:{fw_token(server_name, item['address'])}")]
            for item in blocks[:SHOW_LIMIT]]
        rows.append([InlineKeyboardButton(
            "⬅️ Назад", callback_data=f"fw_menu:{fw_token(server_name)}")])
        await safe_edit_message(
            query, f"✅ Снять блокировку — {server_name}\n\n"
                   "Адрес снимается сразу, без подтверждения: разблокировка "
                   "ничего не ломает.",
            reply_markup=InlineKeyboardMarkup(rows))

    elif section == "unblockgo":
        _name, address = payload
        try:
            await asyncio.to_thread(do_unblock, server_name, address)
        except Exception as e:
            await query.message.reply_text(
                f"❌ Не удалось снять {address}:\n{str(e).splitlines()[0][:200]}")
            return
        audit.log_config_change(query.from_user, "fwunblock", server_name, address)
        blocks = await asyncio.to_thread(store.list_blocks, server_name)
        white = await asyncio.to_thread(store.list_whitelist, server_name)
        await safe_edit_message(
            query, f"✅ {address} разблокирован.\n\n"
                   + format_menu(server_name, blocks, white),
            reply_markup=menu_kb(server_name))

    elif section == "white":
        white = await asyncio.to_thread(store.list_whitelist, server_name)
        rows = [[InlineKeyboardButton(
            f"🗑 Убрать {item['address']}",
            callback_data=f"fw_whitedel:{fw_token(server_name, item['address'])}")]
            for item in white[:SHOW_LIMIT]]
        rows.append([InlineKeyboardButton(
            "➕ Добавить", callback_data=f"fw_askwhite:{fw_token(server_name)}")])
        rows.append([InlineKeyboardButton(
            "⬅️ Назад", callback_data=f"fw_menu:{fw_token(server_name)}")])
        lines = [f"⚪ Белый список — {server_name}", "",
                 "Адреса, которые бот заблокировать откажется. Сюда стоит "
                 "занести свой офис и узлы обратного прокси.", ""]
        lines += ([f"⚪ {i['address']}" + (f" — {i['note']}" if i.get('note') else "")
                   for i in white[:SHOW_LIMIT]] or ["Список пуст."])
        await safe_edit_message(query, "\n".join(lines),
                                reply_markup=InlineKeyboardMarkup(rows))

    elif section == "whitedel":
        _name, address = payload
        await asyncio.to_thread(store.remove_white, server_name, address)
        white = await asyncio.to_thread(store.list_whitelist, server_name)
        await safe_edit_message(
            query, f"🗑 {address} убран из белого списка.\n"
                   f"Осталось в списке: {len(white)}",
            reply_markup=menu_kb(server_name))

    elif section == "sync":
        await safe_edit_message(query, f"⏳ Читаю правило на {server_name}…")
        try:
            server = await asyncio.to_thread(load_server, server_name)
            on_server = await asyncio.to_thread(read_blocks, server)
        except Exception as e:
            await query.message.reply_text(
                f"❌ Правило прочитать не удалось:\n{str(e).splitlines()[0][:200]}",
                reply_markup=menu_kb(server_name))
            return
        in_bot = await asyncio.to_thread(_addresses, server_name)
        rows = []
        if set(on_server) != set(in_bot):
            rows.append([InlineKeyboardButton(
                "🔄 Перезаписать правило списком бота",
                callback_data=f"fw_fix:{fw_token(server_name)}")])
        rows.append([InlineKeyboardButton(
            "⬅️ Назад", callback_data=f"fw_menu:{fw_token(server_name)}")])
        await query.message.reply_text(
            format_sync(server_name, on_server, in_bot),
            reply_markup=InlineKeyboardMarkup(rows))

    elif section == "fix":
        try:
            in_bot = await asyncio.to_thread(_addresses, server_name)
            applied = await asyncio.to_thread(_apply, server_name, in_bot)
        except Exception as e:
            await query.message.reply_text(
                f"❌ Не удалось перезаписать правило:\n{str(e).splitlines()[0][:200]}")
            return
        audit.log_config_change(query.from_user, "fwsync", server_name,
                                f"адресов в правиле: {len(applied)}")
        await safe_edit_message(
            query, f"✅ Правило на {server_name} перезаписано: "
                   f"адресов {len(applied)}.",
            reply_markup=menu_kb(server_name))


async def pick_callback(query, context, section: str, token: str):
    """Кнопки экрана выбора: отметить, снять, срок, заблокировать."""
    state = context.user_data.get(PICK_KEY)
    if not state:
        await query.message.reply_text(
            "Список кандидатов устарел (бот перезапускался). "
            "Откройте 🛡 Блокировка IP заново.")
        return

    if not can_configure(query.from_user):
        await query.message.reply_text(DENY)
        return

    server_name = state["server"]
    items, chosen = state["items"], state["chosen"]

    if section == "tog":
        try:
            index = int(token)
        except ValueError:
            return
        if 0 <= index < len(items):
            chosen.discard(index) if index in chosen else chosen.add(index)

    elif section == "pickall":
        chosen.update(range(len(items)))

    elif section == "picknone":
        chosen.clear()

    elif section == "pickdays":
        state["days"] = next_days(state["days"])

    elif section == "pickgo":
        if not chosen:
            await query.message.reply_text(
                "Ничего не выбрано — отметь адреса кнопками.")
            return
        addresses = [items[i]["address"] for i in sorted(chosen)
                     if 0 <= i < len(items)]
        days = state["days"]
        await safe_edit_message(
            query, f"⏳ Блокирую адресов: {len(addresses)}…")
        user = query.from_user
        try:
            await asyncio.to_thread(do_block_many, server_name, addresses,
                                    days, f"{user.id}" if user else "")
        except Exception as e:
            await query.message.reply_text(
                f"❌ Не удалось заблокировать:\n"
                f"{str(e).splitlines()[0][:200]}\n\n"
                "Правило на сервере не изменилось.")
            return
        audit.log_config_change(
            user, "fwblock", server_name,
            f"{len(addresses)} адресов из кандидатов, срок: {_days_name(days)}")
        context.user_data.pop(PICK_KEY, None)
        blocks = await asyncio.to_thread(store.list_blocks, server_name)
        white = await asyncio.to_thread(store.list_whitelist, server_name)
        await query.message.reply_text(
            f"🚫 Заблокировано адресов: {len(addresses)} "
            f"({_days_name(days)})\n\n"
            + "\n".join(f"• {a}" for a in addresses[:20])
            + ("\n…" if len(addresses) > 20 else "")
            + "\n\n" + format_menu(server_name, blocks, white),
            reply_markup=menu_kb(server_name))
        return

    await safe_edit_message(
        query, pick_text(server_name, items, chosen, state["geo"]),
        reply_markup=pick_kb(items, chosen, state["geo"], server_name,
                             state["days"]))


# ─── Приём адреса текстом ────────────────────────────────────

async def handle_firewall_text(update, context) -> bool:
    """Возвращает True, если сообщение было адресом для этого раздела."""
    pending = context.user_data.get(AWAIT_KEY)
    if not pending:
        return False
    context.user_data.pop(AWAIT_KEY, None)

    if not can_configure(update.effective_user):
        await update.message.reply_text(DENY)
        return True

    server_name = pending["server"]
    text = update.message.text or ""

    if pending["mode"] == "white":
        address = normalize_target(text.split()[0] if text.split() else "")
        if not address:
            await update.message.reply_text(
                f"❌ «{text.strip()[:60]}» — это не IP и не подсеть.")
            return True
        note = text.split(maxsplit=1)[1].strip() if len(text.split()) > 1 else ""
        try:
            was = await asyncio.to_thread(do_whitelist, server_name, address, note)
        except Exception as e:
            await update.message.reply_text(
                f"❌ Не удалось: {str(e).splitlines()[0][:200]}")
            return True
        audit.log_config_change(update.effective_user, "fwwhite", server_name, address)
        await update.message.reply_text(
            f"⚪ {address} в белом списке."
            + (" Блокировка снята." if was else ""),
            reply_markup=menu_kb(server_name))
        return True

    address, days, error = parse_block_input(text)
    if error:
        await update.message.reply_text(f"❌ {error}")
        return True

    try:
        server = await asyncio.to_thread(load_server, server_name)
        white = [i["address"] for i in
                 await asyncio.to_thread(store.list_whitelist, server_name)]
        blocked = await asyncio.to_thread(_addresses, server_name)
    except Exception as e:
        await update.message.reply_text(
            f"❌ Сервер не прочитан: {str(e).splitlines()[0][:120]}")
        return True

    reason = refuse_reason(address, server, white)
    if reason:
        await update.message.reply_text(f"⛔ {reason}")
        return True

    if len(blocked) >= MAX_ADDRESSES and address not in blocked:
        await update.message.reply_text(
            f"⛔ В правиле уже {len(blocked)} адресов при потолке "
            f"{MAX_ADDRESSES}. Сними лишние или заблокируй подсеть целиком.")
        return True

    already = " (уже заблокирован — срок продлится)" if address in blocked else ""
    text_out = (f"🚫 Заблокировать {address} на {server_name}?{already}\n\n"
                f"Срок: {'бессрочно' if days is None else f'{days} дн.'}\n"
                "Блокируется весь входящий трафик с этого адреса.")
    warning = warn_reason(address)
    if warning:
        text_out += f"\n\n{warning}"
    await update.message.reply_text(text_out, reply_markup=InlineKeyboardMarkup([[
        InlineKeyboardButton(
            "✅ Да, заблокировать",
            callback_data=f"fw_blockgo:{fw_token(server_name, address, days)}"),
        InlineKeyboardButton(
            "❌ Отмена", callback_data=f"fw_menu:{fw_token(server_name)}"),
    ]]))
    return True
