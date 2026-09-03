"""
bot/fail2ban_bot.py

Раздел «🛡 Блокировка (fail2ban)» в карточке Linux-сервера: кого поймала
автоматика, кого она пропустила и ручная блокировка кнопкой.

Раздел не заменяет fail2ban, а показывает его. Банит по-прежнему он сам —
по своим порогам и со своим сроком; бот добавляет две вещи, которых у
командной строки нет.

Первая — видимость. Список забаненных лежит в цепочках iptables, куда
никто не смотрит, и узнать, что кого-то отрезали по ошибке, можно было
только по жалобе пользователя.

Вторая — кандидаты. Порог `maxretry` считает попытки с одного адреса, а
распылённый перебор идёт по одной-две с каждого из десятков адресов, и под
порог не попадает никогда. Это не недонастройка, а свойство признака:
закрыть пробел может только человек, которому список показали.

Адреса кандидатов приходят из почтовых находок (`suspects` в сводке
Zimbra и Exchange) — тех же, по которым бот шлёт алерты.
"""
import asyncio
import itertools
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

import audit
from config_editor import can_configure
from fail2ban import ban, has_fail2ban, read_state, unban
from geoip import resolve as geo_resolve
from mail_store import read_snapshots
from refresh import load_server
from tg_utils import safe_edit_message

F2B_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
F2B_TOKENS_MAX = 500
_SEQ = itertools.count(1)

# Строк на экран. Забаненных бывают сотни, а сообщение Telegram конечно.
SHOW_LIMIT = 20

# Кандидатов показываем меньше: это выбор, а не чтение.
PICK_LIMIT = 10

DENY = "Блокировкой управляют только пользователи из TELEGRAM_DELETE_USERS."


def f2b_token(*payload) -> str:
    token = f"b{next(_SEQ)}"
    F2B_TOKENS[token] = payload
    while len(F2B_TOKENS) > F2B_TOKENS_MAX:
        F2B_TOKENS.popitem(last=False)
    return token


def default_jail(state: dict) -> str:
    """Куда идут ручные баны.

    Клетка с почтовыми портами, если она есть: основной перебор идёт туда.
    Иначе первая попавшаяся — на сервере без почты выбор всё равно один.
    """
    names = [j.get("jail") or "" for j in state.get("jails") or []]
    for name in names:
        if "auth" in name or "mail" in name or "smtp" in name:
            return name
    return names[0] if names else ""


def suspects_for(server_name: str, state: dict, snapshots=None) -> list:
    """Кандидаты: адреса из почтовых находок, которых fail2ban не поймал.

    Уже забаненные и адреса из белого списка отсеиваются — предлагать
    заблокировать то, что заблокировано, или то, что fail2ban откажется
    банить, значит тратить время человека на заведомо пустое действие.
    """
    banned = {a for jail in state.get("jails") or []
              for a in jail.get("addresses") or []}
    ignored = set(state.get("ignored") or [])

    found, seen = [], set()
    for row in snapshots if snapshots is not None else read_snapshots():
        if row.get("server") != server_name:
            continue
        for item in (row.get("summary") or {}).get("suspects") or []:
            ip = (item.get("ip") or "").strip()
            if not ip or ip in seen or ip in banned or ip in ignored:
                continue
            seen.add(ip)
            found.append({"ip": ip, "reason": item.get("reason") or ""})
    return found[:PICK_LIMIT]


def _geo(address: str, geo: dict) -> str:
    tag = (geo or {}).get(address)
    return f" ({tag})" if tag else ""


def format_state(server_name: str, state: dict, candidates: list,
                 geo: dict = None) -> str:
    jails = state.get("jails") or []
    if not jails:
        return (f"🛡 Блокировка — {server_name}\n\n"
                "fail2ban не отвечает или клеток нет.")

    lines = [f"🛡 Блокировка — {server_name}",
             "Банит fail2ban сам, по своим порогам. Бот показывает и "
             "позволяет добавить вручную.\n"]

    for jail in jails:
        lines.append(
            f"📦 {jail['jail']} — заблокировано {jail['banned_now']}, "
            f"всего за время работы {jail['banned_total']}, "
            f"попыток поймано {jail['failed_total']}")
        for address in (jail.get("addresses") or [])[:SHOW_LIMIT]:
            lines.append(f"   🔴 {address}{_geo(address, geo)}")
        hidden = len(jail.get("addresses") or []) - SHOW_LIMIT
        if hidden > 0:
            lines.append(f"   … и ещё {hidden}")
        lines.append("")

    if state.get("ignored"):
        lines.append("⚪ Белый список fail2ban: "
                     + ", ".join(state["ignored"][:10]))
        lines.append("")

    if candidates:
        lines.append("🟠 Автоматика их не поймала — по одной-две попытки с "
                     "адреса не добирают до порога:")
        for item in candidates:
            lines.append(f"   {item['ip']}{_geo(item['ip'], geo)} — "
                         f"{item['reason']}")
    else:
        lines.append("Кандидатов из почтовых находок нет.")

    return "\n".join(lines)


def menu_kb(server_name: str, state: dict, candidates: list) -> InlineKeyboardMarkup:
    jail = default_jail(state)
    rows = [[InlineKeyboardButton(
        f"🚫 Заблокировать {item['ip']}",
        callback_data=f"f2b_ban:{f2b_token(server_name, jail, item['ip'])}",
    )] for item in candidates[:5]]

    banned = [a for j in state.get("jails") or []
              for a in (j.get("addresses") or [])]
    for address in banned[:5]:
        owner = next(j["jail"] for j in state["jails"]
                     if address in (j.get("addresses") or []))
        rows.append([InlineKeyboardButton(
            f"✅ Разбанить {address}",
            callback_data=f"f2b_unban:{f2b_token(server_name, owner, address)}",
        )])

    rows.append([
        InlineKeyboardButton(
            "🔄 Обновить",
            callback_data=f"f2b_menu:{f2b_token(server_name)}"),
        InlineKeyboardButton("← Назад", callback_data=f"server:{server_name}"),
    ])
    return InlineKeyboardMarkup(rows)


def _trouble(server_name: str, error: str) -> str:
    """Понятный текст вместо общего «произошла ошибка».

    Причин ровно две, и обе чинятся на сервере, а не в боте: нет правила
    sudo на fail2ban-client либо сам fail2ban не запущен. Общая ошибка
    заставляла бы искать это вслепую.
    """
    first = (error or "").strip().splitlines()[0][:200] if error else ""
    hint = ""
    if "sudo" in first.lower() or "password" in first.lower():
        hint = ("\n\nПохоже, нет правила sudo. Учётке SSH нужно разрешить "
                "без пароля: fail2ban-client status, get * ignoreip, "
                "set * banip, set * unbanip.")
    elif "not find" in first.lower() or "command not found" in first.lower():
        hint = "\n\nПохоже, fail2ban на сервере не установлен."
    elif "socket" in first.lower() or "refused" in first.lower():
        hint = "\n\nПохоже, служба fail2ban не запущена."
    return (f"🛡 Блокировка — {server_name}\n\n"
            f"Не удалось прочитать состояние fail2ban.\n{first}{hint}")


async def _show(query, server_name: str, note: str = ""):
    server = load_server(server_name)
    try:
        state = await asyncio.to_thread(read_state, server)
    except Exception as e:
        await safe_edit_message(
            query, _trouble(server_name, str(e)),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(
                    "🔄 Повторить",
                    callback_data=f"f2b_menu:{f2b_token(server_name)}"),
                InlineKeyboardButton("← Назад",
                                     callback_data=f"server:{server_name}"),
            ]]))
        return
    candidates = suspects_for(server_name, state)

    addresses = [a for j in state.get("jails") or []
                 for a in (j.get("addresses") or [])]
    addresses += [c["ip"] for c in candidates]
    try:
        geo = await asyncio.to_thread(geo_resolve, addresses)
    except Exception:
        geo = {}

    text = format_state(server_name, state, candidates, geo)
    if note:
        text = f"{note}\n\n{text}"
    await safe_edit_message(query, text,
                            reply_markup=menu_kb(server_name, state, candidates))


async def fail2ban_callback(query, context):
    section, _, token = query.data[len("f2b_"):].partition(":")
    payload = F2B_TOKENS.get(token)
    if payload is None:
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку заново.")
        return
    server_name = payload[0]

    if section == "menu":
        await _show(query, server_name)
        return

    if not can_configure(query.from_user):
        await query.message.reply_text(DENY)
        return

    _, jail, address = payload
    server = load_server(server_name)
    action, verb = (ban, "заблокирован") if section == "ban" else (unban,
                                                                  "разблокирован")
    try:
        await asyncio.to_thread(action, server, jail, address)
    except Exception as e:
        await query.message.reply_text(
            f"Не вышло: {str(e).splitlines()[0][:200]}")
        return

    audit.log_config_change(
        query.from_user,
        "fail2ban ban" if section == "ban" else "fail2ban unban",
        target=f"{server_name}:{address}", details=f"клетка {jail}")

    # Бан применяется асинхронно: fail2ban-client возвращает управление
    # раньше, чем правило появляется в iptables. Без паузы список
    # перечитается прежним и покажет, будто ничего не произошло.
    await asyncio.sleep(1.5)
    await _show(query, server_name, note=f"✅ {address} {verb} ({jail})")
