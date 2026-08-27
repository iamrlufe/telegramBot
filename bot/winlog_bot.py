"""
bot/winlog_bot.py

Раздел «📜 Логи Windows» в карточке сервера: перезагрузки и падения,
упавшие службы, ошибки дисков, неудачные входы, ошибки приложений.

Кнопка показывается у серверов типа windows. Устройство работы то же, что
у SQL-логов: состояние живёт под токеном (callback_data ограничен 64
байтами), данные читаются в момент нажатия, алертов отсюда не шлётся.
"""
import asyncio
import itertools
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

from winlog import (
    read_reboots, read_service_failures, read_disk_errors,
    read_app_errors, read_failed_logons, group_failed_logons,
    explain_event, friendly_winlog_error,
)
from refresh import load_server
from server_check import server_type
from tg_utils import safe_edit_message

WIN_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
WIN_TOKENS_MAX = 500
_SEQ = itertools.count(1)

PERIOD_SHORT_HOURS = 24
PERIOD_LONG_HOURS = 24 * 7
SHOW_LIMIT = 15


def win_token(server_name: str, hours: int) -> str:
    token = f"w{next(_SEQ)}"
    WIN_TOKENS[token] = (server_name, hours)
    while len(WIN_TOKENS) > WIN_TOKENS_MAX:
        WIN_TOKENS.popitem(last=False)
    return token


def has_winlog(server: dict) -> bool:
    """Event Log есть только у Windows: device и vmware опрашиваются иначе."""
    return server_type(server) == "windows"


def period_name(hours: int) -> str:
    return "24 часа" if hours <= PERIOD_SHORT_HOURS else "7 дней"


def winlog_menu_kb(server_name: str, hours: int) -> InlineKeyboardMarkup:
    def cb(section: str) -> str:
        return f"winlog_{section}:{win_token(server_name, hours)}"

    other = PERIOD_LONG_HOURS if hours <= PERIOD_SHORT_HOURS else PERIOD_SHORT_HOURS
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("♻️ Перезагрузки", callback_data=cb("reboot")),
            InlineKeyboardButton("🛠 Службы", callback_data=cb("service")),
        ],
        [
            InlineKeyboardButton("💽 Диски", callback_data=cb("disk")),
            InlineKeyboardButton("🔐 Входы", callback_data=cb("logon")),
        ],
        [
            InlineKeyboardButton("⚠️ Приложения", callback_data=cb("app")),
        ],
        [
            InlineKeyboardButton(f"⏱ {period_name(other)}",
                                 callback_data=f"winlog_menu:{win_token(server_name, other)}"),
            InlineKeyboardButton("◀️ К серверу", callback_data=f"server:{server_name}"),
        ],
    ])


def section_kb(server_name: str, hours: int, section: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("◀️ К логам",
                                 callback_data=f"winlog_menu:{win_token(server_name, hours)}"),
            InlineKeyboardButton("🔄 Обновить",
                                 callback_data=f"winlog_{section}:{win_token(server_name, hours)}"),
        ],
    ])


# ─── Форматирование ──────────────────────────────────────────

def _when(value) -> str:
    if not isinstance(value, str) or len(value) < 16:
        return value or ""
    return f"{value[8:10]}.{value[5:7]} {value[11:16]}"


def _short(text, limit: int) -> str:
    if not isinstance(text, str):
        return ""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def _format_events(rows: list, title: str, hours: int, empty: str) -> str:
    if not rows:
        return f"{title} за {period_name(hours)}\n\n{empty}"

    # Одна и та же запись повторяется десятками строк (падающая по кругу
    # служба, сыплющийся диск) — схлопываем, иначе экран занимает одна беда.
    grouped = {}
    for row in rows:
        key = (row.get("id"), _short(row.get("msg"), 200))
        item = grouped.get(key)
        if item is None:
            grouped[key] = {"id": row.get("id"), "src": row.get("src"),
                            "msg": _short(row.get("msg"), 200),
                            "last": row.get("d") or "", "count": 1}
        else:
            item["count"] += 1
            item["last"] = max(item["last"], row.get("d") or "")
    items = sorted(grouped.values(), key=lambda i: i["last"], reverse=True)

    lines = [f"{title} за {period_name(hours)} — {len(rows)} событий\n"]
    for item in items[:SHOW_LIMIT]:
        head = f"{_when(item['last'])}  код {item['id']}"
        if item["count"] > 1:
            head += f"  · {item['count']} раз"
        lines.append(head)
        explanation = explain_event(item["id"])
        if explanation:
            lines.append(f"   ↳ {explanation}")
        if item["msg"]:
            lines.append(f"   {item['msg']}")
    if len(items) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(items) - SHOW_LIMIT} видов событий")
    return "\n".join(lines)


def format_reboots(rows: list, hours: int) -> str:
    return _format_events(
        rows, "♻️ Перезагрузки и падения", hours,
        "Записей нет: система не перезагружалась и аварийно не завершалась.\n\n"
        "Ищутся коды 6008 (неожиданное завершение), 41 (Kernel-Power), "
        "1074/1076 (кто инициировал перезагрузку), 6005/6006 (старт и "
        "штатное выключение).")


def format_services(rows: list, hours: int) -> str:
    return _format_events(
        rows, "🛠 Сбои служб", hours,
        "Ни одна служба не падала и не зависала при запуске.\n\n"
        "Ищутся коды 7031/7034 (служба завершилась неожиданно), "
        "7000/7009 (не смогла запуститься), 7011 (не ответила вовремя).")


def format_disks(rows: list, hours: int) -> str:
    return _format_events(
        rows, "💽 Ошибки дисков", hours,
        "Ошибок дисков, контроллеров и файловой системы нет.\n\n"
        "Ищутся коды 7/11/51 (сбойные блоки и ошибки контроллера), "
        "55 (повреждение структуры NTFS), 129/153 (хранилище не отвечает), "
        "52 (диск предупреждает об отказе).")


def format_apps(rows: list, hours: int) -> str:
    return _format_events(
        rows, "⚠️ Ошибки приложений", hours,
        "Ошибок и критических событий в журнале приложений нет.")


def format_logons(rows: list, hours: int) -> str:
    if not rows:
        return (f"🔐 Неудачные входы за {period_name(hours)}\n\n"
                "Отказов входа нет.\n\nЕсли ожидали увидеть записи, проверьте, "
                "что учётная запись мониторинга состоит в группе Event Log "
                "Readers: без неё журнал Security недоступен.")
    total = sum(row.get("count", 1) for row in rows)
    lines = [f"🔐 Неудачные входы за {period_name(hours)} — {total} событий\n"]
    for row in rows[:SHOW_LIMIT]:
        user = row.get("user") or "неизвестный пользователь"
        domain = row.get("domain") or ""
        who = f"{domain}\\{user}" if domain and domain != "-" else user
        head = f"{_when(row.get('last'))}  {who}"
        source = row.get("ip") or row.get("host") or ""
        if source and source != "-":
            head += f"  ← {source}"
        else:
            head += "  ← источник не указан"
        lines.append(head)
        detail = row.get("reason") or f"код {row.get('code') or '?'}"
        if row.get("how"):
            detail += f" · {row['how']}"
        if row.get("count", 1) > 1:
            detail += f" · {row['count']} попыток"
        lines.append(f"       {detail}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} источников")
    return "\n".join(lines)


def _read_logons(server, hours):
    return group_failed_logons(read_failed_logons(server, hours))


SECTIONS = {
    "reboot": (read_reboots, format_reboots),
    "service": (read_service_failures, format_services),
    "disk": (read_disk_errors, format_disks),
    "app": (read_app_errors, format_apps),
    "logon": (_read_logons, format_logons),
}


async def winlog_callback(query, context):
    section, _, token = query.data[len("winlog_"):].partition(":")

    state = WIN_TOKENS.get(token)
    if state is None:
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку сервера заново."
        )
        return
    server_name, hours = state

    if section == "menu":
        await safe_edit_message(
            query,
            f"📜 Логи Windows — {server_name}\nПериод: {period_name(hours)}",
            reply_markup=winlog_menu_kb(server_name, hours),
        )
        return

    handler = SECTIONS.get(section)
    if handler is None:
        return
    reader, formatter = handler

    await safe_edit_message(query, f"⏳ Читаю журнал событий: {server_name}…")
    try:
        server = await asyncio.to_thread(load_server, server_name)
        rows = await asyncio.to_thread(reader, server, hours)
        text = formatter(rows, hours)
    except Exception as e:
        text = f"⚠️ Не удалось прочитать журнал {server_name}:\n{friendly_winlog_error(e)}"

    await safe_edit_message(query, text,
                            reply_markup=section_kb(server_name, hours, section))
