"""
bot/sqllog_bot.py

Раздел «🗄 SQL-логи» в карточке сервера: отказы входа, ошибки копирования,
ошибки движка, история джоб Agent и история копий из msdb.

Кнопка показывается у серверов с флагом `dbsize` — он и означает «здесь MSSQL».
Отдельного флага нет намеренно: два переключателя на один и тот же факт
расходятся при первой же правке конфига.

Состояние (сервер + период) живёт в кэше под коротким токеном — как в
dirdig: callback_data ограничен 64 байтами, а имена серверов бывают длинными.
"""
import asyncio
import itertools
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

from mssql_log import (
    read_login_errors, read_backup_errors, read_engine_errors,
    read_agent_jobs, read_backup_history, friendly_sql_error,
)
from refresh import load_server
from tg_utils import safe_edit_message

SQL_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
SQL_TOKENS_MAX = 500
_SEQ = itertools.count(1)

PERIOD_SHORT_HOURS = 24
PERIOD_LONG_HOURS = 24 * 7

# Строк на экран. Больше не помещается осмысленно: Telegram режет сообщение,
# а глазами всё равно читают верхушку.
SHOW_LIMIT = 20


def sql_token(server_name: str, hours: int) -> str:
    token = f"q{next(_SEQ)}"
    SQL_TOKENS[token] = (server_name, hours)
    while len(SQL_TOKENS) > SQL_TOKENS_MAX:
        SQL_TOKENS.popitem(last=False)
    return token


def has_mssql(server: dict) -> bool:
    """Признак сервера с MSSQL — тот же флаг, что и у сбора размеров баз."""
    return bool(server.get("dbsize")) and server.get("type", "windows") == "windows"


def period_name(hours: int) -> str:
    return "24 часа" if hours <= PERIOD_SHORT_HOURS else "7 дней"


def sqllog_menu_kb(server_name: str, hours: int) -> InlineKeyboardMarkup:
    def cb(section: str) -> str:
        return f"sqllog_{section}:{sql_token(server_name, hours)}"

    other = PERIOD_LONG_HOURS if hours <= PERIOD_SHORT_HOURS else PERIOD_SHORT_HOURS
    switch = f"sqllog_menu:{sql_token(server_name, other)}"
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔐 Ошибки входа", callback_data=cb("login")),
            InlineKeyboardButton("💾 Ошибки бэкапа", callback_data=cb("backup")),
        ],
        [
            InlineKeyboardButton("⚠️ Движок", callback_data=cb("engine")),
            InlineKeyboardButton("🕒 Джобы Agent", callback_data=cb("jobs")),
        ],
        [
            InlineKeyboardButton("📼 Копии из msdb", callback_data=cb("history")),
        ],
        [
            InlineKeyboardButton(f"⏱ {period_name(other)}", callback_data=switch),
            InlineKeyboardButton("◀️ К серверу", callback_data=f"server:{server_name}"),
        ],
    ])


def section_kb(server_name: str, hours: int, section: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("◀️ К SQL-логам",
                                 callback_data=f"sqllog_menu:{sql_token(server_name, hours)}"),
            InlineKeyboardButton("🔄 Обновить",
                                 callback_data=f"sqllog_{section}:{sql_token(server_name, hours)}"),
        ],
    ])


# ─── Форматирование ──────────────────────────────────────────

def format_logins(data, hours: int) -> str:
    rows = data.get("rows", []) if isinstance(data, dict) else data
    truncated = data.get("truncated") if isinstance(data, dict) else False
    if not rows:
        return (f"🔐 Ошибки входа за {period_name(hours)}\n\nНет отказов входа. "
                "Если ожидали увидеть записи — учтите, что ERRORLOG обнуляется "
                "при перезапуске службы SQL.")
    total = sum(row.get("count", 1) for row in rows)
    lines = [f"🔐 Ошибки входа за {period_name(hours)} — {total} записей\n"]
    for row in rows[:SHOW_LIMIT]:
        when = _when(row.get("last"))
        user = row.get("user") or "неизвестный логин"
        head = f"{when}  {user}"
        # Адрес есть не в каждом сообщении: ошибка 4060 («Cannot open
        # database») пишется без [CLIENT], и молчание тут выглядело бы как
        # «вход был локальным».
        head += f"  ← {row['client']}" if row.get("client") else "  ← адрес не записан"
        if row.get("database"):
            head += f"  → база {row['database']}"
        lines.append(head)
        detail = row.get("reason") or "причина не указана"
        if row.get("state"):
            detail += f" (state {row['state']})"
        if row.get("count", 1) > 1:
            detail += f" · {row['count']} попыток"
        lines.append(f"       {detail}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} источников, показаны свежие")
    if truncated:
        lines.append("\n⚠️ Достигнут предел выборки: отказов за период больше, "
                     "показаны самые свежие.")
    return "\n".join(lines)


def format_backup_errors(data: dict, hours: int) -> str:
    engine, jobs = data.get("engine", []), data.get("jobs", [])
    lines = [f"💾 Ошибки бэкапа за {period_name(hours)}\n"]
    if not engine and not jobs:
        lines.append("Ошибок копирования не найдено.")
    for row in engine[:SHOW_LIMIT]:
        when = _when(row.get("d"))
        lines.append(f"❌ {when}")
        lines.append(f"   {_short(row.get('t'), 300)}")
    for row in jobs[:SHOW_LIMIT]:
        when = _when(row.get("when"))
        step = row.get("stepname") or f"шаг {row.get('step')}"
        lines.append(f"❌ {when}  джоб «{row.get('job')}», {step}")
        if row.get("msg"):
            lines.append(f"   {_short(row.get('msg'), 300)}")
    for err in data.get("errors", []):
        lines.append(f"\n⚠️ {err}")
    return "\n".join(lines)


def format_engine(rows: list, hours: int) -> str:
    if not rows:
        return (f"⚠️ Ошибки движка за {period_name(hours)}\n\n"
                "Ничего серьёзного: нет записей severity ≥ 17, повреждений "
                "и предупреждений о медленном вводе-выводе.")
    lines = [f"⚠️ Ошибки движка за {period_name(hours)} — {len(rows)} записей\n"]
    for row in rows[:SHOW_LIMIT]:
        lines.append(f"{_when(row.get('d'))}  {_short(row.get('t'), 300)}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} записей")
    return "\n".join(lines)


JOB_STATUS = {0: "❌ упал", 1: "✅ успех", 2: "🔁 повтор",
              3: "⏹ отменён", 4: "⏳ выполняется"}


def format_jobs(rows: list, hours: int) -> str:
    if not rows:
        return (f"🕒 Джобы Agent за {period_name(hours)}\n\nЗапусков не было. "
                "Стоит проверить, что служба SQL Server Agent запущена.")
    lines = [f"🕒 Джобы Agent за {period_name(hours)} — {len(rows)} запусков\n"]
    for row in rows[:SHOW_LIMIT]:
        status = JOB_STATUS.get(row.get("status"), "?")
        line = f"{status}  {_when(row.get('when'))}  {row.get('job')}"
        if row.get("took"):
            line += f"  ({row['took']})"
        lines.append(line)
        if row.get("status") == 0 and row.get("msg"):
            lines.append(f"   {_short(row.get('msg'), 200)}")
    return "\n".join(lines)


BACKUP_TYPE = {"D": "Full", "I": "Diff", "L": "Log", "F": "File", "G": "FileDiff"}


def format_history(rows: list, hours: int) -> str:
    if not rows:
        return (f"📼 Копии из msdb за {period_name(hours)}\n\n"
                "SQL не записал ни одной копии. "
                "Если файлы на диске при этом появляются — их делает не SQL "
                "(например, снапшот гипервизора), и RESTORE из них не гарантирован.")
    lines = [f"📼 Копии из msdb за {period_name(hours)} — {len(rows)} шт.\n"]
    for row in rows[:SHOW_LIMIT]:
        btype = BACKUP_TYPE.get(row.get("btype"), row.get("btype") or "?")
        size = row.get("size_gb")
        size_txt = f"{size} ГБ" if size not in (None, "") else "?"
        lines.append(f"{_when(row.get('finished'))}  {row.get('db')}  "
                     f"{btype}  {size_txt}")
        if row.get("device"):
            lines.append(f"   {_short(row.get('device'), 120)}")
    if len(rows) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(rows) - SHOW_LIMIT} записей")
    return "\n".join(lines)


def _when(value) -> str:
    """'2026-08-27 00:00:00' → '27.08 00:00'.

    Срез ISO-строки давал '08-27 00:00': месяц-день читается как день-месяц
    и сбивает с толку, а год для суточного окна не нужен.
    """
    if not isinstance(value, str) or len(value) < 16:
        return value or ""
    return f"{value[8:10]}.{value[5:7]} {value[11:16]}"


def _short(text, limit: int) -> str:
    """Сообщения SQL многострочные — в списке нужна одна строка."""
    if not isinstance(text, str):
        return ""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


# ─── Callback ────────────────────────────────────────────────

SECTIONS = {
    "login": (read_login_errors, format_logins),
    "backup": (read_backup_errors, format_backup_errors),
    "engine": (read_engine_errors, format_engine),
    "jobs": (read_agent_jobs, format_jobs),
    "history": (read_backup_history, format_history),
}


async def sqllog_callback(query, context):
    data = query.data
    section, _, token = data[len("sqllog_"):].partition(":")

    state = SQL_TOKENS.get(token)
    if state is None:
        # Кэш живёт в памяти процесса: после рестарта бота старые кнопки мертвы.
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку сервера заново."
        )
        return
    server_name, hours = state

    if section == "menu":
        await safe_edit_message(
            query,
            f"🗄 SQL-логи — {server_name}\nПериод: {period_name(hours)}",
            reply_markup=sqllog_menu_kb(server_name, hours),
        )
        return

    handler = SECTIONS.get(section)
    if handler is None:
        return
    reader, formatter = handler

    await safe_edit_message(query, f"⏳ Читаю SQL-лог: {server_name}…")
    try:
        server = await asyncio.to_thread(load_server, server_name)
        if section == "history":
            # msdb фильтруется днями, а подпись периода — общая для всех разделов
            days = max(1, hours // 24)
            rows = await asyncio.to_thread(reader, server, days)
            text = formatter(rows, hours)
        else:
            rows = await asyncio.to_thread(reader, server, hours)
            text = formatter(rows, hours)
    except Exception as e:
        text = f"⚠️ Не удалось прочитать журнал {server_name}:\n{friendly_sql_error(e)}"

    await safe_edit_message(query, text,
                            reply_markup=section_kb(server_name, hours, section))
