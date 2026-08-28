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
    explain_engine_error, explain_backup_error, summarize_job_message,
    JOB_MESSAGE_TRUNCATED,
)
from mssql_health import (
    read_log_files, read_checkdb, read_activity, read_file_space,
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
            InlineKeyboardButton("📓 Журналы транзакций", callback_data=cb("tlog")),
            InlineKeyboardButton("🩺 CHECKDB", callback_data=cb("checkdb")),
        ],
        [
            InlineKeyboardButton("⏳ Что идёт сейчас", callback_data=cb("now")),
            InlineKeyboardButton("📦 Файлы БД", callback_data=cb("files")),
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
        lines.append(f"❌ {_when(row.get('d'))}")
        lines.append(f"   {_short(row.get('t'), 300)}")
        why = explain_backup_error(row.get("t") or "")
        if why:
            lines.append(f"   ↳ {why}")
    for row in jobs[:SHOW_LIMIT]:
        step = row.get("stepname") or f"шаг {row.get('step')}"
        lines.append(f"❌ {_when(row.get('when'))}  джоб «{row.get('job')}», {step}")
        raw = row.get("msg") or ""
        summary = summarize_job_message(raw, limit=300)
        if summary:
            lines.append(f"   {summary}")
        why = (explain_backup_error(raw)
               or (JOB_MESSAGE_TRUNCATED if raw and not summary else ""))
        if why:
            lines.append(f"   ↳ {why}")
    for err in data.get("errors", []):
        lines.append(f"\n⚠️ {err}")
    return "\n".join(lines)


def format_engine(rows: list, hours: int) -> str:
    if not rows:
        return (f"⚠️ Ошибки движка за {period_name(hours)}\n\n"
                "Записей нет. Проверялись четыре вида:\n"
                "• severity 17+ — нехватка ресурсов и фатальные ошибки;\n"
                "• коды 823/824/825 — сбои чтения страниц с диска;\n"
                "• ввод-вывод дольше 15 секунд — тормоза хранилища;\n"
                "• взаимоблокировки.\n\n"
                "Пустой список — не всегда «всё хорошо»: ERRORLOG обнуляется "
                "при перезапуске службы SQL и по sp_cycle_errorlog, "
                "и тогда смотреть попросту не в чем.")

    # Одна и та же ошибка повторяется десятками строк (особенно 825 и жалобы
    # на ввод-вывод) — без схлопывания экран занимает одна проблема.
    grouped = {}
    for row in rows:
        text = _short(row.get("t"), 300)
        item = grouped.get(text)
        if item is None:
            grouped[text] = {"text": text, "last": row.get("d") or "", "count": 1}
        else:
            item["count"] += 1
            item["last"] = max(item["last"], row.get("d") or "")
    items = sorted(grouped.values(), key=lambda i: i["last"], reverse=True)

    lines = [f"⚠️ Ошибки движка за {period_name(hours)} — {len(rows)} записей\n"]
    for item in items[:SHOW_LIMIT]:
        head = f"{_when(item['last'])}  {item['text']}"
        if item["count"] > 1:
            head += f"  · {item['count']} раз"
        lines.append(head)
        explanation = explain_engine_error(item["text"])
        if explanation:
            lines.append(f"   ↳ {explanation}")
    if len(items) > SHOW_LIMIT:
        lines.append(f"\n… ещё {len(items) - SHOW_LIMIT} видов записей")
    return "\n".join(lines)


JOB_STATUS = {0: "❌ упал", 1: "✅ успех", 2: "🔁 повтор",
              3: "⏹ отменён", 4: "⏳ выполняется"}


def format_jobs(data, hours: int) -> str:
    rows = data.get("rows", []) if isinstance(data, dict) else data
    total = data.get("jobs_total", 0) if isinstance(data, dict) else 0

    if not rows:
        head = f"🕒 Джобы Agent за {period_name(hours)}\n\nЗапусков не найдено.\n\n"
        if total > 0:
            return head + (f"Джоб видно: {total}. Значит Agent доступен, но за "
                           "период ни один джоб не отработал — проверьте их "
                           "расписание, а также что копии делает именно Agent, "
                           "а не сторонний планировщик или Veeam.")
        if total == 0:
            # Самая частая причина, и она не выглядит как ошибка: без роли
            # SQLAgentReaderRole учётная запись видит только собственные джобы,
            # а чужие молча не попадают в выборку.
            return head + ("Не видно ни одного джоба. Скорее всего учётной "
                           "записи мониторинга не выдана роль SQLAgentReaderRole "
                           "в базе msdb: без неё чужие джобы не видны, и SQL "
                           "не возвращает ошибку — список просто пуст. "
                           "Второй вариант: джобов на сервере действительно нет.")
        return head + ("Список джоб недоступен — учётной записи не хватает прав "
                       "в базе msdb (нужна роль SQLAgentReaderRole).")

    lines = [f"🕒 Джобы Agent за {period_name(hours)} — {len(rows)} запусков\n"]
    for row in rows[:SHOW_LIMIT]:
        status = JOB_STATUS.get(row.get("status"), "?")
        line = f"{status}  {_when(row.get('when'))}  {row.get('job')}"
        if row.get("took"):
            line += f"  ({row['took']})"
        lines.append(line)
        if row.get("status") == 0 and row.get("msg"):
            # Пустая суть означает обрезанное Agent-ом сообщение: пустая
            # строка вместо неё выглядела бы как «джоб упал молча».
            summary = summarize_job_message(row.get("msg"), limit=200)
            lines.append(f"   {summary}" if summary
                         else "   текст шага не сохранился — только шапка dtexec")
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


def format_tlog(rows: list, hours: int) -> str:
    if not rows:
        return "📓 Журналы транзакций\n\nНет пользовательских баз или нет доступа."
    lines = ["📓 Журналы транзакций\n"]
    for row in rows[:SHOW_LIMIT]:
        lines.append(f"{row.get('db')}  журнал {row.get('log_gb')} ГБ  "
                     f"(данные {row.get('data_gb')} ГБ)  {row.get('model')}")
        wait = (row.get("waitfor") or "").strip()
        if wait and wait.upper() != "NOTHING":
            detail = row.get("why") or wait
            lines.append(f"   ⚠️ {detail}")
    lines.append("\nЖурнал растёт, пока его нельзя переиспользовать. Модель Full "
                 "без регулярного BACKUP LOG — самая частая причина.")
    return "\n".join(lines)


def format_checkdb(rows: list, hours: int) -> str:
    if not rows:
        return ("🩺 DBCC CHECKDB\n\nДанные не получены. Чтение даты последней "
                "проверки идёт через DBCC DBINFO и требует прав sysadmin.")
    lines = ["🩺 Последняя проверка целостности\n"]
    for row in rows[:SHOW_LIMIT]:
        last = row.get("lastgood") or ""
        days = row.get("days")
        # 1900-01-01 — заглушка SQL: проверки не было ни разу.
        if not last or last.startswith("1900"):
            lines.append(f"❌ {row.get('db')} — не проверялась ни разу")
            continue
        mark = "✅" if isinstance(days, int) and days <= 14 else "⚠️"
        lines.append(f"{mark} {row.get('db')} — {_when(last)}"
                     f"{f', {days} дн. назад' if days is not None else ''}")
    lines.append("\nБез CHECKDB повреждение находят при попытке восстановиться, "
                 "когда испорченные копии уже вытеснили здоровые.")
    return "\n".join(lines)


def format_activity(rows: list, hours: int) -> str:
    if not rows:
        return ("⏳ Сейчас на сервере\n\nДолгих запросов и блокировок нет: "
                "ничего не выполняется дольше 5 секунд и никто никого не ждёт.")
    lines = ["⏳ Сейчас на сервере\n"]
    for row in rows[:SHOW_LIMIT]:
        head = (f"spid {row.get('spid')}  {row.get('sec')} с  "
                f"{row.get('db') or '?'}  {row.get('login') or ''}")
        lines.append(head)
        blocker = row.get("blocker")
        if blocker and str(blocker) not in ("0", "None"):
            lines.append(f"   ⛔ заблокирован сессией {blocker}")
        source = " · ".join(x for x in (row.get("hostname"), row.get("app")) if x)
        if source:
            lines.append(f"   {_short(source, 90)}")
        if row.get("sqltext"):
            lines.append(f"   {_short(row.get('sqltext'), 150)}")
    return "\n".join(lines)


def format_files(rows: list, hours: int) -> str:
    if not rows:
        return "📦 Файлы БД\n\nДанные не получены."
    capped = [r for r in rows if r.get("capped")]
    lines = ["📦 Файлы БД\n"]
    if capped:
        lines.append("⚠️ Не смогут вырасти (автоприрост выключен или задан предел):")
        for row in capped[:SHOW_LIMIT]:
            lines.append(f"   {row.get('db')} · {row.get('fname')} "
                         f"({row.get('kind')})  {row.get('size_gb')} ГБ")
        lines.append("")
    lines.append("Крупнейшие файлы:")
    for row in rows[:SHOW_LIMIT]:
        limit = row.get("limit_gb")
        tail = f"  предел {limit} ГБ" if limit else ""
        lines.append(f"   {row.get('db')} · {row.get('fname')} "
                     f"({row.get('kind')})  {row.get('size_gb')} ГБ{tail}")
    lines.append("\nМесто на диске и возможность вырасти — разные вещи: файл с "
                 "выключенным автоприростом встаёт, когда диск ещё наполовину пуст.")
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
    "tlog": (read_log_files, format_tlog),
    "checkdb": (read_checkdb, format_checkdb),
    "now": (read_activity, format_activity),
    "files": (read_file_space, format_files),
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
            f"🗄 SQL — {server_name}\nПериод журналов: {period_name(hours)}\n"
            f"Разделы состояния (журналы транзакций, CHECKDB, файлы, "
            f"«что идёт сейчас») период не используют.",
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
        if section in ("tlog", "checkdb", "now", "files"):
            # Состояние — это «сейчас», окно времени к нему неприменимо
            rows = await asyncio.to_thread(reader, server)
            text = formatter(rows, hours)
        elif section == "history":
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
