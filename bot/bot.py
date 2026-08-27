import os
import re
import json
import asyncio
import traceback
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from telegram import (
    Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton,
    BotCommand, BotCommandScopeChat, BotCommandScopeDefault,
    BotCommandScopeAllGroupChats,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

from charts import build_server_chart, build_dashboard_chart, build_top_dirs_chart, period_label
from db import (
    get_servers_status, get_server_detail, get_disk_usage, get_server_disks,
    get_problems, build_report,
)
from net_tools import http_report, ports_report, resolve_target, single_port_report
from ping_tools import load_targets, ping_report
from refresh import refresh_server, load_server
from dirdig import DIG_MAX_DEPTH, DIG_TOKENS, dig_kb
from sqllog_bot import has_mssql, sql_token, sqllog_callback
from winlog_bot import has_winlog, win_token, winlog_callback
from exchange_bot import has_exchange, ex_token, exchange_callback
from remote_ops import get_top_dirs, restart_service, reboot_server
from backup_bot import (
    cmd_backup_menu,
    backup_callback,
    send_backup_charts,
    send_backup_digest_report,
)
from config_editor import (
    cmd_config_menu,
    config_callback,
    handle_config_text,
    can_configure,
    STATE_KEY as CONFIG_STATE_KEY,
)
from pg_admin import get_pg_stats, cleanup_options_kb
import audit
from alerts_ack import ack_alert
from tg_utils import (
    safe_edit_message,
    safe_answer_query,
    load_muted,
    save_muted,
    mute_expired,
    split_message,
)


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Переменная окружения {name} не задана. Проверьте .env")
    return value


def _require_int_env(name: str) -> int:
    value = _require_env(name)
    try:
        return int(value)
    except ValueError:
        raise RuntimeError(f"Переменная окружения {name}={value!r} должна быть числом (Telegram ID)")


ALLOWED_USER_ID = _require_int_env("TELEGRAM_ALLOWED_USER_ID")
_group_env = os.getenv("TELEGRAM_GROUP_ID")
GROUP_ID = int(_group_env) if _group_env else None
NOTIFY_ID = GROUP_ID if GROUP_ID else ALLOWED_USER_ID
ALMATY = ZoneInfo("Asia/Almaty")
ALERTS_DISABLED_FILE = "/app/data/alerts_disabled.json"

KEYBOARD = [
    ["🖥 Серверы"],
    ["📊 Дашборд"],
    ["📡 Пинг"],
    ["📋 Отчёт"],
    ["🚨 Проблемы"],
    ["💾 Бэкапы"],
    ["⚙️ Настройка"],
]

MENU_LABELS = {label for row in KEYBOARD for label in row}


# Меню команд, которое Telegram показывает по нажатию "/" в поле ввода.
# Ставится точечно (личка владельца + группа), а глобальный список чистится —
# иначе подсказки видят посторонние, хотя is_allowed их всё равно не пустит.
BOT_COMMANDS = [
    BotCommand("start", "Меню и клавиатура"),
    BotCommand("servers", "Статус серверов"),
    BotCommand("dashboard", "Дашборд-график"),
    BotCommand("report", "Текстовый отчёт"),
    BotCommand("problems", "Текущие проблемы"),
    BotCommand("ping", "Пинг: /ping [хост]"),
    BotCommand("graph", "График: /graph СЕРВЕР [7d|12h]"),
    BotCommand("mute", "Заглушить алерты: /mute СЕРВЕР"),
    BotCommand("unmute", "Вернуть алерты: /unmute СЕРВЕР"),
    BotCommand("mutes", "Список заглушённых"),
    BotCommand("pgsize", "Размеры таблиц PostgreSQL"),
    BotCommand("pgcleanup", "Очистка истории (только админам)"),
]


async def setup_commands(app):
    """Регистрирует меню команд. Сбой сети не должен ронять старт бота.

    Каждый scope ставится отдельно: раньше все вызовы стояли под одним try,
    и падение на группе (типичное — неверный TELEGRAM_GROUP_ID после
    конвертации в супергруппу) выглядело как «в личке команды есть,
    в группе только /start».
    """
    async def _set(scope, label) -> bool:
        try:
            await app.bot.set_my_commands(BOT_COMMANDS, scope=scope)
            print(f"[bot] Меню команд: {label} — ок", flush=True)
            return True
        except Exception as e:
            print(f"[bot] Меню команд: {label} — ОШИБКА: {e}", flush=True)
            return False

    try:
        await app.bot.set_my_commands([], scope=BotCommandScopeDefault())
    except Exception as e:
        print(f"[bot] Меню команд: очистка глобального списка — ОШИБКА: {e}", flush=True)

    await _set(BotCommandScopeChat(ALLOWED_USER_ID), f"личка {ALLOWED_USER_ID}")

    if GROUP_ID:
        # Сначала убеждаемся, что группа вообще достижима: неверный
        # TELEGRAM_GROUP_ID (чаще всего — старый ID до конвертации в
        # супергруппу) означает, что туда не уйдут ни меню, ни алерты.
        try:
            chat = await app.bot.get_chat(GROUP_ID)
            print(f"[bot] Группа уведомлений: {chat.title!r} ({GROUP_ID}) — доступна", flush=True)
        except Exception as e:
            print(
                f"[bot] ВНИМАНИЕ: группа {GROUP_ID} недоступна: {e}\n"
                f"[bot] Уведомления в группу приходить не будут. Проверьте, что бот "
                f"добавлен в чат, и что TELEGRAM_GROUP_ID — актуальный ID "
                f"(у супергруппы он начинается с -100).",
                flush=True
            )

        # Fallback на все группы: если ID группы неверный, точечный scope не
        # применится, и меню в группе останется пустым без явной причины.
        if not await _set(BotCommandScopeChat(GROUP_ID), f"группа {GROUP_ID}"):
            await _set(BotCommandScopeAllGroupChats(), "все группы (fallback)")
    else:
        print("[bot] Меню команд: TELEGRAM_GROUP_ID не задан, группа пропущена", flush=True)


# ─── Авторизация ─────────────────────────────────────────────

def is_allowed(update: Update) -> bool:
    user_id = update.effective_user.id if update.effective_user else None
    chat_id = update.effective_chat.id if update.effective_chat else None
    if user_id == ALLOWED_USER_ID:
        return True
    if GROUP_ID and chat_id == GROUP_ID:
        return True
    return False


# ─── Хендлеры команд ─────────────────────────────────────────

async def reply_long_message(message, text: str, reply_markup=None):
    """Кнопки вешаются на последнюю часть, чтобы остались под текстом."""
    chunks = split_message(text)
    for chunk in chunks[:-1]:
        await message.reply_text(chunk)
    await message.reply_text(chunks[-1], reply_markup=reply_markup)


async def send_top_dirs(message, server_name: str, disk_name: str,
                        path: str = None, depth: int = 0):
    """Разбор занятого места: топ вложенных каталогов + кнопки вглубь.

    depth=0 — корень диска: показываем диаграмму и сверяем сумму с df.
    Глубже сверять не с чем (df знает только про диск целиком), поэтому
    там только текст со списком.
    """
    target = path or disk_name
    await message.reply_text(
        f"📂 Считаю каталоги {target} на {server_name}...\n"
        f"На большом каталоге это может занять пару минут."
    )
    try:
        server = await asyncio.to_thread(load_server, server_name)
        top_dirs = await asyncio.to_thread(get_top_dirs, server, target)
    except Exception as e:
        await message.reply_text(f"⚠️ Не удалось посчитать каталоги: {str(e)[:150]}")
        return

    if not top_dirs:
        if depth > 0:
            # Провалились в файл или в пустой каталог — это не ошибка,
            # но и показывать нечего: возвращаем кнопку наверх.
            await message.reply_text(
                f"📂 {target}: внутри пусто.\n"
                f"Либо это файл, а не каталог, либо каталог пуст.",
                reply_markup=dig_kb(server_name, disk_name, target, depth, []),
            )
        else:
            await message.reply_text(
                f"📂 {disk_name} на {server_name}: ничего не найдено.\n"
                f"Обычно это значит, что у пользователя мониторинга нет прав "
                f"на чтение корня диска (или диск пуст)."
            )
        return

    used_gb = free_gb = None
    if depth == 0:
        # Занятое/свободное берём из последнего замера: нужно и для сверки
        # суммы каталогов, и для диаграммы. Недоступность БД тут не повод
        # терять уже посчитанный список.
        try:
            usage = await asyncio.to_thread(get_disk_usage, server_name, disk_name)
        except Exception as e:
            print(f"[bot] Нет данных о занятости {disk_name} на {server_name}: {e}", flush=True)
            usage = None
        used_gb = usage[1] if usage else None
        free_gb = usage[0] if usage else None

    header = (f"📂 {disk_name} на {server_name} — самое тяжёлое (каталоги и файлы корня):"
              if depth == 0 else
              f"📂 {target} — самое тяжёлое внутри (уровень {depth}):")
    lines = [header + "\n"]
    for child, size_gb in top_dirs:
        lines.append(f"• {child} — {size_gb} ГБ")

    # Сумма топа заведомо меньше занятого места (показаны не все каталоги),
    # но разрыв в разы — это уже не «хвост», а недосчёт: чаще всего du
    # работал без sudo и не прочитал чужие каталоги, либо место держат
    # удалённые файлы в открытых процессами дескрипторах (df их видит, du — нет).
    if used_gb:
        counted = sum(size for _, size in top_dirs)
        if counted < used_gb * 0.7:
            lines.append(
                f"\n⚠️ Учтено {counted:.1f} ГБ из {used_gb:.1f} ГБ занятых — "
                f"не хватает {used_gb - counted:.1f} ГБ.\n"
                f"Обычно причина одна из двух: у пользователя мониторинга нет "
                f"sudo без пароля на du (часть каталогов не прочитана) "
                f"или место держат удалённые файлы в работающих процессах "
                f"(проверить: sudo lsof +L1)."
            )

    if depth >= DIG_MAX_DEPTH:
        lines.append(f"\nГлубже {DIG_MAX_DEPTH} уровней бот не спускается — "
                     f"дальше быстрее посмотреть через du на самом сервере.")

    await reply_long_message(
        message, "\n".join(lines),
        reply_markup=dig_kb(server_name, disk_name, target, depth, top_dirs),
    )

    if depth > 0:
        return  # диаграмма строится от занятости диска — для вложенных бессмысленна

    # Диаграмма снизу: размеры папок, % от диска, цвет по величине.
    # Ошибка построения не критична — текст уже отправлен.
    try:
        chart_path = await asyncio.to_thread(
            build_top_dirs_chart, server_name, disk_name, top_dirs, used_gb, free_gb)
        try:
            with open(chart_path, "rb") as image:
                await message.reply_photo(photo=image, caption=f"💽 {disk_name} · {server_name}")
        finally:
            try:
                os.remove(chart_path)
            except OSError:
                pass
    except Exception as e:
        print(f"[bot] Диаграмма топ-каталогов не построена: {e}", flush=True)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    await update.message.reply_text(
        "AgentMonitor",
        reply_markup=ReplyKeyboardMarkup(KEYBOARD, resize_keyboard=True)
    )


async def cmd_servers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    text, keyboard = await asyncio.to_thread(get_servers_status)
    await update.message.reply_text(
        text,
        reply_markup=InlineKeyboardMarkup(keyboard) if keyboard else None
    )


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    await update.message.reply_text("⏳ Формирую отчёт...")
    await reply_long_message(update.message, await asyncio.to_thread(build_report))


async def cmd_problems(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    await reply_long_message(update.message, await asyncio.to_thread(get_problems))


PING_MENU_TEXT = "📡 Выбери сервер или укажи IP/hostname командой:\n/ping 8.8.8.8"


def build_ping_keyboard():
    """Уровень 1 — выбор цели: только список серверов и ручной ввод."""
    buttons = [
        InlineKeyboardButton(f"📡 {target['name']}", callback_data=f"ping:{target['name']}")
        for target in load_targets()
    ]
    keyboard = [buttons[i:i+2] for i in range(0, len(buttons), 2)]
    keyboard.append([InlineKeyboardButton("✏️ Указать IP", callback_data="ping_custom")])
    return keyboard


def build_ping_actions_keyboard(active: str, closed_ports=None):
    """Уровень 2 — карточка выбранной цели. Список серверов сюда не попадает:
    рядом с двумя кнопками проверок он превращал меню в стену кнопок, и было
    непонятно, к какому серверу относятся 🔌 и 🌐."""
    def label(key: str, text: str) -> str:
        return f"• {text}" if key == active else text

    keyboard = [[
        InlineKeyboardButton(label("ping", "📡 Пинг"), callback_data="ping_again"),
        InlineKeyboardButton(label("ports", "🔌 Порты"), callback_data="ping_ports"),
        InlineKeyboardButton(label("http", "🌐 HTTP"), callback_data="ping_http"),
    ]]
    # Кнопки перепроверки — только для портов, которые не открылись:
    # повторять успешную проверку незачем.
    if closed_ports:
        row = [
            InlineKeyboardButton(f"🔁 {port}", callback_data=f"ping_port:{port}")
            for port in closed_ports[:4]
        ]
        keyboard.append(row)
    if active in ("ports", "port"):
        keyboard.append([
            InlineKeyboardButton("✏️ Свой порт", callback_data="ping_port_custom")
        ])
    keyboard.append([
        InlineKeyboardButton("◀️ К списку серверов", callback_data="ping_menu")
    ])
    return keyboard


def remember_ping_target(context, label: str, host: str):
    """Цель последней проверки — в user_data, а не в callback_data кнопки:
    Telegram ограничивает callback 64 байтами, а hostname бывает длиннее."""
    context.user_data["ping_target"] = {"label": label, "host": host}
    context.user_data.pop("ping_closed_ports", None)


async def cmd_ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return

    if context.args:
        await send_ping_card(update.message, context, " ".join(context.args))
        return

    await update.message.reply_text(
        PING_MENU_TEXT,
        reply_markup=InlineKeyboardMarkup(build_ping_keyboard())
    )


async def send_ping_card(message, context, value: str):
    """Пинг введённой цели. Имя сервера из конфига распознаётся, поэтому
    `/ping sql-01` показывает IP и дальше проверяет порты этого сервера,
    а не общий набор для неизвестного хоста."""
    target = await asyncio.to_thread(resolve_target, value)
    remember_ping_target(context, target["label"], target["host"])
    text = await asyncio.to_thread(ping_report, target["label"], target["host"])
    await message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(build_ping_actions_keyboard("ping"))
    )


async def cmd_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    await update.message.reply_text("📊 Собираю дашборд...")
    try:
        path = await asyncio.to_thread(build_dashboard_chart)
    except Exception as e:
        await update.message.reply_text(f"⚠️ Не удалось построить дашборд: {e}")
        return

    try:
        with open(path, "rb") as image:
            await update.message.reply_photo(
                photo=image,
                caption="📊 Дашборд · вся инфраструктура за 24 часа"
            )
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


async def send_server_chart(message, server_name: str, hours: int = 24):
    try:
        path = await asyncio.to_thread(build_server_chart, server_name, hours)
    except Exception as e:
        await message.reply_text(f"⚠️ Не удалось построить график: {e}")
        return

    try:
        with open(path, "rb") as image:
            await message.reply_photo(
                photo=image,
                caption=f"📈 {server_name} · график за {period_label(hours)}"
            )
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


GRAPH_PERIOD_RE = re.compile(r"^(\d{1,3})([hdчд])$", re.IGNORECASE)
GRAPH_MAX_HOURS = 30 * 24  # данные хранятся 30 дней


def parse_graph_args(args: list[str]) -> tuple[str, int]:
    """
    "/graph SQL01 7d" → ("SQL01", 168). Период опционален: 12h/7d (или 12ч/7д).
    """
    hours = 24
    if len(args) > 1:
        m = GRAPH_PERIOD_RE.match(args[-1])
        if m:
            value = int(m.group(1))
            unit = m.group(2).lower()
            hours = value * 24 if unit in ("d", "д") else value
            args = args[:-1]
    hours = max(1, min(hours, GRAPH_MAX_HOURS))
    return " ".join(args).strip(), hours


async def cmd_graph(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Использование: /graph SERVER_NAME [период]\n"
            "Например: /graph SQL01 7d или /graph SQL01 12h\n"
            "По умолчанию 24 часа, максимум 30d"
        )
        return

    server_name, hours = parse_graph_args(list(context.args))
    await update.message.reply_text("📈 Строю график...")
    await send_server_chart(update.message, server_name, hours)


async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    if not context.args:
        await update.message.reply_text("Использование: /mute SERVER_NAME")
        return

    server_name = " ".join(context.args).strip()
    muted = load_muted()
    muted[server_name] = True
    save_muted(muted)
    await update.message.reply_text(f"🔕 Алерты отключены для {server_name}")


async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    if not context.args:
        await update.message.reply_text("Использование: /unmute SERVER_NAME")
        return

    server_name = " ".join(context.args).strip()
    muted = load_muted()
    if server_name in muted:
        del muted[server_name]
        save_muted(muted)
        await update.message.reply_text(f"🔔 Алерты включены для {server_name}")
    else:
        await update.message.reply_text(f"ℹ️ {server_name} не был в mute")


async def cmd_pgsize(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    await update.message.reply_text("⏳ Считаю размеры...")
    text = await asyncio.to_thread(get_pg_stats)
    await reply_long_message(update.message, text)


async def cmd_pgcleanup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    if not can_configure(update.effective_user):
        await update.message.reply_text(
            "⛔ Нет прав на очистку истории.\n"
            "Доступ настраивается через TELEGRAM_DELETE_USERS."
        )
        return
    await update.message.reply_text(
        "🗑 ОЧИСТКА ИСТОРИИ МОНИТОРИНГА\n\n"
        "Удаляет старые записи из базы бота (метрики, статусы, история backup).\n"
        "На сами бэкапы и серверы не влияет.\n\n"
        "Выбери порог:",
        reply_markup=cleanup_options_kb()
    )


async def cmd_mutes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    muted = load_muted()

    # Истёкшие временные mute убираем из файла
    now = datetime.now(timezone.utc)
    lines = []
    changed = False
    for name, value in sorted(muted.items()):
        if value is True:
            lines.append(f"• {name}")
            continue
        try:
            expires = datetime.fromisoformat(str(value))
        except ValueError:
            lines.append(f"• {name}")
            continue
        if expires <= now:
            changed = True
            continue
        until = expires.astimezone(ALMATY).strftime("%H:%M")
        lines.append(f"• {name} — до {until}")
    if changed:
        save_muted({
            name: value for name, value in muted.items()
            if not mute_expired(value, now)
        })

    if not lines:
        await update.message.reply_text("🔔 Нет серверов с отключёнными алертами")
        return
    await update.message.reply_text("🔕 Алерты отключены:\n\n" + "\n".join(lines))


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    text = update.message.text

    if text in MENU_LABELS:
        # Кнопка главного меню прерывает активный мастер настройки
        context.user_data.pop(CONFIG_STATE_KEY, None)
    elif await handle_config_text(update, context):
        return

    if context.user_data.pop("awaiting_ping_host", False):
        await send_ping_card(update.message, context, text)
    elif context.user_data.pop("awaiting_ping_port", False):
        target = context.user_data.get("ping_target")
        if not target:
            await update.message.reply_text(PING_MENU_TEXT,
                reply_markup=InlineKeyboardMarkup(build_ping_keyboard()))
            return
        if not text.strip().isdigit():
            await update.message.reply_text("❌ Порт — это число от 1 до 65535")
            return
        report = await asyncio.to_thread(
            single_port_report, target["label"], int(text.strip())
        )
        await update.message.reply_text(
            report,
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(build_ping_actions_keyboard(
                "port", context.user_data.get("ping_closed_ports")
            ))
        )
    elif text == "🖥 Серверы":
        await cmd_servers(update, context)
    elif text == "📊 Дашборд":
        await cmd_dashboard(update, context)
    elif text == "📡 Пинг":
        await cmd_ping(update, context)
    elif text == "📋 Отчёт":
        await cmd_report(update, context)
    elif text == "🚨 Проблемы":
        await cmd_problems(update, context)
    elif text == "💾 Бэкапы":
        await cmd_backup_menu(update, context)
    elif text == "⚙️ Настройка":
        await cmd_config_menu(update, context)


# ─── Приём алертов ──────────────────────────────────────────

async def ack_callback(query):
    """Кнопка «Принято» под алертом: подавляет именно этот алерт.

    Полезно, когда причина известна и устранена, а источник ещё какое-то
    время отдаёт старые записи — например джоб удалён, но его ошибки
    остаются в логе SQL на сутки.
    """
    digest = query.data.split(":", 1)[1]
    key, until = await asyncio.to_thread(ack_alert, digest)
    if key is None:
        await query.message.reply_text(
            "Не удалось определить алерт — вероятно, состояние сброшено."
        )
        return
    await query.message.reply_text(
        f"✅ Принято: {key}\n"
        f"Такой алерт не придёт до {until.strftime('%d.%m %H:%M')}.\n"
        f"Список принятых и отмена — ⚙️ Настройка → 🔕 Принятые алерты.",
    )


# ─── Инлайн кнопки — детали сервера ─────────────────────────

def server_detail_kb(server_name: str) -> InlineKeyboardMarkup:
    """Кнопки под карточкой сервера. Перезагрузка проверяет права по клику."""
    rows = [
        [
            InlineKeyboardButton("◀️ Назад", callback_data="servers_list"),
            InlineKeyboardButton("🔄 Обновить", callback_data=f"refresh:{server_name}"),
        ],
        [
            InlineKeyboardButton("📈 График", callback_data=f"chart:{server_name}"),
            InlineKeyboardButton("♻️ Перезагрузить", callback_data=f"srv_reboot:{server_name}"),
        ],
        [
            InlineKeyboardButton("📂 Кто съел место", callback_data=f"disks:{server_name}"),
        ],
    ]

    # SQL-логи только там, где есть MSSQL. Признак — тот же флаг dbsize:
    # заводить второй переключатель на тот же факт означало бы, что рано или
    # поздно они разойдутся. Сломанный конфиг не должен уносить всю карточку.
    try:
        server = load_server(server_name)
        logs_row = []
        if has_mssql(server):
            logs_row.append(InlineKeyboardButton(
                "🗄 SQL-логи",
                callback_data=f"sqllog_menu:{sql_token(server_name, 24)}",
            ))
        if has_winlog(server):
            logs_row.append(InlineKeyboardButton(
                "📜 Логи Windows",
                callback_data=f"winlog_menu:{win_token(server_name, 24)}",
            ))
        if logs_row:
            rows.append(logs_row)
        if has_exchange(server):
            rows.append([InlineKeyboardButton(
                "📧 Почта (Exchange)",
                callback_data=f"exlog_menu:{ex_token(server_name, 24)}",
            )])
    except Exception as e:
        print(f"[bot] Логи: сервер {server_name} не прочитан: {e}", flush=True)

    return InlineKeyboardMarkup(rows)


def server_disks_kb(server_name: str, disks: list) -> InlineKeyboardMarkup:
    """Выбор диска для разбора занятого места: по кнопке на диск + возврат."""
    rows = []
    for disk_name, free_gb, used_gb in disks:
        data = f"al_topdirs:{server_name}:{disk_name}"
        # Telegram режет callback_data на 64 байтах: длинную пару
        # сервер+точка монтирования кнопкой не передать, показывать её нельзя.
        if len(data.encode("utf-8")) > 64:
            continue
        total = free_gb + used_gb
        pct = f" · {used_gb / total * 100:.0f}%" if total else ""
        rows.append([InlineKeyboardButton(
            f"📂 {disk_name} — занято {used_gb:.0f} ГБ{pct}",
            callback_data=data,
        )])
    rows.append([InlineKeyboardButton("◀️ К серверу", callback_data=f"server:{server_name}")])
    return InlineKeyboardMarkup(rows)


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await safe_answer_query(query)

    if not is_allowed(update):
        return

    if query.data.startswith("ack:"):
        await ack_callback(query)

    elif query.data.startswith("backup_"):
        await backup_callback(query, context)

    elif query.data.startswith("sqllog_"):
        await sqllog_callback(query, context)

    elif query.data.startswith("winlog_"):
        await winlog_callback(query, context)

    elif query.data.startswith("exlog_"):
        await exchange_callback(query, context)

    elif query.data.startswith("cfg_"):
        await config_callback(query, context)

    elif query.data.startswith("server:"):
        server_name = query.data.split(":", 1)[1]
        text = await asyncio.to_thread(get_server_detail, server_name)
        await safe_edit_message(query, text, reply_markup=server_detail_kb(server_name))

    elif query.data.startswith("refresh:"):
        server_name = query.data.split(":", 1)[1]
        ok, error = await asyncio.to_thread(refresh_server, server_name)
        text = await asyncio.to_thread(get_server_detail, server_name)
        if not ok and error:
            first_line = error.splitlines()[0][:120]
            text += f"\n\n⚠️ Принудительное обновление не удалось:\n{first_line}"
        await safe_edit_message(query, text, reply_markup=server_detail_kb(server_name))

    elif query.data.startswith("disks:"):
        server_name = query.data.split(":", 1)[1]
        disks = await asyncio.to_thread(get_server_disks, server_name)
        if not disks:
            await safe_edit_message(
                query,
                f"📂 {server_name}: нет данных о дисках.\n"
                f"Сначала нажми «🔄 Обновить» — разбор места идёт по последнему замеру.",
                reply_markup=server_detail_kb(server_name),
            )
            return
        await safe_edit_message(
            query,
            f"📂 {server_name} — какой диск разобрать?\n"
            f"Считаю каталоги прямо на сервере, на большом диске это пара минут.",
            reply_markup=server_disks_kb(server_name, disks),
        )

    elif query.data.startswith("chart:"):
        server_name = query.data.split(":", 1)[1]
        await query.message.reply_text("📈 Строю график...")
        await send_server_chart(query.message, server_name)

    # Кнопки из алертов монитора: отвечаем новым сообщением,
    # не трогая текст самого алерта
    elif query.data.startswith("al_refresh:"):
        server_name = query.data.split(":", 1)[1]
        await query.message.reply_text(f"🔄 Проверяю {server_name}...")
        ok, error = await asyncio.to_thread(refresh_server, server_name)
        text = await asyncio.to_thread(get_server_detail, server_name)
        if not ok and error:
            first_line = error.splitlines()[0][:120]
            text += f"\n\n⚠️ Проверка не удалась:\n{first_line}"
        chunks = split_message(text)
        for chunk in chunks[:-1]:
            await query.message.reply_text(chunk)
        await query.message.reply_text(
            chunks[-1],
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("📈 График", callback_data=f"chart:{server_name}")
            ]])
        )

    elif query.data.startswith("al_topdirs:"):
        _, server_name, disk_name = query.data.split(":", 2)
        await send_top_dirs(query.message, server_name, disk_name)

    elif query.data.startswith("dig:"):
        token = query.data.split(":", 1)[1]
        entry = DIG_TOKENS.get(token)
        if not entry:
            # Кэш путей живёт в памяти процесса: после рестарта бота
            # старые кнопки бесполезны — честно просим начать заново.
            await query.message.reply_text(
                "⌛ Кнопка устарела (бот перезапускался).\n"
                "Открой разбор заново: карточка сервера → «📂 Кто съел место»."
            )
            return
        server_name, disk_name, path, depth = entry
        await send_top_dirs(query.message, server_name, disk_name, path, depth)

    elif query.data.startswith("al_svcfix:"):
        if not can_configure(query.from_user):
            await query.message.reply_text(
                "⛔ Перезапуск сервисов доступен только пользователям из TELEGRAM_DELETE_USERS."
            )
            return
        _, server_name, service_name = query.data.split(":", 2)
        await query.message.reply_text(
            f"🔁 Перезапустить сервис {service_name} на {server_name}?",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(
                    "✅ Да, перезапустить",
                    callback_data=f"al_svcgo:{server_name}:{service_name}"
                ),
                InlineKeyboardButton("❌ Отмена", callback_data="al_svccancel"),
            ]])
        )

    elif query.data == "al_svccancel":
        await safe_edit_message(query, "❌ Перезапуск отменён.")

    elif query.data.startswith("al_svcgo:"):
        if not can_configure(query.from_user):
            await query.message.reply_text("⛔ Нет прав на перезапуск сервисов.")
            return
        _, server_name, service_name = query.data.split(":", 2)
        await safe_edit_message(query, f"🔁 Перезапускаю {service_name} на {server_name}...")
        try:
            server = await asyncio.to_thread(load_server, server_name)
            ok, status = await asyncio.to_thread(restart_service, server, service_name)
        except Exception as e:
            ok, status = False, str(e)[:150]
        user = query.from_user
        print(f"[bot] {user.id if user else '?'} перезапустил {server_name}/{service_name}: "
              f"{'ok' if ok else status}", flush=True)
        if ok:
            await query.message.reply_text(
                f"✅ Сервис {service_name} на {server_name} перезапущен (статус: {status})"
            )
        else:
            await query.message.reply_text(
                f"❌ Не удалось перезапустить {service_name} на {server_name}:\n{status}"
            )

    elif query.data.startswith("srv_reboot:"):
        if not can_configure(query.from_user):
            await query.message.reply_text(
                "⛔ Перезагрузка сервера доступна только пользователям из TELEGRAM_DELETE_USERS."
            )
            return
        server_name = query.data.split(":", 1)[1]
        try:
            server = await asyncio.to_thread(load_server, server_name)
        except Exception as e:
            await query.message.reply_text(f"❌ Сервер не найден: {str(e)[:120]}")
            return

        reg_path = (server.get("reg_file") or "").strip()
        warning = (
            f"♻️ Перезагрузить сервер {server_name}?\n\n"
            f"🌐 {server.get('host', '?')}\n"
        )
        if reg_path:
            warning += (
                f"\n📝 Перед перезагрузкой в реестр будет импортирован:\n{reg_path}\n"
                "Если импорт не удастся — перезагрузка будет отменена.\n"
            )
        warning += "\n⚠️ Все службы и пользователи на сервере будут отключены."

        await query.message.reply_text(
            warning,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Да, перезагрузить",
                                     callback_data=f"srv_rebootgo:{server_name}"),
                InlineKeyboardButton("❌ Отмена", callback_data="srv_rebootcancel"),
            ]])
        )

    elif query.data == "srv_rebootcancel":
        await safe_edit_message(query, "❌ Перезагрузка отменена.")

    elif query.data.startswith("srv_rebootgo:"):
        if not can_configure(query.from_user):
            await query.message.reply_text("⛔ Нет прав на перезагрузку сервера.")
            return
        server_name = query.data.split(":", 1)[1]
        await safe_edit_message(query, f"♻️ Перезагружаю {server_name}...")
        try:
            server = await asyncio.to_thread(load_server, server_name)
            ok, report = await asyncio.to_thread(reboot_server, server)
        except Exception as e:
            ok, report = False, str(e)[:200]
        user = query.from_user
        audit.log_config_change(
            user, "reboot", server_name,
            "успешно" if ok else f"ошибка: {str(report).splitlines()[0][:80]}"
        )
        icon = "✅" if ok else "❌"
        await query.message.reply_text(f"{icon} {server_name}\n\n{report}")

    elif query.data.startswith("al_mute:"):
        server_name = query.data.split(":", 1)[1]
        muted = load_muted()
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        muted[server_name] = expires.isoformat()
        save_muted(muted)
        until = expires.astimezone(ALMATY).strftime("%H:%M")
        await query.message.reply_text(
            f"🔇 Алерты для {server_name} отключены на 1 час (до {until})"
        )

    elif query.data.startswith("ping:"):
        server_name = query.data.split(":", 1)[1]
        target = await asyncio.to_thread(resolve_target, server_name)
        remember_ping_target(context, target["label"], target["host"])
        text = await asyncio.to_thread(ping_report, target["label"], target["host"])
        await safe_edit_message(
            query,
            text,
            reply_markup=InlineKeyboardMarkup(build_ping_actions_keyboard("ping")),
            parse_mode="HTML"
        )

    elif query.data == "ping_menu":
        await safe_edit_message(
            query,
            PING_MENU_TEXT,
            reply_markup=InlineKeyboardMarkup(build_ping_keyboard())
        )

    elif query.data in ("ping_again", "ping_ports", "ping_http") or \
            query.data.startswith("ping_port:"):
        target = context.user_data.get("ping_target")
        if not target:
            await safe_edit_message(
                query,
                PING_MENU_TEXT,
                reply_markup=InlineKeyboardMarkup(build_ping_keyboard())
            )
            return

        label, host = target["label"], target["host"]
        closed = context.user_data.get("ping_closed_ports")

        if query.data == "ping_again":
            await safe_edit_message(query, f"📡 Пингую {label}...")
            text = await asyncio.to_thread(ping_report, label, host)
            active = "ping"
        elif query.data == "ping_ports":
            await safe_edit_message(query, f"🔌 Проверяю порты {label}...")
            text, closed = await asyncio.to_thread(ports_report, label)
            context.user_data["ping_closed_ports"] = closed
            active = "ports"
        elif query.data == "ping_http":
            await safe_edit_message(query, f"🌐 Запрашиваю {label}...")
            text = await asyncio.to_thread(http_report, label)
            active = "http"
        else:
            port = int(query.data.split(":", 1)[1])
            await safe_edit_message(query, f"🔁 Перепроверяю порт {port}...")
            text = await asyncio.to_thread(single_port_report, label, port)
            active = "port"

        await safe_edit_message(
            query,
            text,
            reply_markup=InlineKeyboardMarkup(
                build_ping_actions_keyboard(active, closed)
            ),
            parse_mode="HTML"
        )

    elif query.data == "ping_port_custom":
        context.user_data["awaiting_ping_port"] = True
        await safe_edit_message(
            query,
            "✏️ Отправь номер порта следующим сообщением.\nНапример: 8080",
            reply_markup=InlineKeyboardMarkup(build_ping_actions_keyboard(
                "port", context.user_data.get("ping_closed_ports")
            ))
        )

    elif query.data == "ping_custom":
        context.user_data["awaiting_ping_host"] = True
        await safe_edit_message(
            query,
            "✏️ Отправь IP или hostname следующим сообщением.\nНапример: 192.0.2.10",
            reply_markup=InlineKeyboardMarkup(build_ping_keyboard())
        )

    elif query.data == "servers_list":
        text, keyboard = await asyncio.to_thread(get_servers_status)
        await safe_edit_message(
            query,
            text,
            reply_markup=InlineKeyboardMarkup(keyboard) if keyboard else None
        )

    elif query.data.startswith("servers_list:"):
        page = int(query.data.split(":", 1)[1])
        text, keyboard = await asyncio.to_thread(get_servers_status, page)
        await safe_edit_message(
            query,
            text,
            reply_markup=InlineKeyboardMarkup(keyboard) if keyboard else None
        )

    elif query.data == "noop":
        return


# ─── Запланированный отчёт ───────────────────────────────────

async def _send_text_to_notify(context: ContextTypes.DEFAULT_TYPE, text: str):
    """Плановая отправка с фолбэком в личку.

    Если группа недоступна (неверный TELEGRAM_GROUP_ID, бота удалили из чата),
    отчёт раньше терялся вместе с исключением в логе. Теперь он всё равно
    доходит владельцу, а причина видна в тексте.
    """
    try:
        await context.bot.send_message(chat_id=NOTIFY_ID, text=text)
    except Exception as e:
        if NOTIFY_ID == ALLOWED_USER_ID:
            raise
        print(f"[bot] Не удалось отправить в группу {NOTIFY_ID}: {e}", flush=True)
        await context.bot.send_message(
            chat_id=ALLOWED_USER_ID,
            text=f"⚠️ Группа {NOTIFY_ID} недоступна — проверьте TELEGRAM_GROUP_ID.\n\n{text}"
        )


async def _send_photo_to_notify(context: ContextTypes.DEFAULT_TYPE, path: str, caption: str):
    try:
        with open(path, "rb") as image:
            await context.bot.send_photo(chat_id=NOTIFY_ID, photo=image, caption=caption)
    except Exception as e:
        if NOTIFY_ID == ALLOWED_USER_ID:
            raise
        print(f"[bot] Не удалось отправить фото в группу {NOTIFY_ID}: {e}", flush=True)
        with open(path, "rb") as image:
            await context.bot.send_photo(chat_id=ALLOWED_USER_ID, photo=image, caption=caption)


async def scheduled_backup_charts(context: ContextTypes.DEFAULT_TYPE):
    """Утром и вечером уходят только графики бэкапов: свежесть по серверам и
    общий объём за 30 дней. Текстовый отчёт по расписанию не шлётся — он
    длинный и читается редко, для него есть кнопка 📋 Отчёт и /report."""
    try:
        async def send_photo(path, caption):
            await _send_photo_to_notify(context, path, caption)

        await send_backup_charts(send_photo)
    except Exception as e:
        print(f"[bot] Ошибка плановых графиков бэкапов: {e}", flush=True)


async def weekly_report(context: ContextTypes.DEFAULT_TYPE):
    if datetime.now(ALMATY).weekday() != 6:
        return

    try:
        report = await asyncio.to_thread(build_report, "📊 ЕЖЕНЕДЕЛЬНЫЙ ОТЧЁТ ПО ИНФРАСТРУКТУРЕ")
        for chunk in split_message(report):
            await _send_text_to_notify(context, chunk)
    except Exception as e:
        print(f"[bot] Ошибка еженедельного отчёта: {e}", flush=True)

    try:
        async def send_text(text):
            await _send_text_to_notify(context, text)

        async def send_photo(path, caption):
            await _send_photo_to_notify(context, path, caption)

        # Без графиков: свежесть и объём уже приходят утром и вечером
        await send_backup_digest_report(send_text, send_photo, with_charts=False)
    except Exception as e:
        print(f"[bot] Ошибка еженедельного дайджеста бэкапов: {e}", flush=True)

    # Картинка-дашборд в дополнение к текстовому дайджесту
    try:
        path = await asyncio.to_thread(build_dashboard_chart)
        try:
            await _send_photo_to_notify(
                context, path, "📊 Дашборд · вся инфраструктура за 24 часа"
            )
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    except Exception as e:
        print(f"[bot] Ошибка дашборда в еженедельном отчёте: {e}", flush=True)


# ─── Глобальный обработчик ошибок ────────────────────────────

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    tb = "".join(traceback.format_exception(
        type(context.error), context.error, context.error.__traceback__
    ))
    print(f"[bot] Ошибка в хендлере:\n{tb}", flush=True)
    try:
        if isinstance(update, Update):
            if update.callback_query:
                await update.callback_query.message.reply_text(
                    "⚠️ Произошла ошибка. Попробуйте ещё раз."
                )
            elif update.effective_message:
                await update.effective_message.reply_text(
                    "⚠️ Произошла ошибка. Попробуйте ещё раз."
                )
    except Exception:
        pass


# ─── Запуск ──────────────────────────────────────────────────

def main():
    print("[bot] Запуск AgentMonitor Bot...", flush=True)
    print(f"[bot] Уведомления → {'группа ' + str(GROUP_ID) if GROUP_ID else 'личка ' + str(ALLOWED_USER_ID)}", flush=True)

    app = (
        ApplicationBuilder()
        .token(_require_env("TELEGRAM_TOKEN"))
        .post_init(setup_commands)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("servers", cmd_servers))
    app.add_handler(CommandHandler("dashboard", cmd_dashboard))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("problems", cmd_problems))
    app.add_handler(CommandHandler("ping", cmd_ping))
    app.add_handler(CommandHandler("graph", cmd_graph))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CommandHandler("mutes", cmd_mutes))
    app.add_handler(CommandHandler("pgsize", cmd_pgsize))
    app.add_handler(CommandHandler("pgcleanup", cmd_pgcleanup))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    app.add_error_handler(on_error)

    app.job_queue.run_daily(
        scheduled_backup_charts,
        time(hour=8, minute=0, tzinfo=ALMATY)
    )
    app.job_queue.run_daily(
        scheduled_backup_charts,
        time(hour=18, minute=0, tzinfo=ALMATY)
    )
    app.job_queue.run_daily(
        weekly_report,
        time(hour=9, minute=0, tzinfo=ALMATY)
    )

    app.run_polling()


if __name__ == "__main__":
    main()
