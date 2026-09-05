"""
bot/backup_bot.py

Telegram-интерфейс раздела 💾 Бэкапы.
"""
import json
import os
import uuid
import asyncio
from collections import defaultdict
from datetime import datetime, timezone


from telegram import InlineKeyboardMarkup, InlineKeyboardButton, Update
from telegram.ext import ContextTypes

from backup_bot_db import (
    build_backup_digest,
    get_latest_backup_metrics,
    get_backup_report,
    get_db_sizes,
    get_files_for_cleanup,
    get_backup_servers,
    get_cleanup_servers,
    get_config_backup_targets,
    get_growth_servers,
    get_latest_verifications,
    get_verify_backup_servers,
    has_config_server,
    load_server_config,
    run_verify_now,
)
from charts import build_growth_chart, build_backup_freshness_chart, build_backup_volume_chart
from backup_files import delete_backup_files, deletable_backup_targets, NO_DELETE_TYPES
from backup_copy import (
    clear_run,
    copy_servers,
    copy_settings,
    find_server,
    load_state as load_copy_state,
    read_remote_log_info,
    remote_file_size,
    start_copy_now,
    target_path,
    target_settings,
    type_label,
)
from copy_log import (
    common_log,
    database_log,
    log_dir,
    parse_common_log,
    progress_percent,
    summary_lines,
    winscp_highlights,
    winscp_is_transferring,
    winscp_last_time,
)
from backup_schedule import (
    load_schedule_map,
    schedule_for,
    weekly_age_text,
    weekly_backup_missed,
)
from tg_utils import TELEGRAM_TEXT_LIMIT, safe_edit_message, split_message
import audit
from settings import ALMATY

CLEANUP_PENDING_FILE = "/app/data/cleanup_pending.json"
CLEANUP_PENDING_TTL_MINUTES = 15
DELETE_USERS_ENV = "TELEGRAM_DELETE_USERS"
SERVER_PICKER_PAGE_SIZE = 8
TEXT_PAGE_BLOCKS = 6
BACKUP_PATH_ERROR_STATUS = "error"

# Живые фоновые задачи (verify): см. do_verify_run
_BACKGROUND_TASKS: set = set()


# ─── Helpers ─────────────────────────────────────────────────

def utcnow_naive() -> datetime:
    """Текущее время UTC без tzinfo — для сравнения с naive-UTC датами из БД."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_utc_naive(dt):
    """Приводит datetime к naive UTC (aware конвертируется, naive считается UTC)."""
    if getattr(dt, "tzinfo", None):
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def fmt_size(gb: float) -> str:
    if gb >= 1000:
        return f"{gb/1024:.2f} ТБ"
    if gb >= 1:
        return f"{gb:.2f} ГБ"
    return f"{gb*1024:.1f} МБ"


def fmt_date(dt) -> str:
    """Время файла бэкапа (naive UTC или строка) → местное время (Алматы)."""
    if not dt:
        return "нет данных"
    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt
    if not hasattr(dt, "strftime"):
        return str(dt)
    if getattr(dt, "tzinfo", None) is None:
        dt = dt.replace(tzinfo=timezone.utc)   # времена файлов хранятся как UTC
    return dt.astimezone(ALMATY).strftime("%d.%m.%Y %H:%M")


def fmt_age(dt) -> str:
    if not dt:
        return "?"

    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return "?"

    delta = utcnow_naive() - to_utc_naive(dt)

    days = delta.days
    if days >= 1:
        return f"{days} дн назад"

    hours = int(delta.total_seconds() // 3600)
    if hours >= 1:
        return f"{hours} ч назад"

    minutes = int(delta.total_seconds() // 60)
    return f"{minutes} мин назад"


def free_pct_or_none(disk_free, disk_total):
    """Процент свободного места; None если данных о диске нет."""
    total = float(disk_total or 0)
    if total <= 0:
        return None
    return round(float(disk_free or 0) / total * 100, 1)


def short_error_text(error: str | None) -> str:
    if not error:
        return "Путь недоступен"
    line = str(error).strip().splitlines()[0]
    return line[:120]


def merge_backup_items(server_name: str, rows: list[dict]) -> list[dict]:
    by_key = {(row["backup_type"], row["backup_path"]): row for row in rows}
    config_items = get_config_backup_targets(server_name).get(server_name, [])
    if has_config_server(server_name):
        merged = []
        for item in config_items:
            key = (item["backup_type"], item["backup_path"])
            merged.append(by_key.get(key, {
                "backup_type": item["backup_type"],
                "backup_path": item["backup_path"],
                "file_count": None,
                "oldest_file": None,
                "newest_file": None,
                "total_size_gb": None,
                "disk_total_gb": None,
                "disk_free_gb": None,
                "status": None,
                "error": None,
            }))
        return merged

    return rows


def load_delete_user_ids() -> set[int]:
    raw = os.getenv(DELETE_USERS_ENV, "")
    allowed = set()
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            allowed.add(int(item))
        except ValueError:
            print(f"[backup] Некорректный user_id в {DELETE_USERS_ENV}: {item}", flush=True)
    return allowed


def can_delete_backups(query) -> bool:
    user = getattr(query, "from_user", None)
    if not user:
        return False
    return user.id in load_delete_user_ids()


def back_kb():
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("◀️ Назад", callback_data="backup_menu")
    ]])


def backup_menu_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 Backup Health", callback_data="backup_health")],
        [InlineKeyboardButton("📦 Backup Report", callback_data="backup_report_servers")],
        [InlineKeyboardButton("🗄 DB Size",        callback_data="backup_dbsize")],
        [InlineKeyboardButton("📈 Рост баз",       callback_data="backup_growth_servers")],
        [InlineKeyboardButton("🧹 Cleanup",        callback_data="backup_cleanup_servers")],
        [InlineKeyboardButton("🧪 Verify статус",  callback_data="backup_verify")],
        [InlineKeyboardButton("📤 Копирование",    callback_data="backup_copy")],
        [InlineKeyboardButton("📋 Дайджест",       callback_data="backup_digest")],
    ])


def build_paginated_server_keyboard(servers: list[str], callback_prefix: str,
                                    page: int, back_callback: str = "backup_menu") -> InlineKeyboardMarkup:
    total_pages = max(1, (len(servers) + SERVER_PICKER_PAGE_SIZE - 1) // SERVER_PICKER_PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    start = page * SERVER_PICKER_PAGE_SIZE
    end = start + SERVER_PICKER_PAGE_SIZE
    page_servers = servers[start:end]

    buttons = [
        [InlineKeyboardButton(server, callback_data=f"{callback_prefix}:{server}")]
        for server in page_servers
    ]

    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton("◀️", callback_data=f"{callback_prefix}_servers:{page - 1}"))
    nav_row.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="backup_noop"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton("▶️", callback_data=f"{callback_prefix}_servers:{page + 1}"))
    buttons.append(nav_row)
    buttons.append([InlineKeyboardButton("◀️ Назад", callback_data=back_callback)])

    return InlineKeyboardMarkup(buttons)


def paginate_text_blocks(header: str, blocks: list[str], page: int,
                         callback_prefix: str, back_callback: str = "backup_menu") -> tuple[str, InlineKeyboardMarkup]:
    if not blocks:
        return header, back_kb()

    total_pages = max(1, (len(blocks) + TEXT_PAGE_BLOCKS - 1) // TEXT_PAGE_BLOCKS)
    page = max(0, min(page, total_pages - 1))
    start = page * TEXT_PAGE_BLOCKS
    end = start + TEXT_PAGE_BLOCKS
    text = header + "\n\n".join(blocks[start:end])

    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton("◀️", callback_data=f"{callback_prefix}:{page - 1}"))
    nav_row.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="backup_noop"))
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton("▶️", callback_data=f"{callback_prefix}:{page + 1}"))

    keyboard = [nav_row, [InlineKeyboardButton("◀️ Назад", callback_data=back_callback)]]
    return text, InlineKeyboardMarkup(keyboard)


# ─── Меню ────────────────────────────────────────────────────

async def cmd_backup_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "💾 БЭКАПЫ\n\nВыбери раздел:",
        reply_markup=backup_menu_kb()
    )


# ─── Backup Health ────────────────────────────────────────────

async def show_backup_health(query, context, page: int = 0):
    server_names = await asyncio.to_thread(get_backup_servers)
    rows = await asyncio.to_thread(get_latest_backup_metrics)

    if not server_names and not rows:
        await safe_edit_message(
            query,
            "⚠️ Нет данных. Дождитесь первого цикла сбора (до 5 минут).",
            reply_markup=back_kb()
        )
        return

    servers = defaultdict(list)
    for row in rows:
        servers[row["server_name"]].append(row)

    schedule_map = await asyncio.to_thread(load_schedule_map)
    all_names = sorted(server_names or servers.keys())
    ok = warn = crit = 0
    details = []

    for server_name in all_names:
        items = await asyncio.to_thread(merge_backup_items, server_name, servers.get(server_name, []))
        block = [f"🖥 {server_name}"]
        if not items:
            crit += 1
            block.append("   ⚠️ Нет данных сбора")
            block.append("   На сервере нет настроенных backup-путей")
            details.append("\n".join(block))
            continue

        for item in items:
            btype = item["backup_type"]
            path = item["backup_path"]
            status = item.get("status")
            error = item.get("error")
            file_count = item["file_count"] or 0
            newest = item["newest_file"]
            free_pct = free_pct_or_none(item["disk_free_gb"], item["disk_total_gb"])

            if not status:
                icon = "🟠"
                warn += 1
            elif status == BACKUP_PATH_ERROR_STATUS:
                icon = "🔴"
                crit += 1
            elif file_count == 0 or (free_pct is not None and free_pct < 10):
                icon = "🔴"
                crit += 1
            elif newest:
                age_h = (utcnow_naive() - to_utc_naive(newest)).total_seconds() / 3600
                schedule = schedule_for(schedule_map, server_name, btype, path)
                if schedule:
                    # Недельная копия: смотрим на пропуск дедлайна, не на возраст
                    if weekly_backup_missed(to_utc_naive(newest), schedule[0], schedule[1]):
                        icon = "🔴"
                        crit += 1
                    else:
                        icon = "✅"
                        ok += 1
                elif age_h > 24:
                    icon = "🟠"
                    warn += 1
                else:
                    icon = "✅"
                    ok += 1
            else:
                icon = "🔴"
                crit += 1

            block.append(f"   {icon} {btype.upper()} — {path}")
            if not status:
                block.append("      ⚠️ Нет данных сбора")
            elif status == BACKUP_PATH_ERROR_STATUS:
                block.append(f"      ❌ Путь недоступен: {short_error_text(error)}")
            elif file_count == 0:
                block.append("      ❌ Каталог пуст")
            else:
                block.append(f"      Файлов: {file_count} | Новый: {fmt_age(newest)}")
                schedule = schedule_for(schedule_map, server_name, btype, path)
                if schedule:
                    # Иначе «✅» при файле недельной давности выглядит ошибкой
                    block.append(f"      🗓 {weekly_age_text(newest, schedule[0], schedule[1])}")
            if free_pct is not None and free_pct < 10:
                block.append(f"      ⚠️ Свободно: {free_pct}%")

        details.append("\n".join(block))

    header = (
        f"📊 BACKUP HEALTH\n\n"
        f"Серверов: {len(all_names)}\n"
        f"✅ Норма: {ok}\n"
        f"🟠 Предупреждение: {warn}\n"
        f"🔴 Ошибка: {crit}\n\n"
        f"{'━'*20}\n\n"
    )

    text, keyboard = paginate_text_blocks(
        header,
        details,
        page=page,
        callback_prefix="backup_health_page"
    )
    await safe_edit_message(query, text, reply_markup=keyboard)


# ─── Verify статус (RESTORE VERIFYONLY) ──────────────────────

async def show_verify_status(query, context, page: int = 0):
    verifications = await asyncio.to_thread(get_latest_verifications)

    if not verifications:
        await safe_edit_message(
            query,
            "🧪 VERIFY СТАТУС\n\n"
            "Нет данных. Либо verify_backup не включён ни у одного сервера, "
            "либо проверка ещё не запускалась (раз в сутки).",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("▶️ Запустить сейчас", callback_data="backup_verify_run_servers")],
                [InlineKeyboardButton("◀️ Назад", callback_data="backup_menu")],
            ])
        )
        return

    by_server = defaultdict(list)
    for v in verifications:
        by_server[v["server_name"]].append(v)

    ok = fail = 0
    details = []
    for server_name in sorted(by_server):
        block = [f"🖥 {server_name}"]
        for v in sorted(by_server[server_name], key=lambda r: r["backup_path"]):
            when = v["created_at"].strftime("%d.%m.%Y %H:%M") if v.get("created_at") else "?"
            size = v.get("file_size_gb")
            size_txt = f", {round(float(size), 1)} ГБ" if size is not None else ""
            if v["status"] == "ok":
                ok += 1
                block.append(f"   ✅ {v['backup_path']}: ok ({when}{size_txt})")
            else:
                fail += 1
                detail = short_error_text(v.get("error") or v["status"] or "")
                block.append(f"   ❌ {v['backup_path']}: {v['status']} ({when})")
                block.append(f"      {detail}")
        details.append("\n".join(block))

    header = (
        f"🧪 VERIFY СТАТУС (7 дн)\n\n"
        f"✅ ok: {ok}\n"
        f"❌ ошибка: {fail}\n\n"
        f"{'━'*20}\n\n"
    )

    text, keyboard = paginate_text_blocks(
        header,
        details,
        page=page,
        callback_prefix="backup_verify_page"
    )
    rows = list(keyboard.inline_keyboard)
    rows.insert(-1, [InlineKeyboardButton("▶️ Запустить сейчас", callback_data="backup_verify_run_servers")])
    await safe_edit_message(query, text, reply_markup=InlineKeyboardMarkup(rows))


async def show_verify_run_servers(query, context, page: int = 0):
    servers = await asyncio.to_thread(get_verify_backup_servers)
    if not servers:
        await safe_edit_message(
            query,
            "⚠️ Ни у одного сервера не включён verify_backup.\n\n"
            "Включить можно в ⚙️ Настройка → сервер → кнопка Verify.",
            reply_markup=back_kb()
        )
        return

    await safe_edit_message(
        query,
        "🧪 ЗАПУСК VERIFY\n\nВыбери сервер (может занять до 2 часов на больших базах):",
        reply_markup=build_paginated_server_keyboard(servers, "backup_verify_run", page, back_callback="backup_verify")
    )


async def do_verify_run(query, context, server_name: str):
    if not can_delete_backups(query):
        await safe_edit_message(
            query,
            "⛔ Нет прав на запуск проверки.\n\nОбратитесь к администратору.",
            reply_markup=back_kb()
        )
        return

    await safe_edit_message(
        query,
        f"🧪 Проверка запущена в фоне для {server_name}.\n\n"
        f"Может занять до 2 часов на больших базах — бот сам пришлёт "
        f"результат отдельным сообщением, когда закончит. Ботом можно "
        f"пользоваться дальше, ждать здесь не нужно.",
        reply_markup=back_kb()
    )
    # Фоновая задача, не await здесь: иначе этот хендлер (и весь бот, пока
    # обновления обрабатываются последовательно) завис бы до конца verify.
    # Ссылку держим сами: asyncio хранит задачи только слабой ссылкой, и
    # многочасовой verify мог быть собран сборщиком мусора на полпути.
    task = asyncio.create_task(
        _run_verify_background(context, query.message.chat_id, server_name, query.from_user)
    )
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)


async def _run_verify_background(context, chat_id: int, server_name: str, user):
    try:
        results = await asyncio.to_thread(run_verify_now, server_name)
    except Exception as e:
        await context.bot.send_message(chat_id, f"❌ {server_name}: ошибка verify: {str(e)[:300]}")
        return

    if not results:
        await context.bot.send_message(
            chat_id, f"⚠️ {server_name}: нет путей в backups.sql — проверять нечего."
        )
        return

    lines = [f"🧪 Готово: {server_name}\n"]
    for r in results:
        if r["status"] == "ok":
            size_txt = f", {round(float(r['size_gb']), 1)} ГБ" if r.get("size_gb") is not None else ""
            dur_txt = f" за {r['duration_sec']} сек" if r.get("duration_sec") is not None else ""
            lines.append(f"✅ {r['path']}: ok{size_txt}{dur_txt}")
        else:
            detail = short_error_text(r.get("error") or r["status"] or "")
            lines.append(f"❌ {r['path']}: {r['status']}\n   {detail}")

    audit.log_config_change(
        user, "verify_run", server_name,
        ", ".join(f"{r['path']}={r['status']}" for r in results)
    )
    await context.bot.send_message(chat_id, "\n".join(lines))


# ─── Копирование копий на приёмник ───────────────────────────

def _copy_server_lines(server: dict, entry: dict) -> list:
    """Что показать про один сервер-источник: настройка и последний рейс."""
    settings = copy_settings(server)
    lines = [f"🖥 {server['name']}"]
    # Скриптов может быть несколько — свой на полную и на разностную.
    # Показываем каждый: иначе непонятно, что именно запустит кнопка.
    for btype, script in settings["scripts"].items():
        lines.append(f"   📜 {type_label(btype)}: {script}")

    auto = "включён" if settings["auto"] else "ВЫКЛЮЧЕН"
    lines.append(f"   🔁 автозапуск: {auto}")

    run = (entry or {}).get("run")
    last = (entry or {}).get("last_run")
    if run:
        what = f" [{type_label(run['type'])}]" if run.get("type") else ""
        lines.append(f"   ⏳ идёт{what} с {run.get('started')} "
                     f"(PID {run.get('pid')})")
    elif last:
        minutes = last.get("minutes")
        by = last.get("by") or "монитор"
        what = f" [{type_label(last['type'])}]" if last.get("type") else ""
        icon, verdict = {
            "failed": ("❌", f", код возврата {last.get('code')}"),
            "lost": ("❌", ", процесс исчез"),
            "reset": ("⏹", ", сброшен вручную"),
        }.get(last.get("state"), ("✅", ""))
        lines.append(
            f"   {icon} последний рейс{what}: {last.get('ended')}"
            + (f", ехал {minutes} мин" if minutes is not None else "")
            + verdict
            + f" (запустил {by})"
        )
        if last.get("log"):
            lines.append(f"   📄 журнал: {last['log']}")
    else:
        lines.append("   ⏸ рейсов ещё не было")
    return lines


# Telegram режет callback_data длиннее 64 байт, и кнопка молча перестаёт
# работать. Длинное имя сервера плюс тип в лимит могут не влезть — тогда
# показываем общий выбор, а тип спрашиваем следующим экраном.
COPY_CALLBACK_LIMIT = 64


def copy_type_buttons(server_name: str, settings: dict) -> list:
    """Кнопка на каждый тип копии: «Полная», «Разностная», «Журнал».

    Один сервер — самый частый случай, и лишний экран выбора сервера, а
    потом ещё один выбора типа, тут только мешает: кнопки видно сразу.
    """
    scripts = settings.get("scripts") or {}
    if len(set(scripts.values())) < 2:
        # Скрипт один на все типы — выбирать нечего, тип ничего не меняет
        return []

    buttons = []
    for btype in scripts:
        data = f"backup_copy_go:{server_name}:{btype}"
        if len(data.encode()) > COPY_CALLBACK_LIMIT:
            return []
        buttons.append(InlineKeyboardButton(
            f"📤 {type_label(btype).capitalize()}", callback_data=data))
    return buttons


async def show_copy_status(query, context, page: int = 0):
    names = await asyncio.to_thread(copy_servers)
    if not names:
        await safe_edit_message(
            query,
            "📤 КОПИРОВАНИЕ\n\n"
            "Ни у одного сервера не задан скрипт копирования.\n\n"
            "Это опция: пока она не включена, копии возит планировщик "
            "Windows, как раньше. Чтобы копированием управлял бот — "
            "⚙️ Настройка → сервер-источник → «Скрипт копирования». "
            "Подробности: ⚙️ Настройка → 📖 Справка → 📤 Копирование копий.",
            reply_markup=back_kb()
        )
        return

    state = await asyncio.to_thread(load_copy_state)
    blocks = []
    for name in names:
        server = await asyncio.to_thread(find_server, name)
        if not server:
            continue
        blocks.append("\n".join(_copy_server_lines(server, state.get(name))))

    text, keyboard = paginate_text_blocks(
        f"📤 КОПИРОВАНИЕ\n\nСерверов-источников: {len(blocks)}\n\n{'━'*20}\n\n",
        blocks,
        page=page,
        callback_prefix="backup_copy_page"
    )
    rows = list(keyboard.inline_keyboard)
    run_rows = []
    if len(names) == 1:
        # Источник один: сразу кнопки типов, без лишнего выбора сервера.
        server = await asyncio.to_thread(find_server, names[0])
        settings = copy_settings(server) if server else None
        buttons = copy_type_buttons(names[0], settings or {}) if settings else []
        if buttons:
            # По кнопке в ряд, если типов больше двух: подписи длинные
            run_rows = [buttons] if len(buttons) <= 2 else [[b] for b in buttons]
        else:
            data = f"backup_copy_run:{names[0]}"
            if len(data.encode()) > COPY_CALLBACK_LIMIT:
                data = "backup_copy_run_servers"
            run_rows = [[InlineKeyboardButton("📤 Скопировать сейчас",
                                              callback_data=data)]]
    elif len(names) <= SERVER_PICKER_PAGE_SIZE:
        # Источников немного: кнопка на каждый ведёт сразу к выбору типа,
        # отдельный экран «выбери сервер» тут был бы лишним шагом.
        for name in names:
            data = f"backup_copy_run:{name}"
            if len(data.encode()) > COPY_CALLBACK_LIMIT:
                run_rows = []
                break
            run_rows.append([InlineKeyboardButton(f"📤 {name}",
                                                  callback_data=data)])

    if not run_rows:
        run_rows = [[InlineKeyboardButton(
            "📤 Скопировать сейчас",
            callback_data="backup_copy_run_servers")]]

    # Журнал самого скрипта: он знает то, чего не знает бот, — сколько
    # баз обошли, что залито, что пропущено.
    for name in names:
        data = f"backup_copy_log:{name}"
        if len(data.encode()) > COPY_CALLBACK_LIMIT:
            continue
        run_rows.append([InlineKeyboardButton(
            f"📄 Журнал{'' if len(names) == 1 else ' · ' + name}",
            callback_data=data)])
    rows[-1:-1] = run_rows

    # Рейс, который числится идущим: если он завис или его убили руками,
    # без сброса следующая копия не поедет — бот считает сервер занятым.
    for name in names:
        if not (state.get(name) or {}).get("run"):
            continue
        data = f"backup_copy_reset:{name}"
        if len(data.encode()) > COPY_CALLBACK_LIMIT:
            continue
        rows.insert(-1, [InlineKeyboardButton(
            f"⏹ Сбросить рейс{'' if len(names) == 1 else ' · ' + name}",
            callback_data=data)])
    await safe_edit_message(query, text, reply_markup=InlineKeyboardMarkup(rows))


def _copy_script_path(server: dict, btype: str = None) -> str:
    """Скрипт, от которого считается каталог журналов. Скрипты разных
    типов обычно лежат рядом, поэтому для каталога годится любой."""
    scripts = (copy_settings(server) or {}).get("scripts") or {}
    if btype and scripts.get(btype):
        return scripts[btype]
    return next(iter(scripts.values()), "")


async def show_copy_log_types(query, context, server_name: str):
    """Какой журнал смотреть: у каждого типа копии он свой."""
    server = await asyncio.to_thread(find_server, server_name)
    settings = copy_settings(server) if server else None
    if not settings:
        await safe_edit_message(query, f"⚠️ У {server_name} не задан скрипт "
                                       f"копирования.", reply_markup=back_kb())
        return

    directory = log_dir(_copy_script_path(server))
    rows = []
    for btype in settings["scripts"]:
        data = f"backup_copy_logt:{server_name}:{btype}"
        if len(data.encode()) > COPY_CALLBACK_LIMIT:
            continue
        rows.append([InlineKeyboardButton(
            f"📄 {type_label(btype).capitalize()}", callback_data=data)])
    rows.append([InlineKeyboardButton("◀️ Назад", callback_data="backup_copy")])

    await safe_edit_message(
        query,
        f"📄 ЖУРНАЛ СКРИПТА · {server_name}\n\n"
        f"Каталог за сегодня:\n{directory}\n\n"
        f"Это журнал вашего скрипта, а не бота: в нём видно, какие базы "
        f"обошли, что залито и что пропущено.\n\nВыбери тип копии:",
        reply_markup=InlineKeyboardMarkup(rows)
    )


async def show_copy_log(query, context, server_name: str, btype: str):
    server = await asyncio.to_thread(find_server, server_name)
    if not server:
        await safe_edit_message(query, f"❌ Сервер {server_name} не найден.",
                                reply_markup=back_kb())
        return

    script = _copy_script_path(server, btype)
    path = common_log(script, btype)
    try:
        text = (await asyncio.to_thread(read_remote_log_info, server, path))["text"]
    except Exception as e:
        await safe_edit_message(
            query,
            f"❌ Не прочитать журнал {path}:\n{str(e)[:300]}",
            reply_markup=back_kb()
        )
        return

    back = [InlineKeyboardButton("◀️ Назад",
                                 callback_data=f"backup_copy_log:{server_name}")]
    if not text:
        await safe_edit_message(
            query,
            f"📄 {server_name} · {type_label(btype)}\n\n"
            f"Журнала за сегодня нет:\n{path}\n\n"
            f"Это нормально, если копий этого типа сегодня ещё не было.",
            reply_markup=InlineKeyboardMarkup([back])
        )
        return

    summary = parse_common_log(text)
    await _fill_progress(server, summary)
    lines = [f"🖥 {server_name}"] + summary_lines(summary)

    if summary.get("target_error"):
        lines.append("")
        lines.append(f"⚠️ Процент не посчитан: {summary['target_error']}")

    rows = []
    for entry in summary.get("databases") or []:
        data = f"backup_copy_logdb:{server_name}:{btype}:{entry['name']}"
        if len(data.encode()) > COPY_CALLBACK_LIMIT:
            continue
        rows.append([InlineKeyboardButton(f"🔎 {entry['name']}",
                                          callback_data=data)])
    rows.append(back)

    # Баз может быть много: обрезаем с конца, чтобы шапка со сводкой
    # осталась на месте — она и есть ответ на «как прошло».
    await safe_edit_message(query, "\n".join(lines)[:TELEGRAM_TEXT_LIMIT],
                            reply_markup=InlineKeyboardMarkup(rows))


# Хвост протокольного лога WinSCP: 4 КБ там — это пара секунд обмена,
# значимых строк в них может не оказаться вовсе.
WINSCP_TAIL_BYTES = 65536

# Журнал WinSCP крупнее этого — почти наверняка включён отладочный
# уровень: на копии в 44 ГБ такой файл дорастает до гигабайта.
WINSCP_BIG_LOG_MB = 200


def _winscp_body(path: str, info: dict) -> str:
    """Что показать по журналу WinSCP: он протокольный, не человеческий."""
    size_mb = round(info["size"] / 1024 / 1024, 1)
    lines = [path, f"📦 Размер журнала: {size_mb} МБ"]

    last = winscp_last_time(info["text"])
    if last:
        lines.append(f"🕒 Последняя запись: {last}")
    if winscp_is_transferring(info["text"]):
        lines.append("⏳ В хвосте идёт передача файла")

    if size_mb > WINSCP_BIG_LOG_MB:
        lines.append("")
        lines.append("⚠️ Журнал разросся: у WinSCP включён отладочный "
                     "уровень, он пишет по строке на каждые 32 КБ данных. "
                     "Понизьте /loglevel в скрипте, иначе на каждую "
                     "большую копию уходит около гигабайта диска.")

    highlights = winscp_highlights(info["text"])
    lines.append("")
    if highlights:
        lines.append("📄 Значимое из хвоста:")
        lines += [f"  {line}" for line in highlights]
    else:
        lines.append("📄 В хвосте только протокольный обмен — значимых "
                     "строк нет. Это нормально для идущей передачи.")
    return "\n".join(lines)


async def _fill_progress(server: dict, summary: dict):
    """Дописывает процент к базам, которые ещё в пути.

    Спрашиваем приёмник: у SFTP нет обратной связи о ходе передачи, и на
    стороне отправителя процента взять неоткуда. Ходим только за теми,
    кто реально едет, — обычно это одна база.
    """
    target = target_settings(server)
    if not target:
        return
    running = [e for e in summary.get("databases") or []
               if e["status"] == "upload" and e.get("remote") and e.get("bytes")]
    if not running:
        return

    receiver = await asyncio.to_thread(find_server, target["server"])
    if not receiver:
        summary["target_error"] = (f"сервера-приёмника {target['server']} "
                                   f"нет в конфиге")
        return

    for entry in running:
        path = target_path(target["root"], entry["remote"])
        try:
            size = await asyncio.to_thread(remote_file_size, receiver, path)
        except Exception as e:
            summary["target_error"] = str(e)[:120]
            return
        if size is None:
            continue
        entry["percent"] = progress_percent(entry["bytes"], size)
        entry["remote_gb"] = round(size / 1024 ** 3, 2)


async def show_copy_log_db(query, context, server_name: str, btype: str,
                           database: str):
    """Подробности WinSCP по одной базе — как есть, хвостом."""
    server = await asyncio.to_thread(find_server, server_name)
    if not server:
        await safe_edit_message(query, f"❌ Сервер {server_name} не найден.",
                                reply_markup=back_kb())
        return

    path = database_log(_copy_script_path(server, btype), btype, database)
    try:
        info = await asyncio.to_thread(read_remote_log_info, server, path,
                                       WINSCP_TAIL_BYTES, 300)
    except Exception as e:
        info, error = {"text": "", "size": 0}, str(e)[:300]
    else:
        error = ""

    back = [InlineKeyboardButton(
        "◀️ Назад", callback_data=f"backup_copy_logt:{server_name}:{btype}")]
    if error:
        body = f"❌ Не прочитать: {error}"
    elif not info["size"]:
        body = f"Файла нет:\n{path}"
    else:
        body = _winscp_body(path, info)

    await safe_edit_message(
        query,
        f"🔎 {database} · {type_label(btype)}\n\n{body}"[-TELEGRAM_TEXT_LIMIT:],
        reply_markup=InlineKeyboardMarkup([back])
    )


async def ask_copy_reset(query, context, server_name: str):
    state = await asyncio.to_thread(load_copy_state)
    run = (state.get(server_name) or {}).get("run") or {}
    await safe_edit_message(
        query,
        f"⏹ Сбросить рейс на {server_name}?\n\n"
        f"▶️ Числится идущим с {run.get('started')} (PID {run.get('pid')})\n"
        f"📜 {run.get('script') or '?'}\n\n"
        f"Бот перестанет считать сервер занятым и сможет запускать "
        f"копирование снова.\n"
        f"⚠️ Процесс на сервере при этом НЕ убивается: если он всё-таки "
        f"работает, получится два копирования разом. Убедитесь, что в "
        f"диспетчере задач его нет.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Да, сбросить",
                                 callback_data=f"backup_copy_resetgo:{server_name}"),
            InlineKeyboardButton("❌ Отмена", callback_data="backup_copy"),
        ]])
    )


async def do_copy_reset(query, context, server_name: str):
    if not can_delete_backups(query):
        await safe_edit_message(
            query,
            "⛔ Нет прав на сброс рейса.\n\nОбратитесь к администратору.",
            reply_markup=back_kb()
        )
        return
    try:
        run = await asyncio.to_thread(clear_run, server_name)
    except Exception as e:
        await safe_edit_message(query, f"❌ {str(e)[:300]}", reply_markup=back_kb())
        return

    audit.log_config_change(query.from_user, "copy_reset", server_name,
                            f"pid={run.get('pid')}")
    await show_copy_status(query, context)


async def show_copy_run_servers(query, context, page: int = 0):
    names = await asyncio.to_thread(copy_servers)
    if not names:
        await safe_edit_message(
            query,
            "⚠️ Ни у одного сервера не задан скрипт копирования.",
            reply_markup=back_kb()
        )
        return

    await safe_edit_message(
        query,
        "📤 ЗАПУСК КОПИРОВАНИЯ\n\n"
        "Выбери сервер-источник. Скрипт запустится на нём самом; "
        "большая база едет часами, ждать здесь не нужно.",
        reply_markup=build_paginated_server_keyboard(
            names, "backup_copy_run", page, back_callback="backup_copy")
    )


async def show_copy_types(query, context, server_name: str, scripts: dict):
    """Какую копию везти, когда скриптов несколько. Гадать нельзя: полная
    и разностная едут разными скриптами в разные каталоги."""
    rows = [[button] for button in
            copy_type_buttons(server_name, {"scripts": scripts})]
    rows.append([InlineKeyboardButton("◀️ Назад", callback_data="backup_copy")])

    await safe_edit_message(
        query,
        f"📤 {server_name}\n\nКакую копию везти?\n\n"
        + "\n".join(f"{type_label(t)}: {p}" for t, p in scripts.items()),
        reply_markup=InlineKeyboardMarkup(rows)
    )


async def do_copy_run(query, context, server_name: str, btype: str = None):
    if not can_delete_backups(query):
        await safe_edit_message(
            query,
            "⛔ Нет прав на запуск копирования.\n\nОбратитесь к администратору.",
            reply_markup=back_kb()
        )
        return

    if btype is None:
        server = await asyncio.to_thread(find_server, server_name)
        settings = copy_settings(server) if server else None
        if not settings:
            await safe_edit_message(
                query,
                f"⚠️ У {server_name} не задан скрипт копирования.",
                reply_markup=back_kb()
            )
            return
        scripts = settings["scripts"]
        # Один и тот же скрипт на несколько типов — выбирать нечего
        if len(set(scripts.values())) > 1:
            await show_copy_types(query, context, server_name, scripts)
            return

    await safe_edit_message(query, f"⏳ Запускаю копирование на {server_name}...")
    try:
        run = await asyncio.to_thread(start_copy_now, server_name, "бот", btype)
    except Exception as e:
        await safe_edit_message(
            query,
            f"❌ {server_name}: копирование не запущено.\n\n{str(e)[:300]}",
            reply_markup=back_kb()
        )
        return

    audit.log_config_change(query.from_user, "copy_run", server_name,
                            f"pid={run.get('pid')} {run.get('script') or ''}".strip())
    await safe_edit_message(
        query,
        f"📤 Копирование запущено: {server_name}\n\n"
        f"📜 {run.get('script') or 'скрипт сервера'}\n"
        f"▶️ Старт: {run.get('started')} (PID {run.get('pid')})\n\n"
        f"Скрипт работает на самом сервере — ботом можно пользоваться "
        f"дальше. Если копирование затянется дольше порога, придёт алерт "
        f"«КОПИРОВАНИЕ ЗАВИСЛО».",
        reply_markup=back_kb()
    )


# ─── Backup Report: выбор сервера ────────────────────────────

async def show_report_servers(query, context, page: int = 0):
    servers = await asyncio.to_thread(get_backup_servers)
    if not servers:
        await safe_edit_message(query, "⚠️ Нет данных по бэкапам.", reply_markup=back_kb())
        return

    await safe_edit_message(
        query,
        "📦 BACKUP REPORT\n\nВыбери сервер:",
        reply_markup=build_paginated_server_keyboard(servers, "backup_report", page)
    )


async def show_report_server(query, context, server_name: str, page: int = 0):
    rows = await asyncio.to_thread(get_backup_report, server_name)
    rows = await asyncio.to_thread(merge_backup_items, server_name, rows)
    if not rows:
        await safe_edit_message(
            query,
            f"⚠️ По серверу {server_name} ещё нет данных.\n\n"
            f"На сервере нет настроенных backup-путей.",
            reply_markup=back_kb()
        )
        return

    blocks = []
    for row in rows:
        btype = row["backup_type"]
        path = row["backup_path"]
        status = row.get("status")
        error = row.get("error")
        file_count = row["file_count"] or 0
        oldest = row["oldest_file"]
        newest = row["newest_file"]
        total_gb = float(row["total_size_gb"] or 0)
        disk_total = float(row["disk_total_gb"] or 0)
        disk_free = float(row["disk_free_gb"] or 0)
        free_pct = free_pct_or_none(disk_free, disk_total)

        # Срок хранения
        retention = "?"
        if oldest and newest:
            retention = f"{(to_utc_naive(newest) - to_utc_naive(oldest)).days} дней"

        lines = [f"Тип:      {btype.upper()}", f"Путь:     {path}"]

        if not status:
            lines += [
                "Статус:   Нет данных сбора",
                "Действие: Дождитесь цикла monitor или проверьте WinRM/доступ к пути",
            ]
            blocks.append("\n".join(lines))
            continue

        if status == BACKUP_PATH_ERROR_STATUS:
            lines += [
                "Статус:   Путь недоступен",
                f"Ошибка:   {short_error_text(error)}",
            ]
            blocks.append("\n".join(lines))
            continue

        if free_pct is None:
            disk_lines = ["Диск:     нет данных"]
        else:
            disk_lines = [
                f"Диск:     {fmt_size(disk_total)}",
                f"Свободно: {fmt_size(disk_free)} ({free_pct}%)",
                f"Занято:   {round(100 - free_pct, 1)}%",
            ]

        if file_count == 0:
            lines += [
                "Статус:   Каталог пуст",
                f"Размер:   {fmt_size(total_gb)}",
                *disk_lines,
            ]
            blocks.append("\n".join(lines))
            continue

        lines += [
            f"Файлов:   {file_count}",
            f"Старый:   {fmt_date(oldest)}",
            f"Новый:    {fmt_date(newest)} ({fmt_age(newest)})",
            f"Хранение: {retention}",
            f"Размер:   {fmt_size(total_gb)}",
            *disk_lines,
        ]
        blocks.append("\n".join(lines))

    header = f"💾 {server_name}\n\n{'━'*20}\n\n"
    text, keyboard = paginate_text_blocks(
        header,
        blocks,
        page=page,
        callback_prefix=f"backup_report_page:{server_name}",
        back_callback="backup_report_servers",
    )
    await safe_edit_message(query, text, reply_markup=keyboard)


# ─── DB Size ─────────────────────────────────────────────────

async def show_dbsize(query, context, page: int = 0):
    rows = await asyncio.to_thread(get_db_sizes)
    if not rows:
        await safe_edit_message(
            query,
            "⚠️ Нет данных. Убедитесь что dbsize=true в servers.json.",
            reply_markup=back_kb()
        )
        return

    by_server = defaultdict(list)
    for row in rows:
        by_server[row["server_name"]].append(row)

    blocks = []
    for server_name, dbs in sorted(by_server.items()):
        lines = [f"🖥 {server_name}\n"]
        for db in dbs:
            size_gb = float(db["size_gb"] or 0)
            lines.append(f"   📊 {db['database_name']}: {fmt_size(size_gb)}")
        blocks.append("\n".join(lines))

    text, keyboard = paginate_text_blocks(
        "🗄 РАЗМЕР БАЗ ДАННЫХ\n\n",
        blocks,
        page=page,
        callback_prefix="backup_dbsize_page"
    )
    await safe_edit_message(query, text, reply_markup=keyboard)


# ─── Рост баз и бэкапов ───────────────────────────────────────

async def show_growth_servers(query, context, page: int = 0):
    servers = await asyncio.to_thread(get_growth_servers)
    if not servers:
        await safe_edit_message(
            query,
            "⚠️ Нет истории размеров. Дождитесь сбора метрик.",
            reply_markup=back_kb()
        )
        return

    await safe_edit_message(
        query,
        "📈 РОСТ БАЗ И БЭКАПОВ\n\nВыбери сервер (график за 30 дней):",
        reply_markup=build_paginated_server_keyboard(servers, "backup_growth", page)
    )


async def send_growth_chart(query, server_name: str):
    try:
        path = await asyncio.to_thread(build_growth_chart, server_name)
    except Exception as e:
        await safe_edit_message(
            query,
            f"⚠️ Не удалось построить график: {e}",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("◀️ Назад", callback_data="backup_growth_servers")
            ]])
        )
        return

    try:
        with open(path, "rb") as image:
            await query.message.reply_photo(
                photo=image,
                caption=f"📈 {server_name} · рост за 30 дней"
            )
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    await safe_edit_message(
        query,
        f"📈 График роста {server_name} отправлен.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("◀️ Назад", callback_data="backup_growth_servers")
        ]])
    )


BACKUP_CHARTS = (
    (build_backup_freshness_chart, "🗂 Свежесть бэкапов по серверам"),
    (build_backup_volume_chart, "📦 Общий объём бэкапов · 30 дней"),
)


async def send_backup_charts(send_photo, send_text=None):
    """Тепловая карта свежести и общий объём за 30 дней.

    Вынесено из дайджеста отдельно, чтобы те же графики можно было приложить
    к плановому отчёту, не таща туда весь текст дайджеста.

    send_text не обязателен: в плановом job'е ошибку построения незачем слать
    в чат — она уходит в лог, а отчёт всё равно доставляется.
    """
    for builder, caption in BACKUP_CHARTS:
        try:
            path = await asyncio.to_thread(builder)
        except Exception as e:
            message = f"⚠️ Не удалось построить график ({caption}): {e}"
            if send_text:
                await send_text(message)
            else:
                print(f"[backup] {message}", flush=True)
            continue
        try:
            await send_photo(path, caption)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


async def send_backup_digest_report(send_text, send_photo, with_charts: bool = True):
    """Текст дайджеста + тепловая карта свежести + общий объём во времени.

    send_text(str) и send_photo(path, caption) — тонкие обёртки, чтобы одна
    и та же логика работала и по кнопке (query.message), и из планового
    job'а (context.bot + фиксированный chat_id).

    with_charts=False — только текст: в еженедельном отчёте те же графики
    уже приходят по расписанию утром и вечером, дублировать их незачем.
    """
    digest = await asyncio.to_thread(build_backup_digest)
    for chunk in split_message(digest):
        await send_text(chunk)

    if with_charts:
        await send_backup_charts(send_photo, send_text)


async def show_backup_digest(query, context):
    async def send_text(text):
        await query.message.reply_text(text)

    async def send_photo(path, caption):
        with open(path, "rb") as image:
            await query.message.reply_photo(photo=image, caption=caption)

    await send_backup_digest_report(send_text, send_photo)

    await safe_edit_message(
        query,
        "📋 Дайджест бэкапов отправлен.",
        reply_markup=back_kb()
    )


# ─── Cleanup: выбор сервера ───────────────────────────────────

async def show_cleanup_servers(query, context, page: int = 0):
    servers = await asyncio.to_thread(get_cleanup_servers)
    if not servers:
        await safe_edit_message(query, "⚠️ Нет данных по бэкапам.", reply_markup=back_kb())
        return

    await safe_edit_message(
        query,
        "🧹 CLEANUP\n\nВыбери сервер:",
        reply_markup=build_paginated_server_keyboard(servers, "backup_cleanup", page)
    )


async def show_cleanup_server(query, context, server_name: str):
    """Показать анализ и кнопки выбора возраста для удаления."""
    rows = await asyncio.to_thread(get_backup_report, server_name)
    if not rows:
        await safe_edit_message(query, f"⚠️ Нет данных по {server_name}", reply_markup=back_kb())
        return

    lines = [f"🧹 {server_name}\n"]
    has_deletable = False

    for row in rows:
        btype = row["backup_type"]
        if btype in NO_DELETE_TYPES:
            lines.append(f"{'━'*20}")
            lines.append(f"📁 {btype.upper()} — {row['backup_path']}")
            lines.append("   ⛔ Veeam не удаляется")
            lines.append("")
            continue

        has_deletable = True
        path = row["backup_path"]
        file_count = row["file_count"] or 0
        oldest = row["oldest_file"]
        newest = row["newest_file"]
        total_gb = float(row["total_size_gb"] or 0)
        free_pct = free_pct_or_none(row["disk_free_gb"], row["disk_total_gb"])

        lines += [
            f"{'━'*20}",
            f"Тип:     {btype.upper()}",
            f"Путь:    {path}",
            f"Файлов:  {file_count}",
            f"Старый:  {fmt_date(oldest)}",
            f"Новый:   {fmt_date(newest)}",
            f"Размер:  {fmt_size(total_gb)}",
            f"Свободно: {'?' if free_pct is None else f'{free_pct}%'}",
            "",
        ]

    text = "\n".join(lines)
    if not has_deletable:
        await safe_edit_message(query, text, reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("◀️ Назад", callback_data="backup_cleanup_servers")
        ]]))
        return

    # Несколько каталогов (часто на разных дисках) — сначала выбор куда чистить:
    # диски заполняются по-разному, и срок хранения для них тоже разный.
    targets = await asyncio.to_thread(cleanup_targets_for, server_name)
    if len(targets) > 1:
        keyboard = []
        for idx, target in enumerate(targets):
            keyboard.append([InlineKeyboardButton(
                f"💽 {target['disk']} · {target['type'].upper()} — {_short_path(target['path'])}",
                callback_data=f"backup_clpath:{server_name}:{idx}"
            )])
        keyboard.append([InlineKeyboardButton(
            "🗂 Все каталоги сразу", callback_data=f"backup_clpath:{server_name}:a")])
        keyboard.append([InlineKeyboardButton(
            "◀️ Назад", callback_data="backup_cleanup_servers")])
        await safe_edit_message(
            query,
            text + f"\n{'━'*20}\nКаталогов для очистки: {len(targets)}.\n"
                   "Выбери, где чистить — срок можно задать свой для каждого:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    # Один каталог — сразу выбор срока, с точным указанием пути (а не «все»)
    target_key = "0" if len(targets) == 1 else "a"
    await show_cleanup_days(query, context, server_name, target_key, header=text)


def _short_path(path: str, limit: int = 28) -> str:
    path = str(path or "")
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


def cleanup_targets_for(server_name: str) -> list:
    """Каталоги сервера, из которых разрешено удалять (без veeam)."""
    server = load_server_config(server_name)
    return deletable_backup_targets(server) if server else []


async def show_cleanup_days(query, context, server_name: str,
                            target_key: str, header: str = None):
    """Кнопки выбора возраста файлов для конкретного каталога (или всех)."""
    scope_note = "во всех каталогах"
    if target_key != "a":
        targets = await asyncio.to_thread(cleanup_targets_for, server_name)
        try:
            target = targets[int(target_key)]
        except (ValueError, IndexError):
            await safe_edit_message(
                query,
                "❌ Каталог не найден — возможно, конфиг изменился. Начни заново.",
                reply_markup=back_kb()
            )
            return
        scope_note = f"{target['disk']} · {target['type'].upper()}\n{target['path']}"

    text = (header + f"\n{'━'*20}\n") if header else f"🧹 {server_name}\n\n"
    text += f"Чистим: {scope_note}\n\nУдалить файлы старше:"

    def day_button(days: int):
        return InlineKeyboardButton(
            f"🗑 {days} дн",
            callback_data=f"backup_preview:{server_name}:{days}:{target_key}"
        )

    back_cb = (f"backup_cleanup:{server_name}" if target_key != "a"
               else "backup_cleanup_servers")
    kb = InlineKeyboardMarkup([
        [day_button(3), day_button(4), day_button(5)],
        [day_button(6), day_button(7), day_button(14)],
        [day_button(30)],
        [InlineKeyboardButton("◀️ Назад", callback_data=back_cb)],
    ])
    await safe_edit_message(query, text, reply_markup=kb)


async def show_cleanup_preview(query, context, server_name: str, age_days: int,
                               target_key: str = "a"):
    """Показать файлы которые будут удалены и запросить подтверждение."""
    only_path = None
    scope_line = "все каталоги"
    if target_key != "a":
        targets = await asyncio.to_thread(cleanup_targets_for, server_name)
        try:
            target = targets[int(target_key)]
        except (ValueError, IndexError):
            await safe_edit_message(
                query,
                "❌ Каталог не найден — возможно, конфиг изменился. Начни заново.",
                reply_markup=back_kb()
            )
            return
        only_path = target["path"]
        scope_line = f"{target['disk']} · {target['type'].upper()} — {only_path}"

    files = await asyncio.to_thread(
        get_files_for_cleanup, server_name, age_days, only_path)

    if not files:
        await safe_edit_message(
            query,
            f"✅ {server_name}\n\nНет файлов старше {age_days} дней.\nГде смотрели: {scope_line}",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("◀️ Назад", callback_data=f"backup_cleanup:{server_name}")
            ]])
        )
        return

    total_size = sum(f["size_gb"] for f in files)
    lines = [
        "🗑 ПРЕДПРОСМОТР УДАЛЕНИЯ\n",
        f"Сервер:    {server_name}",
        f"Каталог:   {scope_line}",
        f"Старше:    {age_days} дней",
        f"Файлов:    {len(files)}",
        f"Освободится: {fmt_size(total_size)}\n",
        f"{'━'*20}",
        "Будут удалены:\n",
    ]

    for f in files[:30]:  # показываем первые 30
        lines.append(
            f"🗑 {f['file_name']}\n"
            f"   {fmt_size(f['size_gb'])} | {fmt_date(f['modified'])} ({fmt_age(f['modified'])})"
        )

    if len(files) > 30:
        lines.append(f"\n... и ещё {len(files) - 30} файлов")

    # Сохраняем pending: только пути/размеры, без учётных данных.
    # Токен привязывает кнопку подтверждения именно к этому списку.
    token = uuid.uuid4().hex[:12]
    pending = {
        "token": token,
        "created_at": utcnow_naive().strftime("%Y-%m-%d %H:%M:%S"),
        "server_name": server_name,
        "age_days": age_days,
        "scope": scope_line,
        "files": [
            {
                "full_path": f["full_path"],
                "file_name": f["file_name"],
                "size_gb":   f["size_gb"],
            }
            for f in files
        ]
    }
    os.makedirs("/app/data", exist_ok=True)
    with open(CLEANUP_PENDING_FILE, "w") as fp:
        json.dump(pending, fp, ensure_ascii=False, default=str)

    text = "\n".join(lines)
    if len(text) > 3800:
        text = text[:3750] + "\n\n⚠️ Список обрезан"

    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Подтвердить удаление", callback_data=f"backup_cleanup_confirm:{token}"),
            InlineKeyboardButton("❌ Отмена", callback_data=f"backup_cleanup:{server_name}"),
        ]
    ])
    await safe_edit_message(query, text, reply_markup=kb)


def _load_pending(token: str) -> tuple[dict | None, str | None]:
    """Возвращает (pending, error_text)."""
    try:
        with open(CLEANUP_PENDING_FILE) as fp:
            pending = json.load(fp)
    except Exception:
        return None, "❌ Список устарел. Запустите Cleanup заново."

    if pending.get("token") != token:
        return None, "❌ Этот список уже неактуален (был сформирован новый). Запустите Cleanup заново."

    try:
        created = datetime.strptime(pending["created_at"], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None, "❌ Список повреждён. Запустите Cleanup заново."

    age_min = (utcnow_naive() - created).total_seconds() / 60
    if age_min > CLEANUP_PENDING_TTL_MINUTES:
        return None, (
            f"⏳ Список сформирован {round(age_min)} мин назад и устарел "
            f"(лимит {CLEANUP_PENDING_TTL_MINUTES} мин). Запустите Cleanup заново."
        )

    return pending, None


async def do_cleanup_confirm(query, context, token: str):
    """Выполнить удаление после подтверждения."""
    if not can_delete_backups(query):
        await safe_edit_message(
            query,
            "⛔ Нет прав на удаление файлов.\n\n"
            "Обратитесь к администратору.",
            reply_markup=back_kb()
        )
        user = getattr(query, "from_user", None)
        user_id = user.id if user else "unknown"
        print(f"[backup] Отказано в удалении файлов: user_id={user_id}", flush=True)
        return

    pending, error_text = _load_pending(token)
    if pending is None:
        await safe_edit_message(query, error_text, reply_markup=back_kb())
        return

    server_name = pending["server_name"]
    files = pending["files"]

    # Учётные данные берём из конфига в момент подтверждения —
    # в pending-файле они не хранятся.
    server = await asyncio.to_thread(load_server_config, server_name)
    if not server:
        await safe_edit_message(
            query,
            f"❌ Сервер {server_name} не найден в config/servers.json.",
            reply_markup=back_kb()
        )
        return

    lines = [f"🧹 РЕЗУЛЬТАТ ОЧИСТКИ\n🖥 {server_name}"]
    if pending.get("scope"):
        lines.append(f"📁 {pending['scope']}")
    lines.append("")
    total_deleted = 0
    total_freed = 0.0

    paths = [f["full_path"] for f in files]
    by_path = {f["full_path"]: f for f in files}
    try:
        results = await asyncio.to_thread(delete_backup_files, server, paths)
        for full_path, ok, err in results:
            f_info = by_path.get(full_path, {})
            fname = f_info.get("file_name", os.path.basename(full_path))
            size_gb = f_info.get("size_gb", 0)
            if ok:
                lines.append(f"✅ {fname} ({fmt_size(size_gb)})")
                total_deleted += 1
                total_freed += size_gb
            else:
                lines.append(f"❌ {fname}: {err[:60]}")
    except Exception as e:
        lines.append(f"❌ Ошибка подключения к {server['host']}: {str(e)[:80]}")

    lines += [
        f"\n{'━'*20}",
        f"Удалено:    {total_deleted} файлов",
        f"Освобождено: {fmt_size(total_freed)}",
    ]

    # Лог удаления
    log_path = "/app/data/cleanup_log.txt"
    try:
        user = getattr(query, "from_user", None)
        user_id = user.id if user else "unknown"
        with open(log_path, "a") as log:
            log.write(
                f"\n[{utcnow_naive().strftime('%Y-%m-%d %H:%M:%S')} UTC] "
                f"{server_name} (user_id={user_id}): удалено {total_deleted} файлов, "
                f"освобождено {fmt_size(total_freed)}\n"
            )
            for f in files:
                log.write(f"  {f['full_path']}\n")
    except Exception:
        pass

    try:
        os.remove(CLEANUP_PENDING_FILE)
    except Exception:
        pass

    summary = (
        f"🧹 РЕЗУЛЬТАТ ОЧИСТКИ\n"
        f"🖥 {server_name}\n\n"
        f"Удалено: {total_deleted} файлов\n"
        f"Освобождено: {fmt_size(total_freed)}"
    )

    await safe_edit_message(query, summary, reply_markup=back_kb())


# ─── Главный callback-роутер ─────────────────────────────────

async def backup_callback(query, context: ContextTypes.DEFAULT_TYPE):
    data = query.data

    if data == "backup_menu":
        await safe_edit_message(query, "💾 БЭКАПЫ\n\nВыбери раздел:", reply_markup=backup_menu_kb())

    elif data == "backup_health":
        await safe_edit_message(query, "⏳ Получаю данные...")
        await show_backup_health(query, context)

    elif data.startswith("backup_health_page:"):
        page = int(data.split(":", 1)[1])
        await show_backup_health(query, context, page=page)

    elif data == "backup_digest":
        await safe_edit_message(query, "⏳ Формирую дайджест...")
        await show_backup_digest(query, context)

    elif data == "backup_verify":
        await safe_edit_message(query, "⏳ Получаю verify-статус...")
        await show_verify_status(query, context)

    elif data.startswith("backup_verify_page:"):
        page = int(data.split(":", 1)[1])
        await show_verify_status(query, context, page=page)

    elif data == "backup_verify_run_servers":
        await show_verify_run_servers(query, context)

    elif data.startswith("backup_verify_run_servers:"):
        page = int(data.split(":", 1)[1])
        await show_verify_run_servers(query, context, page=page)

    elif data.startswith("backup_verify_run:"):
        server_name = data.split(":", 1)[1]
        await do_verify_run(query, context, server_name)

    elif data == "backup_copy":
        await safe_edit_message(query, "⏳ Смотрю состояние копирования...")
        await show_copy_status(query, context)

    elif data.startswith("backup_copy_page:"):
        page = int(data.split(":", 1)[1])
        await show_copy_status(query, context, page=page)

    elif data == "backup_copy_run_servers":
        await show_copy_run_servers(query, context)

    elif data.startswith("backup_copy_run_servers:"):
        page = int(data.split(":", 1)[1])
        await show_copy_run_servers(query, context, page=page)

    elif data.startswith("backup_copy_run:"):
        server_name = data.split(":", 1)[1]
        await do_copy_run(query, context, server_name)

    elif data.startswith("backup_copy_logdb:"):
        rest = data[len("backup_copy_logdb:"):]
        server_name, btype, database = rest.split(":", 2)
        await safe_edit_message(query, "⏳ Читаю журнал...")
        await show_copy_log_db(query, context, server_name, btype, database)

    elif data.startswith("backup_copy_logt:"):
        server_name, btype = data[len("backup_copy_logt:"):].rsplit(":", 1)
        await safe_edit_message(query, "⏳ Читаю журнал...")
        await show_copy_log(query, context, server_name, btype)

    elif data.startswith("backup_copy_log:"):
        await show_copy_log_types(query, context, data.split(":", 1)[1])

    elif data.startswith("backup_copy_reset:"):
        await ask_copy_reset(query, context, data.split(":", 1)[1])

    elif data.startswith("backup_copy_resetgo:"):
        await do_copy_reset(query, context, data.split(":", 1)[1])

    elif data.startswith("backup_copy_go:"):
        server_name, btype = data[len("backup_copy_go:"):].rsplit(":", 1)
        await do_copy_run(query, context, server_name, btype)

    elif data == "backup_report_servers":
        await show_report_servers(query, context)

    elif data.startswith("backup_report_servers:"):
        page = int(data.split(":", 1)[1])
        await show_report_servers(query, context, page=page)

    elif data.startswith("backup_report_page:"):
        server_name, page_str = data[len("backup_report_page:"):].rsplit(":", 1)
        await show_report_server(query, context, server_name, page=int(page_str))

    elif data.startswith("backup_report:"):
        server_name = data.split(":", 1)[1]
        await safe_edit_message(query, "⏳ Формирую отчёт...")
        await show_report_server(query, context, server_name)

    elif data == "backup_dbsize":
        await safe_edit_message(query, "⏳ Получаю размеры БД...")
        await show_dbsize(query, context)

    elif data.startswith("backup_dbsize_page:"):
        page = int(data.split(":", 1)[1])
        await show_dbsize(query, context, page=page)

    elif data == "backup_growth_servers":
        await show_growth_servers(query, context)

    elif data.startswith("backup_growth_servers:"):
        page = int(data.split(":", 1)[1])
        await show_growth_servers(query, context, page=page)

    elif data.startswith("backup_growth:"):
        server_name = data.split(":", 1)[1]
        await safe_edit_message(query, "📈 Строю график роста...")
        await send_growth_chart(query, server_name)

    elif data == "backup_cleanup_servers":
        await show_cleanup_servers(query, context)

    elif data.startswith("backup_cleanup_servers:"):
        page = int(data.split(":", 1)[1])
        await show_cleanup_servers(query, context, page=page)

    elif data.startswith("backup_cleanup_confirm:"):
        token = data.split(":", 1)[1]
        await safe_edit_message(query, "⏳ Удаляю файлы...")
        await do_cleanup_confirm(query, context, token)

    elif data.startswith("backup_cleanup:"):
        server_name = data.split(":", 1)[1]
        await safe_edit_message(query, "⏳ Анализирую бэкапы...")
        await show_cleanup_server(query, context, server_name)

    elif data.startswith("backup_clpath:"):
        _, server_name, target_key = data.split(":", 2)
        await show_cleanup_days(query, context, server_name, target_key)

    elif data.startswith("backup_preview:"):
        # backup_preview:<server>:<days>[:<индекс каталога|a>]
        parts = data.split(":")
        server_name, age_str = parts[1], parts[2]
        target_key = parts[3] if len(parts) > 3 else "a"
        await safe_edit_message(query, "⏳ Собираю список файлов...")
        await show_cleanup_preview(query, context, server_name, int(age_str), target_key)

    elif data == "backup_noop":
        return
