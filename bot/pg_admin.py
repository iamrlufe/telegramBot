"""
bot/pg_admin.py

Обслуживание собственной БД мониторинга (PostgreSQL):
- размер базы и таблиц;
- ручная очистка истории старше 20/25/30 дней с предпросмотром.

Автоочистка монитора (30 дней) продолжает работать независимо —
ручная нужна, чтобы освободить место раньше.
"""
import os
import asyncio

import psycopg2

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

from pgconn import get_conn
from tg_utils import safe_edit_message

# (таблица, колонка времени) — имена только из этого списка, ввод пользователя
# в SQL не попадает
TABLES = [
    ("server_status",        "checked_at"),
    ("disk_metrics",         "created_at"),
    ("service_status",       "checked_at"),
    ("process_metrics",      "created_at"),
    ("backup_metrics",       "created_at"),
    ("database_sizes",       "collected_at"),
    ("onec_log_metrics",     "created_at"),
    ("backup_verifications", "created_at"),
]

CLEANUP_DAYS_OPTIONS = [30, 25, 20]


# ─── Статистика ──────────────────────────────────────────────

def get_pg_stats() -> str:
    rows = []
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT pg_size_pretty(pg_database_size(current_database()))")
        total = cur.fetchone()[0]

        for table, ts_col in TABLES:
            try:
                cur.execute(
                    f"SELECT pg_size_pretty(pg_total_relation_size('{table}')), "
                    f"       COUNT(*), MIN({ts_col}) "
                    f"FROM {table}"
                )
                size, count, oldest = cur.fetchone()
                rows.append((table, size, count, oldest))
            except psycopg2.Error:
                conn.rollback()

    lines = [
        "🐘 БАЗА МОНИТОРИНГА (PostgreSQL)",
        "━" * 20,
        f"Всего: {total}",
        "",
    ]
    for table, size, count, oldest in sorted(rows, key=lambda r: r[0]):
        oldest_str = oldest.strftime("%d.%m.%Y") if oldest else "—"
        lines.append(f"{table}:")
        lines.append(f"   {size} · {count:,} строк · с {oldest_str}".replace(",", " "))
    lines.append("")
    lines.append("Автоочистка: данные старше 30 дней удаляются раз в сутки.")
    return "\n".join(lines)


# ─── Очистка ─────────────────────────────────────────────────

def count_old_rows(days: int) -> list[tuple[str, int]]:
    """[(таблица, сколько строк старше days)] — только таблицы с данными."""
    result = []
    with get_conn() as conn:
        cur = conn.cursor()
        for table, ts_col in TABLES:
            try:
                cur.execute(
                    f"SELECT COUNT(*) FROM {table} "
                    f"WHERE {ts_col} < NOW() - make_interval(days => %s)",
                    (days,)
                )
                count = cur.fetchone()[0]
                if count:
                    result.append((table, count))
            except psycopg2.Error:
                conn.rollback()
    return result


def delete_old_rows(days: int) -> list[tuple[str, int]]:
    """Удаляет строки старше days. Возвращает [(таблица, удалено)]."""
    result = []
    with get_conn() as conn:
        cur = conn.cursor()
        for table, ts_col in TABLES:
            try:
                cur.execute(
                    f"DELETE FROM {table} "
                    f"WHERE {ts_col} < NOW() - make_interval(days => %s)",
                    (days,)
                )
                if cur.rowcount:
                    result.append((table, cur.rowcount))
            except psycopg2.Error:
                conn.rollback()

    # VACUUM нельзя выполнять в транзакции — отдельное autocommit-подключение.
    # Возвращает место под повторное использование и обновляет статистику.
    vacuum_conn = None
    try:
        vacuum_conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST"),
            dbname=os.getenv("POSTGRES_DB"),
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD")
        )
        vacuum_conn.autocommit = True
        cur = vacuum_conn.cursor()
        for table, _ in result:
            try:
                cur.execute(f"VACUUM ANALYZE {table}")
            except psycopg2.Error:
                pass
    except Exception as e:
        print(f"[pg_admin] VACUUM не выполнен: {e}", flush=True)
    finally:
        # Закрываем в finally: без него сбой на VACUUM оставлял живое
        # подключение к Postgres на каждый вызов очистки
        if vacuum_conn is not None:
            try:
                vacuum_conn.close()
            except Exception:
                pass

    return result


# ─── UI ──────────────────────────────────────────────────────

def back_to_cfg_kb():
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("◀️ Назад", callback_data="cfg_menu")
    ]])


def cleanup_options_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(f"🗑 Старше {days} дн", callback_data=f"cfg_pgclean:{days}")
            for days in CLEANUP_DAYS_OPTIONS
        ],
        [InlineKeyboardButton("◀️ Назад", callback_data="cfg_menu")],
    ])


async def show_pg_stats(query):
    text = await asyncio.to_thread(get_pg_stats)
    await safe_edit_message(query, text, reply_markup=back_to_cfg_kb())


async def show_cleanup_menu(query):
    await safe_edit_message(
        query,
        "🗑 ОЧИСТКА ИСТОРИИ МОНИТОРИНГА\n\n"
        "Удаляет старые записи из базы бота (метрики, статусы, история backup).\n"
        "На сами бэкапы и серверы не влияет.\n\n"
        "Выбери порог:",
        reply_markup=cleanup_options_kb()
    )


async def show_cleanup_preview(query, days: int):
    counts = await asyncio.to_thread(count_old_rows, days)
    if not counts:
        await safe_edit_message(
            query,
            f"✅ Нет записей старше {days} дней.",
            reply_markup=cleanup_options_kb()
        )
        return

    total = sum(c for _, c in counts)
    lines = [f"🗑 Будут удалены записи старше {days} дней:", ""]
    for table, count in counts:
        lines.append(f"   {table}: {count:,}".replace(",", " "))
    lines.append("")
    lines.append(f"Итого: {total:,} строк".replace(",", " "))

    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Удалить", callback_data=f"cfg_pgclean_do:{days}"),
            InlineKeyboardButton("❌ Отмена", callback_data="cfg_pgclean_menu"),
        ]
    ])
    await safe_edit_message(query, "\n".join(lines), reply_markup=kb)


async def do_cleanup(query, days: int):
    await safe_edit_message(query, f"⏳ Удаляю записи старше {days} дней...")
    deleted = await asyncio.to_thread(delete_old_rows, days)

    total = sum(c for _, c in deleted)
    lines = [f"🧹 ОЧИСТКА ИСТОРИИ (> {days} дн)", ""]
    if deleted:
        for table, count in deleted:
            lines.append(f"   {table}: {count:,}".replace(",", " "))
        lines.append("")
    lines.append(f"Удалено всего: {total:,} строк".replace(",", " "))

    user = getattr(query, "from_user", None)
    print(
        f"[pg_admin] {user.id if user else '?'} удалил {total} строк старше {days} дн",
        flush=True
    )
    await safe_edit_message(query, "\n".join(lines), reply_markup=back_to_cfg_kb())
