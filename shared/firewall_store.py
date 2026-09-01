"""
shared/firewall_store.py

Список заблокированных адресов и белый список. Пишет бот, читает бот и
монитор (он снимает истёкшие блокировки).

Список живёт в базе, а не на сервере, по трём причинам: правило Windows
Firewall не хранит ни срока, ни причины, ни автора; пересозданный или
поправленный руками сервер теряет список целиком; и разбирать «за что этот
адрес тут лежит» через полгода иначе не по чему.

Правило на сервере — производная от этих строк: см. `apply_blocks` в
shared/firewall.py, оно каждый раз собирает правило из списка целиком.
"""
import threading
from datetime import datetime, timedelta, timezone

from pgconn import get_conn

_ready = False
_ready_lock = threading.Lock()

# Срок по умолчанию. Три дня — из того же соображения, что и в исходном
# скрипте: сканирование с адреса обычно заканчивается за сутки-двое, а
# бессрочная блокировка копится и однажды отрезает того, кто давно сменил
# владельца адреса.
DEFAULT_DAYS = 3


def ensure_tables():
    """Создаёт таблицы на существующих установках: init.sql накатывается
    только при первом старте базы."""
    global _ready
    if _ready:
        return
    with _ready_lock:
        if _ready:
            return
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fw_blocks (
                    server_name TEXT NOT NULL,
                    address     TEXT NOT NULL,
                    reason      TEXT,
                    author      TEXT,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at  TIMESTAMPTZ,
                    PRIMARY KEY (server_name, address)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fw_whitelist (
                    server_name TEXT NOT NULL,
                    address     TEXT NOT NULL,
                    note        TEXT,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (server_name, address)
                )
            """)
        _ready = True


def expires_from_days(days) -> datetime:
    """Срок в днях → момент снятия. None означает «бессрочно»."""
    if days is None:
        return None
    return datetime.now(timezone.utc) + timedelta(days=int(days))


# ─── Блокировки ──────────────────────────────────────────────

def list_blocks(server_name: str) -> list:
    """Действующие блокировки: [{address, reason, author, created_at,
    expires_at}]. Истёкшие не отдаются — их снимет монитор, но в списке им
    делать нечего уже сейчас."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT address, reason, author, created_at, expires_at
            FROM fw_blocks
            WHERE server_name = %s
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
        """, (server_name,))
        return [{"address": row[0], "reason": row[1], "author": row[2],
                 "created_at": row[3], "expires_at": row[4]}
                for row in cur.fetchall()]


def add_block(server_name: str, address: str, reason: str = "",
              author: str = "", days=DEFAULT_DAYS):
    """Заводит или продлевает блокировку. Повторная блокировка того же
    адреса — это продление срока, а не ошибка."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO fw_blocks (server_name, address, reason, author,
                                   created_at, expires_at)
            VALUES (%s, %s, %s, %s, NOW(), %s)
            ON CONFLICT (server_name, address) DO UPDATE
              SET reason = EXCLUDED.reason,
                  author = EXCLUDED.author,
                  created_at = NOW(),
                  expires_at = EXCLUDED.expires_at
        """, (server_name, address, reason or None, author or None,
              expires_from_days(days)))


def remove_block(server_name: str, address: str) -> bool:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM fw_blocks WHERE server_name = %s AND address = %s",
            (server_name, address))
        return cur.rowcount > 0


def take_expired() -> dict:
    """Удаляет истёкшие блокировки и возвращает {сервер: [адреса]}.

    Удаление и выдача — одним запросом (DELETE … RETURNING): иначе между
    «прочитали» и «удалили» вклинивается ручное снятие из бота, и адрес
    снимается дважды или не снимается вовсе.
    """
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM fw_blocks
            WHERE expires_at IS NOT NULL AND expires_at <= NOW()
            RETURNING server_name, address
        """)
        result = {}
        for server_name, address in cur.fetchall():
            result.setdefault(server_name, []).append(address)
    return result


# ─── Белый список ────────────────────────────────────────────

def list_whitelist(server_name: str) -> list:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT address, note FROM fw_whitelist
            WHERE server_name = %s ORDER BY address
        """, (server_name,))
        return [{"address": row[0], "note": row[1]} for row in cur.fetchall()]


def add_white(server_name: str, address: str, note: str = ""):
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO fw_whitelist (server_name, address, note)
            VALUES (%s, %s, %s)
            ON CONFLICT (server_name, address) DO UPDATE
              SET note = EXCLUDED.note
        """, (server_name, address, note or None))


def remove_white(server_name: str, address: str) -> bool:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM fw_whitelist WHERE server_name = %s AND address = %s",
            (server_name, address))
        return cur.rowcount > 0


def forget_server(server_name: str):
    """Сервер убрали из конфига — его списки больше ничего не значат."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        for table in ("fw_blocks", "fw_whitelist"):
            cur.execute(f"DELETE FROM {table} WHERE server_name = %s",
                        (server_name,))
