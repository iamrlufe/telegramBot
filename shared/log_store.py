"""
shared/log_store.py

Хранение сводки журналов Windows и SQL: пишет монитор, читает бот.

Хранится снимок, а не история. Монитор каждый раз читает журналы за
последние сутки, и запись снимком означает, что в базе всегда ровно то же,
что показал бы сервер сейчас: ни дублей при повторном чтении одного и того
же события, ни разрастания таблицы. Ретеншн такому хранению не нужен —
объём не зависит от времени, только от числа серверов.

Снимок заменяется только при успешном чтении. Если сервер не ответил,
предыдущие записи остаются на месте, а в log_scans появляется ошибка и
время попытки: «данные от вчера» полезнее пустого экрана, но обязано быть
подписано как несвежее.
"""
import threading

from pgconn import get_conn

_ready = False
_ready_lock = threading.Lock()

SOURCES = ("win", "sql")


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
                CREATE TABLE IF NOT EXISTS log_events (
                    id          SERIAL PRIMARY KEY,
                    server_name TEXT NOT NULL,
                    source      TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    level       TEXT NOT NULL,
                    event_at    TEXT,
                    event_id    TEXT,
                    title       TEXT NOT NULL,
                    detail      TEXT,
                    event_count INTEGER NOT NULL DEFAULT 1,
                    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_log_events_server
                    ON log_events (server_name, source)
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS log_scans (
                    server_name  TEXT NOT NULL,
                    source       TEXT NOT NULL,
                    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    error        TEXT,
                    PRIMARY KEY (server_name, source)
                )
            """)
        _ready = True


def save_snapshot(server_name: str, source: str, events: list, error: str = ""):
    """Заменяет снимок сервера по одному источнику. Всё в одной транзакции:
    иначе между удалением и вставкой дашборд успевал бы прочитать пустоту."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM log_events WHERE server_name = %s AND source = %s",
            (server_name, source)
        )
        for event in events:
            cur.execute("""
                INSERT INTO log_events (server_name, source, category, level,
                                        event_at, event_id, title, detail, event_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (server_name, source, event["category"], event["level"],
                  event.get("event_at") or None, event.get("event_id") or None,
                  event["title"], event.get("detail") or None,
                  event.get("count", 1)))
        cur.execute("""
            INSERT INTO log_scans (server_name, source, collected_at, error)
            VALUES (%s, %s, NOW(), %s)
            ON CONFLICT (server_name, source)
            DO UPDATE SET collected_at = NOW(), error = EXCLUDED.error
        """, (server_name, source, error or None))


def save_failure(server_name: str, source: str, error: str):
    """Сервер не ответил: снимок не трогаем, отмечаем неудачную попытку."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO log_scans (server_name, source, collected_at, error)
            VALUES (%s, %s, NOW(), %s)
            ON CONFLICT (server_name, source)
            DO UPDATE SET collected_at = NOW(), error = EXCLUDED.error
        """, (server_name, source, error or "неизвестная ошибка"))


def read_snapshot() -> tuple[list, dict]:
    """Все события и состояние последнего сбора по (сервер, источник)."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT server_name, source, category, level, event_at, event_id,
                   title, detail, event_count
            FROM log_events
            ORDER BY server_name, source, event_at DESC NULLS LAST
        """)
        events = [
            {"server": row[0], "source": row[1], "category": row[2],
             "level": row[3], "event_at": row[4] or "", "event_id": row[5] or "",
             "title": row[6], "detail": row[7] or "", "count": row[8]}
            for row in cur.fetchall()
        ]
        cur.execute("SELECT server_name, source, collected_at, error FROM log_scans")
        scans = {
            (row[0], row[1]): {"collected_at": row[2], "error": row[3] or ""}
            for row in cur.fetchall()
        }
    return events, scans


def forget_server(server_name: str):
    """Сервер убрали из конфига — его записи больше не нужны."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM log_events WHERE server_name = %s", (server_name,))
        cur.execute("DELETE FROM log_scans WHERE server_name = %s", (server_name,))
