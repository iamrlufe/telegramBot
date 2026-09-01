"""
shared/iis_store.py

Хранение сводки IIS: пишет монитор, читает бот.

Здесь, в отличие от журналов Windows, копится **накопление, а не снимок**.
Логи читаются по смещению, каждый проход приносит только новые строки, и
сводка за сутки складывается из этих кусков: строки за 24 часа суммируются
по ключу при чтении.

Смещения живут отдельно (`iis_state`) — потерять их значит либо перечитать
20 ГБ истории, либо пропустить сутки.

Факты о конфигурации (публикации, пулы, объём каталога логов) меняются
редко и хранятся снимком в `iis_facts`.
"""
import json
import threading

from pgconn import get_conn
from iis_log import detect_brute_force

_ready = False
_ready_lock = threading.Lock()

# Дашборд показывает сутки, карточка сервера — до недели. Держим восемь
# дней: счётчики компактные, а неделя должна быть полной до последнего часа.
KEEP_DAYS = 8


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
                CREATE TABLE IF NOT EXISTS iis_events (
                    id          SERIAL PRIMARY KEY,
                    server_name TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    item        TEXT NOT NULL,
                    count       BIGINT NOT NULL DEFAULT 0,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_iis_events_created
                    ON iis_events (created_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_iis_events_server
                    ON iis_events (server_name, category)
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS iis_state (
                    server_name TEXT NOT NULL,
                    source      TEXT NOT NULL,
                    file_name   TEXT NOT NULL,
                    position    BIGINT NOT NULL,
                    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (server_name, source, file_name)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS iis_facts (
                    server_name TEXT NOT NULL,
                    fact        TEXT NOT NULL,
                    value       TEXT,
                    error       TEXT,
                    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (server_name, fact)
                )
            """)
        _ready = True


# ─── Смещения ────────────────────────────────────────────────

def load_state(server_name: str, source: str) -> dict:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT file_name, position FROM iis_state
            WHERE server_name = %s AND source = %s
        """, (server_name, source))
        return {row[0]: int(row[1]) for row in cur.fetchall()}


def save_state(server_name: str, source: str, state: dict):
    """Сохраняет смещения и убирает файлы, которых больше нет в окне: иначе
    список рос бы вечно и раздувал скрипт, который уезжает на сервер."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM iis_state WHERE server_name = %s AND source = %s
        """, (server_name, source))
        for file_name, position in (state or {}).items():
            cur.execute("""
                INSERT INTO iis_state (server_name, source, file_name, position)
                VALUES (%s, %s, %s, %s)
            """, (server_name, source, file_name, int(position)))


# ─── Счётчики ────────────────────────────────────────────────

def save_events(server_name: str, rows: list):
    """rows — [(category, item, count)]. Пустой проход тоже записываем как
    факт сбора: строка с category='total' и нулём отличает «тихо» от
    «не собиралось»."""
    ensure_tables()
    if not rows:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        for category, item, count in rows:
            cur.execute("""
                INSERT INTO iis_events (server_name, category, item, count)
                VALUES (%s, %s, %s, %s)
            """, (server_name, category, str(item)[:400], int(count)))


def read_events(hours: int = 24) -> dict:
    """Счётчики за период, сложенные по ключу:
    {сервер: {категория: [{"item", "count"}, ...]}}."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT server_name, category, item, SUM(count)
            FROM iis_events
            WHERE created_at >= NOW() - make_interval(hours => %s)
            GROUP BY server_name, category, item
            ORDER BY server_name, category, SUM(count) DESC
        """, (hours,))
        result = {}
        for server_name, category, item, total in cur.fetchall():
            result.setdefault(server_name, {}).setdefault(category, []).append(
                {"item": item, "count": int(total)}
            )
    return result


def cleanup(days: int = KEEP_DAYS) -> int:
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM iis_events WHERE created_at < NOW() - make_interval(days => %s)",
            (days,)
        )
        return cur.rowcount


# ─── Факты о конфигурации ────────────────────────────────────

def save_fact(server_name: str, fact: str, value, error: str = ""):
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO iis_facts (server_name, fact, value, error, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (server_name, fact)
            DO UPDATE SET value = EXCLUDED.value, error = EXCLUDED.error,
                          updated_at = NOW()
        """, (server_name, fact, json.dumps(value, ensure_ascii=False), error or None))


def read_facts() -> dict:
    """{сервер: {факт: значение, "_updated": время, "_error": текст}}."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT server_name, fact, value, error, updated_at FROM iis_facts")
        result = {}
        for server_name, fact, value, error, updated_at in cur.fetchall():
            entry = result.setdefault(server_name, {})
            try:
                entry[fact] = json.loads(value) if value else None
            except (TypeError, ValueError):
                entry[fact] = None
            entry["_updated"] = updated_at
            if error:
                entry["_error"] = error
    return result


def forget_server(server_name: str):
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        for table in ("iis_events", "iis_state", "iis_facts"):
            cur.execute(f"DELETE FROM {table} WHERE server_name = %s", (server_name,))


# ─── Находки для сводки проблем и алертов ────────────────────

def iis_findings() -> list:
    """Находки IIS для сводки проблем: [(сервер, {level, text, key, hint})].

    Три вещи, ради которых стоит идти на сервер: сканер получил успешный
    ответ, идёт подбор пароля, публикации были недоступны. Всё остальное из
    IIS-сводки — фон, ему место в дашборде, а не в тревоге.
    """
    try:
        day = read_events(24)
        hour = read_events(1)
    except Exception as e:
        print(f"[iis] Сводка недоступна: {e}", flush=True)
        return []

    found = []
    for server_name, events in day.items():
        for row in (events.get("hit") or [])[:5]:
            uri, ip, _ua = (str(row["item"]).split("|") + ["", "", ""])[:3]
            found.append((server_name, {
                "level": "crit",
                "text": f"🔴 сервер отдал {uri} — запрос с {ip}",
                "hint": "посторонний путь ответил содержимым",
                "key": f"iis_hit:{server_name}:{uri}",
            }))

        down = [row for row in (events.get("herr") or [])
                if row["item"] in ("QueueFull", "AppOffline", "Connections_Refused")]
        for row in down:
            found.append((server_name, {
                "level": "crit",
                "text": f"🔴 публикации были недоступны: {row['item']} × {row['count']}",
                "hint": row["item"],
                "key": f"iis_down:{server_name}:{row['item']}",
            }))

    for server_name, events in hour.items():
        logins = [{"parts": (str(r["item"]).split("|") + ["", ""])[:2],
                   "count": r["count"]} for r in events.get("login") or []]
        requests = [{"parts": [str(r["item"])], "count": r["count"]}
                    for r in events.get("ip") or []]
        for item in detect_brute_force(logins, requests):
            if item["working"]:
                continue
            found.append((server_name, {
                "level": "crit",
                "text": (f"🔴 подбор пароля 1С: {item['ip']} → {item['base']}, "
                         f"{item['count']} входов за час"),
                "hint": f"{item['count']} входов за час с {item['ip']}",
                "key": f"iis_brute:{server_name}:{item['ip']}",
            }))
    return found
