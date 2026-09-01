"""
bot/audit.py

Аудит изменений конфигурации серверов (добавление/изменение/удаление и т.п.)
из раздела ⚙️ Настройка. Пишется в PostgreSQL (таблица config_audit) с датой
и Telegram user_id — для расследований «кто и когда поменял сервер».

Раньше эти события уходили только в stdout контейнера; теперь остаётся
постоянный след, доступный из бота (📜 Аудит).
"""
from datetime import timezone
from zoneinfo import ZoneInfo

from pgconn import get_conn

ALMATY = ZoneInfo("Asia/Almaty")

# Человекочитаемые подписи действий для экрана аудита
ACTION_LABELS = {
    "add":      "➕ добавлен",
    "edit":     "✏️ изменён",
    "toggle":   "🔀 переключено",
    "services": "⚙️ сервисы",
    "delete":   "🗑 удалён",
    "reboot":   "♻️ перезагрузка",
    "fwblock":  "🚫 блокировка IP",
    "fwunblock": "✅ снята блокировка",
    "fwwhite":  "⚪ белый список",
    "fwsync":   "🔄 правило перезаписано",
}

_table_ready = False


def _ensure_table():
    """Создаёт таблицу на существующих инсталляциях, где init.sql уже отработал
    до появления config_audit. Выполняется один раз за процесс."""
    global _table_ready
    if _table_ready:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS config_audit (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                user_id     BIGINT,
                username    TEXT,
                action      TEXT NOT NULL,
                target      TEXT,
                details     TEXT
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_config_audit_created
                ON config_audit (created_at DESC)
        """)
    _table_ready = True


def log_config_change(user, action: str, target: str = None, details: str = None):
    """Записывает изменение конфига. user — объект Telegram (from_user) либо id.

    Аудит не должен ронять основную операцию: любая ошибка записи только
    логируется в stdout, исключение наружу не пробрасывается."""
    user_id, username = _user_fields(user)
    try:
        _ensure_table()
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO config_audit (user_id, username, action, target, details) "
                "VALUES (%s, %s, %s, %s, %s)",
                (user_id, username, action, target, details),
            )
    except Exception as e:
        print(f"[audit] Не удалось записать аудит ({action} {target}): {e}", flush=True)
    finally:
        print(f"[audit] {user_id} {action} {target or ''} — {details or ''}", flush=True)


def _user_fields(user):
    if user is None:
        return None, None
    if isinstance(user, int):
        return user, None
    uid = getattr(user, "id", None)
    uname = getattr(user, "username", None) or getattr(user, "full_name", None)
    return uid, uname


def get_recent_audit(limit: int = 20) -> list:
    """[(created_at, user_id, username, action, target, details)] — свежие сверху."""
    try:
        _ensure_table()
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT created_at, user_id, username, action, target, details "
                "FROM config_audit ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
            return cur.fetchall()
    except Exception as e:
        print(f"[audit] Не удалось прочитать аудит: {e}", flush=True)
        return []


def format_audit(rows: list) -> str:
    if not rows:
        return "📜 АУДИТ ИЗМЕНЕНИЙ\n\nПока нет записей."

    lines = ["📜 АУДИТ ИЗМЕНЕНИЙ", "━" * 20, ""]
    for created_at, user_id, username, action, target, details in rows:
        when = created_at.astimezone(ALMATY).strftime("%d.%m %H:%M") if created_at else "?"
        who = f"@{username}" if username else str(user_id or "?")
        label = ACTION_LABELS.get(action, action)
        line = f"{when} · {who}\n   {label} {target or ''}".rstrip()
        if details:
            line += f" — {details}"
        lines.append(line)
    return "\n".join(lines)
