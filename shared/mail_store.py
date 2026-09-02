"""
shared/mail_store.py

Хранение почтовой сводки Zimbra и Exchange: пишет монитор, читает бот.

Хранится снимок, а не история — как в log_store. Оба сборщика каждый раз
читают журналы за последние сутки, и запись снимком означает, что в базе
всегда ровно то же, что показал бы сервер сейчас: ни дублей при повторном
чтении, ни разрастания таблицы.

Дашборд не ходит на почтовые серверы сам, и это не оптимизация. Один разбор
mail.log Zimbra — это awk по 25 МБ, один проход по логам IIS Exchange —
сотни мегабайт строк. При каждой плановой рассылке дашборда это минуты
ожидания на каждый сервер, поэтому раздел читает готовое.

Снимок заменяется только при успешном чтении. Если сервер не ответил,
прежняя сводка остаётся на месте, а в строку пишется ошибка и время
попытки: «данные от вчера» полезнее пустого экрана, но обязано быть
подписано как несвежее.

Форма сводки общая для обеих почт и намеренно безымянная — kpis, groups,
alarms. Знание о том, чем ActiveSync отличается от IMAP, живёт в сборщике;
дашборду достаточно уметь рисовать плитки и списки, иначе третья почтовая
система означала бы третью ветку в отрисовке.
"""
import json
import threading

from pgconn import get_conn

_ready = False
_ready_lock = threading.Lock()

KINDS = ("zimbra", "exchange")

KIND_LABELS = {"zimbra": "Zimbra", "exchange": "Exchange"}


def ensure_tables():
    """Создаёт таблицу на существующих установках: init.sql накатывается
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
                CREATE TABLE IF NOT EXISTS mail_snapshots (
                    server_name  TEXT NOT NULL,
                    kind         TEXT NOT NULL,
                    payload      TEXT,
                    error        TEXT,
                    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (server_name, kind)
                )
            """)
        _ready = True


def save_snapshot(server_name: str, kind: str, summary: dict = None,
                  error: str = ""):
    """Заменяет сводку одного сервера. Пустая summary при ошибке оставляет
    прежний payload: раздел покажет вчерашнее с пометкой о неудачном сборе,
    а не пустоту."""
    if kind not in KINDS:
        raise ValueError(f"Неизвестный вид почты: {kind}")
    ensure_tables()
    payload = json.dumps(summary, ensure_ascii=False) if summary else None
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO mail_snapshots (server_name, kind, payload, error, collected_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (server_name, kind) DO UPDATE
               SET payload = COALESCE(EXCLUDED.payload, mail_snapshots.payload),
                   error = EXCLUDED.error,
                   collected_at = NOW()
        """, (server_name, kind, payload, (error or "")[:500]))


def read_snapshots() -> list:
    """Сводки всех почтовых серверов. Битый payload — не повод ронять
    дашборд: такая строка отдаётся с пустой сводкой и своей ошибкой."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT server_name, kind, payload, error, collected_at
            FROM mail_snapshots
            ORDER BY server_name, kind
        """)
        rows = cur.fetchall()

    out = []
    for server_name, kind, payload, error, collected_at in rows:
        try:
            summary = json.loads(payload) if payload else {}
        except ValueError:
            summary, error = {}, error or "сводка в базе испорчена"
        out.append({"server": server_name, "kind": kind, "summary": summary,
                    "error": error or "", "collected_at": collected_at})
    return out


def forget_server(server_name: str):
    """Сервер убрали из конфига — его сводка больше не нужна."""
    ensure_tables()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM mail_snapshots WHERE server_name = %s",
                    (server_name,))
