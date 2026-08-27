"""Сводка проблем: категории вместо трёх десятков однотипных строк.

Плоский список печатал по строке на каждый путь бэкапа — 28 строк, из
которых 26 об одном и том же. Теперь категории + разбор по серверу.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_bot_db():
    spec = importlib.util.spec_from_file_location("bot_db", ROOT / "bot" / "db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bot_db = _load_bot_db()


def _p(level, kind, server, text, weight=0.0, hint=None):
    return {"level": level, "kind": kind, "server": server, "text": text,
            "weight": weight, "hint": hint}


PROBLEMS = (
    [
        _p("warn", "backup", "nas-01.example.local",
           f"🟠 SQL /volume4/db_{i}: последний backup 2.5 дн назад",
           weight=2.5, hint="худший 2.5 дн")
        for i in range(16)
    ]
    + [
        _p("warn", "backup", "sql-02.example.local",
           f"🟠 SQL F:\\Backups\\daily\\base_{i}: последний backup 10.5 дн назад",
           weight=10.5, hint="худший 10.5 дн")
        for i in range(4)
    ]
    + [
        _p("crit", "service", "app-01.example.local", "🚨 сервис W3SVC = stopped"),
        _p("crit", "disk", "app-01.example.local", "🔴 C: свободно 4.2% (10.0 ГБ)",
           weight=95.8, hint="минимум 4.2% свободно"),
        _p("warn", "onec", "onec-01.example.local", "🟠 1C log: размер 7.71 ГБ",
           weight=7.71, hint="крупнейший 7.71 ГБ"),
    ]
)


def test_summary_counts_by_category():
    msg = bot_db.format_problems_summary(PROBLEMS)

    assert "🔴 Критично: 2 · 🟠 Предупреждений: 21" in msg
    assert "💾 Бэкапы: 20 на 2 серверах · худший 10.5 дн" in msg
    assert "💽 Диски: 1 · минимум 4.2% свободно" in msg
    assert "📋 Журналы 1С: 1 · крупнейший 7.71 ГБ" in msg
    assert "🚨 Службы: 1" in msg


def test_summary_stays_short():
    """Ради этого всё и затевалось: 23 проблемы — не 23 строки."""
    msg = bot_db.format_problems_summary(PROBLEMS)
    assert len(msg.splitlines()) <= 12
    # ни один конкретный путь в сводку не попадает
    assert "/volume4/db_0" not in msg


def test_summary_without_problems():
    assert bot_db.format_problems_summary([]) == bot_db.NO_PROBLEMS


def test_servers_sorted_by_severity():
    servers = bot_db.problems_by_server(PROBLEMS)

    # сервер с критичным — первым, дальше по количеству замечаний
    assert servers[0]["name"] == "app-01.example.local"
    assert servers[0]["crit"] == 2
    assert servers[1]["name"] == "nas-01.example.local"
    assert servers[1]["total"] == 16


def test_server_detail_lists_everything():
    servers = bot_db.problems_by_server(PROBLEMS)
    nas = [s for s in servers if s["name"].startswith("nas-01")][0]
    msg = bot_db.format_problems_for_server(nas)

    assert msg.startswith("🖥 nas-01.example.local")
    assert "🔴 Критично: 0 · 🟠 Предупреждений: 16" in msg
    assert "💾 БЭКАПЫ (16)" in msg
    assert msg.count("последний backup") == 16
    # имя сервера в каждой строке не повторяется — оно в заголовке
    assert msg.count("nas-01.example.local") == 1


def test_server_detail_puts_critical_first():
    servers = bot_db.problems_by_server(PROBLEMS)
    app = [s for s in servers if s["name"].startswith("app-01")][0]
    msg = bot_db.format_problems_for_server(app)

    assert "🚨 СЛУЖБЫ (1)" in msg
    assert msg.index("сервис W3SVC") < msg.index("C: свободно")


def test_short_server_name_for_buttons():
    assert bot_db.short_server_name("nas.example.local") == "nas"
    assert bot_db.short_server_name("a" * 30) == "a" * 17 + "…"
