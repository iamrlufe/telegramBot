"""Дашборд отдаётся HTML-файлом вместо PNG.

Проверяются два свойства, без которых отчёт бесполезен. Он самодостаточный:
ни одного внешнего запроса — иначе файл, открытый в Telegram без сети,
развалится, а у бота появится повод смотреть наружу, чего в этом проекте
быть не должно. И он работает без JavaScript: просмотрщик файлов в Telegram
открывает страницу со скриптами выключёнными, на этом первая версия и
попалась — кнопки просто не нажимались, кольца не закрашивались.

`import db` в тестах достаётся из monitor/ — одноимённый модуль бота
приходится подставлять по пути.
"""
import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_dashboard_html():
    """dashboard_html тянет пороги из bot/db.py — на время импорта он и
    должен быть модулем `db`, иначе подхватится monitor/db.py."""
    saved = sys.modules.get("db")
    sys.modules["db"] = _load("db", ROOT / "bot" / "db.py")
    try:
        return _load("dashboard_html", ROOT / "bot" / "dashboard_html.py")
    finally:
        if saved is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = saved


dh = _load_dashboard_html()


def _disk(name, free_pct, total_gb=100):
    return {"name": name, "free_pct": free_pct,
            "free_gb": round(total_gb * free_pct / 100), "total_gb": total_gb}


def _server(name, state="ok", cpu=(10, 20, 30), ram=(40, 50), disks=(), problems=()):
    return {
        "name": name, "host": "192.0.2.10", "state": state,
        "raw_status": "host_unreachable" if state == "down" else "online",
        "age_min": 5.0, "checked_at": "23:40",
        "cpu": list(cpu), "ram": list(ram), "disks": list(disks),
        "problems": [{"level": lvl, "text": text} for lvl, text in problems],
    }


def _data(servers, hours=24):
    return {"servers": servers, "hours": hours, "generated_at": "31.08.2026 23:40"}


def _render(servers, hours=24):
    return dh.render_dashboard(_data(servers, hours))


# ─── Самодостаточность файла ─────────────────────────────────

def test_report_has_no_external_requests():
    """Ни CDN, ни шрифтов, ни картинок: файл читается офлайн."""
    page = _render([_server("sql-01.example.local", disks=[_disk("C:", 42)])])

    assert "http://" not in page
    assert "https://" not in page
    assert "<script" not in page
    assert "<link" not in page
    assert "url(" not in page.replace("url(#", "")  # градиенты SVG не в счёт


def test_report_is_smaller_than_a_chart():
    """Смысл замены PNG: файл лёгкий даже на десятке серверов с суточной
    историей (картинка matplotlib весила 200–400 КБ)."""
    servers = [
        _server(f"srv-{i:02d}.example.local",
                cpu=list(range(0, 72)), ram=list(range(20, 92)),
                disks=[_disk("C:", 30), _disk("D:", 55)])
        for i in range(10)
    ]

    assert len(_render(servers).encode("utf-8")) < 150_000


# ─── Содержимое ──────────────────────────────────────────────

def test_problem_servers_come_first():
    page = _render([
        _server("ok-01.example.local", state="ok"),
        _server("down-01.example.local", state="down"),
        _server("warn-01.example.local", state="warn"),
    ])

    assert page.index("down-01") < page.index("warn-01") < page.index("ok-01")


def test_no_javascript_at_all():
    """Скрипты в просмотрщике Telegram не выполняются: всё интерактивное
    обязано держаться на разметке и CSS."""
    page = _render([_server("a.example.local", disks=[_disk("C:", 42)])])

    assert "<script" not in page
    assert "onclick" not in page
    assert "addEventListener" not in page


def test_filter_opens_on_problem_servers():
    """Открывается на проблемных: ради них отчёт и запрашивают.
    Прячет здоровых CSS по выбранному radio, а не инлайн-стиль в карточке."""
    page = _render([
        _server("ok-01.example.local", state="ok"),
        _server("down-01.example.local", state="down"),
    ])
    cards = re.findall(r'<details class="card"[^>]*>', page)

    assert len(cards) == 2
    assert not any("display:none" in card for card in cards)
    assert 'id="f-bad" checked' in page
    assert '#f-bad:checked~.wrap .card[data-state="ok"]{display:none}' in page


def test_filter_opens_on_full_list_when_everything_is_fine():
    """Иначе экран был бы пустым: проблемных нет, а фильтр стоит на них."""
    page = _render([_server("ok-01.example.local"), _server("ok-02.example.local")])

    assert 'id="f-all" checked' in page
    assert 'id="f-bad" checked' not in page


def test_theme_choice_is_pure_css():
    """Системная тема плюс ручной выбор — тремя radio, без скрипта."""
    page = _render([_server("a.example.local")])

    assert 'id="t-auto" checked' in page
    assert "#t-dark:checked~.wrap{" in page
    assert "#t-light:checked~.wrap{" in page


def test_ring_shows_worst_disk():
    """Кольцо — про худший диск, а не про первый в списке."""
    page = _render([_server("sql-01.example.local",
                            disks=[_disk("C:", 6.2), _disk("D:", 71)])])

    assert "6%</b>" in page
    assert "своб. · C:" in page
    assert "своб. · D:" not in page


def test_ring_survives_server_without_disk_metrics():
    """У ESXi и части NAS метрик по дискам нет — карточка обязана строиться."""
    page = _render([_server("esxi-01.example.local", disks=[])])

    assert "нет данных</span>" in page
    assert "esxi-01.example.local" in page


def test_problem_text_is_escaped():
    """Текст проблемы приходит из базы: угловые скобки в путь попадают
    редко, но экранирование — не место для «редко»."""
    page = _render([_server("app-01.example.local", state="warn",
                            problems=[("crit", "🔴 <script>alert(1)</script>")])])

    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page


def test_counters_match_states():
    page = _render([
        _server("a.example.local", state="down"),
        _server("b.example.local", state="warn"),
        _server("c.example.local", state="stale"),
        _server("d.example.local", state="ok"),
    ])

    assert "Требуют внимания · 3" in page
    assert "Все · 4" in page
    assert "В норме · 1" in page


def test_missing_metrics_do_not_break_card():
    page = _render([_server("nas-01.example.local", cpu=[], ram=[])])

    assert "нет данных" in page
    assert "nas-01.example.local" in page


# ─── Спарклайн ───────────────────────────────────────────────

def test_sparkline_scales_to_flat_series():
    """Ряд 2–4 % не должен рисоваться прямой линией по нижнему краю."""
    path = dh.sparkline_path([2, 4, 2, 4])
    ys = [float(m) for m in re.findall(r"[ML][\d.]+ ([\d.]+)", path)]

    assert max(ys) - min(ys) > 5


def test_sparkline_handles_single_point():
    assert dh.sparkline_path([50]).startswith("M")


def test_sparkline_empty_series_draws_nothing():
    assert dh.sparkline_path([]) == ""


# ─── Тема ────────────────────────────────────────────────────

@pytest.mark.parametrize("scope", [
    "@media (prefers-color-scheme:dark)",
    "#t-dark:checked~.wrap",
])
def test_dark_theme_declared_for_both_scopes(scope):
    """Системная тема и ручное переключение кнопкой ◐ — два разных
    селектора, и оба обязаны быть в файле."""
    assert scope in _render([_server("a.example.local")])


# ─── Вкладки: журналы и бэкапы ───────────────────────────────

def _log_group(server, source, events, error="", level=None):
    from datetime import datetime, timezone
    return {
        "server": server, "source": source, "events": events,
        "categories": [{"key": e["category"], "icon": "•", "label": e["category"],
                        "count": e.get("count", 1), "level": e["level"]} for e in events],
        "total": sum(e.get("count", 1) for e in events),
        "level": level or ("crit" if any(e["level"] == "crit" for e in events)
                           else "warn" if events or error else "ok"),
        "error": error,
        "collected_at": datetime.now(timezone.utc),
    }


def _log_event(category, level="warn", title="Событие", detail="", event_at="2026-09-01 04:12:00",
               event_id="6008", count=1):
    return {"category": category, "level": level, "title": title, "detail": detail,
            "event_at": event_at, "event_id": event_id, "count": count}


def _backup_server(name, state, counts, items):
    return {"name": name, "state": state, "counts": counts, "items": items,
            "size_gb": sum(i["size_gb"] for i in items)}


def _backup_item(state, path="E:\\Backups", btype="SQL", files=10, age_h=2.0,
                 size_gb=1.0, free_pct=50.0, missing=False, error=""):
    return {"type": btype, "path": path, "state": state, "files": files, "age_h": age_h,
            "size_gb": size_gb, "free_pct": free_pct, "missing": missing, "error": error}


def _full(servers=(), logs=None, backups=None):
    data = _data(list(servers) or [_server("a.example.local")])
    data["logs"] = logs or {"win": [], "sql": []}
    data["backups"] = backups or {"servers": [], "totals": {}, "size_gb": 0}
    return dh.render_dashboard(data)


def test_tabs_are_pure_css_too():
    """Вкладки переключаются тем же radio + :checked, что и фильтр: скриптов
    в файле нет вообще."""
    page = _full()

    assert 'id="v-srv" checked' in page
    assert '#v-win:checked~.wrap .pane-win' in page
    assert "<script" not in page


def test_log_tab_shows_events_and_counters():
    page = _full(logs={"win": [_log_group("term-01.example.local", "win", [
        _log_event("service", "crit", "Служба не запустилась", "TermService", count=3)])],
        "sql": []})

    assert "term-01.example.local" in page
    assert "Служба не запустилась" in page
    assert "код 6008" in page
    assert "3 за сутки" in page


def test_log_collection_failure_is_visible():
    """«В журналах чисто» и «журнал не прочитан» не должны выглядеть одинаково."""
    page = _full(logs={"win": [_log_group("app-02.example.local", "win", [],
                                          error="нет прав на чтение журнала")],
                       "sql": []})

    assert "сбор не удался" in page
    assert "нет прав на чтение журнала" in page


def test_log_event_text_is_escaped():
    page = _full(logs={"win": [_log_group("a.example.local", "win", [
        _log_event("app", "warn", "<script>alert(1)</script>", "<b>x</b>")])], "sql": []})

    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page


def test_empty_log_tab_explains_itself():
    """Пустая вкладка должна объяснять, что сбор ещё не отработал."""
    page = _full()

    assert "Сводка журналов ещё не собрана" in page


def test_backup_tab_summarises_then_details():
    """Сводка сверху, разбор по серверу — внутри."""
    page = _full(backups={
        "servers": [_backup_server("sql-01.example.local", "crit",
                                   {"crit": 1, "warn": 0, "ok": 1},
                                   [_backup_item("crit", path="E:\\Backups\\DIFF", age_h=51.0),
                                    _backup_item("ok", path="E:\\Backups\\daily")])],
        "totals": {"crit": 1, "warn": 0, "ok": 1}, "size_gb": 2.0})

    assert "устарели" in page and "свежие" in page
    assert "E:\\Backups\\DIFF" in page
    assert "sql-01.example.local" in page


def test_backup_path_without_metrics_is_named_as_such():
    """Путь, по которому сбор ни разу не отработал, — самая опасная ситуация,
    и выглядеть как «просто нет копий» он не должен."""
    page = _full(backups={
        "servers": [_backup_server("nas-01.example.local", "crit", {"crit": 1, "warn": 0, "ok": 0},
                                   [_backup_item("crit", missing=True, files=None, age_h=None,
                                                 size_gb=0, free_pct=None)])],
        "totals": {"crit": 1}, "size_gb": 0})

    assert "сбор ни разу не отработал" in page
    assert "нет копий" in page


def test_server_card_carries_log_badges():
    """Бейдж в карточке отвечает «есть ли что-то в журналах у этого сервера»."""
    server = _server("term-01.example.local", state="warn")
    server["logs"] = {
        "win": [_log_group("term-01.example.local", "win",
                           [_log_event("logon", "crit", "41 отказов входа", count=41)])],
        "sql": [],
    }

    page = _full([server])

    assert "📜 Windows" in page
    assert "41" in page


def test_server_without_logs_gets_no_badges():
    page = _full([_server("a.example.local")])

    assert '<div class="badges">' not in page
