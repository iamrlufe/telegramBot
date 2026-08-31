"""Дашборд отдаётся HTML-файлом вместо PNG.

Проверяется главное свойство отчёта: он самодостаточный. Ни одного внешнего
запроса — иначе файл, открытый в Telegram без сети, развалится, а у бота
появится повод смотреть наружу, чего в этом проекте быть не должно.

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
    assert "<script src" not in page
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


def test_healthy_servers_hidden_until_filter_switched():
    """Открывается на проблемных: ради них отчёт и запрашивают."""
    page = _render([
        _server("ok-01.example.local", state="ok"),
        _server("down-01.example.local", state="down"),
    ])
    cards = re.findall(r'<details class="card"[^>]*>', page)

    assert len(cards) == 2
    assert sum("display:none" in card for card in cards) == 1
    assert 'data-f="bad" aria-pressed="true"' in page


def test_all_servers_visible_when_everything_is_fine():
    page = _render([_server("ok-01.example.local"), _server("ok-02.example.local")])
    cards = re.findall(r'<details class="card"[^>]*>', page)

    assert not any("display:none" in card for card in cards)
    assert 'data-f="all" aria-pressed="true"' in page


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
    ':root[data-theme="dark"]',
])
def test_dark_theme_declared_for_both_scopes(scope):
    """Системная тема и ручное переключение кнопкой ◐ — два разных
    селектора, и оба обязаны быть в файле."""
    assert scope in _render([_server("a.example.local")])
