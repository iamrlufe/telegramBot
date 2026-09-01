"""Раздел 🌐 IIS в карточке сервера и находки для сводки проблем.

Раздел ничего не читает по нажатию: суточный лог публикации — полмиллиона
строк. Данные берутся готовыми из базы, их дочитывает монитор по смещению.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


iis_bot = _load("iis_bot", ROOT / "bot" / "iis_bot.py")
iis_store = _load("iis_store", ROOT / "shared" / "iis_store.py")

SERVER = {"name": "web-01.example.local", "services": ["W3SVC", "WAS"]}


def _events(**categories):
    return {name: [{"item": item, "count": count} for item, count in rows]
            for name, rows in categories.items()}


# ─── Кнопка ──────────────────────────────────────────────────

def test_button_shown_for_iis_servers():
    """Признак — служба W3SVC, как dbsize для MSSQL."""
    assert iis_bot.has_iis(SERVER) is True
    assert iis_bot.has_iis({"name": "x", "services": ["MSSQLSERVER"]}) is False


def test_service_name_case_insensitive():
    assert iis_bot.has_iis({"name": "x", "services": ["w3svc"]}) is True


def test_token_cache_is_bounded():
    """callback_data ограничен 64 байтами, поэтому состояние живёт в кэше —
    и кэш не должен расти вечно."""
    for i in range(iis_bot.IIS_TOKENS_MAX + 50):
        iis_bot.iis_token(f"srv-{i}.example.local", 24)

    assert len(iis_bot.IIS_TOKENS) <= iis_bot.IIS_TOKENS_MAX


# ─── Разделы ─────────────────────────────────────────────────

def test_clean_scan_explains_why_redirects_are_not_findings():
    """301 на порту 80 отдаётся на любой путь — считать это находкой нельзя,
    и человек должен понимать, почему в отчёте ноль."""
    text = iis_bot.format_scan(
        _events(total=[("alien", 889)], scan=[("192.0.2.99|libredtail-http", 47)]), 24)

    assert "Ничего не отдано" in text
    assert "Редиректы" in text
    assert "robots.txt" in text
    assert "192.0.2.99" in text


def test_scanner_hit_comes_first():
    """Единственное, ради чего сюда заходят срочно."""
    text = iis_bot.format_scan(
        _events(total=[("alien", 41)],
                hit=[("/uploads/x.php|192.0.2.99|curl", 2)],
                scan=[("192.0.2.99|curl", 41)]), 24)

    assert text.index("СЕРВЕР ОТДАЛ СОДЕРЖИМОЕ") < text.index("Кто стучится")
    assert "/uploads/x.php" in text


def test_login_section_separates_brute_from_reconnect():
    events = _events(login=[("agro|192.0.2.30", 26)])
    brute = [
        {"base": "agro", "ip": "192.0.2.99", "count": 180, "requests": 181,
         "working": False},
        {"base": "agro", "ip": "192.0.2.30", "count": 60, "requests": 4000,
         "working": True},
    ]

    text = iis_bot.format_login(events, 24, brute)

    assert "это подбор пароля" in text
    assert "переподключается по кругу" in text


def test_publications_without_traffic_named():
    facts = {"apps": [{"p": "/agro"}, {"p": "/copy_ivan"}], "pools": [],
             "logs_mb": 20831.9, "oldest_log": "2025-10-24"}

    text = iis_bot.format_pubs(_events(pub=[("agro", 253332)]), facts, 24)

    assert "Без трафика: 1" in text
    assert "copy_ivan" in text
    assert "20.3 ГБ" in text


def test_httperr_explains_reasons():
    text = iis_bot.format_herr(
        _events(herr=[("Timer_ConnectionIdle", 10595), ("Verb", 12)]), 24)

    assert "почерк сканеров" in text
    assert "штатное закрытие" in text


def test_empty_section_explains_the_delay():
    """Пустой раздел не должен выглядеть как «всё хорошо», если сбор просто
    ещё не отработал."""
    text = iis_bot.format_scan({}, 24)

    assert "раз в час" in text


# ─── Находки для сводки и алертов ────────────────────────────

def _findings(monkeypatch, day, hour):
    monkeypatch.setattr(iis_store, "read_events",
                        lambda hours=24: day if hours == 24 else hour)
    return iis_store.iis_findings()


def test_only_three_things_reach_the_alert(monkeypatch):
    """Фон в тревогу не идёт: 404 сканеров и медленные запросы живут
    в дашборде, будить ими незачем."""
    day = {"web-01.example.local": _events(
        alienuri=[("/index.php", 743)], slowuri=[("/agro/e1cib/logForm|192.0.2.30", 16)],
        scan=[("192.0.2.99|curl", 276)])}

    assert _findings(monkeypatch, day, {}) == []


def test_scanner_hit_becomes_a_finding(monkeypatch):
    day = {"web-01.example.local": _events(hit=[("/uploads/x.php|192.0.2.99|curl", 2)])}

    found = _findings(monkeypatch, day, {})

    assert len(found) == 1
    assert found[0][0] == "web-01.example.local"
    assert "/uploads/x.php" in found[0][1]["text"]
    assert found[0][1]["key"].startswith("iis_hit:")


def test_unavailable_publications_become_a_finding(monkeypatch):
    day = {"web-01.example.local": _events(
        herr=[("Timer_ConnectionIdle", 10595), ("QueueFull", 6)])}

    found = _findings(monkeypatch, day, {})

    assert len(found) == 1
    assert "QueueFull" in found[0][1]["text"]


def test_reconnecting_client_does_not_raise_alarm(monkeypatch):
    """Ключевое отличие: после входов идёт работа в базе."""
    hour = {"web-01.example.local": _events(
        login=[("agro|192.0.2.30", 60)], ip=[("192.0.2.30", 4000)])}

    assert _findings(monkeypatch, {}, hour) == []


def test_silent_login_burst_raises_alarm(monkeypatch):
    hour = {"web-01.example.local": _events(
        login=[("agro|192.0.2.99", 180)], ip=[("192.0.2.99", 181)])}

    found = _findings(monkeypatch, {}, hour)

    assert len(found) == 1
    assert "подбор пароля" in found[0][1]["text"]
    assert found[0][1]["key"] == "iis_brute:web-01.example.local:192.0.2.99"


def test_finding_keys_are_stable(monkeypatch):
    """Ключ должен переживать смену счётчиков: иначе «Принял» слетал бы,
    а алерт уходил бы каждый час на одно и то же."""
    hour_a = {"web-01.example.local": _events(
        login=[("agro|192.0.2.99", 180)], ip=[("192.0.2.99", 181)])}
    hour_b = {"web-01.example.local": _events(
        login=[("agro|192.0.2.99", 420)], ip=[("192.0.2.99", 425)])}

    first = _findings(monkeypatch, {}, hour_a)[0][1]["key"]
    second = _findings(monkeypatch, {}, hour_b)[0][1]["key"]

    assert first == second
