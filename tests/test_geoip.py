"""Тесты страны и города по IP (shared/geoip.py) и их показа в разделах.

Главное, что здесь проверяется: свои адреса наружу не уходят, метка
подсети сильнее геосервиса, и отсутствие геоданных не ломает раздел.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bot"))

import geoip


# ─── Флаг ────────────────────────────────────────────────────

def test_flag_from_country_code():
    assert geoip.flag("KZ") == "🇰🇿"
    assert geoip.flag("ru") == "🇷🇺"


def test_flag_of_garbage_is_empty():
    for value in ("", "K", "KAZ", "12", None):
        assert geoip.flag(value) == ""


# ─── Свои сети ───────────────────────────────────────────────

def test_private_networks_recognised():
    for address in ("10.20.30.5", "192.168.1.1", "172.16.0.5",
                    "100.64.0.1", "127.0.0.1", "fe80::1"):
        assert geoip.is_private(address), address


def test_public_address_is_not_private():
    assert not geoip.is_private("203.0.113.5")


# ─── Метки подсетей ──────────────────────────────────────────

LABELS = [
    {"network": "10.0.0.0/8", "label": "🏢 Вся сеть"},
    {"network": "10.20.30.0/24", "label": "🏢 Главный офис"},
    {"network": "192.0.2.7/32", "label": "🏢 Филиал"},
]


def test_narrowest_network_wins():
    """10.0.0.0/8 и 10.20.30.0/24 заданы обе — верен второй ответ."""
    assert geoip.match_label("10.20.30.5", LABELS) == "🏢 Главный офис"
    assert geoip.match_label("10.20.0.1", LABELS) == "🏢 Вся сеть"


def test_label_works_for_external_address():
    """Смысл меток не только во внутренних сетях: у филиала статический
    внешний IP, и своё имя полезнее города из геобазы."""
    assert geoip.match_label("192.0.2.7", LABELS) == "🏢 Филиал"


def test_no_label_for_unknown_address():
    assert geoip.match_label("203.0.113.5", LABELS) == ""


def test_broken_network_in_labels_is_skipped():
    assert geoip.match_label("10.20.30.5", [{"network": "мусор", "label": "x"}]) == ""


# ─── Сборка пометки ──────────────────────────────────────────

def test_describe_country_and_city():
    assert geoip.describe({"found": True, "country_code": "KZ",
                           "country": "Kazakhstan", "city": "Astana"}) == "🇰🇿 Astana"


def test_describe_without_city_shows_flag():
    assert geoip.describe({"found": True, "country_code": "KZ",
                           "country": "Kazakhstan", "city": ""}) == "🇰🇿"


def test_describe_of_unknown_is_empty():
    assert geoip.describe({"found": False}) == ""
    assert geoip.describe(None) == ""


def test_tag_adds_separator_only_when_there_is_something():
    geo = {"203.0.113.5": "🇰🇿 Astana"}
    assert geoip.tag("203.0.113.5", geo) == " · 🇰🇿 Astana"
    assert geoip.tag("198.51.100.1", geo) == ""
    assert geoip.tag(None, geo) == ""


# ─── Resolve: что уходит наружу ──────────────────────────────

def _no_network(monkeypatch, seen: list):
    monkeypatch.setattr(geoip, "list_labels", lambda: LABELS)
    monkeypatch.setattr(geoip, "_read_cache", lambda addresses: {})
    monkeypatch.setattr(geoip, "_write_cache", lambda rows: None)

    def fake_fetch(addresses):
        seen.extend(addresses)
        return {a: {"found": True, "country_code": "KZ", "country": "Kazakhstan",
                    "city": "Astana"} for a in addresses}

    monkeypatch.setattr(geoip, "_fetch", fake_fetch)


def test_private_addresses_never_leave(monkeypatch):
    seen = []
    _no_network(monkeypatch, seen)
    out = geoip.resolve(["10.20.30.5", "192.168.1.1", "203.0.113.5"])
    assert seen == ["203.0.113.5"], "наружу ушёл внутренний адрес"
    assert out["192.168.1.1"] == "🏢 локальная сеть"


def test_labelled_addresses_never_leave(monkeypatch):
    """Метка уже отвечает на вопрос — спрашивать сервис незачем."""
    seen = []
    _no_network(monkeypatch, seen)
    out = geoip.resolve(["192.0.2.7"])
    assert seen == []
    assert out["192.0.2.7"] == "🏢 Филиал"


def test_disabled_means_no_external_calls(monkeypatch):
    seen = []
    _no_network(monkeypatch, seen)
    monkeypatch.setenv("GEOIP_ENABLED", "false")
    out = geoip.resolve(["203.0.113.5", "10.20.30.5"])
    assert seen == []
    assert out["10.20.30.5"] == "🏢 Главный офис"
    assert out.get("203.0.113.5", "") == ""


def test_addresses_asked_once(monkeypatch):
    seen = []
    _no_network(monkeypatch, seen)
    geoip.resolve(["203.0.113.5", "203.0.113.5", " 203.0.113.5 "])
    assert seen == ["203.0.113.5"]


def test_garbage_is_dropped(monkeypatch):
    seen = []
    _no_network(monkeypatch, seen)
    out = geoip.resolve(["не адрес", "", None, "203.0.113.5"])
    assert seen == ["203.0.113.5"]
    assert list(out) == ["203.0.113.5"]


def test_service_failure_does_not_break_anything(monkeypatch):
    monkeypatch.setattr(geoip, "list_labels", lambda: LABELS)
    monkeypatch.setattr(geoip, "_read_cache", lambda addresses: {})
    monkeypatch.setattr(geoip, "_write_cache", lambda rows: None)
    monkeypatch.setattr(geoip, "_fetch", lambda addresses: {})
    out = geoip.resolve(["203.0.113.5", "10.20.30.5"])
    assert out["203.0.113.5"] == ""
    assert out["10.20.30.5"] == "🏢 Главный офис"


def test_broken_labels_table_does_not_break_resolve(monkeypatch):
    def boom():
        raise RuntimeError("база недоступна")

    monkeypatch.setattr(geoip, "list_labels", boom)
    monkeypatch.setattr(geoip, "_read_cache", lambda addresses: {})
    monkeypatch.setattr(geoip, "_write_cache", lambda rows: None)
    monkeypatch.setattr(geoip, "_fetch", lambda addresses: {})
    assert geoip.resolve(["10.20.30.5"])["10.20.30.5"] == "🏢 локальная сеть"


def test_rate_limit_stops_calls(monkeypatch):
    """Упёрлись в лимит — остаёмся без флажка, а не с баном адреса."""
    monkeypatch.setattr(geoip, "_calls", [])
    monkeypatch.setattr(geoip, "RATE_PER_MINUTE", 1)
    assert geoip._rate_ok()
    assert not geoip._rate_ok()


# ─── Разбор ввода метки ──────────────────────────────────────

def test_parse_net_label():
    from config_editor import parse_net_label

    assert parse_net_label("10.20.30.0/24 = 🏢 Главный офис")[:2] == (
        "10.20.30.0/24", "🏢 Главный офис")


def test_parse_net_label_accepts_single_address():
    from config_editor import parse_net_label

    assert parse_net_label("192.0.2.7 = 🏢 Филиал")[0] == "192.0.2.7/32"


def test_parse_net_label_needs_both_parts():
    from config_editor import parse_net_label

    assert parse_net_label("10.20.30.0/24")[2]
    assert parse_net_label("= метка")[2]


def test_parse_net_label_rejects_bad_network():
    from config_editor import parse_net_label

    assert "не сеть" in parse_net_label("контора = 🏢 Офис")[2]


# ─── Показ в разделах ────────────────────────────────────────

def test_owa_shows_country_next_to_address():
    import exchange_bot

    header, blocks = exchange_bot.format_owa({"rows": [{
        "user": "user@example.local", "ip": "203.0.113.5", "ua": "Chrome",
        "count": 12, "last": "2026-09-01 11:22:00"}], "scanned": 12}, 24,
        {"203.0.113.5": "🇰🇿 Astana"})
    assert "203.0.113.5 · 🇰🇿 Astana" in blocks[0]


def test_owa_header_explains_what_is_counted():
    """«1283 обращений» — это запросы к /owa/, а не входы: одна вкладка
    шлёт их десятками в минуту, и без пояснения число вводит в заблуждение."""
    import exchange_bot

    header, _ = exchange_bot.format_owa({"rows": [{
        "user": "user@example.local", "ip": "203.0.113.5", "ua": "Chrome",
        "count": 12, "last": "2026-09-01 11:22:00"}], "scanned": 12}, 24)
    assert "не входы" in header


def test_owa_without_geo_looks_as_before():
    import exchange_bot

    _header, blocks = exchange_bot.format_owa({"rows": [{
        "user": "user@example.local", "ip": "203.0.113.5", "ua": "Chrome",
        "count": 12, "last": "2026-09-01 11:22:00"}], "scanned": 12}, 24)
    assert "203.0.113.5\n" in blocks[0]


def test_iis_scan_shows_country():
    import iis_bot

    text = iis_bot.format_scan(
        {"total": [{"item": "alien", "count": 5}],
         "scan": [{"item": "203.0.113.5|curl", "count": 5}]},
        24, {"203.0.113.5": "🇳🇱 Amsterdam"})
    assert "🇳🇱 Amsterdam" in text


def test_iis_collects_addresses_from_every_category():
    import iis_bot

    events = {
        "scan": [{"item": "203.0.113.5|curl", "count": 1}],
        "hit": [{"item": "/shell.php|198.51.100.7|curl", "count": 1}],
        "login": [{"item": "base|192.0.2.9", "count": 1}],
        "herrd": [{"item": "Verb|GET|/x|192.0.2.10", "count": 1}],
    }
    found = iis_bot.addresses_of(events)
    assert set(found) == {"203.0.113.5", "198.51.100.7", "192.0.2.9",
                          "192.0.2.10"}


def test_exchange_collects_addresses_from_both_shapes():
    import exchange_bot

    assert exchange_bot.addresses_of({"rows": [{"ip": "203.0.113.5"}]}) == \
        ["203.0.113.5"]
    assert exchange_bot.addresses_of([{"ip": "198.51.100.7"}]) == \
        ["198.51.100.7"]


# ─── Справка ─────────────────────────────────────────────────

def test_help_section_warns_about_external_service():
    from config_editor import HELP_SECTIONS

    text = HELP_SECTIONS["geo"][1]
    assert "ip-api.com" in text
    assert "GEOIP_ENABLED" in text
