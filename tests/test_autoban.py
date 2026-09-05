"""Автоблокировка тех, кто перебирает пароли к почте.

Главное, что проверяется, — сдержанность: блокируется только перебор,
только внешние адреса и только с ИЗВЕСТНОЙ чужой страной. Неизвестная
страна значит «GeoIP промолчал», а не «чужой», и такой адрес обязан
остаться человеку.
"""
import pytest

import autoban
from autoban import (
    autoban_enabled,
    foreign_attackers,
    report_lines,
    run_autoban,
)


def _spray(*addresses, countries=None, attack="brute"):
    return {
        "key": "zm_spray:mail:user@x",
        "text": "перебор пароля",
        "attack": attack,
        "ips": list(addresses),
        "ip_country": countries or {},
    }


# ─── Кого берём ──────────────────────────────────────────────

def test_foreign_addresses_are_picked():
    item = _spray("103.148.45.88", "161.65.64.215",
                  countries={"103.148.45.88": "ID", "161.65.64.215": "NZ"})
    picked = foreign_attackers([item], home="KZ")
    assert [p["ip"] for p in picked] == ["103.148.45.88", "161.65.64.215"]
    assert picked[0]["country"] == "ID"


def test_home_country_is_never_blocked():
    item = _spray("2.72.0.1", countries={"2.72.0.1": "KZ"})
    assert foreign_attackers([item], home="KZ") == []


def test_unknown_country_is_left_to_a_human():
    """GeoIP промолчал — это не улика. Такой адрес остаётся кнопкой."""
    item = _spray("203.0.113.7", countries={})
    assert foreign_attackers([item], home="KZ") == []


def test_private_addresses_are_never_blocked():
    """За внутренним адресом шлюз или рабочее место — отрезали бы своих."""
    item = _spray("192.168.1.10", countries={"192.168.1.10": "ID"})
    assert foreign_attackers([item], home="KZ") == []


def test_only_bruteforce_findings_count():
    """Всплеск отправки или подделка отправителя — не повод банить."""
    item = _spray("103.148.45.88", countries={"103.148.45.88": "ID"},
                  attack=None)
    assert foreign_attackers([item], home="KZ") == []


def test_duplicates_collapse():
    items = [_spray("103.148.45.88", countries={"103.148.45.88": "ID"}),
             _spray("103.148.45.88", countries={"103.148.45.88": "ID"})]
    assert len(foreign_attackers(items, home="KZ")) == 1


# ─── Когда включено ──────────────────────────────────────────

def test_disabled_by_default():
    assert not autoban_enabled({"name": "a", "host": "h", "type": "linux",
                                "firewall": True})


def test_needs_permission_to_block():
    """Без флага firewall блокировать нечем: ни клетки, ни правила."""
    assert not autoban_enabled({"name": "a", "host": "h", "type": "linux",
                                "autoban_brute": True})


def test_enabled_with_both_flags():
    assert autoban_enabled({"name": "a", "host": "h", "type": "linux",
                            "firewall": True, "autoban_brute": True})


# ─── Полный проход ───────────────────────────────────────────

def _wire(monkeypatch, server, blocked_before=(), fail=None):
    calls = {}
    monkeypatch.setattr(autoban, "load_server", lambda name: server)
    monkeypatch.setattr(autoban, "_already_blocked",
                        lambda srv, name: set(blocked_before))

    def _block(srv, name, addresses, reason="x"):
        if fail:
            raise RuntimeError(fail)
        calls["addresses"] = list(addresses)
        return list(addresses), "fail2ban, клетка mail"

    monkeypatch.setattr(autoban, "block_addresses", _block)
    return calls


SERVER = {"name": "mail", "host": "h", "type": "linux",
          "firewall": True, "autoban_brute": True}


def test_run_blocks_and_reports_every_address(monkeypatch):
    calls = _wire(monkeypatch, SERVER)
    item = _spray("103.148.45.88", "103.190.17.25", "161.65.64.215",
                  countries={"103.148.45.88": "ID", "103.190.17.25": "BD",
                             "161.65.64.215": "NZ"})

    result = run_autoban("mail", [item])

    assert calls["addresses"] == ["103.148.45.88", "103.190.17.25", "161.65.64.215"]
    text = "\n".join(report_lines(result))
    # Список не обрезается: человек должен видеть каждый отрезанный адрес
    for ip in calls["addresses"]:
        assert ip in text


def test_run_skips_already_blocked(monkeypatch):
    calls = _wire(monkeypatch, SERVER, blocked_before=["103.148.45.88"])
    item = _spray("103.148.45.88", "103.190.17.25",
                  countries={"103.148.45.88": "ID", "103.190.17.25": "BD"})

    run_autoban("mail", [item])

    assert calls["addresses"] == ["103.190.17.25"]


def test_run_respects_the_cap(monkeypatch):
    calls = _wire(monkeypatch, SERVER)
    monkeypatch.setattr(autoban, "AUTOBAN_MAX_PER_RUN", 2)
    addresses = [f"103.148.45.{n}" for n in range(1, 6)]
    item = _spray(*addresses, countries={ip: "ID" for ip in addresses})

    result = run_autoban("mail", [item])

    assert len(calls["addresses"]) == 2
    assert result["left"] == 3
    assert "вручную" in "\n".join(report_lines(result))


def test_failure_does_not_hide_the_alert(monkeypatch):
    _wire(monkeypatch, SERVER, fail="fail2ban не отвечает")
    item = _spray("103.148.45.88", countries={"103.148.45.88": "ID"})

    result = run_autoban("mail", [item])

    assert result["blocked"] == []
    assert "не сработала" in "\n".join(report_lines(result))


def test_nothing_to_report_when_disabled(monkeypatch):
    _wire(monkeypatch, {"name": "mail", "host": "h", "type": "linux",
                        "firewall": True})
    item = _spray("103.148.45.88", countries={"103.148.45.88": "ID"})

    assert report_lines(run_autoban("mail", [item])) == []
