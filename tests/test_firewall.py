"""Тесты раздела 🛡 Блокировка IP (shared/firewall.py, bot/firewall_bot.py).

Проверяется прежде всего то, ради чего раздел вообще устроен так, а не
иначе: отказ блокировать адреса, которыми отрезаешь доступ себе, и сборка
одного правила со списком вместо правила на адрес.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bot"))

import firewall
import firewall_bot

SERVER = {"name": "mail-01.example.local", "host": "192.0.2.11",
          "username": "u", "password": "p", "firewall": True}


# ─── Разбор адреса ───────────────────────────────────────────

def test_normalize_accepts_ip_and_network():
    assert firewall.normalize_target(" 192.0.2.10 ") == "192.0.2.10"
    assert firewall.normalize_target("192.0.2.0/24") == "192.0.2.0/24"
    assert firewall.normalize_target("2001:db8::1") == "2001:db8::1"


def test_normalize_fixes_sloppy_network():
    """192.0.2.7/24 — это сеть 192.0.2.0/24, а не ошибка ввода."""
    assert firewall.normalize_target("192.0.2.7/24") == "192.0.2.0/24"


def test_normalize_rejects_garbage():
    for value in ("", "example.local", "999.1.1.1", "192.0.2.10 и ещё"):
        assert firewall.normalize_target(value) == ""


# ─── Отказы: чем можно отрезать доступ себе ──────────────────

def test_refuses_own_host():
    reason = firewall.refuse_reason("192.0.2.11", SERVER)
    assert "самого сервера" in reason


def test_refuses_network_containing_own_host():
    """Подсеть с адресом сервера отрезает управление им самим."""
    assert firewall.refuse_reason("192.0.2.0/24", SERVER)


def test_refuses_loopback_and_link_local():
    assert firewall.refuse_reason("127.0.0.1", SERVER)
    assert firewall.refuse_reason("fe80::1", SERVER)


def test_refuses_cloudflare_node():
    """За обратным прокси в логе у всех посетителей адрес прокси: такая
    блокировка выключает сайт целиком."""
    reason = firewall.refuse_reason("104.16.0.5", {"host": "192.0.2.11"})
    assert "Cloudflare" in reason
    assert "X-Forwarded-For" in reason


def test_refuses_huge_network():
    assert "нельзя" in firewall.refuse_reason("8.0.0.0/8", SERVER)


def test_refuses_whitelisted():
    reason = firewall.refuse_reason("203.0.113.5", SERVER, ["203.0.113.5"])
    assert "белом списке" in reason


def test_allows_ordinary_outside_address():
    assert firewall.refuse_reason("203.0.113.5", SERVER, []) == ""


def test_warns_about_private_network():
    assert "внутренней сети" in firewall.warn_reason("10.1.2.3")
    assert "внутренней сети" in firewall.warn_reason("192.168.7.0/24")
    assert firewall.warn_reason("203.0.113.5") == ""


# ─── Сборка правила ──────────────────────────────────────────

def test_apply_script_holds_all_addresses_in_one_rule():
    script = firewall._apply_script(["203.0.113.5", "198.51.100.0/24"])
    assert script.count("New-NetFirewallRule") == 1
    assert "'203.0.113.5','198.51.100.0/24'" in script


def test_empty_list_removes_rule():
    """Последний адрес сняли — правило должно исчезнуть, а не остаться
    пустым: пустое правило в оснастке читается как «блокируем всех»."""
    assert "Remove-NetFirewallRule" in firewall._apply_script([])


def test_apply_rejects_too_many_addresses(monkeypatch):
    monkeypatch.setattr(firewall, "run_ps", lambda *a, **k: "")
    many = ([f"203.0.113.{i}" for i in range(1, 255)]
            + [f"198.51.100.{i}" for i in range(1, 50)])
    try:
        firewall.apply_blocks(SERVER, many)
    except ValueError as e:
        assert "подсеть" in str(e)
    else:
        raise AssertionError("потолок адресов не сработал")


def test_apply_reads_rule_back(monkeypatch):
    """Возвращается то, что на сервере по факту, а не свой же ввод."""
    calls = {}

    def fake_run(host, script, *a, **k):
        calls["script"] = script
        import base64, json
        payload = json.dumps({"applied": ["203.0.113.5"], "removed": False})
        return base64.b64encode(payload.encode()).decode()

    monkeypatch.setattr(firewall, "run_ps", fake_run)
    assert firewall.apply_blocks(SERVER, ["203.0.113.5"]) == ["203.0.113.5"]
    assert "Get-NetFirewallAddressFilter" in calls["script"]


def test_single_address_comes_back_as_list(monkeypatch):
    """ConvertTo-Json схлопывает массив из одного элемента в строку."""
    import base64, json

    monkeypatch.setattr(firewall, "run_ps", lambda *a, **k: base64.b64encode(
        json.dumps({"applied": "203.0.113.5"}).encode()).decode())
    assert firewall.apply_blocks(SERVER, ["203.0.113.5"]) == ["203.0.113.5"]


def test_any_is_not_an_address(monkeypatch):
    """У правила без адресов фильтр возвращает 'Any' — это не блокировка."""
    import base64, json

    monkeypatch.setattr(firewall, "run_ps", lambda *a, **k: base64.b64encode(
        json.dumps({"applied": ["Any"]}).encode()).decode())
    assert firewall.apply_blocks(SERVER, ["203.0.113.5"]) == []


def test_script_fits_winrm_command_line():
    from winrm_client import ps_fits

    assert ps_fits(firewall._apply_script(
        [f"203.0.113.{i}" for i in range(1, 60)]))


# ─── Кнопка в карточке ───────────────────────────────────────

def test_button_needs_explicit_flag():
    """Права администратора на firewall есть не у каждой учётки, поэтому
    раздел не выводится сам по типу сервера."""
    assert firewall.has_firewall(SERVER)
    assert not firewall.has_firewall({"name": "a", "host": "192.0.2.11"})
    assert not firewall.has_firewall(
        {"name": "a", "host": "192.0.2.20", "type": "linux", "firewall": True})


# ─── Ввод из бота ────────────────────────────────────────────

def test_parse_input_defaults_to_three_days():
    address, days, error = firewall_bot.parse_block_input("192.0.2.10")
    assert (address, days, error) == ("192.0.2.10", 3, "")


def test_parse_input_takes_days():
    assert firewall_bot.parse_block_input("192.0.2.10 7")[1] == 7


def test_parse_input_takes_forever():
    assert firewall_bot.parse_block_input("192.0.2.10 навсегда")[1] is None


def test_parse_input_rejects_bad_term():
    assert firewall_bot.parse_block_input("192.0.2.10 400")[2]
    assert firewall_bot.parse_block_input("192.0.2.10 позже")[2]


def test_parse_input_rejects_bad_address():
    assert "не IP" in firewall_bot.parse_block_input("сервер 7")[2]


# ─── Экраны ──────────────────────────────────────────────────

def _block(address, expires_at=None):
    return {"address": address, "reason": "", "author": "1",
            "created_at": None, "expires_at": expires_at}


def test_empty_menu_says_where_to_look():
    text = firewall_bot.format_menu("mail-01", [], [])
    assert "никто не заблокирован" in text
    assert "Сканирование" in text


def test_menu_shows_forever_blocks():
    text = firewall_bot.format_menu("mail-01", [_block("203.0.113.5")], [])
    assert "203.0.113.5" in text
    assert "бессрочно" in text


def test_sync_reports_rule_wiped_by_hand():
    """Главный смысл сверки: адрес числится в боте, но не блокируется."""
    text = firewall_bot.format_sync("mail-01", [], ["203.0.113.5"])
    assert "не блокируются на сервере" in text
    assert "203.0.113.5" in text


def test_sync_reports_match():
    text = firewall_bot.format_sync("mail-01", ["203.0.113.5"], ["203.0.113.5"])
    assert "Совпадает" in text


# ─── Справка ─────────────────────────────────────────────────

def test_help_section_exists():
    from config_editor import HELP_SECTIONS

    text = HELP_SECTIONS["firewall"][1]
    assert "wf.msc" in text
    assert "Cloudflare" in text


# ─── Флаг в конфиге ──────────────────────────────────────────

def test_config_accepts_firewall_flag():
    from config_editor import validate_config

    validate_config([{"name": "mail-01", "host": "192.0.2.11", "firewall": True}])


def test_config_rejects_non_bool_firewall():
    from config_editor import validate_config

    try:
        validate_config([{"name": "mail-01", "host": "192.0.2.11",
                          "firewall": "да"}])
    except ValueError as e:
        assert "firewall" in str(e)
    else:
        raise AssertionError("нестроковое значение флага прошло валидацию")


def test_firewall_flag_is_offered_on_both_systems():
    """Блокировка есть и на Linux, только другим механизмом (fail2ban).
    Пока поле числилось windows-only, флаг было негде включить, и раздел
    у Linux-сервера не появлялся вовсе."""
    from config_editor import WINDOWS_ONLY_FIELDS, LINUX_ONLY_FIELDS
    from config_editor import TOGGLE_FIELDS, WIZARD_ORDER

    assert "firewall" not in WINDOWS_ONLY_FIELDS
    assert "firewall" not in LINUX_ONLY_FIELDS
    assert "firewall" in TOGGLE_FIELDS
    assert "firewall" in WIZARD_ORDER


def test_linux_card_has_the_toggle():
    """Регрессия: без кнопки в клавиатуре редактора флаг для Linux можно
    задать только правкой servers.json руками."""
    import inspect

    from config_editor import edit_fields_kb

    source = inspect.getsource(edit_fields_kb)
    # именно `if`, а не `elif`: первым в функции идёт отбор полей строки,
    # кнопки-переключатели собираются ниже отдельным блоком
    linux_block = source.split('\n    if server_type == "linux":')[1].split(
        'server_type == "vmware"')[0]
    assert "cfg_toggle:firewall" in linux_block


# ─── Кандидаты на блокировку ─────────────────────────────────

def _events(**categories):
    return {name: [{"item": item, "count": count} for item, count in rows]
            for name, rows in categories.items()}


def test_candidate_from_successful_hit():
    """Первый повод: сервер отдал содержимое по постороннему пути."""
    events = _events(hit=[("/shell.php|203.0.113.5|curl", 3)])
    found = firewall_bot.candidates(events, {}, SERVER, [], [])
    assert [i["address"] for i in found] == ["203.0.113.5"]
    assert "/shell.php" in found[0]["reason"]


def test_candidate_from_scan_volume():
    events = _events(scan=[("203.0.113.5|curl", 900)])
    found = firewall_bot.candidates(events, {}, SERVER, [], [])
    assert found[0]["address"] == "203.0.113.5"
    assert "900" in found[0]["reason"]


def test_quiet_address_is_not_offered():
    """Одиночные запросы к /.env шлёт кто угодно — блокировать не за что."""
    events = _events(scan=[("203.0.113.5|curl", 3)])
    assert firewall_bot.candidates(events, {}, SERVER, [], []) == []


def test_candidate_from_brute_force():
    hour = _events(login=[("base|203.0.113.9", 40)],
                   ip=[("203.0.113.9", 41)])
    found = firewall_bot.candidates({}, hour, SERVER, [], [])
    assert found[0]["address"] == "203.0.113.9"
    assert "подбор пароля" in found[0]["reason"]


def test_working_client_is_not_a_candidate():
    """40 входов даёт и сломавшийся клиент, но после входа он работает."""
    hour = _events(login=[("base|203.0.113.9", 40)],
                   ip=[("203.0.113.9", 5000)])
    assert firewall_bot.candidates({}, hour, SERVER, [], []) == []


def test_cloudflare_node_is_never_offered():
    """Предложить узел прокси значит предложить выключить сайт."""
    events = _events(scan=[("104.16.0.5|curl", 5000)])
    assert firewall_bot.candidates(events, {}, SERVER, [], []) == []


def test_own_and_internal_addresses_are_not_offered():
    events = _events(scan=[("127.0.0.1|curl", 5000),
                           ("192.0.2.11|curl", 5000),
                           ("10.20.30.5|curl", 5000)])
    assert firewall_bot.candidates(events, {}, SERVER, [], []) == []


def test_already_blocked_and_whitelisted_are_skipped():
    events = _events(scan=[("203.0.113.5|curl", 900),
                           ("203.0.113.6|curl", 800)])
    found = firewall_bot.candidates(events, {}, SERVER,
                                    ["203.0.113.5"], ["203.0.113.6"])
    assert found == []


def test_hit_beats_volume_in_order():
    """Отданное содержимое важнее объёма: разбирать начинают сверху."""
    events = _events(hit=[("/shell.php|203.0.113.5|curl", 2)],
                     scan=[("203.0.113.7|curl", 9000),
                           ("203.0.113.5|curl", 10)])
    found = firewall_bot.candidates(events, {}, SERVER, [], [])
    assert [i["address"] for i in found] == ["203.0.113.5", "203.0.113.7"]


def test_address_offered_once():
    events = _events(hit=[("/a.php|203.0.113.5|curl", 2),
                          ("/b.php|203.0.113.5|curl", 2)],
                     scan=[("203.0.113.5|curl", 900)])
    found = firewall_bot.candidates(events, {}, SERVER, [], [])
    assert len(found) == 1


def test_candidate_list_is_capped():
    events = _events(scan=[(f"203.0.113.{i}|curl", 900) for i in range(1, 40)])
    assert len(firewall_bot.candidates(events, {}, SERVER, [], [])) == \
        firewall_bot.PICK_LIMIT


# ─── Экран выбора ────────────────────────────────────────────

def test_pick_text_marks_chosen():
    items = [{"address": "203.0.113.5", "reason": "сервер отдал /shell.php",
              "level": 0, "count": 5}]
    text = firewall_bot.pick_text("mail-01", items, {0}, {})
    assert "☑️ 203.0.113.5" in text
    assert "Выбрано: 1 из 1" in text


def test_pick_text_shows_country():
    items = [{"address": "203.0.113.5", "reason": "900 запросов",
              "level": 1, "count": 900}]
    text = firewall_bot.pick_text("mail-01", items, set(),
                                  {"203.0.113.5": "🇳🇱 Amsterdam"})
    assert "🇳🇱 Amsterdam" in text


def test_empty_pick_explains_the_rules():
    text = firewall_bot.pick_text("mail-01", [], set(), {})
    assert "Некого предлагать" in text
    assert "Cloudflare" in text


def test_term_button_cycles():
    assert firewall_bot.next_days(3) == 7
    assert firewall_bot.next_days(7) == 30
    assert firewall_bot.next_days(30) is None
    assert firewall_bot.next_days(None) == 3
