"""
Блокировка на Linux через fail2ban.

Бот не пишет своих правил iptables: банит по-прежнему fail2ban, своими
порогами и со своим сроком. Проверяются разбор его вывода (формат с
псевдографикой стабилен, но порядок полей — нет) и отбор кандидатов.
"""
import fail2ban


STATUS = """Status
|- Number of jail:\t3
`- Jail list:\tsshd, zimbra-auth, zimbra-web
"""

JAIL = """Status for the jail: zimbra-auth
|- Filter
|  |- Currently failed:\t2
|  |- Total failed:\t7161
|  `- File list:\t/var/log/mail.log
`- Actions
   |- Currently banned:\t2
   |- Total banned:\t66
   `- Banned IP list:\t203.0.113.5 198.51.100.7
"""

EMPTY_JAIL = """Status for the jail: zimbra-web
|- Filter
|  |- Currently failed:\t0
|  |- Total failed:\t0
|  `- File list:\t/opt/zimbra/log/audit.log
`- Actions
   |- Currently banned:\t0
   |- Total banned:\t0
   `- Banned IP list:
"""


def test_jail_names_are_parsed():
    assert fail2ban.parse_jails(STATUS) == ["sshd", "zimbra-auth", "zimbra-web"]


def test_jail_names_on_garbage():
    assert fail2ban.parse_jails("") == []
    assert fail2ban.parse_jails("что-то пошло не так") == []


def test_jail_details_are_parsed():
    jail = fail2ban.parse_jail(JAIL, "zimbra-auth")

    assert jail["banned_now"] == 2
    assert jail["banned_total"] == 66
    assert jail["failed_total"] == 7161
    assert jail["addresses"] == ["203.0.113.5", "198.51.100.7"]
    assert jail["logs"] == ["/var/log/mail.log"]


def test_empty_ban_list_is_not_an_error():
    """Пустой список — обычное состояние: сроки бана истекают."""
    jail = fail2ban.parse_jail(EMPTY_JAIL, "zimbra-web")

    assert jail["banned_now"] == 0
    assert jail["addresses"] == []


def test_ignoreip_is_parsed():
    text = "These IP addresses/networks are ignored:\n" \
           "| 127.0.0.1/8 10.100.0.0/16 95.59.126.130\n`-"
    assert fail2ban.parse_ignoreip(text) == [
        "127.0.0.1/8", "10.100.0.0/16", "95.59.126.130"]


def test_commands_ask_for_root_only_when_needed():
    """Под root sudo незачем, под учёткой мониторинга — обязателен, и без
    правила sudo команда должна падать с текстом, а не молчать."""
    command = fail2ban._cmd("status")

    assert 'id -u' in command
    assert "sudo -n fail2ban-client status" in command


def test_section_is_linux_only():
    """У Windows своя блокировка — правилом Windows Firewall."""
    linux = {"host": "mail.example.local", "type": "linux", "firewall": True}
    windows = {"host": "srv.example.local", "type": "windows", "firewall": True}

    assert fail2ban.has_fail2ban(linux)
    assert not fail2ban.has_fail2ban(windows)
    assert not fail2ban.has_fail2ban({"host": "x", "type": "linux"})


# ─── Кандидаты ───────────────────────────────────────────────

def _state(banned=(), ignored=()):
    return {"jails": [{"jail": "zimbra-auth", "addresses": list(banned),
                       "banned_now": len(banned), "banned_total": 0,
                       "failed_total": 0}],
            "ignored": list(ignored)}


def _snapshot(ips):
    return [{"server": "mail-01", "kind": "zimbra", "summary": {
        "suspects": [{"ip": ip, "reason": "распылённый перебор"} for ip in ips]
    }}]


def test_candidates_come_from_mail_findings():
    from fail2ban_bot import suspects_for

    found = suspects_for("mail-01", _state(), _snapshot(["203.0.113.5"]))
    assert [i["ip"] for i in found] == ["203.0.113.5"]


def test_already_banned_is_not_offered():
    from fail2ban_bot import suspects_for

    found = suspects_for("mail-01", _state(banned=["203.0.113.5"]),
                         _snapshot(["203.0.113.5", "198.51.100.7"]))
    assert [i["ip"] for i in found] == ["198.51.100.7"]


def test_whitelisted_is_not_offered():
    """fail2ban откажется банить адрес из ignoreip. Предлагать его — вести
    человека к действию, которое заведомо ничего не сделает."""
    from fail2ban_bot import suspects_for

    found = suspects_for("mail-01", _state(ignored=["95.59.126.130"]),
                         _snapshot(["95.59.126.130", "203.0.113.5"]))
    assert [i["ip"] for i in found] == ["203.0.113.5"]


def test_other_servers_findings_are_not_mixed_in():
    from fail2ban_bot import suspects_for

    snapshots = _snapshot(["203.0.113.5"])
    snapshots.append({"server": "mail-02", "kind": "zimbra", "summary": {
        "suspects": [{"ip": "198.51.100.7", "reason": "перебор"}]}})

    found = suspects_for("mail-01", _state(), snapshots)
    assert [i["ip"] for i in found] == ["203.0.113.5"]


def test_manual_bans_go_to_the_mail_jail():
    """Основной перебор идёт по почтовым портам, и разбан потом ищется в
    одной клетке, а не в двух."""
    from fail2ban_bot import default_jail

    state = {"jails": [{"jail": "sshd"}, {"jail": "zimbra-web"},
                       {"jail": "zimbra-auth"}]}
    assert default_jail(state) == "zimbra-auth"
    assert default_jail({"jails": [{"jail": "sshd"}]}) == "sshd"
    assert default_jail({"jails": []}) == ""


# ─── Подозреваемые из почтовых сводок ────────────────────────

def test_internal_addresses_are_never_suspects():
    """За внутренним адресом шлюз или рабочее место: блокировка отрезает
    своих, причём сразу весь офис."""
    from zimbra_collector import suspects

    events = [{"account": "a@example.local", "ip": "10.100.0.10",
               "protocol": "soap", "ok": False, "count": 900, "last": ""},
              {"account": "a@example.local", "ip": "203.0.113.5",
               "protocol": "smtp", "ok": False, "count": 900, "last": ""}]

    assert [i["ip"] for i in suspects(events)] == ["203.0.113.5"]


def test_spray_addresses_become_suspects():
    """Ради этого раздел и делался: под maxretry такой перебор не попадает
    никогда, и поймать его может только человек."""
    from zimbra_collector import suspects

    events = [{"account": "a@example.local", "ip": f"203.0.113.{i}",
               "protocol": "smtp", "ok": False, "count": 1, "last": ""}
              for i in range(1, 5)]

    assert len(suspects(events)) == 4


def test_exchange_suspects_need_the_threshold():
    from exchange_collector import suspects, FAIL_ALERT

    rows = [{"user": "admin", "ip": "203.0.113.5", "count": FAIL_ALERT},
            {"user": "admin", "ip": "198.51.100.7", "count": 1},
            {"user": "admin", "ip": "10.20.30.5", "count": 500}]

    assert [i["ip"] for i in suspects(rows)] == ["203.0.113.5"]
