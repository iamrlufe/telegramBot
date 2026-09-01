"""Почта Zimbra: разбор журналов и правила тревоги.

Главное, что здесь проверяется, — счёт писем. Одно письмо проходит через
амавис двумя очередями и оставляет 2-3 строки `from=`; наивный подсчёт
строк завышает объём втрое, и порог всплеска становится бессмысленным.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bot"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "monitor"))

import zimbra_log

SERVER = {"name": "mail-01.example.local", "host": "192.0.2.40",
          "type": "linux", "zimbra": True}


# ─── Кнопка ──────────────────────────────────────────────────

def test_button_by_flag_and_by_service():
    assert zimbra_log.has_zimbra(SERVER)
    assert zimbra_log.has_zimbra(
        {"host": "192.0.2.40", "type": "linux", "services": ["postfix"]})
    assert zimbra_log.has_zimbra(
        {"host": "192.0.2.40", "type": "linux", "services": ["zimbra"]})


def test_button_hidden_elsewhere():
    assert not zimbra_log.has_zimbra({"host": "192.0.2.40", "type": "linux"})
    # Windows-сервер: журналов Zimbra там взяться неоткуда
    assert not zimbra_log.has_zimbra({"host": "192.0.2.10", "zimbra": True})


# ─── Происхождение письма ────────────────────────────────────

def test_origin_web():
    """Через веб — это mailboxd с петли и локальная сдача через pickup."""
    assert zimbra_log.origin_kind("127.0.0.1") == "web"
    assert zimbra_log.origin_kind("local") == "web"
    assert zimbra_log.origin_kind("::1") == "web"


def test_origin_inside():
    assert zimbra_log.origin_kind("10.20.30.9") == "inside"
    assert zimbra_log.origin_kind("192.168.1.5") == "inside"


def test_origin_outside():
    assert zimbra_log.origin_kind("203.0.113.5") == "outside"


def test_outside_sender_is_found():
    """Почта от своего адреса, сданная снаружи, — так выглядит угнанная
    учётка: изнутри все пишут через веб."""
    origins = [(["buh@example.local", "203.0.113.5"], 40),
               (["buh@example.local", "127.0.0.1"], 900),
               (["scanner@example.local", "10.20.30.9"], 12)]
    found = zimbra_log.outside_senders(origins, ["example.local"])
    assert len(found) == 1
    assert found[0]["sender"] == "buh@example.local"
    assert found[0]["count"] == 40


def test_foreign_sender_is_not_our_problem():
    """Чужой адрес с белого IP — это обычная входящая почта."""
    origins = [(["someone@other.example", "203.0.113.5"], 100)]
    assert zimbra_log.outside_senders(origins, ["example.local"]) == []


# ─── Входы ───────────────────────────────────────────────────

EVENTS = [
    {"account": "admin@example.local", "ip": "203.0.113.5",
     "protocol": "soap/admin", "ok": False, "count": 1284,
     "last": "2026-09-01 00:45:30"},
    {"account": "buh@example.local", "ip": "198.51.100.7",
     "protocol": "soap", "ok": True, "count": 4,
     "last": "2026-09-01 03:14:00"},
    {"account": "buh@example.local", "ip": "10.20.30.5",
     "protocol": "imap", "ok": True, "count": 400,
     "last": "2026-09-01 09:00:00"},
]


def test_foreign_login_only_when_it_succeeded():
    """Неудачная попытка из-за границы — это перебор, у него своё правило."""
    codes = {"198.51.100.7": "TR", "203.0.113.5": "NL", "10.20.30.5": ""}
    found = zimbra_log.foreign_logins(EVENTS, codes)
    assert [e["account"] for e in found] == ["buh@example.local"]
    assert found[0]["country"] == "TR"


def test_home_country_does_not_alert():
    codes = {"198.51.100.7": "KZ", "10.20.30.5": "KZ"}
    assert zimbra_log.foreign_logins(EVENTS, codes) == []


def test_unknown_country_does_not_alert():
    """Страна не определилась — молчим: гадать хуже, чем не сказать."""
    assert zimbra_log.foreign_logins(EVENTS, {}) == []


def test_brute_force_found_and_admin_marked():
    found = zimbra_log.brute_force(EVENTS, threshold=50)
    assert len(found) == 1
    assert found[0]["account"] == "admin@example.local"
    assert found[0]["admin"] is True
    assert found[0]["guessed"] is False


def test_brute_force_marks_guessed_password():
    """Тот же адрес и та же учётка, но один вход удался — пароль подобран."""
    events = EVENTS + [{"account": "admin@example.local", "ip": "203.0.113.5",
                        "protocol": "soap/admin", "ok": True, "count": 1,
                        "last": "2026-09-01 05:00:00"}]
    assert zimbra_log.brute_force(events, threshold=50)[0]["guessed"] is True


def test_few_failures_are_not_brute_force():
    events = [dict(EVENTS[0], count=3)]
    assert zimbra_log.brute_force(events, threshold=50) == []


# ─── Всплеск отправки ────────────────────────────────────────

def test_heavy_sender_threshold():
    senders = [{"sender": "a@example.local", "messages": 5000, "recipients": 5200},
               {"sender": "b@example.local", "messages": 12, "recipients": 12}]
    found = zimbra_log.heavy_senders(senders, threshold=2000)
    assert [i["sender"] for i in found] == ["a@example.local"]


# ─── Разбор вывода скрипта ───────────────────────────────────

SAMPLE = "\n".join([
    "LOG\t/var/log/mail.log",
    "Q\t3",
    "T\t4\t55\t1\t1\t1",
    "S\tbuh@example.local\t2\t53",
    "S\troot@example.local\t1\t1",
    "X\tbuh@example.local\t203.0.113.5\t1",
    "X\tbuh@example.local\t127.0.0.1\t1",
    "DF\t452 4.2.2 Over quota \t1",
    "DR\tfull@example.local\t1",
    "BR\tgone@example.local\t1",
    "RJ\t550 5.1.1 Recipient address rejected\t1",
    "RI\t198.51.100.7\t1",
    "LD\texample.local\t1",
])


def test_rows_are_split_by_marker():
    rows = zimbra_log._rows(SAMPLE)
    assert rows["Q"] == [["3"]]
    assert len(rows["S"]) == 2


def test_senders_keep_recipient_count():
    """Письмо на пятьдесят адресов и пятьдесят писем — разные вещи."""
    senders = zimbra_log._senders(zimbra_log._rows(SAMPLE)["S"])
    assert senders[0] == {"sender": "buh@example.local", "messages": 2,
                          "recipients": 53}


def test_queue_unknown_is_not_zero():
    """Не прочитали очередь — это «неизвестно», а не «пусто». Ноль вместо
    непрочитанного и был причиной, по которой порог очереди не срабатывал."""
    rows = zimbra_log._rows("Q\t?\nT\t0\t0\t0\t0\t0")
    assert rows["Q"] == [["?"]]


# ─── Скрипты для сервера ─────────────────────────────────────

def test_mail_script_avoids_mktime():
    """На Ubuntu стоит mawk, а mktime и systime там нет: скрипт с ними
    падает на живом сервере, хотя локально на gawk проходит."""
    script = zimbra_log._mail_script(24)
    assert "mktime" not in script
    assert "systime" not in script


def test_mail_script_looks_for_postqueue_in_zimbra_prefix():
    """У Zimbra postqueue не в PATH: без полного пути очередь всегда 0."""
    assert "/opt/zimbra/common/sbin/postqueue" in zimbra_log._mail_script(24)


def test_mail_script_reads_rotated_file_on_boundary():
    assert '"$LOG.1"' in zimbra_log._mail_script(24)


def test_audit_script_reads_yesterdays_archive():
    """Ротация в 02:50, поэтому ночь — а это время подбора пароля — лежит
    во вчерашнем .gz."""
    script = zimbra_log._audit_script(24)
    assert "zcat" in script
    assert "%Y-%m-%d" in script


def test_scripts_report_missing_rights_instead_of_zeroes():
    for script in (zimbra_log._mail_script(24), zimbra_log._audit_script(24)):
        assert "sudo -n" in script
        assert "ERR" in script


# ─── Находки для алертов ─────────────────────────────────────

def test_findings_cover_three_reasons():
    from zimbra_collector import findings_for

    mail = {"origins": [(["buh@example.local", "203.0.113.5"], 40)],
            "local_domains": ["example.local"], "senders": [], "queue": 3}
    audit = {"events": EVENTS}
    geo = {"203.0.113.5": "🇳🇱 Amsterdam", "198.51.100.7": "🇹🇷 Istanbul"}
    found = findings_for("mail-01", mail, audit, geo)
    keys = " ".join(item["key"] for _s, item in found)
    assert "zm_geo:" in keys
    assert "zm_brute:" in keys
    assert "zm_outside:" in keys


def test_queue_finding_key_has_no_number():
    """Иначе каждое изменение очереди — новая находка, и алерт повторяется
    при каждом проходе."""
    from zimbra_collector import findings_for

    mail = {"queue": 5000, "origins": [], "local_domains": [], "senders": []}
    found = findings_for("mail-01", mail, {}, {})
    assert [item["key"] for _s, item in found] == ["zm_queue:mail-01"]


def test_healthy_server_gives_no_findings():
    from zimbra_collector import findings_for

    mail = {"queue": 3, "origins": [(["buh@example.local", "127.0.0.1"], 900)],
            "local_domains": ["example.local"], "senders": []}
    audit = {"events": [EVENTS[2]]}
    assert findings_for("mail-01", mail, audit, {"10.20.30.5": ""}) == []


# ─── Справка ─────────────────────────────────────────────────

def test_help_explains_message_counting():
    from config_editor import HELP_SECTIONS

    text = HELP_SECTIONS["zimbra"][1]
    assert "message-id" in text
    assert "audit.log" in text


# ─── Прогон самого awk ───────────────────────────────────────

# Разбор живёт в awk, а не в Python: суточный mail.log это 25 МБ, и тянуть
# его в бота незачем. Значит и проверять надо сам awk — на строках ровно
# той разметки, что приходит с живого сервера.

MAIL_FIXTURE = """\
Sep  1 06:26:23 mail postfix/pickup[53284]: 88B25A009C: uid=0 from=<root>
Sep  1 06:26:23 mail postfix/cleanup[31450]: 88B25A009C: message-id=<m1@example.local>
Sep  1 06:26:23 mail postfix/qmgr[24698]: 88B25A009C: from=<root@example.local>, size=847, nrcpt=1 (queue active)
Sep  1 06:26:25 mail postfix/cleanup[31450]: F1216A0087: message-id=<m1@example.local>
Sep  1 06:26:25 mail postfix/qmgr[24698]: F1216A0087: from=<root@example.local>, size=900, nrcpt=1 (queue active)
Sep  1 06:26:26 mail postfix/smtp[31461]: 88B25A009C: to=<a@example.local>, relay=127.0.0.1[127.0.0.1]:10024, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as F1216A0087)
Sep  1 06:26:27 mail postfix/lmtp[55201]: F1216A0087: to=<a@example.local>, relay=mail.example.local[127.0.0.1]:7025, dsn=2.0.0, status=sent (250 delivery OK)
Sep  1 08:10:01 mail postfix/smtpd[30468]: AAAA1111: client=localhost[127.0.0.1]
Sep  1 08:10:01 mail postfix/cleanup[31450]: AAAA1111: message-id=<m2@example.local>
Sep  1 08:10:01 mail postfix/qmgr[24698]: AAAA1111: from=<buh@example.local>, size=5000, nrcpt=3 (queue active)
Sep  1 10:00:00 mail postfix/smtpd[30468]: CCCC3333: client=unknown[203.0.113.5]
Sep  1 10:00:00 mail postfix/cleanup[31450]: CCCC3333: message-id=<m4@example.local>
Sep  1 10:00:00 mail postfix/qmgr[24698]: CCCC3333: from=<buh@example.local>, size=100, nrcpt=50 (queue active)
Sep  1 07:03:08 mail postfix/lmtp[55201]: 41B53A0099: to=<full@example.local>, relay=mail.example.local[127.0.0.1]:7025, dsn=4.2.2, status=deferred (host mail.example.local[127.0.0.1] said: 452 4.2.2 Over quota (in reply to end of DATA command))
Sep  1 06:33:53 mail postfix/smtpd[30468]: NOQUEUE: reject: RCPT from smtp.example.local[198.51.100.7]: 550 5.1.1 <nobody@example.local>: Recipient address rejected: mng.example.local; from=<x@example.local> to=<nobody@example.local> proto=ESMTP helo=<smtp.example.local>
Aug 20 06:33:53 mail postfix/qmgr[24698]: OLD00001: from=<old@example.local>, size=1, nrcpt=1 (queue active)
"""

AUDIT_FIXTURE = """\
2026-09-01 00:15:45,087 WARN  [qtp1:https:https://mail.example.local:7073/service/admin/soap/] [name=admin@example.local;oip=203.0.113.5;oport=51288;] security - cmd=Auth; account=admin@example.local; protocol=soap; error=authentication failed for [admin], invalid password;
2026-09-01 00:45:30,218 WARN  [qtp2:https:https://mail.example.local:7073/service/admin/soap/] [name=admin@example.local;oip=203.0.113.5;oport=54806;] security - cmd=Auth; account=admin@example.local; protocol=soap; error=authentication failed for [admin], invalid password;
2026-09-01 08:00:00,001 INFO  [qtp3:https:https://mail.example.local/service/soap/] [name=buh@example.local;oip=198.51.100.7;] security - cmd=Auth; account=buh@example.local; protocol=soap;
2026-08-20 09:00:00,001 INFO  [old] [name=old@example.local;oip=10.20.30.5;] security - cmd=Auth; account=old@example.local; protocol=imap;
"""


def _run_awk(program: str, args: list, inputs: list) -> str:
    import shutil
    import subprocess
    import tempfile

    import pytest

    awk = shutil.which("awk")
    if not awk:
        pytest.skip("awk недоступен")
    paths = []
    with tempfile.TemporaryDirectory() as tmp:
        for index, text in enumerate(inputs):
            path = Path(tmp) / f"in{index}"
            path.write_text(text, encoding="utf-8")
            paths.append(str(path))
        prog = Path(tmp) / "prog.awk"
        prog.write_text(program, encoding="utf-8")
        result = subprocess.run([awk] + args + ["-f", str(prog)] + paths,
                                capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _mail_output() -> dict:
    days = ("Sep  1|1788220800\n"     # 2026-09-01 00:00:00 UTC+0
            "Aug 31|1788134400\n")
    out = _run_awk(zimbra_log._MAIL_AWK, ["-v", "cut=1788134400"],
                   [days, MAIL_FIXTURE])
    return zimbra_log._rows(out)


def test_awk_counts_messages_not_log_lines():
    """Ключевая проверка. В фикстуре три письма, но пять строк `from=`:
    амавис переинжектит первое письмо второй очередью с тем же message-id.
    Наивный grep дал бы пять."""
    rows = _mail_output()
    assert rows["T"][0][0] == "3"


def test_awk_ignores_lines_outside_the_window():
    rows = _mail_output()
    senders = {row[0] for row in rows["S"]}
    assert "old@example.local" not in senders


def test_awk_tells_web_from_outside():
    rows = _mail_output()
    origins = {(row[0], row[1]) for row in rows["X"]}
    assert ("buh@example.local", "127.0.0.1") in origins
    assert ("buh@example.local", "203.0.113.5") in origins
    assert ("root@example.local", "local") in origins


def test_awk_extracts_over_quota_reason():
    rows = _mail_output()
    assert any("Over quota" in row[0] for row in rows["DF"])


def test_awk_groups_rejects_without_recipient():
    """С адресом получателя каждая строка уникальна, и группировка
    рассыпается на тысячи строк по одной."""
    rows = _mail_output()
    reasons = [row[0] for row in rows["RJ"]]
    assert reasons == ["550 5.1.1 Recipient address rejected: mng.example.local"]


def test_awk_learns_local_domains_from_deliveries():
    rows = _mail_output()
    assert [row[0] for row in rows["LD"]] == ["example.local"]


def test_audit_awk_separates_success_and_admin_console():
    out = _run_awk(zimbra_log._AUDIT_AWK,
                   ["-v", "cut=2026-08-31 18:00:00"], [AUDIT_FIXTURE])
    rows = zimbra_log._rows(out)
    assert rows["T"][0] == ["1", "2"]
    by_account = {row[0]: row for row in rows["A"]}
    assert by_account["admin@example.local"][2] == "soap/admin"
    assert by_account["admin@example.local"][3] == "0"
    assert by_account["buh@example.local"][3] == "1"
    assert "old@example.local" not in by_account
