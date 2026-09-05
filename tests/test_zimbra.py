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


def test_origin_outside_only_with_login():
    """Белый адрес сам по себе ничего не значит. Сдача письма — это
    аутентифицированная сессия; без неё та же строка client= означает
    входящее письмо, а адрес отправителя в конверте у него любой."""
    assert zimbra_log.origin_kind("203.0.113.5", authed=True) == "outside"
    assert zimbra_log.origin_kind("203.0.113.5") == "incoming"


def test_outside_sender_is_found():
    """Почта от своего адреса, сданная снаружи ПО ПАРОЛЮ, — так выглядит
    угнанная учётка: изнутри все пишут через веб."""
    origins = [(["buh@example.local", "203.0.113.5", "1"], 40),
               (["buh@example.local", "127.0.0.1", "0"], 900),
               (["scanner@example.local", "10.20.30.9", "0"], 12)]
    found = zimbra_log.outside_senders(origins, ["example.local"])
    assert len(found) == 1
    assert found[0]["sender"] == "buh@example.local"
    assert found[0]["count"] == 40


def test_foreign_sender_is_not_our_problem():
    """Чужой адрес с белого IP — это обычная входящая почта."""
    origins = [(["someone@other.example", "203.0.113.5", "0"], 100)]
    assert zimbra_log.outside_senders(origins, ["example.local"]) == []


def test_spoofed_sender_is_not_a_stolen_account():
    """Регрессия на боевой ложной тревоге. Спам приходит из интернета с
    подделанным адресом своей же организации: тот же smtpd, тот же
    client=, отправитель свой — и правило объявляло девять учёток
    угнанными за сутки. Отличает такое письмо отсутствие входа."""
    origins = [(["buh@example.local", "203.0.113.5", "0"], 1)]

    assert zimbra_log.outside_senders(origins, ["example.local"]) == []


def test_letters_are_declined():
    """«1 писем» в тревоге читается как недоделка."""
    assert zimbra_log.letters(1) == "1 письмо"
    assert zimbra_log.letters(3) == "3 письма"
    assert zimbra_log.letters(9) == "9 писем"
    assert zimbra_log.letters(11) == "11 писем"
    assert zimbra_log.letters(21) == "21 письмо"
    assert zimbra_log.letters(102) == "102 письма"


def test_spoofing_is_still_reported_but_as_one_line():
    """Молчать об этом тоже неправильно: письмо от «коллеги» убедительнее
    любого фишинга, а раз оно дошло — SPF/DMARC его не отбили. Но это одна
    сводка, а не находка на каждое письмо."""
    origins = [(["buh@example.local", "203.0.113.5", "0"], 3),
               (["hr@example.local", "198.51.100.9", "0"], 2),
               (["buh@example.local", "203.0.113.9", "1"], 7),
               (["buh@example.local", "127.0.0.1", "0"], 900),
               (["someone@other.example", "203.0.113.5", "0"], 50)]

    spoof = zimbra_log.spoofed_senders(origins, ["example.local"])

    assert spoof["messages"] == 5
    assert spoof["senders"] == ["buh@example.local", "hr@example.local"]
    assert spoof["ips"] == ["198.51.100.9", "203.0.113.5"]


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

    mail = {"origins": [(["buh@example.local", "203.0.113.5", "1"], 40)],
            "local_domains": ["example.local"], "senders": [], "queue": 3}
    audit = {"events": EVENTS}
    geo = {"203.0.113.5": "🇳🇱 Amsterdam", "198.51.100.7": "🇹🇷 Istanbul"}
    found = findings_for("mail-01", mail, audit, geo)
    keys = " ".join(item["key"] for _s, item in found)
    assert "zm_geo:" in keys
    assert "zm_brute:" in keys
    assert "zm_outside:" in keys


def test_bruteforce_findings_carry_countries_for_autoban():
    """Автоблокировка решает по стране адреса, а страна известна только
    здесь: без неё находка молча перестала бы работать как улика."""
    from zimbra_collector import findings_for

    mail = {"origins": [], "local_domains": ["example.local"], "senders": [],
            "queue": 3}
    audit = {"events": EVENTS}
    geo = {"203.0.113.5": "🇳🇱 Amsterdam", "198.51.100.7": "🇹🇷 Istanbul"}
    brute = [item for _s, item in findings_for("mail-01", mail, audit, geo)
             if item["key"].startswith("zm_brute:")]

    assert brute, "перебор пароля должен находиться"
    for item in brute:
        assert item["attack"] == "brute"
        for ip in item["ips"]:
            assert item["ip_country"].get(ip) in ("NL", "TR")


def test_only_bruteforce_is_marked_for_autoban():
    """Всплеск отправки и очередь баном не лечатся — метки на них быть
    не должно, иначе бот отрежет адрес ни за что."""
    from zimbra_collector import findings_for

    mail = {"queue": 5000, "origins": [], "local_domains": [], "senders": []}
    found = findings_for("mail-01", mail, {}, {})
    assert all(item.get("attack") != "brute" for _s, item in found)


def test_queue_finding_key_has_no_number():
    """Иначе каждое изменение очереди — новая находка, и алерт повторяется
    при каждом проходе."""
    from zimbra_collector import findings_for

    mail = {"queue": 5000, "origins": [], "local_domains": [], "senders": []}
    found = findings_for("mail-01", mail, {}, {})
    assert [item["key"] for _s, item in found] == ["zm_queue:mail-01"]


def test_healthy_server_gives_no_findings():
    from zimbra_collector import findings_for

    mail = {"queue": 3,
            "origins": [(["buh@example.local", "127.0.0.1", "0"], 900)],
            "local_domains": ["example.local"], "senders": []}
    audit = {"events": [EVENTS[2]]}
    assert findings_for("mail-01", mail, audit, {"10.20.30.5": ""}) == []


# ─── Флаги и кнопка блокировки в алерте ──────────────────────

SPRAY_EVENTS = [
    {"account": "kuz@example.local", "ip": "203.0.113.5", "protocol": "smtp",
     "ok": False, "count": 1, "last": "2026-09-01 01:00:00"},
    {"account": "kuz@example.local", "ip": "198.51.100.7", "protocol": "smtp",
     "ok": False, "count": 1, "last": "2026-09-01 02:00:00"},
    {"account": "kuz@example.local", "ip": "192.0.2.9", "protocol": "smtp",
     "ok": False, "count": 1, "last": "2026-09-01 03:00:00"},
    {"account": "kuz@example.local", "ip": "10.20.30.5", "protocol": "smtp",
     "ok": False, "count": 1, "last": "2026-09-01 04:00:00"},
]

SPRAY_GEO = {"203.0.113.5": "🇳🇱 Amsterdam", "198.51.100.7": "🇹🇷 Istanbul",
             "192.0.2.9": "🇷🇺 Moscow", "10.20.30.5": ""}


def _spray_finding():
    from zimbra_collector import findings_for

    mail = {"origins": [], "local_domains": [], "senders": [], "queue": 3}
    found = findings_for("mail-01", {"queue": 3, **mail},
                         {"events": SPRAY_EVENTS}, SPRAY_GEO)
    return next(item for _s, item in found if item["key"].startswith("zm_spray:"))


def test_spray_addresses_carry_flags():
    """Страна отвечает на первый вопрос про адрес: свои так не ходят."""
    text = _spray_finding()["text"]

    assert "203.0.113.5 🇳🇱" in text
    assert "198.51.100.7 🇹🇷" in text
    # Город в перечислении не нужен — он занимает полстроки на каждый адрес.
    assert "Amsterdam" not in text


def test_spray_finding_offers_only_outside_addresses():
    """Кнопка под алертом банит сразу, поэтому внутренний адрес не должен
    попасть в предложение даже случайно: за ним шлюз или рабочее место."""
    ips = _spray_finding()["ips"]

    assert "203.0.113.5" in ips
    assert "10.20.30.5" not in ips


def test_ban_buttons_appear_under_alert():
    from alerts import BAN_BUTTONS, ban_buttons_kb

    kb = ban_buttons_kb("mail-01", ["203.0.113.5", "198.51.100.7",
                                    "192.0.2.9", "192.0.2.10"])
    buttons = [b for row in kb["inline_keyboard"] for b in row]
    bans = [b for b in buttons if b["callback_data"].startswith("al_ban:")]

    assert len(bans) == BAN_BUTTONS
    assert bans[0]["callback_data"] == "al_ban:mail-01:203.0.113.5"
    # Кнопки алерта никуда не делись.
    assert any(b["callback_data"].startswith("al_refresh:") for b in buttons)


def test_too_long_callback_is_not_drawn():
    """Telegram режет callback_data длиннее 64 байт, и кнопка молча
    перестаёт работать — лучше её не рисовать вовсе."""
    from alerts import ban_buttons_kb

    kb = ban_buttons_kb("s" * 60, ["203.0.113.5"])
    data = [b["callback_data"] for row in kb["inline_keyboard"] for b in row]

    assert not [d for d in data if d.startswith("al_ban:")]


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
Sep  1 11:00:00 mail postfix/submission/smtpd[30470]: DDDD4444: client=host.example.net[203.0.113.9], sasl_method=PLAIN, sasl_username=buh@example.local
Sep  1 11:00:00 mail postfix/cleanup[31450]: DDDD4444: message-id=<m5@example.local>
Sep  1 11:00:00 mail postfix/qmgr[24698]: DDDD4444: from=<buh@example.local>, size=200, nrcpt=1 (queue active)
Sep  1 07:03:08 mail postfix/lmtp[55201]: 41B53A0099: to=<full@example.local>, relay=mail.example.local[127.0.0.1]:7025, dsn=4.2.2, status=deferred (host mail.example.local[127.0.0.1] said: 452 4.2.2 Over quota (in reply to end of DATA command))
Sep  1 06:33:53 mail postfix/smtpd[30468]: NOQUEUE: reject: RCPT from smtp.example.local[198.51.100.7]: 550 5.1.1 <nobody@example.local>: Recipient address rejected: mng.example.local; from=<x@example.local> to=<nobody@example.local> proto=ESMTP helo=<smtp.example.local>
Aug 20 06:33:53 mail postfix/qmgr[24698]: OLD00001: from=<old@example.local>, size=1, nrcpt=1 (queue active)
"""

# Строки взяты по форме с живого сервера. Ключевое здесь — 7073 и oproto:
# так выглядит проверка пароля для SMTP-сессии, а вовсе не вход в админку,
# хотя путь в URL у них общий.
AUDIT_FIXTURE = """\
2026-09-01 00:15:45,087 WARN  [qtp1:https:https://mail.example.local:7073/service/admin/soap/] [name=admin@example.local;oip=203.0.113.5;oport=51288;oproto=smtp;] security - cmd=Auth; account=admin@example.local; protocol=soap; error=authentication failed for [admin], invalid password;
2026-09-01 00:45:30,218 WARN  [qtp2:https:https://mail.example.local:7073/service/admin/soap/] [name=admin@example.local;oip=203.0.113.5;oport=54806;oproto=smtp;] security - cmd=Auth; account=admin@example.local; protocol=soap; error=authentication failed for [admin], invalid password;
2026-09-01 08:00:00,001 INFO  [qtp3:https:https://mail.example.local/service/soap/] [name=buh@example.local;oip=198.51.100.7;] security - cmd=Auth; account=buh@example.local; protocol=soap;
2026-09-01 09:10:00,001 WARN  [qtp4:https:https://mail.example.local:7071/service/admin/soap/AuthRequest] [name=root@example.local;oip=203.0.113.77;] security - cmd=Auth; account=root@example.local; protocol=soap; error=authentication failed for [root], invalid password;
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
    """Ключевая проверка. В фикстуре четыре письма, но шесть строк `from=`:
    амавис переинжектит первое письмо второй очередью с тем же message-id.
    Наивный grep дал бы шесть."""
    rows = _mail_output()
    assert rows["T"][0][0] == "4"


def test_awk_ignores_lines_outside_the_window():
    rows = _mail_output()
    senders = {row[0] for row in rows["S"]}
    assert "old@example.local" not in senders


def test_awk_tells_web_from_outside():
    rows = _mail_output()
    origins = {(row[0], row[1], row[2]) for row in rows["X"]}
    assert ("buh@example.local", "127.0.0.1", "0") in origins
    assert ("root@example.local", "local", "0") in origins


def test_awk_marks_authenticated_submission():
    """Признак входа — единственное, чем сдача письма снаружи отличается в
    логе от входящего письма с подделанным отправителем. Оба адреса белые,
    оба письма от своего адреса, строка client= у них одинаковая."""
    rows = _mail_output()
    origins = {(row[0], row[1], row[2]) for row in rows["X"]}

    assert ("buh@example.local", "203.0.113.9", "1") in origins, "сдано по паролю"
    assert ("buh@example.local", "203.0.113.5", "0") in origins, "входящее"


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
    assert rows["T"][0] == ["1", "3"]
    by_account = {row[0]: row for row in rows["A"]}
    # 7073 + oproto=smtp — это перебор пароля к ящику через SMTP, а не
    # попытка влезть в админку, хотя путь в URL у них одинаковый.
    assert by_account["admin@example.local"][2] == "smtp"
    # а вот 7071 — настоящая админ-консоль
    assert by_account["root@example.local"][2] == "soap/admin"
    assert by_account["admin@example.local"][3] == "0"
    assert by_account["buh@example.local"][3] == "1"
    assert "old@example.local" not in by_account


# ─── Сводка для дашборда ─────────────────────────────────────

def _summary(**over):
    from zimbra_collector import summary_for

    mail = {"messages": 5338, "queue": 12, "rejected": 2411,
            "senders": [{"sender": "buh@example.local", "messages": 40,
                         "recipients": 12}],
            # Свои домены нужны сводке, чтобы отделить сотрудников от чужих
            # рассылок, прошедших через тот же сервер.
            "local_domains": ["example.local"],
            "defer_reasons": [(["Connection timed out"], 7)]}
    audit = {"failed": 1284, "ok": 404, "events": EVENTS}
    mail.update(over.pop("mail", {}))
    audit.update(over.pop("audit", {}))
    return summary_for(mail, audit, over.pop("findings", []),
                       over.pop("geo", {}))


def test_summary_has_the_shape_the_dashboard_draws():
    """Форма общая с Exchange: дашборд рисует kpis/groups/alarms и ничего
    не знает ни про postfix, ни про mailboxd."""
    summary = _summary()

    assert {"kpis", "groups", "alarms", "suspects"} == set(summary)
    assert all({"value", "label", "level"} <= set(k) for k in summary["kpis"])
    for group in summary["groups"]:
        assert {"title", "level", "rows"} <= set(group)
        assert all({"level", "left", "title"} <= set(r) for r in group["rows"])


def test_failed_logins_turn_red_only_where_a_password_is_guessed():
    """1284 отказа с одного адреса — подбор, а несколько ошибок за сутки —
    обычная опечатка, и красить их одинаково нельзя."""
    hot = _summary()
    calm = _summary(audit={"failed": 3, "events": [
        {"account": "buh@example.local", "ip": "10.20.30.5", "protocol": "imap",
         "ok": False, "count": 3, "last": "2026-09-01 09:00:00"}]})

    assert [k["level"] for k in hot["kpis"] if k["label"] == "неудачных входов"] == ["crit"]
    assert [k["level"] for k in calm["kpis"] if k["label"] == "неудачных входов"] == ["warn"]


def test_queue_kpi_warns_only_above_the_threshold():
    assert [k["level"] for k in _summary()["kpis"] if k["label"] == "в очереди"] == ["ok"]
    big = _summary(mail={"queue": 5000})
    assert [k["level"] for k in big["kpis"] if k["label"] == "в очереди"] == ["warn"]


def test_only_red_findings_become_alarms():
    """Жёлтые находки (всплеск отправки, очередь) уже видны плитками, а
    число в заголовке вкладки должно означать происшествие."""
    findings = [("mail-01", {"level": "crit", "hint": "1284 неудачных входов",
                             "text": "🔴 подбор пароля: admin ← 203.0.113.5"}),
                ("mail-01", {"level": "warn", "hint": "всплеск отправки",
                             "text": "🟠 buh@example.local: 4000 писем за сутки"})]
    alarms = _summary(findings=findings)["alarms"]

    # В тревогу идёт текст находки, а не подпись к ней: «1284 неудачных
    # входов» без имени учётки и адреса читателю ничего не даёт.
    assert alarms == ["подбор пароля: admin ← 203.0.113.5"]


def test_summary_needs_no_second_read_of_the_log():
    """Сводка собирается из уже прочитанных mail и audit: отдельный проход
    означал бы ещё один awk по 25 МБ mail.log на каждый цикл."""
    import inspect

    import zimbra_collector

    source = inspect.getsource(zimbra_collector.collect_server)
    assert "summary_for(mail, audit" in source
    assert source.count("read_mail(") == 1


# ─── Отбитые попытки подделки ────────────────────────────────
#
# Где на сервере настроен антиспуфинг своего домена, письмо с вашим доменом
# в конверте от чужого отправителя отбивается на RCPT и до spoofed_senders
# не доходит вовсе. Наблюдение переезжает на отказы Postfix.

REJECT_REASONS = [
    (["554 5.7.1 Sender address rejected: Access denied"], 128),
    (["450 4.7.1 Client host rejected: cannot find your hostname"], 640),
    (["554 5.7.1 Sender address rejected: not logged in"], 12),
]


def test_sender_rejects_counts_only_its_own_reason():
    """Остальные отказы (грелист, обратный DNS, спам-листы) в счёт не идут:
    их сотни на любом сервере в интернете, и порог по ним бессмыслен."""
    res = zimbra_log.sender_rejects(REJECT_REASONS)

    assert res["messages"] == 140
    assert [r["count"] for r in res["reasons"]] == [128, 12]


def test_sender_rejects_ignores_case():
    """Формулировку задаёт администратор в restriction_class, регистр в ней
    не гарантирован."""
    assert zimbra_log.sender_rejects(
        [(["554 5.7.1 SENDER ADDRESS REJECTED: Access denied"], 3)]
    )["messages"] == 3


def test_sender_rejects_on_empty_input():
    assert zimbra_log.sender_rejects(None) == {"messages": 0, "reasons": []}
    assert zimbra_log.sender_rejects([])["messages"] == 0


def test_reject_finding_appears_above_threshold():
    from zimbra_collector import findings_for

    mail = {"origins": [], "local_domains": ["example.local"], "senders": [],
            "reject_reasons": REJECT_REASONS}
    found = findings_for("mail-01", mail, {}, {})
    keys = [item["key"] for _s, item in found]

    assert keys == ["zm_sender_reject:mail-01"]
    text = found[0][1]["text"]
    assert "140 писем" in text
    assert "Sender address rejected" in text
    # Текст отказа у Postfix стандартный и одинаковый у карты антиспуфинга и
    # у чёрного списка. Пока они неразличимы, объявлять находку подделкой
    # нельзя: тревога обязана называть то, что известно, и оговаривать
    # неоднозначность, а не выдавать догадку за факт.
    assert text.startswith("🟠 отправитель запрещён:")
    assert "чёрный список" in text
    assert "подделка отправителя:" not in text


def test_reject_mark_is_configurable(monkeypatch):
    """Своё сообщение в карте (REJECT Текст) — единственный способ отделить
    антиспуфинг от чёрного списка. Значит подстрока должна настраиваться."""
    monkeypatch.setattr(zimbra_log, "SENDER_REJECT_MARK",
                        "spoofed sender of local domain")
    reasons = [
        (["554 5.7.1 Sender address rejected: Spoofed sender of local domain"], 7),
        (["554 5.7.1 Sender address rejected: Access denied"], 900),
    ]

    assert zimbra_log.sender_rejects(reasons)["messages"] == 7


def test_reject_mark_default_counts_both_maps():
    """Умолчание — текст Postfix по умолчанию, и он один на обе карты.
    Это осознанный предел, а не ошибка счёта."""
    assert zimbra_log.SENDER_REJECT_MARK == "sender address rejected"


def test_reject_finding_key_has_no_number():
    """Иначе каждая новая попытка — новая находка, и алерт повторяется
    при каждом проходе."""
    from zimbra_collector import findings_for

    mail = {"origins": [], "local_domains": [], "senders": [],
            "reject_reasons": [(["554 5.7.1 Sender address rejected"], 900)]}
    found = findings_for("mail-01", mail, {}, {})
    assert found[0][1]["key"] == "zm_sender_reject:mail-01"


def test_ordinary_reject_noise_gives_no_finding():
    """640 отказов по обратному DNS — фон интернета, а не находка."""
    from zimbra_collector import findings_for

    mail = {"origins": [], "local_domains": [], "senders": [],
            "reject_reasons": [REJECT_REASONS[1]]}
    assert findings_for("mail-01", mail, {}, {}) == []


# ─── Служебные входы самого сервера ──────────────────────────

def test_service_login_is_recognised_by_missing_address():
    assert zimbra_log.is_service_login(
        {"account": "zimbra", "ip": "?", "protocol": "soap/admin", "ok": True})
    assert zimbra_log.is_service_login({"account": "zimbra", "ip": ""})
    assert not zimbra_log.is_service_login(
        {"account": "buh@example.local", "ip": "10.20.30.5"})


def test_service_login_is_hidden_from_dashboard_logins():
    """Учётка zimbra с админ-протоколом набирает за сутки больше входов,
    чем любой человек, и занимала первую строку обзора."""
    events = [
        {"account": "zimbra", "ip": "?", "protocol": "soap/admin",
         "ok": True, "count": 18, "last": "2026-09-01 10:00:00"},
        {"account": "buh@example.local", "ip": "198.51.100.7",
         "protocol": "imap", "ok": True, "count": 9,
         "last": "2026-09-01 09:00:00"},
    ]
    summary = _summary(audit={"failed": 0, "events": events})
    logins = [g for g in summary["groups"] if g["title"] == "Кто заходил"]

    assert logins, "раздел входов пропал целиком"
    titles = " ".join(row["title"] for row in logins[0]["rows"])
    assert "zimbra" not in titles
    assert "buh@example.local" in titles


def test_failed_service_login_stays_visible():
    """Вход без адреса, который НЕ удался, — это сломанный служебный
    пароль, а не фоновая служба."""
    events = [{"account": "zimbra", "ip": "?", "protocol": "soap/admin",
               "ok": False, "count": 40, "last": "2026-09-01 10:00:00"}]
    summary = _summary(audit={"failed": 40, "events": events})
    bad = [g for g in summary["groups"] if g["title"] == "Пароль не подошёл"]

    assert bad and "zimbra" in " ".join(r["title"] for r in bad[0]["rows"])


# ─── Длина списков в сводке ──────────────────────────────────

def test_summary_rows_are_shared_by_both_mail_systems():
    """Вкладка одна: списки Zimbra и Exchange обязаны быть одной длины,
    иначе карточки рядом выглядят по-разному без причины."""
    from pathlib import Path

    import mail_store
    import zimbra_collector
    import exchange_collector

    assert zimbra_collector.SUMMARY_ROWS == mail_store.SUMMARY_ROWS
    assert exchange_collector.SUMMARY_ROWS == mail_store.SUMMARY_ROWS
    # Равенство чисел ни о чём не говорит: два «8» разойдутся при первой же
    # правке одного из них. Предел обязан быть ровно один на оба сборщика.
    for module in (zimbra_collector, exchange_collector):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "SUMMARY_ROWS =" not in source, \
            f"{Path(module.__file__).name}: своя длина списков вместо общей"


def test_summary_rows_do_not_exceed_what_the_server_sends():
    """Больше TOP групп с сервера не приезжает — просить у сводки больше
    строк бессмысленно, список всё равно кончится раньше."""
    import mail_store

    assert mail_store.SUMMARY_ROWS <= zimbra_log.TOP


def test_summary_cuts_long_lists(monkeypatch):
    import zimbra_collector

    monkeypatch.setattr(zimbra_collector, "SUMMARY_ROWS", 3)
    senders = [{"sender": f"user{i}@example.local", "messages": 100 - i,
                "recipients": 2} for i in range(10)]
    summary = _summary(mail={"senders": senders})
    rows = [g for g in summary["groups"] if g["title"] == "Кто отправляет"][0]

    assert len(rows["rows"]) == 3


# ─── Обзор входов: только снаружи ────────────────────────────
#
# У организации со своей сетью входы из неё — это весь список: пятнадцать
# строк заняты внутренними адресами, а вход снаружи, ради которого раздел и
# нужен, в обзор не попадает вовсе.

def test_local_login_is_recognised():
    assert zimbra_log.is_local_login({"ip": "10.100.0.66"})
    assert zimbra_log.is_local_login({"ip": "192.168.1.10"})
    assert not zimbra_log.is_local_login({"ip": "95.59.126.130"})
    assert not zimbra_log.is_local_login({"ip": "?"})


def test_dashboard_logins_keep_only_outside():
    events = [
        {"account": "a@example.local", "ip": "10.100.0.66", "protocol": "soap",
         "ok": True, "count": 10, "last": "2026-09-01 10:00:00"},
        {"account": "b@example.local", "ip": "203.0.113.9", "protocol": "imap",
         "ok": True, "count": 2, "last": "2026-09-01 09:00:00"},
    ]
    summary = _summary(audit={"failed": 0, "events": events})
    rows = [g for g in summary["groups"] if g["title"] == "Кто заходил"][0]["rows"]
    titles = " ".join(r["title"] for r in rows)

    assert "b@example.local" in titles
    assert "a@example.local" not in titles


def test_all_local_logins_give_one_honest_line():
    """Пустой раздел молча исчезает, а «снаружи не заходил никто» — это
    ответ, и его видно."""
    events = [
        {"account": "a@example.local", "ip": "10.100.0.66", "protocol": "soap",
         "ok": True, "count": 10, "last": "2026-09-01 10:00:00"},
        {"account": "b@example.local", "ip": "10.100.0.10", "protocol": "soap",
         "ok": True, "count": 5, "last": "2026-09-01 09:00:00"},
    ]
    summary = _summary(audit={"failed": 0, "events": events})
    rows = [g for g in summary["groups"] if g["title"] == "Кто заходил"][0]["rows"]

    assert len(rows) == 1
    assert rows[0]["left"] == "15"          # входы сосчитаны, а не отброшены
    assert "локальной сети" in rows[0]["title"]


def test_failed_local_login_stays_visible():
    """Отказы фильтру не подлежат: подбор пароля из своей же сети — это
    заражённая машина внутри периметра, худший случай из возможных."""
    events = [{"account": "a@example.local", "ip": "10.100.0.66",
               "protocol": "soap", "ok": False, "count": 400,
               "last": "2026-09-01 10:00:00"}]
    summary = _summary(audit={"failed": 400, "events": events})
    bad = [g for g in summary["groups"] if g["title"] == "Пароль не подошёл"]

    assert bad and "a@example.local" in " ".join(r["title"] for r in bad[0]["rows"])


# ─── Обзор отправителей: без служебных ───────────────────────

def test_service_senders_are_recognised():
    assert zimbra_log.is_service_sender("<>")
    assert zimbra_log.is_service_sender("MAILER-DAEMON@mail.example.local")
    assert zimbra_log.is_service_sender("double-bounce@example.local")
    assert zimbra_log.is_service_sender("")
    assert not zimbra_log.is_service_sender("buh@example.local")


def test_dashboard_senders_drop_the_null_envelope():
    """`<>` — отчёты о недоставке, они стабильно входили в топ и занимали
    место живого отправителя."""
    senders = [
        {"sender": "<>", "messages": 21, "recipients": 22},
        {"sender": "buh@example.local", "messages": 19, "recipients": 19},
    ]
    summary = _summary(mail={"senders": senders})
    rows = [g for g in summary["groups"] if g["title"] == "Кто отправляет"][0]["rows"]

    assert [r["title"] for r in rows] == ["buh@example.local"]


def test_sender_row_says_what_the_number_means():
    """«107» слева — это писем или адресов? Подпись обязана быть."""
    senders = [{"sender": "buh@example.local", "messages": 107,
                "recipients": 136}]
    summary = _summary(mail={"senders": senders})
    row = [g for g in summary["groups"]
           if g["title"] == "Кто отправляет"][0]["rows"][0]

    assert row["left"] == "107"
    assert row["detail"] == "писем · на 136 адресов"


def test_address_count_is_declined():
    """«на 22 адресов» — та же недоделка, что и «1 писем»."""
    assert zimbra_log.addresses(1) == "1 адрес"
    assert zimbra_log.addresses(22) == "22 адреса"
    assert zimbra_log.addresses(13) == "13 адресов"
    assert zimbra_log.addresses(103) == "103 адреса"
    assert zimbra_log.addresses(0) == "0 адресов"


# ─── Свои отправители и чужие рассылки ───────────────────────
#
# Postfix считает всех, кто прошёл через сервер. В одном списке оказывались
# сотрудники и уведомления банков, налоговой и досок вакансий — и всплеск
# отправки у своей учётки терялся среди чужих рассылок.

SPLIT_SENDERS = [
    {"sender": "buh@example.local", "messages": 40, "recipients": 12},
    {"sender": "report@bank.invalid", "messages": 107, "recipients": 136},
]
SPLIT_ORIGINS = [
    # письмо родилось на самом сервере — сотрудник писал через веб
    (["buh@example.local", "127.0.0.1", "0"], 40),
    # чужая рассылка: публичный адрес, входа в почту не было
    (["report@bank.invalid", "203.0.113.9", "0"], 107),
]


def test_own_senders_and_incoming_are_separate_lists():
    summary = _summary(mail={"senders": SPLIT_SENDERS,
                             "origins": SPLIT_ORIGINS})
    titles = {g["title"]: [r["title"] for r in g["rows"]]
              for g in summary["groups"]}

    assert titles["Кто отправляет"] == ["buh@example.local"]
    assert titles["Кто пишет вам"] == ["report@bank.invalid"]


def test_spoofed_own_address_is_not_counted_as_ours():
    """Свой домен в конверте подделывается свободно. Делить только по адресу
    значило бы записывать спам в собственные отправители."""
    senders = [{"sender": "director@example.local", "messages": 9,
                "recipients": 9}]
    origins = [(["director@example.local", "203.0.113.9", "0"], 9)]
    summary = _summary(mail={"senders": senders, "origins": origins})
    titles = {g["title"]: [r["title"] for r in g["rows"]]
              for g in summary["groups"]}

    assert "Кто отправляет" not in titles
    assert titles["Кто пишет вам"] == ["director@example.local"]


def test_sender_without_origin_falls_back_to_domain():
    """Строка сдачи могла не попасть в окно разбора. Терять отправителя из
    обоих списков хуже, чем решить по адресу."""
    res = zimbra_log.split_senders(
        [{"sender": "buh@example.local", "messages": 3, "recipients": 3}],
        [], ["example.local"])

    assert [i["sender"] for i in res["own"]] == ["buh@example.local"]
    assert res["incoming"] == []


def test_inside_submission_counts_as_ours():
    """Сдача по паролю с внутреннего узла — это тоже свой отправитель,
    а не входящее письмо."""
    res = zimbra_log.split_senders(
        [{"sender": "app@example.local", "messages": 5, "recipients": 5}],
        [(["app@example.local", "10.100.0.10", "1"], 5)], ["example.local"])

    assert [i["sender"] for i in res["own"]] == ["app@example.local"]


# ─── Маршрутизатор — не рабочее место ────────────────────────
#
# Zimbra пишет адрес соединения. Если пользователи ходят через
# маршрутизатор, все приходят с его адреса: внешний сотрудник неотличим от
# сидящего в соседней комнате. Прятать такие входы как «локальные» —
# прятать ровно то, ради чего раздел существует.

GATEWAY_EVENTS = [
    {"account": "a@example.local", "ip": "10.100.0.10", "protocol": "soap",
     "ok": True, "count": 10, "last": "2026-09-01 10:00:00"},
    {"account": "b@example.local", "ip": "10.100.0.10", "protocol": "soap",
     "ok": True, "count": 9, "last": "2026-09-01 10:00:00"},
    {"account": "c@example.local", "ip": "10.100.0.10", "protocol": "soap",
     "ok": True, "count": 6, "last": "2026-09-01 10:00:00"},
    {"account": "d@example.local", "ip": "10.100.210.41", "protocol": "soap",
     "ok": True, "count": 4, "last": "2026-09-01 10:00:00"},
]


def test_gateway_is_recognised_by_number_of_accounts():
    """За рабочим местом один человек, за шлюзом — вся сеть."""
    assert zimbra_log.shared_gateways(GATEWAY_EVENTS) == {"10.100.0.10"}


def test_public_address_is_never_a_gateway():
    """Внешний адрес и так показывается: записывать его в шлюзы незачем,
    а страну по нему видно."""
    events = [dict(e, ip="203.0.113.9") for e in GATEWAY_EVENTS]
    assert zimbra_log.shared_gateways(events) == set()


def test_login_through_gateway_stays_visible():
    summary = _summary(audit={"failed": 0, "events": GATEWAY_EVENTS})
    rows = [g for g in summary["groups"] if g["title"] == "Кто заходил"][0]["rows"]
    titles = " ".join(r["title"] for r in rows)

    # трое из-за шлюза видны, рабочее место скрыто
    assert "a@example.local" in titles and "c@example.local" in titles
    assert "d@example.local" not in titles


def test_gateway_row_says_the_address_is_not_the_client():
    """Иначе строку читают как «вход изнутри, всё в порядке» — а это
    может быть кто угодно из интернета."""
    summary = _summary(audit={"failed": 0, "events": GATEWAY_EVENTS})
    rows = [g for g in summary["groups"] if g["title"] == "Кто заходил"][0]["rows"]

    assert all("адрес клиента не виден" in r["detail"] for r in rows)
    # и никакого «локальная сеть» рядом со шлюзом
    assert all("локальная сеть" not in r["title"] for r in rows)


def test_no_claim_about_outside_when_only_workstations():
    """Раньше здесь стояло «снаружи не заходил никто». При NAT это ложь, а
    без NAT — утверждение о том, чего в логе нет."""
    events = [{"account": "d@example.local", "ip": "10.100.210.41",
               "protocol": "soap", "ok": True, "count": 4, "last": ""}]
    summary = _summary(audit={"failed": 0, "events": events})
    row = [g for g in summary["groups"]
           if g["title"] == "Кто заходил"][0]["rows"][0]

    assert "снаружи не заходил никто" not in row["detail"]
    assert row["left"] == "4"


# ─── Чем именно ломятся ──────────────────────────────────────
#
# protocol= в audit.log почти всегда soap: mailboxd проверяет пароль своим
# внутренним SOAP, кто бы ни спрашивал. Настоящий протокол клиента лежит в
# oproto=, и без него перебор паролей к ящикам через SMTP выглядел попыткой
# влезть в админ-консоль — тревога называла не то, что происходит.

def test_smtp_bruteforce_is_not_called_admin_console():
    from zimbra_collector import findings_for

    events = [{"account": "user@example.local", "ip": "203.0.113.5",
               "protocol": "smtp", "ok": False, "count": 300,
               "last": "2026-09-01 05:48:44"}]
    found = findings_for("mail-01", {}, {"events": events}, {})
    text = found[0][1]["text"]

    assert "админ-консоли" not in text
    assert "по smtp" in text


def test_admin_console_bruteforce_still_says_so():
    from zimbra_collector import findings_for

    events = [{"account": "root@example.local", "ip": "203.0.113.77",
               "protocol": "soap/admin", "ok": False, "count": 300,
               "last": "2026-09-01 09:10:00"}]
    found = findings_for("mail-01", {}, {"events": events}, {})
    text = found[0][1]["text"]

    assert "к админ-консоли" in text
    # протокол в тексте не дублируется: «к админ-консоли по soap/admin»
    assert "по soap" not in text


def test_admin_flag_needs_port_7071():
    """Путь /service/admin/ общий у админки и у проверки пароля SMTP —
    отличает их только порт."""
    assert ":7071/service/admin/" in zimbra_log._AUDIT_AWK


# ─── Распылённый перебор ─────────────────────────────────────
#
# Настоящий лог с боевого: одна учётка, шесть стран, по одной-две попытки
# с каждого адреса. Порог «50 неудач с одного адреса» такой перебор не
# берёт никогда — именно так его и обходят.

SPRAY_EVENTS = [
    {"account": "admin@example.local", "ip": "203.0.113.5", "protocol": "smtp",
     "ok": False, "count": 1, "last": "2026-09-01 05:48:44"},
    {"account": "admin@example.local", "ip": "203.0.113.9", "protocol": "smtp",
     "ok": False, "count": 2, "last": "2026-09-01 05:50:08"},
    {"account": "admin@example.local", "ip": "198.51.100.7", "protocol": "smtp",
     "ok": False, "count": 1, "last": "2026-09-01 06:01:00"},
    {"account": "buh@example.local", "ip": "198.51.100.20", "protocol": "imap",
     "ok": False, "count": 2, "last": "2026-09-01 06:10:00"},
]


def test_spray_needs_several_addresses():
    found = zimbra_log.spray_targets(SPRAY_EVENTS)

    assert [i["account"] for i in found] == ["admin@example.local"]
    assert found[0]["count"] == 4          # попытки суммируются по адресам
    assert len(found[0]["addresses"]) == 3


def test_single_address_is_not_spray():
    """Одиночный адрес — это забытый пароль либо работа brute_force,
    у которого свой порог."""
    events = [{"account": "buh@example.local", "ip": "198.51.100.7",
               "protocol": "imap", "ok": False, "count": 40, "last": ""}]
    assert zimbra_log.spray_targets(events) == []


def test_spray_does_not_repeat_what_brute_force_said():
    found = zimbra_log.spray_targets(SPRAY_EVENTS,
                                     skip=["admin@example.local"])
    assert found == []


def test_spray_turns_red_when_a_login_succeeded():
    """Удачный вход с одного из тех же адресов означает, что пароль уже
    подобран, а не что его подбирают."""
    events = SPRAY_EVENTS + [
        {"account": "admin@example.local", "ip": "203.0.113.9",
         "protocol": "imap", "ok": True, "count": 1, "last": ""}]
    found = zimbra_log.spray_targets(events)

    assert found[0]["guessed"] is True


def test_spray_finding_reaches_alerts():
    from zimbra_collector import findings_for

    found = findings_for("mail-01", {}, {"events": SPRAY_EVENTS}, {})
    spray = [item for _s, item in found if item["key"].startswith("zm_spray:")]

    assert len(spray) == 1
    assert spray[0]["level"] == "warn"
    assert "3 адреса" in spray[0]["text"]
    assert "4 попытки" in spray[0]["text"]
    assert "по smtp" in spray[0]["text"]


def test_spray_finding_key_has_no_number():
    from zimbra_collector import findings_for

    found = findings_for("mail-01", {}, {"events": SPRAY_EVENTS}, {})
    keys = [item["key"] for _s, item in found]

    assert keys == ["zm_spray:mail-01:admin@example.local"]


def test_attempts_are_declined():
    assert zimbra_log.attempts(1) == "1 попытка"
    assert zimbra_log.attempts(3) == "3 попытки"
    assert zimbra_log.attempts(11) == "11 попыток"
    assert zimbra_log.attempts(52) == "52 попытки"
