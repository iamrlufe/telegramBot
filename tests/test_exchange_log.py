"""Тесты раздела почты Exchange (shared/exchange_log.py, bot/exchange_bot.py).

Ключевое, что здесь закреплено: успешные входы читаются из логов IIS, а
неудачные — из журнала Security, потому что при форменной аутентификации
IIS не знает имени пользователя. Плюс агрегация на сервере: на живом
Exchange логи в сутки — сотни мегабайт.
"""
import base64
import json

import pytest

import exchange_log
import exchange_bot

SERVER = {"name": "mail-01.example.local", "host": "192.0.2.12",
          "username": "svc", "password": "x",
          "services": ["MSExchangeIS", "MSExchangeTransport", "W3SVC"]}


def _fake_ps(monkeypatch, payload, target=exchange_log):
    scripts = []

    def run_ps(host, script, username=None, password=None, **kwargs):
        scripts.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(target, "run_ps", run_ps)
    return scripts


# ─── Признак почтового сервера ───────────────────────────────

def test_button_shown_for_exchange_services():
    """Отдельного флага нет: признак — служба MSExchange*, как у nginx/docker."""
    assert exchange_bot.has_exchange(SERVER)


def test_button_hidden_without_exchange_services():
    assert not exchange_bot.has_exchange({"services": ["W3SVC", "MSSQLSERVER"]})
    assert not exchange_bot.has_exchange({})


def test_button_hidden_for_non_windows():
    assert not exchange_bot.has_exchange(
        {"type": "linux", "services": ["MSExchangeIS"]})


def test_service_name_case_insensitive():
    assert exchange_bot.has_exchange({"services": ["msexchangeis"]})


# ─── Чтение логов IIS ────────────────────────────────────────

def test_log_directory_taken_from_iis_config(monkeypatch):
    """Каталог логов настраивается — угадывать его нельзя."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    assert "WebAdministration" in scripts[0]
    assert "logFile.directory" in scripts[0]


def test_fields_parsed_by_name_not_position(monkeypatch):
    """Набор колонок в логе IIS настраивается: позиции дадут чужие значения."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    assert "#Fields:" in scripts[0]
    assert "$map[$names[$i]] = $i" in scripts[0]


def test_aggregation_happens_on_server(monkeypatch):
    """Сотни мегабайт логов не должны ехать в контейнер построчно."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    assert "$agg" in scripts[0] and "Sort-Object" in scripts[0]
    assert "Select-Object -First" in scripts[0]


def test_owa_and_activesync_use_different_paths(monkeypatch):
    owa = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)
    eas_scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_activesync(SERVER)
    assert "/owa/" in owa[0]
    assert "activesync" in eas_scripts[0].lower()


def test_missing_log_directory_reported(monkeypatch):
    """Отсутствие каталога — понятная ошибка, а не пустой список."""
    _fake_ps(monkeypatch, {"iis_error": "Каталог логов IIS не найден: C:\\x"})
    with pytest.raises(Exception, match="не найден"):
        exchange_log.read_owa_logins(SERVER)


def test_single_row_normalized(monkeypatch):
    """PowerShell сворачивает список из одного элемента в сам элемент."""
    _fake_ps(monkeypatch, {"rows": {"user": "ivanov", "ip": "192.0.2.55",
                                    "ua": "Chrome", "count": 3,
                                    "last": "2026-08-27 09:14:22"},
                           "scanned": 3})
    data = exchange_log.read_owa_logins(SERVER)
    assert isinstance(data["rows"], list) and len(data["rows"]) == 1


# ─── Неудачные входы: журнал Security ────────────────────────

def test_failures_read_from_security_not_iis(monkeypatch):
    """При форменной аутентификации IIS не знает имени: cs-username пуст."""
    import winlog
    scripts = _fake_ps(monkeypatch, [], target=winlog)
    exchange_log.read_owa_failures(SERVER)
    assert "LogName='Security'" in scripts[0]
    assert "Id=4625" in scripts[0]


def test_failures_filtered_to_web_logons(monkeypatch):
    """Вход по RDP не должен попадать в раздел почты."""
    import winlog
    _fake_ps(monkeypatch, [
        {"d": "2026-08-27 09:00:00", "user": "ivanov", "ip": "192.0.2.55",
         "ltype": "8", "proc": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
         "status": "0xC000006A", "status2": ""},
        {"d": "2026-08-27 09:05:00", "user": "petrov", "ip": "192.0.2.60",
         "ltype": "10", "proc": "C:\\Windows\\System32\\svchost.exe",
         "status": "0xC000006A", "status2": ""},
    ], target=winlog)
    rows = exchange_log.read_owa_failures(SERVER)
    assert len(rows) == 1 and rows[0]["user"] == "ivanov"


def test_failures_grouped_and_explained(monkeypatch):
    import winlog
    _fake_ps(monkeypatch, [
        {"d": f"2026-08-27 09:0{n}:00", "user": "ivanov", "ip": "192.0.2.55",
         "ltype": "8", "proc": "c:\\windows\\system32\\inetsrv\\w3wp.exe",
         "status": "0xC000006A", "status2": ""} for n in range(4)
    ], target=winlog)
    rows = exchange_log.read_owa_failures(SERVER)
    assert rows[0]["count"] == 4
    assert rows[0]["reason"] == "неверный пароль"


# ─── Вывод ───────────────────────────────────────────────────

def _render(result):
    return exchange_bot.render(*result, page=0)[0]


def test_owa_output_shows_user_ip_and_client():
    text = _render(exchange_bot.format_owa({"rows": [
        {"user": "ivanov", "ip": "192.0.2.55", "count": 12,
         "last": "2026-08-27 09:14:22",
         "ua": "Mozilla/5.0+(Windows+NT+10.0)+Chrome/128.0"}], "scanned": 12}, 24))
    assert "ivanov" in text and "192.0.2.55" in text
    assert "Chrome" in text and "Mozilla" not in text


def test_client_name_recognizes_phones():
    assert exchange_bot._client_name("Apple-iPhone14C2/2011.300") == "iPhone"
    assert exchange_bot._client_name("Android/12.0.0-EAS-2.0") == "Android"


def test_client_name_survives_unknown_agent():
    assert exchange_bot._client_name("") == "неизвестный клиент"


def test_empty_owa_points_at_iis_logging():
    """Пустой раздел чаще всего значит выключённые логи IIS."""
    text = _render(exchange_bot.format_owa({"rows": [], "scanned": 0}, 24))
    assert "журналов IIS" in text


def test_empty_failures_point_at_audit():
    text = _render(exchange_bot.format_failures([], 24))
    assert "4625" in text and "аудит" in text.lower()


def test_failures_output_notes_protocol_ambiguity():
    """OWA, ActiveSync и EWS в Security неразличимы — это надо сказать."""
    text = _render(exchange_bot.format_failures([{
        "user": "ivanov", "ip": "192.0.2.55", "code": "0xC000006A",
        "reason": "неверный пароль", "count": 5,
        "last": "2026-08-27 09:00:00"}], 24))
    assert "ActiveSync" in text and "неразличимы" in text


def test_token_cache_is_bounded():
    for _ in range(exchange_bot.EX_TOKENS_MAX + 50):
        exchange_bot.ex_token("mail-01.example.local", 24)
    assert len(exchange_bot.EX_TOKENS) <= exchange_bot.EX_TOKENS_MAX


def test_iis_script_fits_winrm_limit(monkeypatch):
    """Скрипт агрегации длинный — если не влезет, раздел мёртв целиком."""
    from winrm_client import MAX_PS_COMMAND_CHARS, compact_ps
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER, hours=168)
    encoded = len(base64.b64encode(compact_ps(scripts[0]).encode("utf_16_le")))
    assert encoded < MAX_PS_COMMAND_CHARS, f"{encoded} из {MAX_PS_COMMAND_CHARS}"


def test_help_section_explains_two_sources():
    """Разные источники для успехов и отказов — не очевидно, надо объяснить."""
    from config_editor import HELP_SECTIONS
    text = HELP_SECTIONS["exchange"][1]
    assert "IIS" in text and "4625" in text


# ─── Постраничный вывод ──────────────────────────────────────

def _many_rows(n):
    return {"rows": [{"user": f"user{i}@example.local", "ip": f"192.0.2.{i}",
                      "count": 100 - i, "last": "2026-08-27 09:00:00",
                      "ua": "Chrome/128"} for i in range(n)], "scanned": 5000}


def test_long_list_is_paginated():
    """Раньше остаток обрывался фразой «… ещё 25» и был недоступен."""
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    assert len(blocks) == 40
    text, page, total = exchange_bot.render(header, blocks, 0)
    assert total == 3, "40 записей по 15 на страницу — три страницы"
    assert "Показано 1–15 из 40" in text
    assert "… ещё" not in text


def test_second_page_shows_next_records():
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    text, page, total = exchange_bot.render(header, blocks, 1)
    assert "user15@example.local" in text
    assert "user0@example.local" not in text
    assert "Показано 16–30 из 40" in text


def test_last_page_is_partial():
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    text, page, total = exchange_bot.render(header, blocks, 2)
    assert "Показано 31–40 из 40" in text


def test_page_number_clamped():
    """Кнопка из старого сообщения может указывать на исчезнувшую страницу."""
    header, blocks = exchange_bot.format_owa(_many_rows(40), 24)
    _, page, total = exchange_bot.render(header, blocks, 99)
    assert page == total - 1


def test_short_list_has_no_pagination_line():
    header, blocks = exchange_bot.format_owa(_many_rows(5), 24)
    text, _, total = exchange_bot.render(header, blocks, 0)
    assert total == 1 and "Показано" not in text


def test_nav_buttons_only_when_needed():
    from tg_utils import nav_row
    assert nav_row("exlog_page:r1:", 0, 1) == []
    row = nav_row("exlog_page:r1:", 1, 3)
    assert len(row) == 3, "назад, счётчик, вперёд"


def test_result_cache_is_bounded():
    """Кэш сводок не должен расти бесконечно в долгоживущем процессе."""
    for n in range(exchange_bot.EX_RESULTS_MAX + 30):
        exchange_bot.result_token("mail-01.example.local", 24, "owa",
                                  [f"b{n}"], "h")
    assert len(exchange_bot.EX_RESULTS) <= exchange_bot.EX_RESULTS_MAX


def test_paginate_helper_boundaries():
    from tg_utils import paginate
    chunk, page, total = paginate(list(range(10)), 0, 4)
    assert chunk == [0, 1, 2, 3] and total == 3
    chunk, page, total = paginate(list(range(10)), 2, 4)
    assert chunk == [8, 9] and page == 2
    chunk, page, total = paginate([], 0, 4)
    assert chunk == [] and total == 1


# ─── Чтение занятого файла ───────────────────────────────────

def test_current_day_log_opened_with_shared_access(monkeypatch):
    """Текущие сутки IIS держит открытыми: монопольный ReadLines падает с
    «файл используется другим процессом», а при SilentlyContinue — падает
    молча, и раздел показывал пустоту вместо сегодняшних сеансов."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)

    assert "ReadLines" not in scripts[0]
    assert "'Open', 'Read', 'ReadWrite'" in scripts[0]
    assert "StreamReader" in scripts[0]


def test_unreadable_file_is_reported_not_swallowed(monkeypatch):
    """Файл, который всё же не открылся, попадает в $failed — неполная
    выборка обязана быть названа."""
    scripts = _fake_ps(monkeypatch, {"rows": [], "scanned": 0})
    exchange_log.read_owa_logins(SERVER)

    assert "$failed" in scripts[0]
    assert "failed = $failed" in scripts[0]


def test_incomplete_read_is_visible_in_the_card():
    """Пользователь должен видеть, что выборка неполная, а не гадать."""
    data = {"rows": [{"user": "petrov", "ip": "192.0.2.30", "ua": "1CV8C",
                      "count": 3, "last": "2026-09-01 08:00:00"}],
            "scanned": 3, "failed": ["u_ex260901.log"]}

    header, _blocks = exchange_bot.format_owa(data, 24)

    assert "не удалось прочитать" in header.lower()


def test_complete_read_says_nothing_extra():
    data = {"rows": [{"user": "petrov", "ip": "192.0.2.30", "ua": "1CV8C",
                      "count": 3, "last": "2026-09-01 08:00:00"}],
            "scanned": 3, "failed": []}

    header, _blocks = exchange_bot.format_owa(data, 24)

    assert "не удалось" not in header.lower()


# ─── Сводка для дашборда ─────────────────────────────────────

def _ex_summary(**over):
    from exchange_collector import summary_for

    owa = {"scanned": 18422, "rows": [
        {"user": "buh", "ip": "10.20.30.5", "count": 900,
         "last": "2026-09-01 09:00:00"},
        {"user": "buh", "ip": "203.0.113.5", "count": 12,
         "last": "2026-09-01 03:00:00"}]}
    eas = {"rows": [{"user": "buh", "ua": "Apple-iPhone14C1/2000.1", "count": 420}]}
    failures = [{"user": "admin", "ip": "203.0.113.5", "count": 240,
                 "code": "0xC000006A", "reason": "неверный пароль",
                 "last": "2026-09-01 04:00:00"}]
    owa.update(over.pop("owa", {}))
    return summary_for(owa, over.pop("eas", eas), over.pop("failures", failures),
                       over.pop("geo", {}), over.pop("track", None))


def test_summary_shape_matches_zimbra():
    """Обе почты приезжают в дашборд в одной форме — иначе вторая почтовая
    система означала бы вторую ветку в отрисовке."""
    summary = _ex_summary()

    assert {"kpis", "groups", "alarms", "suspects"} == set(summary)
    assert all({"value", "label", "level"} <= set(k) for k in summary["kpis"])
    for group in summary["groups"]:
        assert {"title", "level", "rows"} <= set(group)
        assert all({"level", "left", "title"} <= set(r) for r in group["rows"])


def test_users_counted_not_log_rows():
    """Один пользователь с двух адресов — это один пользователь. Строк в
    логе IIS у него десятки тысяч, и считать их как людей нельзя."""
    summary = _ex_summary()

    assert [k["value"] for k in summary["kpis"] if k["label"] == "пользователей"] == [1]


def test_persistent_failures_raise_an_alarm():
    """Человек ошибается паролем несколько раз и идёт к администратору.
    240 попыток с одного адреса — это не забытый пароль."""
    hot = _ex_summary()
    calm = _ex_summary(failures=[{"user": "buh", "ip": "10.20.30.5", "count": 3,
                                  "code": "0xC000006A", "reason": "неверный пароль"}])

    assert hot["alarms"] == ["подбор пароля с 203.0.113.5"]
    assert calm["alarms"] == []
    assert [k["level"] for k in hot["kpis"] if k["label"] == "неверных паролей"] == ["crit"]
    assert [k["level"] for k in calm["kpis"] if k["label"] == "неверных паролей"] == ["warn"]


def test_failures_go_first():
    """Порядок разделов задан вопросом, ради которого сюда заходят."""
    assert _ex_summary()["groups"][0]["title"] == "Пароль не подошёл"


def test_quiet_server_gives_no_alarms_and_no_empty_groups():
    summary = _ex_summary(failures=[], eas={"rows": []})

    assert summary["alarms"] == []
    assert [g["title"] for g in summary["groups"]] == ["Кто работает в OWA"]


# ─── Пробы Managed Availability ──────────────────────────────
#
# HealthMailbox-* создаёт сама Exchange и раз в минуту дёргает ими каждый
# протокол. На боевом сервере эти ящики занимали треть списка телефонов и
# давали больше обращений, чем живые пользователи.

def test_health_mailbox_is_recognised():
    import exchange_log

    assert exchange_log.is_service_client("HealthMailboxe48a406@corp.example.local")
    assert exchange_log.is_service_client("SystemMailbox{bb558c35}@example.local")
    assert exchange_log.is_service_client(agent="AMProbe/Local/ClientAccess")
    assert exchange_log.is_service_client(agent="TestActiveSyncConnectivity")
    assert not exchange_log.is_service_client("buh@example.local",
                                              "Apple-iPhone14C1/2000.1")


def test_probes_are_hidden_from_dashboard_lists():
    summary = _ex_summary(
        owa={"rows": [
            {"user": "HealthMailbox1@corp.example.local", "ip": "10.20.30.5",
             "count": 5000, "last": ""},
            {"user": "buh@example.local", "ip": "10.20.30.6", "count": 10,
             "last": ""}]},
        eas={"rows": [
            {"user": "HealthMailbox2@corp.example.local",
             "ua": "AMProbe/Local/ClientAccess", "count": 489},
            {"user": "zh@example.local", "ua": "Apple-iPhone14C5/2307.71",
             "count": 538}]})

    lists = {g["title"]: [r["title"] for r in g["rows"]]
             for g in summary["groups"]}

    assert not any("HealthMailbox" in t for t in lists["Кто работает в OWA"])
    assert not any("HealthMailbox" in t for t in lists["Телефоны (ActiveSync)"])
    assert any("buh@example.local" in t for t in lists["Кто работает в OWA"])
    assert lists["Телефоны (ActiveSync)"] == ["zh@example.local"]


# ─── Поток писем из трассировки ──────────────────────────────
#
# До этого про Exchange было известно только то, что видно в логах IIS:
# кто заходил в OWA и с какого телефона. Писем там нет вовсе, поэтому
# карточка выглядела втрое беднее Zimbra.

TRACK = {
    "messages_in": 4210, "messages_out": 812, "recipients": 5300,
    "failed": 17, "queue": 5, "poison": 0,
    "senders_out": [{"sender": "buh@example.local", "messages": 300,
                     "recipients": 640},
                    {"sender": "hr@example.local", "messages": 12,
                     "recipients": 12}],
    "senders_in": [{"sender": "news@bank.invalid", "messages": 107,
                    "recipients": 136}],
    "fail_reasons": [{"reason": "550 5.1.1 User unknown", "count": 12}],
    "sources": [{"ip": "203.0.113.9", "count": 90}],
}


def test_mail_flow_appears_in_kpis():
    summary = _ex_summary(track=TRACK)
    labels = {k["label"]: k["value"] for k in summary["kpis"]}

    assert labels["писем принято"] == 4210
    assert labels["отправлено"] == 812
    assert labels["в очереди"] == 5


def test_senders_are_split_like_zimbra():
    summary = _ex_summary(track=TRACK)
    titles = {g["title"]: [r["title"] for r in g["rows"]]
              for g in summary["groups"]}

    assert titles["Кто отправляет"] == ["buh@example.local", "hr@example.local"]
    assert titles["Кто пишет вам"] == ["news@bank.invalid"]
    assert titles["Не доставлено"] == ["550 5.1.1 User unknown"]


def test_sender_row_says_what_the_number_means():
    rows = [g for g in _ex_summary(track=TRACK)["groups"]
            if g["title"] == "Кто отправляет"][0]["rows"]

    assert rows[0]["left"] == "300"
    assert rows[0]["detail"] == "писем · на 640 адресов"


def test_heavy_sender_is_marked():
    """Всплеск отправки у своей учётки — первый признак того, что ею
    начали рассылать спам."""
    import exchange_collector

    track = dict(TRACK, senders_out=[
        {"sender": "buh@example.local",
         "messages": exchange_collector.SEND_ALERT + 1, "recipients": 9000}])
    rows = [g for g in _ex_summary(track=track)["groups"]
            if g["title"] == "Кто отправляет"][0]["rows"]

    assert rows[0]["level"] == "warn"


def test_queue_and_poison_reach_alarms():
    import exchange_collector

    summary = _ex_summary(track=dict(
        TRACK, queue=exchange_collector.QUEUE_ALERT + 1, poison=3))

    assert any("poison" in a for a in summary["alarms"])
    assert any("очередь" in a for a in summary["alarms"])


def test_unknown_queue_is_not_reported_as_empty():
    """Счётчики могли не сняться. «Очередь пуста» в этом случае означало бы
    обратное тому, что произошло."""
    summary = _ex_summary(track=dict(TRACK, queue=None))
    labels = {k["label"]: k["value"] for k in summary["kpis"]}

    assert labels["в очереди"] == "?"
    assert not any("очередь" in a for a in summary["alarms"])


def test_old_kpis_stay_when_tracking_is_unavailable():
    """Нет прав на каталог трассировки или снимок старый — карточка
    остаётся прежней, а не показывает нули вместо писем."""
    labels = {k["label"] for k in _ex_summary()["kpis"]}

    assert "обращений в OWA" in labels
    assert "писем принято" not in labels


def test_tracking_script_fits_winrm_limit():
    """Первая версия скрипта не влезла в командную строку WinRM (9476 из
    8000 после кодирования), и раздел молча остался без данных. Проверка
    здесь дешевле, чем ещё один такой заход на боевой сервер."""
    from winrm_client import MAX_PS_COMMAND_CHARS, ps_encoded_length
    import exchange_track

    encoded = ps_encoded_length(exchange_track._script(24))
    assert encoded <= MAX_PS_COMMAND_CHARS, f"{encoded} из {MAX_PS_COMMAND_CHARS}"


def test_tracking_script_has_no_comments_or_indentation():
    """Пояснения живут в Python-докстроке: в PowerShell они стоят места в
    той же командной строке, в которую скрипт и не влез."""
    import exchange_track

    lines = exchange_track._script(24).splitlines()
    assert not any(line.startswith((" ", "\t")) for line in lines)
    assert not any(line.lstrip().startswith("#") for line in lines
                   if "Fields" not in line)


def test_tracking_script_reads_fields_by_name():
    """Схема лога трассировки менялась между версиями Exchange: разбор по
    позициям молча дал бы чужие значения."""
    import exchange_track

    script = exchange_track._script(24)
    assert "#Fields:" in script
    assert "ConvertFrom-Csv -Header $c" in script


def test_tracking_script_counts_messages_not_lines():
    """Одно письмо проходит транспорт несколькими событиями (RECEIVE,
    RESOLVE, AGENTINFO, SEND, DELIVER). Счёт строк завысил бы объём в
    несколько раз — та же ошибка, что и со строками mail.log у Zimbra."""
    import exchange_track

    script = exchange_track._script(24)
    assert "$seen.ContainsKey($id)" in script
    assert "$e -ne 'RECEIVE'" in script


def test_tracking_script_trusts_exchange_about_direction():
    """directionality проставляет сама Exchange, зная свои домены. Это
    надёжнее разбора адреса: подделанный свой адрес в конверте туда не
    пролезет."""
    import exchange_track

    assert "$r.directionality -eq 'Originating'" in exchange_track._script(24)


def test_tracking_parser_keeps_unknown_queue_as_none():
    import exchange_track

    assert exchange_track._rows(None) == []
    assert exchange_track._rows({"a": 1}) == [{"a": 1}]
    assert exchange_track._rows([{"a": 1}, {"b": 2}]) == [{"a": 1}, {"b": 2}]
