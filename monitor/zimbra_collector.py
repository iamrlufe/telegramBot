"""
monitor/zimbra_collector.py

Фоновый разбор почтовых журналов Zimbra и находки для алертов.

Раздел в карточке читает логи по нажатию — тут же они читаются по
расписанию, чтобы угнанную учётку было видно ночью, а не утром.

Будят три вещи и только они:

* удачный вход не из домашней страны — пароль уже знают;
* подбор пароля: неудачные попытки с одного адреса на одну учётку;
* письма своей учётки сданы с белого адреса — здесь все пишут через веб,
  а несколько служебных учёток сдают почту напрямую с внутренних узлов;
  отправка снаружи не описывается ни тем, ни другим.

Объём отправки, очередь и отбитые на входе — фон. Отбитых на живом сервере
тысячи в сутки, и это признак того, что защита работает, а не тревога.
"""
import time
from concurrent.futures import ThreadPoolExecutor

from alerts import check_zimbra_alerts
from geoip import resolve as geo_resolve
from mail_store import SUMMARY_ROWS, save_snapshot
from settings import int_env
from zimbra_log import (
    QUEUE_ALERT, SENDER_REJECT_ALERT, SPOOF_ALERT,
    _origin_rows, addresses, brute_force, foreign_logins, is_local_login,
    is_service_login, is_service_sender, sender_rejects, shared_gateways,
    split_senders, spray_targets, attempts,
    has_zimbra, heavy_senders, letters, outside_senders, read_audit,
    read_mail,
    spoofed_senders,
)


def _int_env(name: str, default: int) -> int:
    """settings.int_env с префиксом этого модуля в логе о некорректном значении."""
    return int_env(name, default, tag="zimbra")


ZIMBRA_SCAN_MINUTES = _int_env("ZIMBRA_SCAN_MINUTES", 30)
MAX_PARALLEL_ZIMBRA_SERVERS = _int_env("MAX_PARALLEL_ZIMBRA_SERVERS", 2)

# Окно разбора. Сутки, а не полчаса: подбор пароля идёт размеренно, по
# несколько попыток в час, и в получасовом окне он не виден вовсе.
WINDOW_HOURS = 24

_last_scan = None


def _codes(geo: dict) -> dict:
    """Пометки geoip → коды стран. Флаг собран из двух regional indicator
    symbols, поэтому код восстанавливается обратно без второго запроса."""
    out = {}
    for address, label in (geo or {}).items():
        text = (label or "").strip()
        if len(text) >= 2 and all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in text[:2]):
            out[address] = "".join(
                chr(ord(c) - 0x1F1E6 + ord("A")) for c in text[:2])
    return out


def findings_for(server_name: str, mail: dict, audit: dict, geo: dict) -> list:
    """Находки одного сервера: [(сервер, {level, text, key, hint})].

    Чистая функция ради теста: правила здесь важнее, чем то, как читался лог.
    """
    found = []
    codes = _codes(geo)
    tag = {a: (geo.get(a) or "") for a in geo or {}}

    def place(ip):
        return f" ({tag[ip]})" if tag.get(ip) else ""

    def flag(ip):
        """Только флаг, без города. В перечислении из трёх адресов город
        занимает полстроки, а страна и так отвечает на главный вопрос:
        свои так не ходят."""
        label = (tag.get(ip) or "").strip()
        if len(label) >= 2 and all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in label[:2]):
            return f" {label[:2]}"
        return ""

    def attackers(addresses):
        """Адреса, которые имеет смысл предлагать к блокировке.

        Внутренние не предлагаются никогда: за ними шлюз или рабочее место,
        и блокировка отрезала бы своих. То же правило стоит в кандидатах
        раздела 🛡 Блокировка — здесь оно нужно ещё раз, потому что кнопка
        под алертом банит сразу, без списка."""
        from geoip import is_private

        out = []
        for ip in addresses or []:
            ip = (ip or "").strip()
            if ip and ip not in ("?", "-") and not is_private(ip) and ip not in out:
                out.append(ip)
        return out

    for item in foreign_logins(audit.get("events"), codes):
        found.append((server_name, {
            "level": "crit",
            "text": (f"🔴 вход в {item['account']} из {item['country']}"
                     f"{place(item['ip'])} — адрес {item['ip']}, "
                     f"вход удался"),
            "hint": "вход не из домашней страны",
            "key": f"zm_geo:{server_name}:{item['account']}:{item['ip']}",
        }))

    for item in brute_force(audit.get("events")):
        where = " к админ-консоли" if item["admin"] else ""
        # Чем именно ломятся — половина ответа. SMTP означает попытку
        # разослать спам от вашего имени, IMAP — прочитать почту, и
        # действия по этим находкам разные.
        proto = item.get("protocol") or ""
        how = f" по {proto}" if proto and proto != "?" and not item["admin"] else ""
        found.append((server_name, {
            "level": "crit",
            "text": (f"🔴 подбор пароля{where}{how}: {item['account']} ← "
                     f"{item['ip']}{place(item['ip'])}, "
                     f"{item['count']} неудачных за сутки"
                     + (" — И ОДИН УДАЧНЫЙ, пароль подобран"
                        if item["guessed"] else "")),
            "hint": f"{item['count']} неудачных входов",
            "key": f"zm_brute:{server_name}:{item['account']}:{item['ip']}",
            "ips": attackers([item["ip"]]),
        }))

    # Распылённый перебор: порог по одному адресу его не берёт, а это самая
    # обычная форма — по одной попытке с десятков адресов из разных стран.
    louder = {item["account"] for item in brute_force(audit.get("events"))}
    for item in spray_targets(audit.get("events"), skip=louder):
        where = ", ".join(f"{ip}{flag(ip)}" for ip in item["addresses"][:3])
        more = (f" и ещё {len(item['addresses']) - 3}"
                if len(item["addresses"]) > 3 else "")
        how = (" по " + ", ".join(item["protocols"])) if item["protocols"] else ""
        found.append((server_name, {
            "level": "crit" if item["guessed"] else "warn",
            "text": (f"{'🔴' if item['guessed'] else '🟠'} перебор пароля"
                     f"{how} к {item['account']}: {attempts(item['count'])} с "
                     f"{addresses(len(item['addresses']))} ({where}{more})"
                     + (" — И ОДИН УДАЧНЫЙ ВХОД С ТЕХ ЖЕ АДРЕСОВ, "
                        "пароль подобран" if item["guessed"] else
                        ". По одному адресу порог не срабатывает — так его "
                        "и обходят")),
            "hint": f"перебор с {len(item['addresses'])} адресов",
            # Ключ без чисел: иначе каждая новая попытка — новая находка.
            "key": f"zm_spray:{server_name}:{item['account']}",
            "ips": attackers(item["addresses"]),
        }))

    for item in outside_senders(mail.get("origins"), mail.get("local_domains")):
        found.append((server_name, {
            "level": "crit",
            "text": (f"🔴 {item['sender']}: {letters(item['count'])} сдано "
                     f"с белого адреса {item['ip']}{place(item['ip'])} "
                     f"по паролю, а не через веб"),
            "hint": "отправка снаружи",
            "key": f"zm_outside:{server_name}:{item['sender']}:{item['ip']}",
        }))

    spoof = spoofed_senders(mail.get("origins"), mail.get("local_domains"))
    if spoof["messages"] >= SPOOF_ALERT:
        names = ", ".join(spoof["senders"][:5])
        more = f" и ещё {len(spoof['senders']) - 5}" if len(spoof["senders"]) > 5 else ""
        found.append((server_name, {
            "level": "warn",
            "text": (f"🟠 подделка отправителя: {letters(spoof['messages'])} "
                     f"пришло снаружи от ваших адресов ({names}{more}) "
                     f"с {len(spoof['ips'])} адресов, без входа в почту. "
                     f"Учётки целы — SPF/DMARC такие письма не отбивают"),
            "hint": "письма от своих адресов приходят снаружи",
            # Ключ без чисел: иначе каждое новое письмо — новая находка.
            "key": f"zm_spoof:{server_name}",
        }))

    rejects = sender_rejects(mail.get("reject_reasons"))
    if rejects["messages"] >= SENDER_REJECT_ALERT:
        reason = rejects["reasons"][0]["reason"] if rejects["reasons"] else ""
        found.append((server_name, {
            "level": "warn",
            "text": (f"🟠 отправитель запрещён: {letters(rejects['messages'])} "
                     f"отбито на входе — Postfix не принял их по адресу "
                     f"отправителя. Это подделка вашего домена, чёрный список "
                     f"или оба сразу: в логе у них один и тот же текст"
                     + (f". Причина отказа: {reason}" if reason else "")
                     + ". Защита работает, знать стоит о самих попытках"),
            "hint": "отказы по адресу отправителя",
            # Ключ без чисел: иначе каждая новая попытка — новая находка.
            "key": f"zm_sender_reject:{server_name}",
        }))

    for item in heavy_senders(mail.get("senders")):
        found.append((server_name, {
            "level": "warn",
            "text": (f"🟠 {item['sender']}: {item['messages']} писем за сутки "
                     f"на {item['recipients']} адресов"),
            "hint": "всплеск отправки",
            "key": f"zm_burst:{server_name}:{item['sender']}",
        }))

    queue = mail.get("queue")
    if queue is not None and queue > QUEUE_ALERT:
        found.append((server_name, {
            "level": "warn",
            "text": f"🟠 в очереди {queue} писем при пороге {QUEUE_ALERT}",
            "hint": "очередь не разгребается",
            # Ключ без числа: иначе каждое изменение очереди — новая находка.
            "key": f"zm_queue:{server_name}",
        }))
    return found



def summary_for(mail: dict, audit: dict, findings: list, geo: dict = None) -> dict:
    """Сводка одного сервера для дашборда: плитки, списки, тревоги.

    Чистая функция и общая форма с Exchange: дашборд рисует
    kpis/groups/alarms, ничего не зная про postfix и mailboxd. Третья
    почтовая система добавится сборщиком, а не веткой в отрисовке.

    Второго чтения журналов здесь нет: сводка собирается из того же mail и
    audit, которые уже прочитаны ради алертов. Отдельный проход означал бы
    ещё один awk по 25 МБ mail.log на каждый цикл.
    """
    mail = mail or {}
    audit = audit or {}
    tag = {a: (geo or {}).get(a) or "" for a in geo or {}}

    def place(ip):
        return f" ({tag[ip]})" if tag.get(ip) else ""

    queue = mail.get("queue")
    failed = audit.get("failed") or 0
    brute = brute_force(audit.get("events"))
    kpis = [
        {"value": mail.get("messages") or 0, "label": "писем за сутки",
         "level": "ok"},
        {"value": queue if queue is not None else "?", "label": "в очереди",
         "level": "warn" if (queue or 0) > QUEUE_ALERT else "ok"},
        {"value": mail.get("rejected") or 0, "label": "отбито на входе",
         "level": "ok"},
        {"value": failed, "label": "неудачных входов",
         "level": "crit" if brute else "warn" if failed else "ok"},
    ]

    groups = []
    # Служебные отправители (отчёты о недоставке, ящики самой почты) из
    # обзора убраны: пятнадцать строк, и каждая занятая службой — минус один
    # живой отправитель. В карточке бота список остаётся полным.
    live = [item for item in (mail.get("senders") or [])
            if not is_service_sender(item.get("sender"))]
    split = split_senders(live, mail.get("origins"), mail.get("local_domains"))
    heavy = {i.get("sender") for i in heavy_senders(mail.get("senders"))}

    def sender_rows(items):
        return [
            {"level": "warn" if item.get("sender") in heavy else "ok",
             "left": str(item.get("messages") or 0),
             "title": item.get("sender") or "",
             # Голое число слева не читается: «107» — это писем или адресов?
             # Подпись ставится здесь, рядом со вторым числом.
             "detail": f"писем · на {addresses(item.get('recipients') or 0)}"}
            for item in items[:SUMMARY_ROWS]
        ]

    # Два списка, а не один: сотрудники и чужие рассылки решают разные
    # задачи. В общем списке уведомления банков и налоговой занимали верх
    # топа, и всплеск отправки у своей учётки — то, ради чего раздел и
    # нужен, — терялся среди них.
    if split["own"]:
        groups.append({"title": "Кто отправляет", "level": "ok",
                       "rows": sender_rows(split["own"])})
    if split["incoming"]:
        groups.append({"title": "Кто пишет вам", "level": "ok",
                       "rows": sender_rows(split["incoming"])})

    events = audit.get("events") or []
    bad = [e for e in events if not e.get("ok")][:SUMMARY_ROWS]
    if bad:
        hot = {(i["account"], i["ip"]) for i in brute}
        groups.append({"title": "Пароль не подошёл", "level": "warn", "rows": [
            {"level": "crit" if (e["account"], e["ip"]) in hot else "warn",
             "left": str(e.get("count") or 0),
             "title": f"{e.get('account') or '—'} ← {e.get('ip') or '—'}"
                      + place(e.get("ip")),
             "detail": e.get("protocol") or ""}
            for e in bad
        ]})

    # Из обзора успешных входов убраны двое: служебные обращения самого
    # сервера (учётка zimbra набирает за сутки больше входов, чем любой
    # человек) и входы с рабочих мест в локальной сети — ими заполнялся
    # весь список, и вход снаружи в пятнадцать строк уже не попадал.
    #
    # Шлюзы — исключение, и оно тут главное. Если пользователи ходят в
    # почту через маршрутизатор, все они приходят с его адреса, и внешний
    # сотрудник неотличим от сидящего в соседней комнате. Такие входы
    # прячутся ровно наоборот тому, зачем раздел нужен, поэтому остаются —
    # с подписью, что настоящий адрес до сервера не доехал.
    good = [e for e in events if e.get("ok") and not is_service_login(e)]
    gateways = shared_gateways(events)
    shown = [e for e in good if not is_local_login(e, gateways)]

    def login_row(event):
        ip = event.get("ip") or "—"
        gateway = ip in gateways
        return {
            "level": "ok",
            "left": str(event.get("count") or 0),
            "title": f"{event.get('account') or '—'} ← {ip}"
                     + ("" if gateway else place(ip)),
            "detail": ((event.get("protocol") or "") + " · через шлюз, "
                       "адрес клиента не виден") if gateway
                      else (event.get("protocol") or ""),
        }

    rows = [login_row(e) for e in shown[:SUMMARY_ROWS]]
    # Пустой раздел молча исчезает, а «входили только с рабочих мест» —
    # это ответ, и он стоит строки. Утверждать при этом, что снаружи никто
    # не заходил, нельзя: за шлюзом адреса не видно, а без шлюза видно
    # только тех, кто пришёл напрямую.
    if good and not rows:
        rows = [{"level": "ok",
                 "left": str(sum(e.get("count") or 0 for e in good)),
                 "title": "входов с рабочих мест в локальной сети",
                 "detail": "адресов снаружи среди них нет"}]
    if rows:
        groups.append({"title": "Кто заходил", "level": "ok", "rows": rows})

    stuck = (mail.get("defer_reasons") or [])[:SUMMARY_ROWS]
    if stuck:
        groups.append({"title": "Почему не доставлено", "level": "warn", "rows": [
            {"level": "warn", "left": str(count),
             "title": (parts[0] if parts else "")[:200], "detail": ""}
            for parts, count in stuck
        ]})

    # В тревоги идут только красные находки: жёлтые (всплеск отправки,
    # очередь) уже видны плитками, и дублировать их значит заполнить
    # заголовок вкладки числом, за которым нет происшествия.
    alarms = [(item.get("text") or item.get("hint") or "").lstrip("🔴 ").strip()
              for _server, item in findings
              if item.get("level") == "crit"]
    return {"kpis": kpis, "groups": groups, "alarms": sorted(set(alarms)),
            "suspects": suspects(audit.get("events"))}


def suspects(events) -> list:
    """Адреса, которые стоит предложить к блокировке вручную.

    Нужны потому, что fail2ban по построению пропускает распылённый
    перебор: порог maxretry считает попытки с одного адреса, а их там одна
    или две. Автоматика в этом не виновата — так устроен её признак; но
    пробел от этого не исчезает, и закрыть его может только человек,
    которому список показали.

    Внутренние адреса не предлагаются никогда: за ними шлюз или рабочее
    место, и блокировка отрезает своих. Это же правило стоит в белом
    списке самого fail2ban, но полагаться на чужую настройку здесь нельзя.
    """
    from geoip import is_private

    found = {}

    def add(ip, reason, weight):
        ip = (ip or "").strip()
        if not ip or ip in ("?", "-") or is_private(ip):
            return
        old = found.get(ip)
        if not old or weight > old["weight"]:
            found[ip] = {"ip": ip, "reason": reason, "weight": weight}

    for item in brute_force(events):
        add(item["ip"], f"подбор пароля к {item['account']}: "
                        f"{item['count']} неудачных", 3)
    for item in spray_targets(events):
        for ip in item["addresses"]:
            add(ip, f"распылённый перебор к {item['account']}", 2)

    return [dict(i) for i in sorted(found.values(),
                                    key=lambda i: -i["weight"])]


def collect_server(server: dict) -> list:
    """Оба журнала одного сервера. Сбой одного не отменяет второй: audit.log
    читается, даже если mail.log недоступен по правам, и наоборот."""
    name = server["name"]
    mail, audit = {}, {}
    errors = []
    try:
        mail = read_mail(server, WINDOW_HOURS)
    except Exception as e:
        errors.append(f"mail.log — {str(e).splitlines()[0][:200]}")
        print(f"[zimbra] {name}: {errors[-1]}", flush=True)
    try:
        audit = read_audit(server, WINDOW_HOURS)
    except Exception as e:
        errors.append(f"audit.log — {str(e).splitlines()[0][:200]}")
        print(f"[zimbra] {name}: {errors[-1]}", flush=True)
    if not mail and not audit:
        # Прежняя сводка остаётся в базе, к ней дописывается причина: пустая
        # вкладка выглядела бы как «на почте тихо».
        try:
            save_snapshot(name, "zimbra", None, error="; ".join(errors))
        except Exception as e:
            print(f"[zimbra] {name}: ошибка не записана — {str(e)[:200]}",
                  flush=True)
        return []

    addresses = [e["ip"] for e in audit.get("events") or []]
    addresses += [ip for _s, ip, _a, _c
                  in _origin_rows(mail.get("origins"))]
    try:
        geo = geo_resolve(addresses)
    except Exception:
        geo = {}
    findings = findings_for(name, mail, audit, geo)

    # Та же прочитанная пара журналов уходит в базу для вкладки 📮 Почта.
    # Сбой записи не отменяет алерты: угнанную учётку показать важнее, чем
    # дорисовать карточку в отчёте.
    try:
        save_snapshot(name, "zimbra", summary_for(mail, audit, findings, geo),
                      error="; ".join(errors))
    except Exception as e:
        print(f"[zimbra] {name}: сводка не сохранена — {str(e)[:200]}",
              flush=True)
    return findings


def _collect_safe(server: dict) -> list:
    try:
        return collect_server(server)
    except Exception as e:
        print(f"[zimbra] ❌ {server.get('name')}: {e}", flush=True)
        return []


def zimbra_scan_due(now: float, last: float) -> bool:
    if ZIMBRA_SCAN_MINUTES <= 0:
        return True
    if last is None:
        return True
    return now - last >= ZIMBRA_SCAN_MINUTES * 60


def run_zimbra_cycle(servers: list, on_progress=None) -> int:
    work = [s for s in servers if has_zimbra(s)]
    if not work:
        return 0

    findings = []
    with ThreadPoolExecutor(
        max_workers=min(MAX_PARALLEL_ZIMBRA_SERVERS, len(work))
    ) as pool:
        for items in pool.map(_collect_safe, work):
            findings.extend(items)
            if on_progress:
                on_progress()

    try:
        check_zimbra_alerts(findings)
    except Exception as e:
        print(f"[zimbra] Алерты не отправлены: {e}", flush=True)

    print(f"[zimbra] Почта проверена: серверов {len(work)}, "
          f"находок {len(findings)}", flush=True)
    return len(work)


def maybe_run_zimbra_cycle(servers: list, on_progress=None) -> bool:
    global _last_scan
    now = time.monotonic()
    if not zimbra_scan_due(now, _last_scan):
        return False
    _last_scan = now
    run_zimbra_cycle(servers, on_progress=on_progress)
    return True
