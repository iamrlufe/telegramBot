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
import os
import time
from concurrent.futures import ThreadPoolExecutor

from alerts import check_zimbra_alerts
from geoip import resolve as geo_resolve
from zimbra_log import (
    QUEUE_ALERT, brute_force, foreign_logins, has_zimbra, heavy_senders,
    outside_senders, read_audit, read_mail,
)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        print(f"[zimbra] Некорректный {name}={raw!r}, беру {default}", flush=True)
        return default


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
        found.append((server_name, {
            "level": "crit",
            "text": (f"🔴 подбор пароля{where}: {item['account']} ← "
                     f"{item['ip']}{place(item['ip'])}, "
                     f"{item['count']} неудачных за сутки"
                     + (" — И ОДИН УДАЧНЫЙ, пароль подобран"
                        if item["guessed"] else "")),
            "hint": f"{item['count']} неудачных входов",
            "key": f"zm_brute:{server_name}:{item['account']}:{item['ip']}",
        }))

    for item in outside_senders(mail.get("origins"), mail.get("local_domains")):
        found.append((server_name, {
            "level": "crit",
            "text": (f"🔴 {item['sender']}: {item['count']} писем сдано "
                     f"с белого адреса {item['ip']}{place(item['ip'])}, "
                     f"а не через веб"),
            "hint": "отправка снаружи",
            "key": f"zm_outside:{server_name}:{item['sender']}:{item['ip']}",
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


def collect_server(server: dict) -> list:
    """Оба журнала одного сервера. Сбой одного не отменяет второй: audit.log
    читается, даже если mail.log недоступен по правам, и наоборот."""
    name = server["name"]
    mail, audit = {}, {}
    try:
        mail = read_mail(server, WINDOW_HOURS)
    except Exception as e:
        print(f"[zimbra] {name}: mail.log — {str(e).splitlines()[0][:200]}",
              flush=True)
    try:
        audit = read_audit(server, WINDOW_HOURS)
    except Exception as e:
        print(f"[zimbra] {name}: audit.log — {str(e).splitlines()[0][:200]}",
              flush=True)
    if not mail and not audit:
        return []

    addresses = [e["ip"] for e in audit.get("events") or []]
    addresses += [ip for (_s, ip), _c in mail.get("origins") or []]
    try:
        geo = geo_resolve(addresses)
    except Exception:
        geo = {}
    return findings_for(name, mail, audit, geo)


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
