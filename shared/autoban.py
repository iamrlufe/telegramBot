"""
shared/autoban.py

Автоблокировка адресов, которые перебирают пароли к почте.

Почему для почты можно то, чего нельзя для веба. В IIS автоблокировка
опасна: за одним адресом стоит офис или обратный прокси, и первая же
ошибка отрезает всех посетителей сайта. У почтового перебора признаки
другие и куда более узкие — это неудачные ВХОДЫ по SMTP/IMAP с чужого
адреса, а не запросы. Свой сотрудник с таким адресом не ходит: у него
либо местный адрес, либо VPN конторы.

Отсюда три условия, и все три обязаны совпасть:
  * находка — именно перебор пароля (обычный или распылённый);
  * адрес внешний (частные сети не блокируются никогда);
  * страна адреса ИЗВЕСТНА и не домашняя.

Последнее — главная защита. Неизвестная страна значит «GeoIP промолчал»,
а не «чужой»: блокировать вслепую нельзя, такой адрес остаётся человеку
кнопкой под алертом.

Механизм блокировки — тот же, что у ручной кнопки: fail2ban на Linux,
правило фаервола на Windows. Ничего своего автоблокировка не заводит,
поэтому снимается она обычным путём — раздел 🛡 в карточке сервера.
"""
import json

import firewall_store as store
from fail2ban import ban as f2b_ban, has_fail2ban, read_state as f2b_state
from firewall import apply_blocks, has_firewall
from geoip import flag, is_private
from settings import SERVERS_FILE, int_env
from zimbra_log import HOME_COUNTRY


# Потолок на один заход. Распылённый перебор идёт с десятков адресов, и
# без потолка одна кривая находка увела бы в правило сотню строк. Всё
# сверх потолка остаётся человеку — адреса названы в самом алерте.
AUTOBAN_MAX_PER_RUN = int_env("AUTOBAN_MAX_PER_RUN", 20)

# Насколько блокировка ставится на Windows. На Linux срок свой у клетки
# fail2ban, и трогать его отсюда незачем.
AUTOBAN_DAYS = int_env("AUTOBAN_DAYS", 7)

AUTHOR = "автоблокировка"


def autoban_enabled(server: dict) -> bool:
    """Включена ли автоблокировка. Опция, по умолчанию выключена: молча
    отрезать адреса бот не должен ни при каких обстоятельствах."""
    if not server or not server.get("autoban_brute"):
        return False
    # Флаг firewall — это и есть «боту разрешено блокировать на этом
    # сервере». Без него блокировать нечем: ни клетки, ни правила.
    return has_fail2ban(server) or has_firewall(server)


def foreign_attackers(items: list, home: str = None) -> list:
    """Кого блокировать по находкам одного сервера: [{ip, country}].

    items — находки в том виде, в каком их делает сборщик почты. Берутся
    только помеченные `"attack": "brute"`, и только те адреса, у которых
    страна известна и не домашняя.
    """
    home = (home or HOME_COUNTRY or "").upper()
    picked, seen = [], set()
    for item in items or []:
        if item.get("attack") != "brute":
            continue
        countries = item.get("ip_country") or {}
        for address in item.get("ips") or []:
            country = (countries.get(address) or "").upper()
            if not country or country == home:
                continue
            if not address or address in seen or is_private(address):
                continue
            seen.add(address)
            picked.append({"ip": address, "country": country})
    return picked


def load_server(server_name: str) -> dict:
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
    except Exception:
        return None
    for server in servers:
        if server.get("name") == server_name:
            return server
    return None


def _already_blocked(server: dict, server_name: str) -> set:
    """Что уже отрезано: повторно банить незачем, а в сообщении такой
    адрес выглядел бы как новая мера."""
    if has_fail2ban(server):
        try:
            state = f2b_state(server)
        except Exception:
            return set()
        return {a for jail in state.get("jails") or []
                for a in jail.get("addresses") or []}
    try:
        return {b["address"] for b in store.list_blocks(server_name)}
    except Exception:
        return set()


def _default_jail(state: dict) -> str:
    """Куда сажать. Клетка с почтовыми портами, если она есть, — перебор
    идёт туда; иначе первая попавшаяся."""
    names = [j.get("jail") or "" for j in state.get("jails") or []]
    for name in names:
        if "auth" in name or "mail" in name or "smtp" in name:
            return name
    return names[0] if names else ""


def block_addresses(server: dict, server_name: str, addresses: list,
                    reason: str = "перебор пароля к почте") -> tuple:
    """Блокирует адреса. Возвращает (что заблокировано, чем).

    Механизм выбирается по серверу, как и у ручной кнопки: fail2ban на
    Linux, правило фаервола на Windows.
    """
    if not addresses:
        return [], ""

    if has_fail2ban(server):
        state = f2b_state(server)
        jail = _default_jail(state)
        if not jail:
            raise RuntimeError("fail2ban не отвечает или клеток нет")
        done = []
        for address in addresses:
            f2b_ban(server, jail, address)
            done.append(address)
        return done, f"fail2ban, клетка {jail}"

    if has_firewall(server):
        # Правило собирается из списка целиком и пишется первым: если WinRM
        # не ответил, в базе не должно остаться записи о блокировке,
        # которой на сервере нет.
        white = {w["address"] for w in store.list_whitelist(server_name)}
        fresh = [a for a in addresses if a not in white]
        if not fresh:
            return [], ""
        current = [b["address"] for b in store.list_blocks(server_name)]
        apply_blocks(server, current + fresh)
        for address in fresh:
            store.add_block(server_name, address, reason=reason,
                            author=AUTHOR, days=AUTOBAN_DAYS)
        return fresh, f"фаервол, {AUTOBAN_DAYS} дн."

    return [], ""


def run_autoban(server_name: str, items: list) -> dict:
    """Полный проход по находкам одного сервера.

    Возвращает {"blocked": [{ip, country}], "where": "...", "left": N,
    "error": "..."}. Ничего не бросает: неудачная блокировка не должна
    отменять сам алерт — о переборе человек обязан узнать в любом случае.
    """
    result = {"blocked": [], "where": "", "left": 0, "error": ""}
    server = load_server(server_name)
    if not autoban_enabled(server):
        return result

    targets = foreign_attackers(items)
    if not targets:
        return result

    known = _already_blocked(server, server_name)
    targets = [t for t in targets if t["ip"] not in known]
    if not targets:
        return result

    if len(targets) > AUTOBAN_MAX_PER_RUN:
        result["left"] = len(targets) - AUTOBAN_MAX_PER_RUN
        targets = targets[:AUTOBAN_MAX_PER_RUN]

    try:
        done, where = block_addresses(server, server_name,
                                      [t["ip"] for t in targets])
    except Exception as e:
        result["error"] = str(e).splitlines()[0][:200]
        return result

    done_set = set(done)
    result["blocked"] = [t for t in targets if t["ip"] in done_set]
    result["where"] = where
    return result


def report_lines(result: dict) -> list:
    """Строки для сообщения. Список адресов НЕ обрезается: человек должен
    видеть каждый адрес, который бот отрезал без него."""
    if result.get("error"):
        return ["", f"🛡 Автоблокировка не сработала: {result['error']}"]

    blocked = result.get("blocked") or []
    if not blocked:
        return []

    lines = ["", f"🛡 Заблокировано автоматически: {len(blocked)} "
                 f"({result.get('where') or 'блокировка'})"]
    for item in blocked:
        lines.append(f"  {item['ip']} {flag(item['country'])}".rstrip())
    if result.get("left"):
        lines.append(f"  … ещё {result['left']} адресов сверх потолка "
                     f"({AUTOBAN_MAX_PER_RUN} за раз) — заблокируйте вручную")
    lines.append("Снять — раздел 🛡 в карточке сервера.")
    return lines
