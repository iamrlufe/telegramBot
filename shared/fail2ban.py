"""
shared/fail2ban.py

Блокировка адресов на Linux — через fail2ban, а не своими правилами.

На почтовом сервере fail2ban уже стоит и работает: читает логи, банит по
порогу, снимает бан по сроку. Писать рядом второй механизм означало бы два
источника истины в одном iptables и вопрос «кто это заблокировал» без
ответа. Поэтому бот пользуется тем же инструментом: `fail2ban-client`.

Что отсюда следует:

- **автоматика остаётся за fail2ban.** Бот не банит сам ни при каких
  условиях — как и раздел Windows Firewall (см. `shared/firewall.py`):
  ошибка в один адрес отрезает офис или филиал, и решение принимает
  человек;
- **срок бана считает fail2ban.** Ручной бан живёт столько же, сколько
  автоматический (`bantime` клетки), и снимается сам;
- **белый список (`ignoreip`) читается и уважается.** Адрес оттуда fail2ban
  не забанит при всём желании, и предлагать его к блокировке — вводить в
  заблуждение.

`fail2ban-client` работает через сокет, доступный только root, поэтому
команды идут через `sudo -n`. Правило sudo ограничено четырьмя формами
(status, get ignoreip, set banip, set unbanip): учётка мониторинга не
должна уметь останавливать fail2ban или менять его настройки.
"""
import re

from linux_check import run_ssh
from server_check import server_type

CLIENT = "fail2ban-client"

# Бан применяется асинхронно: `set banip` возвращает управление сразу, а
# правило в iptables появляется чуть позже. Проверять результат тем же
# вызовом бессмысленно — состояние перечитывается отдельно.
BAN_OK = re.compile(r"^\s*[\d.:a-fA-F]+\s*$", re.M)


def _cmd(args: str) -> str:
    """Команда с повышением прав, только если оно нужно.

    Под root sudo незачем, а под учёткой мониторинга без правила sudo
    команда честно падает с текстом ошибки — это лучше пустого списка,
    который читается как «никто не заблокирован»."""
    return (f'if [ "$(id -u)" = "0" ]; then {CLIENT} {args}; '
            f'else sudo -n {CLIENT} {args}; fi')


# Всё состояние читается ОДНОЙ сессией SSH.
#
# Сначала было по вызову на каждый вопрос: статус, потом статус каждой
# клетки, потом белый список — пять подключений на одно открытие раздела.
# Экран открывался секундами, а на боевом сервере рукопожатия начали
# рваться с «Error reading SSH protocol banner»: пять коротких соединений
# подряд упираются в ограничения sshd. Один скрипт с разделителями решает
# и то, и другое.
_STATE_SH = r"""
set -u
BIN=$(command -v fail2ban-client 2>/dev/null || echo /usr/bin/fail2ban-client)
f2b() { if [ "$(id -u)" = "0" ]; then "$BIN" "$@"; else sudo -n "$BIN" "$@"; fi; }
S=$(f2b status) || exit 1
echo "===STATUS==="
printf '%s\n' "$S"
JAILS=$(printf '%s\n' "$S" | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d '[:space:]' | tr ',' ' ')
for j in $JAILS; do
  echo "===JAIL:$j==="
  f2b status "$j"
done
FIRST=$(echo $JAILS | awk '{print $1}')
if [ -n "$FIRST" ]; then
  echo "===IGNORE==="
  f2b get "$FIRST" ignoreip
fi
echo "===HISTORY==="
for f in /var/log/fail2ban.log.1 /var/log/fail2ban.log; do
  if [ -r "$f" ]; then grep -h "] Ban " "$f" 2>/dev/null | tail -400; fi
done
"""


def _run(server: dict, args: str, timeout: int = 60, script: str = "") -> str:
    return run_ssh(
        server["host"], script or _cmd(args),
        server.get("username"), server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
        timeout=timeout,
    )


def parse_jails(text: str) -> list:
    """Имена клеток из вывода `fail2ban-client status`."""
    for line in (text or "").splitlines():
        if "Jail list:" in line:
            names = line.split("Jail list:", 1)[1]
            return [n.strip() for n in names.split(",") if n.strip()]
    return []


def parse_jail(text: str, name: str = "") -> dict:
    """Разбор `fail2ban-client status <клетка>`.

    Формат вывода с псевдографикой стабилен между версиями, но полагаться
    на порядок строк нельзя: набор полей отличается у клеток с несколькими
    действиями. Поэтому ищем по названиям полей.
    """
    def number(label):
        found = re.search(rf"{label}:\s*(\d+)", text or "")
        return int(found.group(1)) if found else 0

    addresses = []
    banned = re.search(r"Banned IP list:\s*(.*)", text or "")
    if banned:
        addresses = [a for a in banned.group(1).split() if a]

    files = []
    logs = re.search(r"File list:\s*(.*)", text or "")
    if logs:
        files = [f for f in logs.group(1).split() if f]

    return {
        "jail": name,
        "failed_now": number("Currently failed"),
        "failed_total": number("Total failed"),
        "banned_now": number("Currently banned"),
        "banned_total": number("Total banned"),
        "addresses": addresses,
        "logs": files,
    }


def parse_ignoreip(text: str) -> list:
    """Белый список из `fail2ban-client get <клетка> ignoreip`.

    Вывод бывает и списком с заголовком, и одной строкой через пробел —
    зависит от версии. Разбираем оба, отбрасывая служебные слова.
    """
    found = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("these ip", "|", "`")):
            line = re.sub(r"^[|`\s-]+", "", line)
        for token in re.split(r"[\s,]+", line):
            token = token.strip()
            if re.fullmatch(r"[0-9a-fA-F.:]+(/\d{1,3})?", token or "") and any(
                    c in token for c in ".:"):
                found.append(token)
    return found


def parse_state(output: str) -> dict:
    """Разбор вывода одного скрипта: секции с разделителями ===ИМЯ===."""
    sections, current = {}, None
    for line in (output or "").splitlines():
        marker = line.strip()
        if marker.startswith("===") and marker.endswith("===") and len(marker) > 6:
            current = marker.strip("=")
            sections[current] = []
            continue
        if current:
            sections[current].append(line)

    def text(name):
        return "\n".join(sections.get(name) or [])

    jails = [parse_jail("\n".join(lines), name[len("JAIL:"):])
             for name, lines in sections.items() if name.startswith("JAIL:")]
    # Порядок как в `status`: клетки в словаре секций лежат как попало, а
    # на экране они должны идти так же, как их показывает сам fail2ban.
    order = parse_jails(text("STATUS"))
    jails.sort(key=lambda j: order.index(j["jail"])
               if j["jail"] in order else len(order))
    return {"jails": jails, "ignored": parse_ignoreip(text("IGNORE")),
            "history": parse_history(text("HISTORY"))}


# Строка бана в логе: «2026-09-03 14:07:49,112 fail2ban.actions [1788]:
# NOTICE  [zimbra-web] Ban 203.0.113.5».
_BAN_LINE = re.compile(
    r"^(?P<when>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)"
    r".*\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>\S+)")


def parse_history(text: str, limit: int = 20) -> list:
    """Кого банили за время, что лежит в логе.

    Нужна потому, что `status` знает только тех, кто забанен сейчас, а при
    часовом bantime это почти всегда пусто: на экране «заблокировано 0»
    рядом с «всего 66» читается как поломка, хотя оба числа верны.

    Повторные баны одного адреса схлопываются: важно, что он возвращался,
    и когда это было в последний раз, а не каждая отметка отдельно.
    """
    found = {}
    for line in (text or "").splitlines():
        match = _BAN_LINE.match(line.strip())
        if not match:
            continue
        ip = match.group("ip")
        item = found.setdefault(ip, {"ip": ip, "jail": match.group("jail"),
                                     "count": 0, "last": ""})
        item["count"] += 1
        item["jail"] = match.group("jail")
        if match.group("when") > item["last"]:
            item["last"] = match.group("when")
    rows = sorted(found.values(), key=lambda i: i["last"], reverse=True)
    return rows[:limit]


def read_state(server: dict) -> dict:
    """Полное состояние: клетки, забаненные адреса, белый список.

    Одним подключением — см. комментарий к _STATE_SH.
    """
    return parse_state(_run(server, "", script=_STATE_SH, timeout=90))


def ban(server: dict, jail: str, address: str) -> str:
    """Ручной бан. Срок берётся из bantime клетки, снимется сам."""
    return _run(server, f"set {jail} banip {address}")


def unban(server: dict, jail: str, address: str) -> str:
    return _run(server, f"set {jail} unbanip {address}")


def has_fail2ban(server: dict) -> bool:
    """Раздел включается тем же флагом `firewall`, что и у Windows: смысл
    один — блокировка адресов, — а механизм зависит от системы."""
    return bool(server.get("firewall")) and server_type(server) == "linux"
