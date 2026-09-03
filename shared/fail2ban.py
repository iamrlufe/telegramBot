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


def _run(server: dict, args: str, timeout: int = 60) -> str:
    return run_ssh(
        server["host"], _cmd(args),
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


def read_state(server: dict) -> dict:
    """Полное состояние: клетки, забаненные адреса, белый список."""
    jails = parse_jails(_run(server, "status"))
    details, ignored = [], []
    for name in jails:
        details.append(parse_jail(_run(server, f"status {name}"), name))
    if jails:
        ignored = parse_ignoreip(_run(server, f"get {jails[0]} ignoreip"))
    return {"jails": details, "ignored": ignored}


def ban(server: dict, jail: str, address: str) -> str:
    """Ручной бан. Срок берётся из bantime клетки, снимется сам."""
    return _run(server, f"set {jail} banip {address}")


def unban(server: dict, jail: str, address: str) -> str:
    return _run(server, f"set {jail} unbanip {address}")


def has_fail2ban(server: dict) -> bool:
    """Раздел включается тем же флагом `firewall`, что и у Windows: смысл
    один — блокировка адресов, — а механизм зависит от системы."""
    return bool(server.get("firewall")) and server_type(server) == "linux"
