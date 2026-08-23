import json
import re
import subprocess

SERVERS_FILE = "/app/config/servers.json"


def load_targets() -> list:
    with open(SERVERS_FILE) as f:
        servers = json.load(f)

    return [
        {
            "name": server["name"],
            "host": server["host"],
        }
        for server in servers
        if server.get("name") and server.get("host")
    ]


def get_target(name: str) -> dict:
    for target in load_targets():
        if target["name"] == name:
            return target
    raise ValueError(f"Сервер {name} не найден")


HOST_RE = re.compile(
    r"^(?!-)[A-Za-z0-9]([A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$"
)


def is_valid_host(host: str) -> bool:
    return bool(HOST_RE.match(host))


def ping_host(host: str, count: int = 4, timeout: int = 2) -> tuple:
    if not is_valid_host(host):
        return False, "Некорректный IP или hostname"

    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            capture_output=True,
            text=True,
            timeout=count * timeout + 3
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Таймаут ping (нет ответа за отведённое время)"


def format_ping_result(label: str, host: str, ok: bool, output: str) -> str:
    packet_loss = None
    transmitted = None
    received = None
    min_ms = None
    avg_ms = None
    max_ms = None
    replies = []

    for line in output.splitlines():
        reply_match = re.search(
            r"icmp_seq=(\d+).*time[=<]([\d.]+)\s*ms",
            line
        )
        if reply_match:
            replies.append((reply_match.group(1), reply_match.group(2)))

    loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    if loss_match:
        packet_loss = loss_match.group(1)

    packet_match = re.search(r"(\d+) packets transmitted, (\d+) received", output)
    if packet_match:
        transmitted = packet_match.group(1)
        received = packet_match.group(2)

    rtt_match = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/", output)
    if rtt_match:
        min_ms = rtt_match.group(1)
        avg_ms = rtt_match.group(2)
        max_ms = rtt_match.group(3)

    icon = "🟢" if ok else "🔴"
    msg = f"{icon} PING\n\n"
    msg += f"Цель: {label}\n"
    msg += f"Host: {host}\n"
    msg += f"Статус: {'доступен' if ok else 'не отвечает'}\n"

    msg += "\nОтветы:\n"
    if replies:
        for seq, time_ms in replies:
            msg += f"  #{seq}: {time_ms} ms\n"
    else:
        msg += "  нет ответов\n"

    msg += "\nСтатистика:\n"
    if transmitted is not None and received is not None:
        msg += f"Пакеты: {received}/{transmitted}\n"
    if packet_loss is not None:
        msg += f"Потери: {packet_loss}%\n"
    if min_ms is not None and max_ms is not None:
        msg += f"Мин/ср/макс: {min_ms}/{avg_ms}/{max_ms} ms\n"
    if avg_ms is not None:
        msg += f"Среднее: {avg_ms} ms\n"
    return msg


def ping_target(name: str) -> str:
    target = get_target(name)
    ok, output = ping_host(target["host"])
    return format_ping_result(target["name"], target["host"], ok, output)


def ping_custom(host: str) -> str:
    host = host.strip()
    if not host:
        return "Укажи IP или hostname"
    ok, output = ping_host(host)
    return format_ping_result(host, host, ok, output)
