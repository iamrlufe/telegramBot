import html
import ipaddress
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


RESOLVED_IP_RE = re.compile(r"^PING\s+\S+\s+\(([^)\s]+)\)", re.M)


def resolved_address(output: str):
    """IP, до которого реально дорезолвилось имя: ping печатает его в первой
    строке — PING host (192.0.2.31) 56(84) bytes of data."""
    match = RESOLVED_IP_RE.search(output)
    return match.group(1) if match else None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ping_quality(avg_ms, packet_loss):
    if packet_loss is not None:
        loss = float(packet_loss)
        if loss >= 100:
            return "❌ связи нет"
        if loss > 0:
            return f"⚠️ с потерями ({loss:g}%)"
    if avg_ms is None:
        return None
    avg = float(avg_ms)
    if avg < 10:
        return "🟢 отличное"
    if avg < 50:
        return "🟢 хорошее"
    if avg < 150:
        return "🟡 нормальное"
    return "🔴 медленное"


def reply_table(replies: list) -> str:
    """Моноширинная таблица ответов со столбиком относительной задержки."""
    times = [float(time_ms) for _, time_ms in replies]
    peak = max(times) or 1.0
    rows = []
    for (seq, time_ms), value in zip(replies, times):
        bar = "\u2588" * max(1, round(value / peak * 8))
        rows.append(f"#{seq:<3}{time_ms:>8} ms  {bar}")
    return html.escape("\n".join(rows))


def format_ping_result(label: str, host: str, ok: bool, output: str) -> str:
    """Карточка пинга в HTML. Таблица ответов уходит в <pre>: обычный текст
    Telegram рисует пропорциональным шрифтом, и колонки с миллисекундами
    разъезжались."""
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

    resolved_ip = resolved_address(output)

    icon = "🟢" if ok else "🔴"
    esc_label = html.escape(label)
    lines = [
        f"{icon} <b>PING · {esc_label}</b>",
        "━" * 20,
        "",
        f"🖥 Хост: {esc_label}",
    ]

    # Пинг по IP: второй раз тот же адрес показывать незачем.
    if is_ip(host):
        lines.append(f"🌐 Адрес: {html.escape(host)}")
    elif resolved_ip:
        lines.append(f"🌐 IP: {html.escape(resolved_ip)}")
    else:
        lines.append("🌐 IP: имя не разрешается (DNS)")

    lines.append(f"{'✅' if ok else '❌'} Статус: {'доступен' if ok else 'не отвечает'}")
    lines.append("")

    if avg_ms is not None:
        tail = ""
        if min_ms is not None and max_ms is not None:
            tail = f"  (мин {min_ms} / макс {max_ms})"
        lines.append(f"⏱ Отклик: {avg_ms} ms{tail}")
    if transmitted is not None and received is not None:
        loss_tail = f", потерь {packet_loss}%" if packet_loss is not None else ""
        lines.append(f"📦 Пакеты: {received} из {transmitted}{loss_tail}")
    quality = ping_quality(avg_ms, packet_loss)
    if quality:
        lines.append(f"📶 Качество: {quality}")

    if replies:
        lines.append("")
        lines.append("Ответы")
        lines.append(f"<pre>{reply_table(replies)}</pre>")
    else:
        lines.append("")
        lines.append("⚠️ Ответов нет")
        if transmitted is None:
            # ping не отработал вовсе: неверный хост, таймаут, нет прав
            note = " ".join(output.split())[:200]
            if note:
                lines.append(html.escape(note))

    return "\n".join(lines)


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
