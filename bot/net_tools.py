"""Проверка портов и HTTP рядом с пингом.

Пинг отвечает только на вопрос «жив ли хост». Самая частая жалоба звучит
иначе — «пинг идёт, а не работает»: сервер отвечает на ICMP, но нужный порт
закрыт файрволом или служба не поднялась. Отсюда два инструмента:

* TCP-connect по портам, вычисленным из конфига сервера (MSSQL, RDP, WinRM,
  SSH, веб) — быстрый ответ, что именно недоступно;
* HTTP-проверка (аналог `curl -I`) с кодом ответа, цепочкой редиректов и
  сроком TLS-сертификата — та сторона, которую сборщик сертификатов через
  WinRM не видит: он читает хранилище Windows, а здесь смотрим, что реально
  отдаётся клиенту.

Всё на stdlib: в образе бота нет ни curl, ни nc, а добавлять их ради двух
проверок незачем.
"""
import html
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ping_tools import SERVERS_FILE, is_valid_host, pad_left, pad_right

PORT_NAMES = {
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM",
    5986: "WinRM/TLS",
    8080: "HTTP-alt",
}

# Хост без конфига (ручной ввод IP): проверяем то, что чаще всего и спрашивают.
DEFAULT_PORTS = [22, 80, 443, 3389]

MAX_PORTS = 8
CONNECT_TIMEOUT = 2
# Точечная перепроверка одного порта: медленная служба не успевает ответить
# за 2 секунды и в общей сводке ложно выглядит отфильтрованной.
RETRY_TIMEOUT = 5
HTTP_TIMEOUT = 6


def resolve_target(value: str) -> dict:
    """Имя из конфига → его адрес и поля. Пользователь набирает `/ping
    sql-01` руками, и раньше это уходило в ветку «неизвестный хост»:
    проверялись 22/80/443/3389 вместо MSSQL и WinRM этого сервера."""
    value = (value or "").strip()
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
    except (OSError, json.JSONDecodeError):
        servers = []

    for server in servers:
        if server.get("name") == value or server.get("host") == value:
            return {
                "label": server.get("name") or value,
                "host": server.get("host") or value,
                "server": server,
            }
    return {"label": value, "host": value, "server": {}}


def guess_ports(server: dict) -> list:
    """Порты для проверки по полям сервера. Порядок — от самого показательного
    к второстепенному, дубликаты убираются."""
    if not server:
        return list(DEFAULT_PORTS)

    ports = []
    server_type = (server.get("type") or "windows").lower()
    services = [str(s).lower() for s in (server.get("services") or [])]

    if server.get("dbsize") or "mssqlserver" in services:
        ports.append(1433)
    if server.get("exchange"):
        ports += [443, 25]
    if any(s in services for s in ("w3svc", "was", "nginx", "apache2", "httpd")):
        ports += [80, 443]
    if "termservice" in services:
        ports.append(3389)

    if server_type == "linux":
        ports.append(int(server.get("ssh_port") or 22))
    elif server_type == "vmware":
        ports.append(443)
    elif server_type == "device":
        ports += DEFAULT_PORTS
    else:
        # Windows: WinRM — тот самый порт, по которому ходит сам мониторинг,
        # поэтому «офлайн по WinRM» проверяется в первую очередь им.
        ports += [5985, 3389]

    unique = []
    for port in ports:
        if port not in unique:
            unique.append(port)
    return unique[:MAX_PORTS] or list(DEFAULT_PORTS)


def probe_port(host: str, port: int, timeout: int = CONNECT_TIMEOUT) -> dict:
    """Одна TCP-проверка. Ответ — словарь, чтобы форматирование можно было
    тестировать без сети."""
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {
            "port": port,
            "state": "open",
            "ms": (time.monotonic() - started) * 1000,
        }
    except socket.timeout:
        return {"port": port, "state": "filtered", "detail": "нет ответа"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "detail": "отказано в соединении"}
    except socket.gaierror:
        return {"port": port, "state": "error", "detail": "имя не разрешается"}
    except OSError as e:
        return {"port": port, "state": "error", "detail": str(e)[:60]}


def check_ports(host: str, ports: list) -> list:
    """Порты проверяются параллельно: восемь таймаутов по 2 секунды подряд —
    это 16 секунд ожидания в чате."""
    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        return list(pool.map(lambda port: probe_port(host, port), ports))


STATE_ICONS = {
    "open": "✅",
    "closed": "❌",
    "filtered": "⏱",
    "error": "⚠️",
}


def port_row(item: dict, port_width: int = 0, name_width: int = 0) -> str:
    port = str(item["port"])
    name = PORT_NAMES.get(item["port"], "")
    if item["state"] == "open":
        detail = f"{item['ms']:.0f} ms"
    else:
        detail = item.get("detail", "")
    icon = STATE_ICONS.get(item["state"], "⚠️")
    return (
        f"{icon} {pad_left(port, port_width)}  "
        f"{pad_right(name, name_width)}  {detail}".rstrip()
    )


def format_port_results(label: str, host: str, results: list) -> str:
    esc_label = html.escape(label)
    lines = [
        f"🔌 <b>ПОРТЫ · {esc_label}</b>",
        "━" * 20,
        "",
        f"🖥 Хост: {esc_label}",
    ]
    # У сервера из конфига имя и адрес разные — показываем оба; при ручном
    # вводе IP это одна и та же строка, дублировать нечего.
    if host and host != label:
        lines.append(f"🌐 Адрес: <code>{html.escape(host)}</code>")
    lines.append("")

    if not results:
        lines.append("⚠️ Нечего проверять: порты не определены")
        return "\n".join(lines)

    port_width = max(len(str(item["port"])) for item in results)
    name_width = max(len(PORT_NAMES.get(item["port"], "")) for item in results)
    lines += [port_row(item, port_width, name_width) for item in results]

    opened = sum(1 for item in results if item["state"] == "open")
    lines.append("")
    lines.append(f"Открыто {opened} из {len(results)}")

    states = {item["state"] for item in results}
    if "filtered" in states:
        lines.append("⏱ — ответа нет вовсе: чаще всего порт режет файрвол.")
    if "closed" in states:
        lines.append("❌ — хост ответил «отказано»: служба не слушает порт.")
    return "\n".join(lines)


def ports_report(value: str) -> tuple:
    """Сводка по портам цели. Второй элемент — порты, которые не открылись:
    из них строится ряд кнопок точечной перепроверки."""
    target = resolve_target(value)
    label, host = target["label"], target["host"]
    if not is_valid_host(host):
        return "❌ Некорректный IP или hostname", []

    ports = guess_ports(target["server"])
    results = check_ports(host, ports)
    closed = [item["port"] for item in results if item["state"] != "open"]
    return format_port_results(label, host, results), closed


def single_port_report(value: str, port: int) -> str:
    """Один порт с увеличенным таймаутом — ответ на «а вдруг просто медленно»."""
    target = resolve_target(value)
    label, host = target["label"], target["host"]
    if not is_valid_host(host):
        return "❌ Некорректный IP или hostname"
    if not 1 <= port <= 65535:
        return "❌ Порт должен быть числом от 1 до 65535"

    item = probe_port(host, port, timeout=RETRY_TIMEOUT)
    name = PORT_NAMES.get(port, "")
    title = f"{port} · {name}" if name else str(port)
    lines = [
        f"🔌 <b>ПОРТ {html.escape(title)} · {html.escape(label)}</b>",
        "━" * 20,
        "",
        port_row(item),
        "",
        f"Таймаут проверки — {RETRY_TIMEOUT} с (в общей сводке {CONNECT_TIMEOUT} с).",
    ]
    if item["state"] == "open":
        lines.append("Порт открыт: служба слушает и соединение проходит.")
    elif item["state"] == "closed":
        lines.append("Хост ответил «отказано» — служба на этом порту не поднята.")
    elif item["state"] == "filtered":
        lines.append("Ответа нет и за 5 секунд — похоже на файрвол.")
    return "\n".join(lines)


# ─── HTTP ────────────────────────────────────────────────────

class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    """Редиректы нужны в отчёте: «сайт работает» и «сайт отдаёт 301 на
    несуществующий адрес» снаружи выглядят одинаково."""

    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append((code, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def cert_info(host: str, port: int = 443, timeout: int = HTTP_TIMEOUT) -> dict:
    """Срок действия сертификата, который реально отдаёт сервер.

    Проверка делается с полной валидацией: без неё Python возвращает пустой
    словарь вместо полей сертификата. Самоподписанный сертификат — не ошибка
    инструмента, а результат: так и пишем, почему он не проверяется."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"error": f"не доверенный ({e.verify_message or e.reason})"}
    except ssl.SSLError as e:
        return {"error": f"ошибка TLS ({str(e)[:60]})"}
    except OSError as e:
        return {"error": str(e)[:60]}

    subject = ""
    for part in cert.get("subject", ()):
        for key, value in part:
            if key == "commonName":
                subject = value
    until = cert.get("notAfter")
    days = None
    if until:
        expires = datetime.strptime(until, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days = (expires - datetime.now(timezone.utc)).days
        until = expires.strftime("%d.%m.%Y")
    return {"subject": subject, "until": until, "days": days}


def http_probe(host: str, timeout: int = HTTP_TIMEOUT) -> dict:
    """HEAD-запрос сначала по HTTPS, при неудаче — по HTTP. Как `curl -I`."""
    attempts = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        tracker = _RedirectTracker()
        opener = urllib.request.build_opener(tracker)
        request = urllib.request.Request(url, method="HEAD")
        request.add_header("User-Agent", "AgroTNKbot/monitoring")
        started = time.monotonic()
        try:
            with opener.open(request, timeout=timeout) as response:
                return {
                    "url": url,
                    "scheme": scheme,
                    "status": response.status,
                    "reason": response.reason,
                    "ms": (time.monotonic() - started) * 1000,
                    "server": response.headers.get("Server"),
                    "final_url": response.url,
                    "redirects": tracker.chain,
                }
        except urllib.error.HTTPError as e:
            # 4xx/5xx — тоже ответ: сервер жив, но отдаёт ошибку.
            return {
                "url": url,
                "scheme": scheme,
                "status": e.code,
                "reason": e.reason,
                "ms": (time.monotonic() - started) * 1000,
                "server": e.headers.get("Server") if e.headers else None,
                "final_url": url,
                "redirects": tracker.chain,
            }
        except Exception as e:  # URLError, ssl, socket
            attempts.append((url, str(getattr(e, "reason", e))[:80]))
    return {"error": attempts}


def format_http_result(label: str, host: str, probe: dict, cert: dict) -> str:
    esc_label = html.escape(label)
    lines = [
        f"🌐 <b>HTTP · {esc_label}</b>",
        "━" * 20,
        "",
    ]

    if probe.get("error"):
        lines.append("❌ Сайт не ответил")
        lines.append("")
        for url, reason in probe["error"]:
            lines.append(f"• {html.escape(url)} — {html.escape(reason)}")
        return "\n".join(lines)

    status = probe["status"]
    icon = "✅" if status < 400 else ("⚠️" if status < 500 else "❌")
    lines.append(f"🔗 {html.escape(probe['url'])}")
    lines.append(
        f"{icon} Ответ: {status} {html.escape(probe.get('reason') or '')}"
        f" за {probe['ms']:.0f} ms"
    )
    if probe.get("server"):
        lines.append(f"📄 Сервер: {html.escape(probe['server'])}")

    for code, newurl in probe.get("redirects") or []:
        lines.append(f"↪️ {code} → {html.escape(newurl)}")

    if probe["scheme"] == "https" and cert:
        if cert.get("error"):
            lines.append(f"🔓 Сертификат: {html.escape(cert['error'])}")
        else:
            days = cert.get("days")
            if days is None:
                left = ""
            elif days < 0:
                left = " — ПРОСРОЧЕН"
            else:
                left = f" — осталось {days} дн."
            mark = "🔒" if days is None or days > 14 else "⚠️"
            subject = html.escape(cert.get("subject") or "")
            lines.append(
                f"{mark} Сертификат: {subject}, до {cert.get('until')}{left}"
            )
    elif probe["scheme"] == "http":
        lines.append("🔓 HTTPS не ответил, проверено по HTTP")

    return "\n".join(lines)


def http_report(value: str) -> str:
    target = resolve_target(value)
    label, host = target["label"], target["host"]
    if not is_valid_host(host):
        return "❌ Некорректный IP или hostname"
    probe = http_probe(host)
    cert = cert_info(host) if probe.get("scheme") == "https" else {}
    return format_http_result(label, host, probe, cert)
