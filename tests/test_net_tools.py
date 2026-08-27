"""Проверка портов и HTTP: выбор портов по конфигу и вёрстка карточек.

Сеть не трогаем — probe_port/http_probe отделены от форматирования именно
ради этого; проверяется то, что решает, а не socket.
"""
import socket
import threading

from net_tools import (
    DEFAULT_PORTS,
    format_http_result,
    format_port_results,
    guess_ports,
    probe_port,
)


def test_ports_from_mssql_server():
    ports = guess_ports({"name": "sql-01", "dbsize": True,
                         "services": ["MSSQLSERVER", "TermService"]})
    assert ports[0] == 1433
    assert 3389 in ports
    # WinRM — тот же порт, по которому ходит мониторинг
    assert 5985 in ports


def test_ports_from_iis():
    ports = guess_ports({"name": "app-01", "services": ["W3SVC", "WAS"]})
    assert 80 in ports and 443 in ports


def test_ports_from_linux_ssh():
    ports = guess_ports({"name": "web-01", "type": "linux", "ssh_port": 2222,
                         "services": ["apache2"]})
    assert 2222 in ports
    assert 22 not in ports
    assert 80 in ports


def test_ports_for_vmware():
    assert guess_ports({"name": "vc", "type": "vmware"}) == [443]


def test_ports_without_config():
    assert guess_ports({}) == DEFAULT_PORTS


def test_ports_deduplicated_and_capped():
    ports = guess_ports({"name": "all", "dbsize": True, "exchange": True,
                         "services": ["MSSQLSERVER", "W3SVC", "TermService"]})
    assert len(ports) == len(set(ports))
    assert len(ports) <= 8


def test_port_card():
    results = [
        {"port": 1433, "state": "open", "ms": 0.8},
        {"port": 443, "state": "closed", "detail": "отказано в соединении"},
        {"port": 3389, "state": "filtered", "detail": "нет ответа"},
    ]
    msg = format_port_results("sql-01.example.local", "192.0.2.10", results)
    assert "🔌 <b>ПОРТЫ · sql-01.example.local</b>" in msg
    body = msg.split("<pre>", 1)[1].split("</pre>", 1)[0]
    assert "✅ 1433  MSSQL      1 ms" in body
    assert "❌ 443" in body and "⏱ 3389" in body
    assert "Открыто 1 из 3" in msg


def test_port_card_escapes_label():
    msg = format_port_results("a<b", "a<b", [])
    assert "a&lt;b" in msg
    assert "Нечего проверять" in msg


def test_probe_port_open_and_closed():
    """Единственная настоящая проверка сокета — на локальном слушателе."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()

    opened = probe_port("127.0.0.1", port, timeout=2)
    assert opened["state"] == "open"
    assert opened["ms"] >= 0
    srv.close()

    closed = probe_port("127.0.0.1", port, timeout=2)
    assert closed["state"] in ("closed", "filtered")


def test_http_card_ok_with_cert():
    probe = {"url": "https://app-01/", "scheme": "https", "status": 200,
             "reason": "OK", "ms": 43.2, "server": "Microsoft-IIS/10.0",
             "final_url": "https://app-01/", "redirects": []}
    cert = {"subject": "app-01.example.local", "until": "12.01.2027", "days": 138}
    msg = format_http_result("app-01", "app-01", probe, cert)
    assert "✅ Ответ: 200 OK за 43 ms" in msg
    assert "📄 Сервер: Microsoft-IIS/10.0" in msg
    assert "🔒 Сертификат: app-01.example.local, до 12.01.2027 — осталось 138 дн." in msg


def test_http_card_marks_expiring_cert():
    probe = {"url": "https://app-01/", "scheme": "https", "status": 200,
             "reason": "OK", "ms": 10, "server": None, "redirects": []}
    msg = format_http_result("app-01", "app-01", probe,
                             {"subject": "app-01", "until": "01.09.2026", "days": 5})
    assert "⚠️ Сертификат" in msg

    msg = format_http_result("app-01", "app-01", probe,
                             {"subject": "app-01", "until": "01.08.2026", "days": -3})
    assert "ПРОСРОЧЕН" in msg


def test_http_card_untrusted_cert():
    probe = {"url": "https://app-01/", "scheme": "https", "status": 200,
             "reason": "OK", "ms": 10, "server": None, "redirects": []}
    msg = format_http_result("app-01", "app-01", probe,
                             {"error": "не доверенный (self signed certificate)"})
    assert "🔓 Сертификат: не доверенный (self signed certificate)" in msg


def test_http_card_redirects_and_errors():
    probe = {"url": "http://app-01/", "scheme": "http", "status": 500,
             "reason": "Internal Server Error", "ms": 900, "server": None,
             "redirects": [(301, "http://app-01/app/")]}
    msg = format_http_result("app-01", "app-01", probe, {})
    assert "❌ Ответ: 500" in msg
    assert "↪️ 301 → http://app-01/app/" in msg
    assert "HTTPS не ответил" in msg


def test_http_card_no_answer():
    probe = {"error": [("https://app-01/", "connection refused"),
                       ("http://app-01/", "connection refused")]}
    msg = format_http_result("app-01", "app-01", probe, {})
    assert "❌ Сайт не ответил" in msg
    assert "https://app-01/ — connection refused" in msg


def test_port_card_shows_address_only_when_it_differs():
    """Имя сервера и его IP — разные строки; при ручном вводе IP дубля нет."""
    results = [{"port": 443, "state": "open", "ms": 1}]
    from_config = format_port_results("sql-01.example.local", "192.0.2.10", results)
    assert "🌐 Адрес: 192.0.2.10" in from_config

    manual = format_port_results("192.0.2.10", "192.0.2.10", results)
    assert "🌐 Адрес" not in manual
