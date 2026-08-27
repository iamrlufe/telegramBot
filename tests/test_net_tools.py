"""Проверка портов и HTTP: выбор портов по конфигу и вёрстка карточек.

Сеть не трогаем — probe_port/http_probe отделены от форматирования именно
ради этого; проверяется то, что решает, а не socket.
"""
import socket
import threading

from ping_tools import FIGURE_SPACE
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
    """Без <pre>: строки обычного текста, числа выровнены пробелом U+2007."""
    results = [
        {"port": 1433, "state": "open", "ms": 0.8},
        {"port": 443, "state": "closed", "detail": "отказано в соединении"},
        {"port": 3389, "state": "filtered", "detail": "нет ответа"},
    ]
    msg = format_port_results("sql-01.example.local", "192.0.2.10", results)
    assert "🔌 <b>ПОРТЫ · sql-01.example.local</b>" in msg
    assert "<pre>" not in msg
    assert "✅ 1433  MSSQL  1 ms" in msg
    # трёхзначные порты дополняются слева до ширины четырёхзначных
    assert f"❌ {FIGURE_SPACE}443  HTTPS  отказано в соединении" in msg
    assert f"⏱ 3389  RDP{FIGURE_SPACE}{FIGURE_SPACE}  нет ответа" in msg
    assert "Открыто 1 из 3" in msg


def test_port_card_legend_only_for_present_states():
    """Подсказка про файрвол не нужна, когда все порты открыты."""
    all_open = format_port_results("srv", "srv", [{"port": 443, "state": "open",
                                                  "ms": 1}])
    assert "файрвол" not in all_open
    assert "отказано" not in all_open

    mixed = format_port_results("srv", "srv", [
        {"port": 443, "state": "filtered", "detail": "нет ответа"},
    ])
    assert "файрвол" in mixed
    assert "не слушает порт" not in mixed


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
    assert "🌐 Адрес: <code>192.0.2.10</code>" in from_config

    manual = format_port_results("192.0.2.10", "192.0.2.10", results)
    assert "🌐 Адрес" not in manual


def _servers_file(tmp_path, monkeypatch, servers):
    import json

    import net_tools

    path = tmp_path / "servers.json"
    path.write_text(json.dumps(servers), encoding="utf-8")
    monkeypatch.setattr(net_tools, "SERVERS_FILE", str(path))
    return path


def test_typed_server_name_resolves_to_config(tmp_path, monkeypatch):
    """`/ping sql-01` — это сервер из конфига, а не неизвестный хост:
    иначе проверялся бы общий набор портов вместо MSSQL и WinRM."""
    from net_tools import guess_ports, resolve_target

    _servers_file(tmp_path, monkeypatch, [
        {"name": "sql-01", "host": "192.0.2.10", "dbsize": True},
    ])

    target = resolve_target("sql-01")
    assert target["host"] == "192.0.2.10"
    assert 1433 in guess_ports(target["server"])

    # адрес того же сервера тоже узнаётся — заголовок будет с именем
    by_host = resolve_target("192.0.2.10")
    assert by_host["label"] == "sql-01"


def test_unknown_host_stays_as_is(tmp_path, monkeypatch):
    from net_tools import DEFAULT_PORTS, guess_ports, resolve_target

    _servers_file(tmp_path, monkeypatch, [{"name": "sql-01", "host": "192.0.2.10"}])

    target = resolve_target("192.0.2.99")
    assert target["label"] == target["host"] == "192.0.2.99"
    assert guess_ports(target["server"]) == DEFAULT_PORTS


def test_ports_report_returns_closed_ports(tmp_path, monkeypatch):
    """Из непрошедших портов строится ряд кнопок 🔁 — значит их надо вернуть."""
    import net_tools

    _servers_file(tmp_path, monkeypatch, [{"name": "srv", "host": "127.0.0.1"}])
    monkeypatch.setattr(net_tools, "guess_ports", lambda server: [1, 2])
    monkeypatch.setattr(net_tools, "check_ports", lambda host, ports: [
        {"port": 1, "state": "open", "ms": 1},
        {"port": 2, "state": "filtered", "detail": "нет ответа"},
    ])

    text, closed = net_tools.ports_report("srv")
    assert closed == [2]
    assert "Открыто 1 из 2" in text


def test_single_port_report_uses_longer_timeout(tmp_path, monkeypatch):
    import net_tools

    _servers_file(tmp_path, monkeypatch, [])
    seen = {}

    def fake_probe(host, port, timeout=None):
        seen["timeout"] = timeout
        return {"port": port, "state": "filtered", "detail": "нет ответа"}

    monkeypatch.setattr(net_tools, "probe_port", fake_probe)
    text = net_tools.single_port_report("192.0.2.10", 1433)

    assert seen["timeout"] == net_tools.RETRY_TIMEOUT > net_tools.CONNECT_TIMEOUT
    assert "🔌 <b>ПОРТ 1433 · MSSQL · 192.0.2.10</b>" in text
    assert "похоже на файрвол" in text


def test_single_port_rejects_nonsense(tmp_path, monkeypatch):
    import net_tools

    _servers_file(tmp_path, monkeypatch, [])
    assert "от 1 до 65535" in net_tools.single_port_report("192.0.2.10", 99999)
