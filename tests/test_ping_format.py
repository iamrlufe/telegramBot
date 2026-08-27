"""Карточка пинга: IP имени, статистика, моноширинная таблица ответов."""
from ping_tools import format_ping_result, ping_quality

OK_OUTPUT = """PING srv-01.example.local (192.0.2.31) 56(84) bytes of data.
64 bytes from 192.0.2.31: icmp_seq=1 ttl=128 time=0.669 ms
64 bytes from 192.0.2.31: icmp_seq=2 ttl=128 time=0.567 ms
64 bytes from 192.0.2.31: icmp_seq=3 ttl=128 time=0.572 ms
64 bytes from 192.0.2.31: icmp_seq=4 ttl=128 time=0.574 ms

--- srv-01.example.local ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3060ms
rtt min/avg/max/mdev = 0.567/0.595/0.669/0.041 ms
"""

FAIL_OUTPUT = """PING srv-01.example.local (192.0.2.31) 56(84) bytes of data.

--- srv-01.example.local ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3070ms
"""


def test_resolved_ip_shown_for_hostname():
    msg = format_ping_result(
        "srv-01.example.local", "srv-01.example.local", True, OK_OUTPUT
    )
    assert "🌐 IP: 192.0.2.31" in msg
    assert "🖥 Хост: srv-01.example.local" in msg


def test_ip_target_not_duplicated():
    msg = format_ping_result("192.0.2.31", "192.0.2.31", True, OK_OUTPUT)
    assert "🌐 Адрес: 192.0.2.31" in msg
    assert "🌐 IP:" not in msg


def test_replies_go_into_pre_block():
    msg = format_ping_result(
        "srv-01.example.local", "srv-01.example.local", True, OK_OUTPUT
    )
    body = msg.split("<pre>", 1)[1].split("</pre>", 1)[0]
    assert body.count("\n") == 3
    assert "0.669 ms" in body
    # столбик длительности рисуется относительно самого долгого ответа
    assert "█" in body


def test_stats_line():
    msg = format_ping_result(
        "srv-01.example.local", "srv-01.example.local", True, OK_OUTPUT
    )
    assert "📦 Пакеты: 4 из 4, потерь 0%" in msg
    assert "⏱ Отклик: 0.595 ms  (мин 0.567 / макс 0.669)" in msg
    assert "📶 Качество: 🟢 отличное" in msg


def test_no_replies():
    msg = format_ping_result(
        "srv-01.example.local", "srv-01.example.local", False, FAIL_OUTPUT
    )
    assert "🔴" in msg
    assert "❌ Статус: не отвечает" in msg
    assert "⚠️ Ответов нет" in msg
    assert "<pre>" not in msg
    assert "📶 Качество: ❌ связи нет" in msg


def test_unresolvable_name():
    msg = format_ping_result("нет-такого", "нет-такого", False,
                             "ping: нет-такого: Name or service not known")
    assert "🌐 IP: имя не разрешается (DNS)" in msg
    assert "Name or service not known" in msg


def test_html_special_chars_escaped():
    msg = format_ping_result("a<b&c", "a<b&c", False, "ping: bad host")
    assert "a&lt;b&amp;c" in msg
    assert "a<b&c" not in msg


def test_quality_thresholds():
    assert ping_quality("5", "0") == "🟢 отличное"
    assert ping_quality("30", "0") == "🟢 хорошее"
    assert ping_quality("100", "0") == "🟡 нормальное"
    assert ping_quality("300", "0") == "🔴 медленное"
    assert ping_quality("5", "25") == "⚠️ с потерями (25%)"
    assert ping_quality(None, None) is None
