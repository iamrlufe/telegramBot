"""
shared/winrm_errors.py

Классификация ошибок подключения (WinRM и SSH) по тексту исключения.
"""

# (подстрока в ошибке, статус, заголовок для алерта)
ERROR_PATTERNS = [
    ("credentials were rejected",  "auth_failed",      "🔑 Authentication Failed"),
    ("authentication failed",      "auth_failed",      "🔑 Authentication Failed"),
    ("access is denied",           "access_denied",    "⛔ Access Denied"),
    ("timed out",                  "timeout",          "⏱ Connection Timeout"),
    ("name or service not known",  "dns_error",        "🌐 DNS Error"),
    ("connection refused",         "winrm_refused",    "⚠️ Connection Refused"),
    ("unable to connect to port",  "ssh_refused",      "⚠️ SSH Connection Refused"),
    ("no route to host",           "host_unreachable", "🚨 Host Unreachable"),
    ("max retries exceeded",       "host_unreachable", "🚨 Host Unreachable"),
]


def error_to_status(error_text: str) -> tuple:
    """Возвращает (status, title) по тексту ошибки."""
    e = error_text.lower()
    for needle, status, title in ERROR_PATTERNS:
        if needle in e:
            return status, title
    return "unknown", "❓ Unknown Error"


def parse_status(error_text: str) -> str:
    return error_to_status(error_text)[0]
