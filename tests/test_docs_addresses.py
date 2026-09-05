"""В документации не должно быть настоящих адресов.

Репозиторий публичный. В readme попали пять реальных публичных адресов —
их скопировали из живого алерта автобана вместе с флагами стран. Сами по
себе это адреса чужих сканеров, но список говорит, кто и куда стучался, и
делает публичной часть журнала боевого сервера.

Разрешены документационные диапазоны (RFC 5737), частные сети (RFC 1918),
localhost и общеизвестные публичные резолверы, которые в тексте служат
примером «внешнего адреса».
"""
import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ["readme.md", "config/example.servers.json", ".env.example"]

DOC_NETWORKS = [ipaddress.ip_network(net) for net in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # RFC 5737 — примеры
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",       # RFC 1918 — «своя сеть»
    "127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32",
)]
# Публичные резолверы: в тексте они служат примером «внешнего адреса», и
# ничьей инфраструктуры не выдают.
KNOWN_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1"}

# Номера версий выглядят как адреса (8.0.3.0 — это SQL Server). Пока таких
# в проверяемых файлах нет; появится — перечислить здесь, а не ослаблять
# правило целиком.
ALLOWED_LITERALS: set[str] = set()


def _addresses(text: str):
    for raw in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            yield raw, ipaddress.ip_address(raw)
        except ValueError:
            continue


def test_docs_use_only_documentation_addresses():
    bad = []
    for name in DOCS:
        text = (ROOT / name).read_text(encoding="utf-8")
        for raw, address in _addresses(text):
            if raw in ALLOWED_LITERALS or raw in KNOWN_RESOLVERS:
                continue
            if any(address in net for net in DOC_NETWORKS):
                continue
            bad.append(f"{name}: {raw}")
    assert not bad, (
        "в публичной документации настоящие адреса — заменить на 192.0.2.0/24, "
        "198.51.100.0/24 или 203.0.113.0/24: " + ", ".join(sorted(set(bad))))
