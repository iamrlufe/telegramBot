"""
shared/firewall.py

Блокировка адресов правилом Windows Firewall: единственное правило на
сервер, в котором лежит список адресов.

Почему одно правило, а не по правилу на адрес. Сканирование почти всегда
распределённое, адресов набегают сотни; каждый как отдельное правило — это
сотни записей в фильтре, которые Windows перебирает на каждом входящем
пакете, и разобрать этот список руками в оснастке уже невозможно. Одно
правило со списком в `-RemoteAddress` обходится одним проходом фильтра.

Источник истины — база бота, а не сервер. Правило каждый раз собирается
из списка целиком: если кто-то поправил его руками в оснастке или снёс,
следующая же операция вернёт список к тому, что видит бот. Это же делает
операции идемпотентными — повтор после обрыва связи ничего не ломает.

Чего здесь принципиально нет — автоматической блокировки. Решение
принимает человек: на публикации Exchange ошибка в один адрес означает
отрезанный офис или, если сайт за обратным прокси, вообще все посетители
разом. См. `refuse_reason` — там перечислено, что бот блокировать
отказывается.
"""
import ipaddress

from iis_log import is_cloudflare
from server_check import server_type
from winrm_client import run_ps, ps_json, ps_fits, PS_OUT_B64_HELPER

# Имя правила. По нему же его находят в оснастке wf.msc, поэтому имя
# говорящее, а не техническое.
RULE_NAME = "AgroTNKbot: блокировка сканеров"
RULE_GROUP = "AgroTNKbot"

# Потолок на число адресов в правиле. Ограничение не Windows, а транспорта:
# скрипт уезжает на сервер через командную строку WinRM (8192 символа), и
# список туда влезает не любой. Точную границу считает ps_fits, а это —
# ранняя понятная отсечка вместо «The command line is too long» с сервера.
MAX_ADDRESSES = 250


def normalize_target(text: str) -> str:
    """Строка от пользователя → адрес или подсеть в каноническом виде.

    Подсети разрешены намеренно: сканирование часто идёт из одной /24
    хостера, и блокировать её целиком осмысленнее, чем ловить адреса
    поштучно. Пустая строка означает «разобрать не удалось».
    """
    value = (text or "").strip()
    if not value:
        return ""
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _network(target: str):
    """Адрес или подсеть → сеть, чтобы проверять одинаково."""
    return ipaddress.ip_network(target, strict=False)


def refuse_reason(target: str, server: dict = None, whitelist=None) -> str:
    """Причина, по которой блокировать нельзя. Пустая строка — можно.

    Каждый случай здесь — это способ отрезать доступ себе, а не сканеру.
    """
    if not target:
        return "Это не похоже на IP-адрес или подсеть."

    net = _network(target)

    if net.prefixlen <= (8 if net.version == 4 else 32):
        return (f"{target} — это {net.num_addresses} адресов. "
                "Такую сеть блокировать нельзя: под неё попадут не только "
                "сканеры.")

    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        return (f"{target} — служебный адрес самого сервера. Exchange "
                "проверяет себя с 127.0.0.1 и fe80::, блокировка сломает "
                "его собственные проверки.")

    host = str((server or {}).get("host") or "").strip()
    if host:
        try:
            if ipaddress.ip_address(host) in net:
                return f"{target} — это адрес самого сервера ({host})."
        except ValueError:
            pass

    # Края сети достаточно: сети Cloudflare крупнее любой подсети, которую
    # разумно блокировать, поэтому попадание видно уже по первому адресу.
    for address in (net.network_address, net.broadcast_address):
        if is_cloudflare(str(address)):
            return (f"{target} — узел Cloudflare, а не посетитель. За прокси "
                    "в логе виден адрес Cloudflare у всех сразу: блокировка "
                    "отрежет весь сайт. Настоящие адреса появятся, если "
                    "завести в логировании поле X-Forwarded-For.")

    for item in whitelist or []:
        if item == target:
            return f"{target} в белом списке. Сначала убери его оттуда."

    return ""


# Сети, из которых приходят свои, а не сканеры: RFC1918, CGNAT провайдера
# и ULA у IPv6. Отдельным списком, а не через `is_private`: тот считает
# «частными» и документационные диапазоны, и блокировка адреса из них
# получала бы предупреждение про «свой офис» без всяких оснований.
INSIDE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
               "100.64.0.0/10", "fc00::/7")

_INSIDE = None


def is_inside(target: str) -> bool:
    """Адрес или сеть — из своих. Блокировать можно, но предлагать не надо."""
    global _INSIDE

    if not target:
        return False
    net = _network(target)
    if _INSIDE is None:
        _INSIDE = [ipaddress.ip_network(n) for n in INSIDE_NETS]
    return any(net.version == inside.version and net.subnet_of(inside)
               for inside in _INSIDE)


def warn_reason(target: str) -> str:
    """Предупреждение, при котором блокировать всё же можно."""
    net = _network(target)
    if is_inside(target):
        return ("⚠️ Это адрес внутренней сети — скорее всего, свой офис "
                "или филиал, а не сканер извне.")
    if net.num_addresses > 256:
        return f"⚠️ Под блокировку попадёт {net.num_addresses} адресов."
    return ""


def _list_literal(addresses) -> str:
    """Список адресов как литерал массива PowerShell.

    Адреса перед этим прошли через normalize_target и состоят из цифр,
    точек, двоеточий и слэша — кавычки в них появиться не могут, но
    экранирование всё равно сделано: список приходит из базы, а не только
    из свежей проверки.
    """
    items = ",".join("'" + str(a).replace("'", "''") + "'" for a in addresses)
    return f"@({items})"


def _apply_script(addresses) -> str:
    return PS_OUT_B64_HELPER + f"""
$ErrorActionPreference='Stop'
$name='{RULE_NAME}'
$ips={_list_literal(addresses)}
$rule=Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
if($ips.Count -eq 0){{
if($rule){{Remove-NetFirewallRule -DisplayName $name}}
Out-B64 @{{applied=@();removed=$true}}
}}else{{
if($rule){{Set-NetFirewallRule -DisplayName $name -RemoteAddress $ips}}
else{{New-NetFirewallRule -DisplayName $name -Description 'Список ведёт бот мониторинга' -Direction Inbound -Action Block -RemoteAddress $ips -Profile Any -Group '{RULE_GROUP}'|Out-Null}}
$now=@(Get-NetFirewallRule -DisplayName $name|Get-NetFirewallAddressFilter|%{{$_.RemoteAddress}})
Out-B64 @{{applied=$now;removed=$false}}
}}
"""


def _read_script() -> str:
    return PS_OUT_B64_HELPER + f"""
$ErrorActionPreference='SilentlyContinue'
$rule=Get-NetFirewallRule -DisplayName '{RULE_NAME}'
if(-not $rule){{Out-B64 @{{exists=$false;applied=@()}}}}
else{{
$now=@($rule|Get-NetFirewallAddressFilter|%{{$_.RemoteAddress}})
Out-B64 @{{exists=$true;applied=$now;enabled=[string]$rule.Enabled}}
}}
"""


def _addresses_from(data) -> list:
    """Ответ скрипта → список адресов.

    ConvertTo-Json схлопывает массив из одного элемента в строку, поэтому
    один заблокированный адрес приезжает не списком — это разворачивается
    здесь, а не в каждом вызывающем.
    """
    if isinstance(data, list):
        data = data[0] if data else {}
    applied = (data or {}).get("applied") or []
    if isinstance(applied, str):
        applied = [applied]
    return [str(a) for a in applied if a and str(a) != "Any"]


def apply_blocks(server: dict, addresses) -> list:
    """Приводит правило на сервере к переданному списку. Возвращает то, что
    на сервере оказалось по факту, — читая правило обратно, а не повторяя
    свой же ввод."""
    addresses = list(dict.fromkeys(str(a) for a in addresses if a))
    if len(addresses) > MAX_ADDRESSES:
        raise ValueError(
            f"Слишком много адресов: {len(addresses)} при потолке "
            f"{MAX_ADDRESSES}. Заблокируй подсеть целиком вместо списка."
        )
    script = _apply_script(addresses)
    if not ps_fits(script):
        raise ValueError(
            "Список адресов не влезает в командную строку WinRM. "
            "Замени часть адресов подсетью."
        )
    raw = run_ps(server["host"], script,
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=120, read_timeout_sec=180)
    return _addresses_from(ps_json(raw) or {})


def read_blocks(server: dict) -> list:
    """Что реально стоит в правиле на сервере. Нужно, чтобы отличить
    «бот считает заблокированным» от «заблокировано»: правило могли снести
    руками или пересоздать сервер."""
    raw = run_ps(server["host"], _read_script(),
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=60, read_timeout_sec=90)
    return _addresses_from(ps_json(raw) or {})


def has_firewall(server: dict) -> bool:
    """Раздел включён вручную флагом: правами на firewall учётка мониторинга
    обладает не везде, и молча предполагать их нельзя."""
    return bool(server.get("firewall")) and server_type(server) == "windows"
