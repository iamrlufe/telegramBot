"""
shared/winlog.py

Журналы событий Windows через WinRM: перезагрузки и падения, упавшие
службы, ошибки дисков, неудачные входы RDP, ошибки приложений.

Отвечает на вопрос, которого не хватало мониторингу: «сервер был офлайн —
почему». Ping показывает факт, Event Log показывает причину.

Используется Get-WinEvent с -FilterHashtable: фильтр отрабатывает на
стороне провайдера журнала, поэтому запрос не тащит весь журнал в память.
Устаревший Get-EventLog так не умеет и на боевом сервере читает минутами.
"""
import re
from datetime import datetime, timedelta

from winrm_client import run_ps, ps_json, PS_OUT_B64_HELPER

DEFAULT_LIMIT = 40

# Что именно ищем. Коды собраны по смыслу, а не «все ошибки подряд»:
# журнал System на боевом сервере даёт тысячи записей в сутки, и без отбора
# раздел превращается в нечитаемую ленту.
REBOOT_IDS = (6008, 41, 1074, 1076, 6005, 6006)
SERVICE_IDS = (7000, 7009, 7011, 7022, 7023, 7024, 7031, 7034)
DISK_IDS = (7, 9, 11, 15, 51, 52, 55, 98, 129, 153)

# Расшифровка кодов: голый Event ID требует поиска в интернете, а дежурному
# нужно понимать запись сразу.
EVENT_EXPLAIN = {
    6008: "прошлое завершение работы было неожиданным — питание, зависание "
          "или аварийная перезагрузка",
    41: "Kernel-Power: система перезагрузилась без корректного завершения. "
        "Чаще всего пропало питание или сервер завис",
    1074: "перезагрузку инициировал процесс или пользователь — штатное действие",
    1076: "причина предыдущего неожиданного выключения, указанная вручную",
    6005: "журнал событий запущен — система загрузилась",
    6006: "журнал событий остановлен — корректное выключение",
    7000: "служба не смогла запуститься",
    7009: "служба не ответила при запуске (таймаут)",
    7011: "служба не ответила вовремя — сервер перегружен или служба зависла",
    7022: "служба зависла при запуске",
    7023: "служба завершилась с ошибкой",
    7024: "служба завершилась с кодом ошибки",
    7031: "служба завершилась неожиданно и была перезапущена",
    7034: "служба завершилась неожиданно и перезапущена не была",
    7: "устройство обнаружило ошибку блока данных — признак сбоя диска",
    9: "устройство не ответило вовремя (таймаут контроллера)",
    11: "драйвер обнаружил ошибку контроллера диска",
    15: "устройство не готово к работе",
    51: "ошибка подкачки при обращении к диску — сбойные блоки",
    52: "диск предупреждает о скором отказе (SMART)",
    55: "структура файловой системы повреждена, нужна проверка chkdsk",
    98: "ошибка при работе с метаданными тома",
    129: "контроллер сбросил зависший запрос к диску — хранилище не отвечает",
    153: "запрос к диску был отброшен после повторов",
    4625: "неудачный вход в Windows",
}

# Коды 4625: почему вход не удался. Без расшифровки статус выглядит как
# случайный шестнадцатеричный мусор.
LOGON_FAILURE_REASONS = {
    "0xC0000064": "такой учётной записи не существует",
    "0xC000006A": "неверный пароль",
    "0xC000006D": "неверные учётные данные",
    "0xC000006E": "учётная запись есть, но вход запрещён",
    "0xC000006F": "вход вне разрешённого времени",
    "0xC0000070": "вход с этой рабочей станции запрещён",
    "0xC0000071": "срок действия пароля истёк",
    "0xC0000072": "учётная запись отключена",
    "0xC0000133": "часы сервера и клиента разошлись",
    "0xC0000193": "срок действия учётной записи истёк",
    "0xC0000224": "требуется смена пароля",
    "0xC0000234": "учётная запись заблокирована",
}

LOGON_TYPES = {
    "2": "локально (консоль)",
    "3": "по сети (SMB, общие папки)",
    "4": "пакетное задание",
    "5": "служба",
    "7": "разблокировка экрана",
    "8": "сетевой вход с паролем открытым текстом",
    "10": "RDP (удалённый рабочий стол)",
    "11": "кэшированные учётные данные",
}


def explain_event(event_id) -> str:
    try:
        return EVENT_EXPLAIN.get(int(event_id), "")
    except (TypeError, ValueError):
        return ""


def friendly_winlog_error(error: str) -> str:
    """Частые отказы переводим в действие, а не в текст исключения."""
    text = str(error)
    low = text.lower()
    if "access is denied" in low or "отказано в доступе" in low:
        return ("нет прав на чтение журнала — добавьте учётную запись "
                "мониторинга в локальную группу Event Log Readers")
    if "no events were found" in low or "не найдено ни одного события" in low:
        return ""
    return text.splitlines()[0][:300] if text else "неизвестная ошибка"


def _since(hours: int) -> str:
    return (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def _query(server: dict, filter_ps: str, projection: str,
           limit: int, timeout_sec: int = 90) -> list:
    """Общая обвязка: фильтр + проекция → base64(JSON).

    Пустой журнал — не ошибка: Get-WinEvent в этом случае бросает исключение,
    поэтому гасим его SilentlyContinue и возвращаем пустой список.
    """
    script = PS_OUT_B64_HELPER + f"""
    $ErrorActionPreference = 'SilentlyContinue'
    $events = Get-WinEvent -FilterHashtable {filter_ps} -MaxEvents {limit} -ErrorAction SilentlyContinue
    if ($null -eq $events) {{ Out-B64 @(); return }}
    Out-B64 @($events | ForEach-Object {{ {projection} }})
    """
    raw = run_ps(server["host"], script,
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=timeout_sec + 30,
                 read_timeout_sec=timeout_sec + 60)
    data = ps_json(raw) or []
    if isinstance(data, dict):
        data = [data]
    return data


# Проекция общая: время, код, источник и обрезанное сообщение. Полный текст
# события бывает на пол-экрана, а в списке нужна одна строка.
_BASIC_PROJECTION = (
    "@{ d = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
    "id = $_.Id; src = $_.ProviderName; "
    "msg = $(if ($_.Message) { $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) } else { '' }) }"
)


def _ids(values) -> str:
    return ",".join(str(v) for v in values)


def read_reboots(server: dict, hours: int = 24, limit: int = DEFAULT_LIMIT) -> list:
    """Перезагрузки, аварийные завершения и старт/стоп системы."""
    flt = (f"@{{LogName='System'; StartTime='{_since(hours)}'; "
           f"Id={_ids(REBOOT_IDS)}}}")
    return _query(server, flt, _BASIC_PROJECTION, limit)


def read_service_failures(server: dict, hours: int = 24,
                          limit: int = DEFAULT_LIMIT) -> list:
    """Службы, которые падали или не смогли запуститься."""
    flt = (f"@{{LogName='System'; StartTime='{_since(hours)}'; "
           f"Id={_ids(SERVICE_IDS)}}}")
    return _query(server, flt, _BASIC_PROJECTION, limit)


def read_disk_errors(server: dict, hours: int = 24,
                     limit: int = DEFAULT_LIMIT) -> list:
    """Ошибки дисков, контроллеров и файловой системы."""
    flt = (f"@{{LogName='System'; StartTime='{_since(hours)}'; "
           f"Id={_ids(DISK_IDS)}}}")
    return _query(server, flt, _BASIC_PROJECTION, limit)


def read_app_errors(server: dict, hours: int = 24,
                    limit: int = DEFAULT_LIMIT) -> list:
    """Ошибки и критические события журнала приложений (уровни 1 и 2)."""
    flt = f"@{{LogName='Application'; StartTime='{_since(hours)}'; Level=1,2}}"
    return _query(server, flt, _BASIC_PROJECTION, limit)


# Для 4625 читаем EventData из XML, а не Properties[индекс]: порядок полей
# между версиями Windows менялся, и разбор по номеру давал чужие значения.
_LOGON_PROJECTION = (
    "$x = [xml]$_.ToXml(); $d = $x.Event.EventData.Data; "
    "@{ d = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
    "user = ($d | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'; "
    "domain = ($d | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'; "
    "ip = ($d | Where-Object { $_.Name -eq 'IpAddress' }).'#text'; "
    "host = ($d | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'; "
    "ltype = ($d | Where-Object { $_.Name -eq 'LogonType' }).'#text'; "
    "status = ($d | Where-Object { $_.Name -eq 'SubStatus' }).'#text'; "
    "status2 = ($d | Where-Object { $_.Name -eq 'Status' }).'#text' }"
)


def read_failed_logons(server: dict, hours: int = 24,
                       limit: int = DEFAULT_LIMIT) -> list:
    """Неудачные входы в Windows (4625): кто, откуда, каким способом, почему."""
    flt = f"@{{LogName='Security'; StartTime='{_since(hours)}'; Id=4625}}"
    rows = _query(server, flt, _LOGON_PROJECTION, limit)
    for row in rows:
        # SubStatus точнее Status: в 4625 общий Status почти всегда 0xC000006D,
        # а конкретная причина («нет такого пользователя», «пароль неверен»)
        # лежит именно в SubStatus.
        code = (row.get("status") or "").strip()
        if code in ("", "0x0", "0xC000006D"):
            code = (row.get("status2") or code).strip()
        row["code"] = _normalize_status(code)
        row["reason"] = LOGON_FAILURE_REASONS.get(row["code"], "")
        row["how"] = LOGON_TYPES.get(str(row.get("ltype") or "").strip(), "")
    return rows


def _normalize_status(code: str) -> str:
    """0xc000006a → 0xC000006A. Регистр в журнале плавает, ключи — нет."""
    code = (code or "").strip()
    if code.lower().startswith("0x"):
        return "0x" + code[2:].upper()
    return code.upper()


def group_failed_logons(rows: list) -> list:
    """Схлопывает перебор паролей: один источник — одна строка со счётчиком."""
    grouped = {}
    for row in rows:
        key = (row.get("user") or "", row.get("ip") or "",
               row.get("host") or "", row.get("code") or "")
        item = grouped.get(key)
        when = row.get("d") or ""
        if item is None:
            row = dict(row)
            row["count"] = 1
            row["last"] = when
            grouped[key] = row
        else:
            item["count"] += 1
            item["last"] = max(item["last"], when)
    return sorted(grouped.values(), key=lambda i: i["last"], reverse=True)
