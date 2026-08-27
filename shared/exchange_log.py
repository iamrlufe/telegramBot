"""
shared/exchange_log.py

Вход в почту Exchange: успешные сеансы OWA и мобильных клиентов из логов
IIS, неудачные попытки — из журнала Security.

Источники разные не по прихоти. При форменной аутентификации (FBA, режим
OWA по умолчанию) логин и пароль уходят в теле POST-запроса, поэтому в
логе IIS поле cs-username при неудачной попытке пустое: IIS не участвует
в проверке пароля и имени не знает. Имя неудачливого пользователя есть
только в событии 4625 журнала Security. Зато успешные сеансы в логе IIS
размечены протоколом (/owa/, /Microsoft-Server-ActiveSync, /EWS) —
в Security все веб-протоколы Exchange неразличимы, они идут одним
процессом w3wp.exe с типом входа 8.

Логи IIS на живом сервере — сотни мегабайт в сутки, поэтому строки
считаются и группируются на самом сервере: в бот приезжает уже сводка.
"""
from winlog import _query, _normalize_status, LOGON_FAILURE_REASONS
from winrm_client import run_ps, ps_json, PS_OUT_B64_HELPER

# Сколько групп отдаём: сводка, а не поток строк.
DEFAULT_TOP = 40

# Путь к логам берём из конфигурации IIS, но если модуля WebAdministration
# нет, остаётся стандартный каталог — на большинстве серверов он и есть.
DEFAULT_LOG_DIR = r"C:\inetpub\logs\LogFiles\W3SVC1"

PATH_OWA = "/owa/"
PATH_EAS = "/microsoft-server-activesync"

# 4625 от веб-процесса Exchange: тип входа 8 — сетевой вход с паролем
# открытым текстом, именно так работает проверка пароля в OWA.
WEB_LOGON_TYPE = "8"
IIS_PROCESS = "w3wp.exe"


def _aggregate_script(hours: int, path_filter: str, group_by: str,
                      top: int) -> str:
    """PowerShell: считает строки лога IIS и возвращает готовую сводку.

    Разбор идёт по именам колонок из строки «#Fields:», а не по позициям:
    набор полей в логе IIS настраивается, и на другом сервере позиции
    молча дадут чужие значения.
    """
    return PS_OUT_B64_HELPER + f"""
    $ErrorActionPreference = 'SilentlyContinue'
    $start = (Get-Date).AddHours(-{hours})
    $dir = '{DEFAULT_LOG_DIR}'
    if (Get-Module -ListAvailable -Name WebAdministration) {{
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $site = Get-Item 'IIS:\\Sites\\Default Web Site' -ErrorAction SilentlyContinue
        if ($site) {{
            $base = [Environment]::ExpandEnvironmentVariables($site.logFile.directory)
            $guess = Join-Path $base ('W3SVC' + $site.id)
            if (Test-Path $guess) {{ $dir = $guess }}
        }}
    }}
    if (-not (Test-Path $dir)) {{ Out-B64 @{{ iis_error = 'Каталог логов IIS не найден: ' + $dir }}; return }}
    $files = @(Get-ChildItem -Path $dir -Filter 'u_ex*.log' | Where-Object {{ $_.LastWriteTime -gt $start }} | Sort-Object LastWriteTime)
    if (-not $files) {{ Out-B64 @{{ rows = @(); scanned = 0 }}; return }}
    $agg = @{{}}
    $scanned = 0
    foreach ($f in $files) {{
        $map = $null
        foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {{
            if ($line.StartsWith('#')) {{
                if ($line.StartsWith('#Fields:')) {{
                    $map = @{{}}
                    $names = ($line -replace '^#Fields:\\s*', '') -split ' '
                    for ($i = 0; $i -lt $names.Count; $i++) {{ $map[$names[$i]] = $i }}
                }}
                continue
            }}
            if ($null -eq $map) {{ continue }}
            if ($line -notmatch '{path_filter}') {{ continue }}
            $p = $line -split ' '
            $stamp = $p[$map['date']] + ' ' + $p[$map['time']]
            if ($stamp -lt $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) {{ continue }}
            $user = $p[$map['cs-username']]
            if (-not $user -or $user -eq '-') {{ continue }}
            $scanned++
            $key = {group_by}
            if ($agg.ContainsKey($key)) {{
                $agg[$key].n++
                if ($stamp -gt $agg[$key].last) {{ $agg[$key].last = $stamp }}
            }} else {{
                $agg[$key] = @{{ n = 1; last = $stamp; user = $user; ip = $p[$map['c-ip']]; ua = $p[$map['cs(User-Agent)']] }}
            }}
        }}
    }}
    $rows = @($agg.Values | Sort-Object {{ $_.n }} -Descending | Select-Object -First {top} | ForEach-Object {{ @{{ user = $_.user; ip = $_.ip; ua = $_.ua; count = $_.n; last = $_.last }} }})
    Out-B64 @{{ rows = $rows; scanned = $scanned; files = $files.Count }}
    """


def _run_iis(server: dict, script: str) -> dict:
    raw = run_ps(server["host"], script,
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=180, read_timeout_sec=240)
    data = ps_json(raw) or {}
    if isinstance(data, list):
        data = data[0] if data else {}
    if data.get("iis_error"):
        raise Exception(data["iis_error"])
    rows = data.get("rows") or []
    if isinstance(rows, dict):
        rows = [rows]
    data["rows"] = rows
    return data


def read_owa_logins(server: dict, hours: int = 24, top: int = DEFAULT_TOP) -> dict:
    """Успешные сеансы OWA: кто, с какого адреса, чем пользовался."""
    return _run_iis(server, _aggregate_script(
        hours, PATH_OWA, "$user + '|' + $p[$map['c-ip']]", top))


def read_activesync(server: dict, hours: int = 24,
                    top: int = DEFAULT_TOP) -> dict:
    """Мобильные клиенты. Отдельно: телефон со старым паролем стучится
    каждые пару минут и в общем списке зашумил бы всё остальное."""
    return _run_iis(server, _aggregate_script(
        hours, PATH_EAS, "$user + '|' + $p[$map['cs(User-Agent)']]", top))


def read_top_sources(server: dict, hours: int = 24,
                     top: int = DEFAULT_TOP) -> dict:
    """Сводка по адресам: с каких IP вообще ходят в почту."""
    return _run_iis(server, _aggregate_script(
        hours, PATH_OWA, "$p[$map['c-ip']]", top))


# Проекция для 4625: к обычным полям добавлен процесс — по нему
# отличаем веб-вход Exchange от обычного RDP или входа по сети.
_WEB_LOGON_PROJECTION = (
    "$x = [xml]$_.ToXml(); $d = $x.Event.EventData.Data; "
    "@{ d = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
    "user = ($d | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'; "
    "ip = ($d | Where-Object { $_.Name -eq 'IpAddress' }).'#text'; "
    "ltype = ($d | Where-Object { $_.Name -eq 'LogonType' }).'#text'; "
    "proc = ($d | Where-Object { $_.Name -eq 'ProcessName' }).'#text'; "
    "status = ($d | Where-Object { $_.Name -eq 'SubStatus' }).'#text'; "
    "status2 = ($d | Where-Object { $_.Name -eq 'Status' }).'#text' }"
)


def read_owa_failures(server: dict, hours: int = 24, limit: int = 200) -> list:
    """Неудачные попытки входа в почту — из журнала Security.

    В логе IIS их имени нет: при форменной аутентификации пароль
    проверяет Exchange, а не IIS, и поле cs-username остаётся пустым.
    Событие 4625 знает и имя, и адрес, и причину отказа.
    """
    flt = "LogName='Security'; StartTime=$start; Id=4625"
    rows = _query(server, hours, flt, _WEB_LOGON_PROJECTION, limit)

    grouped = {}
    for row in rows:
        if str(row.get("ltype") or "").strip() != WEB_LOGON_TYPE:
            continue
        if IIS_PROCESS not in (row.get("proc") or "").lower():
            continue
        code = _normalize_status(
            (row.get("status") or "").strip() or (row.get("status2") or ""))
        key = (row.get("user") or "", row.get("ip") or "", code)
        item = grouped.get(key)
        when = row.get("d") or ""
        if item is None:
            grouped[key] = {
                "user": row.get("user") or "", "ip": row.get("ip") or "",
                "code": code, "reason": LOGON_FAILURE_REASONS.get(code, ""),
                "count": 1, "last": when,
            }
        else:
            item["count"] += 1
            item["last"] = max(item["last"], when)
    return sorted(grouped.values(), key=lambda i: i["count"], reverse=True)
