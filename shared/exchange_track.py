"""
shared/exchange_track.py

Поток писем Exchange: логи трассировки сообщений (Message Tracking).

До этого модуля про Exchange было известно только то, что видно в логах
IIS: кто заходил в OWA и с какого телефона. Почты там нет вовсе — ни
писем, ни очереди, ни недоставленных, — поэтому карточка Exchange в
дашборде выглядела втрое беднее Zimbra, где всё это даёт mail.log.

Трассировка — родной CSV самой Exchange, включена по умолчанию, лежит в
TransportRoles\\Logs\\MessageTracking. На боевом сервере это 12 МБ в
сутки против 25 МБ у mail.log Zimbra, то есть разбор дешевле.

Считает сам сервер и отдаёт готовую сводку — тот же приём, что у Zimbra
и у логов IIS: тянуть в бота мегабайты, чтобы посчитать в нём же, значит
платить сетью и памятью за то, что PowerShell делает на месте.

Своё и чужое разделяет поле directionality, а не наш разбор адресов: его
проставляет сама Exchange, зная, какие домены обслуживает. Это надёжнее
эвристики по домену отправителя, которой приходится обходиться у Zimbra:
подделанный свой адрес в конверте туда не пролезет.
"""
from winrm_client import (
    PS_OUT_B64_HELPER, compact_ps, ps_json,
    run_ps,
)

# Сколько групп отдавать в каждом списке.
TOP = 20

# Стандартный путь. Настоящий берётся из реестра, но если ключа нет
# (нетиповая установка), этот покрывает большинство серверов.
DEFAULT_TRACK_DIR = (r"C:\Program Files\Microsoft\Exchange Server\V15"
                     r"\TransportRoles\Logs\MessageTracking")

# Счётчики очереди. Poison — письма, на которых транспорт падал: они не
# уйдут никогда и требуют ручного разбора, поэтому считаются отдельно.
QUEUE_COUNTER = "aggregate delivery queue length"
POISON_COUNTER = "poison queue length"


def _script(hours: int, top: int = TOP) -> str:
    """PowerShell: читает трассировку за окно и возвращает сводку.

    Разбор идёт через ConvertFrom-Csv с именами колонок из строки
    «#Fields:», а не по позициям: схема лога менялась между версиями
    Exchange, и позиции молча дали бы чужие значения.

    Письма считаются по уникальному message-id на событии RECEIVE. Одно
    письмо проходит транспорт несколькими событиями (RECEIVE, RESOLVE,
    AGENTINFO, SEND, DELIVER), и наивный счёт строк завысил бы объём в
    несколько раз — та же ошибка, что и со строками mail.log у Zimbra.

    Файлы берутся с запасом в час: лог ротируется по размеру, и письмо из
    начала окна может лежать в файле, дописанном чуть раньше.

    Готовый скрипт прогоняется через compact_ps: пояснения живут здесь, а
    в командную строку WinRM влезает 8000 символов после кодирования, и
    первая же версия с комментариями в них не уместилась (9476).
    """
    return compact_ps(PS_OUT_B64_HELPER + f"""
    $ErrorActionPreference = 'SilentlyContinue'
    $d = '{DEFAULT_TRACK_DIR}'
    $s = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\ExchangeServer\\v15\\Setup' -EA 0
    if ($s -and $s.MsiInstallPath) {{
    $g = Join-Path $s.MsiInstallPath 'TransportRoles\\Logs\\MessageTracking'
    if (Test-Path $g) {{ $d = $g }} }}
    if (-not (Test-Path $d)) {{ Out-B64 @{{ err = 'Нет каталога трассировки: ' + $d }}; return }}
    $t0 = (Get-Date).AddHours(-{hours})
    $cut = $t0.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    $fs = @(Get-ChildItem $d -Filter '*.LOG' | ? {{ $_.LastWriteTime -gt $t0.AddHours(-1) }})
    if (-not $fs) {{ Out-B64 @{{ mi = 0; mo = 0 }}; return }}
    $seen = @{{}}; $o = @{{}}; $i = @{{}}; $f = @{{}}
    $mi = 0; $mo = 0; $rc = 0; $fl = 0; $bad = 0
    foreach ($x in $fs) {{
    try {{ $L = Get-Content -LiteralPath $x.FullName -EA Stop }} catch {{ $bad++; continue }}
    $h = $L | ? {{ $_ -like '#Fields:*' }} | select -First 1
    if (-not $h) {{ continue }}
    $c = ($h -replace '^#Fields:\\s*', '') -split ','
    foreach ($r in ($L | ? {{ $_ -and -not $_.StartsWith('#') }} | ConvertFrom-Csv -Header $c)) {{
    if ($r.'date-time' -lt $cut) {{ continue }}
    $e = $r.'event-id'
    if ($e -eq 'FAIL') {{
    $fl++
    $w = $r.'recipient-status'; if (-not $w) {{ $w = $r.'source-context' }}
    if ($w) {{ if ($w.Length -gt 90) {{ $w = $w.Substring(0, 90) }}
    if ($f.ContainsKey($w)) {{ $f[$w]++ }} else {{ $f[$w] = 1 }} }}
    continue }}
    if ($e -ne 'RECEIVE') {{ continue }}
    $id = $r.'message-id'
    if (-not $id -or $seen.ContainsKey($id)) {{ continue }}
    $seen[$id] = 1
    $n = 0; [int]::TryParse($r.'recipient-count', [ref]$n) | Out-Null
    $rc += $n
    $a = $r.'sender-address'; if (-not $a) {{ $a = '<>' }}
    if ($r.directionality -eq 'Originating') {{ $mo++; $b = $o }} else {{ $mi++; $b = $i }}
    if ($b.ContainsKey($a)) {{ $b[$a].n++; $b[$a].r += $n }} else {{ $b[$a] = @{{ n = 1; r = $n }} }}
    }} }}
    $q = $null; $pz = $null
    $cs = Get-Counter '\\MSExchangeTransport Queues(_total)\\*' -EA 0
    if ($cs) {{ $v = 0
    foreach ($p in $cs.CounterSamples) {{
    if ($p.Path -match '{QUEUE_COUNTER}') {{ $v += [int]$p.CookedValue }}
    if ($p.Path -match '{POISON_COUNTER}') {{ $pz = [int]$p.CookedValue }} }}
    $q = $v }}
    $top = {{ param($b) @($b.GetEnumerator() | sort {{ $_.Value.n }} -Desc | select -First {top} |
    % {{ @{{ sender = $_.Key; messages = $_.Value.n; recipients = $_.Value.r }} }}) }}
    Out-B64 @{{ mi = $mi; mo = $mo; rc = $rc; fl = $fl; q = $q; pz = $pz;
    so = (& $top $o); si = (& $top $i);
    fr = @($f.GetEnumerator() | sort {{ $_.Value }} -Desc | select -First {top} |
    % {{ @{{ reason = $_.Key; count = $_.Value }} }});
    files = $fs.Count; bad = $bad }}
    """)


def _rows(value) -> list:
    """PowerShell отдаёт один элемент объектом, а не списком из одного."""
    if isinstance(value, dict):
        return [value]
    return list(value or [])


def read_tracking(server: dict, hours: int = 24) -> dict:
    """Сводка потока писем за окно. Возвращает счётчики, а не строки."""
    raw = run_ps(server["host"], _script(hours),
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=300, read_timeout_sec=360)
    data = ps_json(raw) or {}
    if isinstance(data, list):
        data = data[0] if data else {}
    if data.get("err"):
        raise Exception(data["err"])

    def number(key):
        value = data.get(key)
        return int(value) if str(value).lstrip("-").isdigit() else None

    # Ключи в скрипте короткие не для красоты: в командную строку WinRM
    # влезает 8000 символов после кодирования, и длинные имена полей —
    # такой же расход, как лишний код. Разворачиваются они здесь.
    return {
        "messages_in": number("mi") or 0,
        "messages_out": number("mo") or 0,
        "recipients": number("rc") or 0,
        "failed": number("fl") or 0,
        # None, а не 0: счётчики могли не сняться, и «очередь пуста» здесь
        # означало бы обратное тому, что произошло.
        "queue": number("q"),
        "poison": number("pz"),
        "senders_out": _rows(data.get("so")),
        "senders_in": _rows(data.get("si")),
        "fail_reasons": _rows(data.get("fr")),
        "files": number("files") or 0,
        "unreadable": number("bad") or 0,
    }
