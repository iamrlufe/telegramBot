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
from winrm_client import run_ps, ps_json, PS_OUT_B64_HELPER

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
    """
    return PS_OUT_B64_HELPER + f"""
    $ErrorActionPreference = 'SilentlyContinue'
    $dir = '{DEFAULT_TRACK_DIR}'
    $setup = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\ExchangeServer\\v15\\Setup' -ErrorAction SilentlyContinue
    if ($setup -and $setup.MsiInstallPath) {{
        $guess = Join-Path $setup.MsiInstallPath 'TransportRoles\\Logs\\MessageTracking'
        if (Test-Path $guess) {{ $dir = $guess }}
    }}
    if (-not (Test-Path $dir)) {{ Out-B64 @{{ track_error = 'Каталог трассировки не найден: ' + $dir }}; return }}

    $start = (Get-Date).AddHours(-{hours})
    $cut = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    # Файл ротируется по размеру, поэтому берём с запасом в час: письмо
    # из начала окна может лежать в файле, дописанном чуть раньше.
    $files = @(Get-ChildItem -Path $dir -Filter '*.LOG' |
               Where-Object {{ $_.LastWriteTime -gt $start.AddHours(-1) }} |
               Sort-Object LastWriteTime)
    if (-not $files) {{ Out-B64 @{{ messages_in = 0; messages_out = 0 }}; return }}

    $seen = @{{}}
    $out = @{{}}; $inn = @{{}}; $fails = @{{}}; $src = @{{}}
    $msgIn = 0; $msgOut = 0; $rcpt = 0; $failed = 0
    $badFiles = @()

    foreach ($f in $files) {{
        try {{ $lines = Get-Content -LiteralPath $f.FullName -ErrorAction Stop }}
        catch {{ $badFiles += $f.Name; continue }}
        $head = $lines | Where-Object {{ $_ -like '#Fields:*' }} | Select-Object -First 1
        if (-not $head) {{ continue }}
        $cols = ($head -replace '^#Fields:\\s*', '') -split ','
        $data = $lines | Where-Object {{ $_ -and -not $_.StartsWith('#') }} |
                ConvertFrom-Csv -Header $cols
        foreach ($r in $data) {{
            if ($r.'date-time' -lt $cut) {{ continue }}
            $event = $r.'event-id'

            if ($event -eq 'FAIL') {{
                $failed++
                $why = $r.'recipient-status'
                if (-not $why) {{ $why = $r.'source-context' }}
                if ($why) {{
                    if ($why.Length -gt 90) {{ $why = $why.Substring(0, 90) }}
                    if ($fails.ContainsKey($why)) {{ $fails[$why]++ }} else {{ $fails[$why] = 1 }}
                }}
                continue
            }}

            if ($event -ne 'RECEIVE') {{ continue }}
            $id = $r.'message-id'
            if (-not $id -or $seen.ContainsKey($id)) {{ continue }}
            $seen[$id] = $true

            $n = 0
            [int]::TryParse($r.'recipient-count', [ref]$n) | Out-Null
            $rcpt += $n
            $from = $r.'sender-address'
            if (-not $from) {{ $from = '<>' }}

            if ($r.directionality -eq 'Originating') {{
                $msgOut++
                $bag = $out
            }} else {{
                $msgIn++
                $bag = $inn
                $ip = $r.'original-client-ip'
                if (-not $ip) {{ $ip = $r.'client-ip' }}
                if ($ip) {{
                    if ($src.ContainsKey($ip)) {{ $src[$ip]++ }} else {{ $src[$ip] = 1 }}
                }}
            }}
            if ($bag.ContainsKey($from)) {{
                $bag[$from].n++; $bag[$from].r += $n
            }} else {{
                $bag[$from] = @{{ n = 1; r = $n }}
            }}
        }}
    }}

    function TopSenders($bag) {{
        @($bag.GetEnumerator() | Sort-Object {{ $_.Value.n }} -Descending |
          Select-Object -First {top} |
          ForEach-Object {{ @{{ sender = $_.Key; messages = $_.Value.n; recipients = $_.Value.r }} }})
    }}
    function TopPairs($bag, $keyName) {{
        @($bag.GetEnumerator() | Sort-Object {{ $_.Value }} -Descending |
          Select-Object -First {top} |
          ForEach-Object {{ @{{ $keyName = $_.Key; count = $_.Value }} }})
    }}

    $queue = $null; $poison = $null
    $counters = Get-Counter '\\MSExchangeTransport Queues(_total)\\*' -ErrorAction SilentlyContinue
    if ($counters) {{
        $q = 0
        foreach ($s in $counters.CounterSamples) {{
            if ($s.Path -match '{QUEUE_COUNTER}') {{ $q += [int]$s.CookedValue }}
            if ($s.Path -match '{POISON_COUNTER}') {{ $poison = [int]$s.CookedValue }}
        }}
        $queue = $q
    }}

    Out-B64 @{{
        messages_in = $msgIn; messages_out = $msgOut;
        recipients = $rcpt; failed = $failed;
        queue = $queue; poison = $poison;
        senders_out = (TopSenders $out); senders_in = (TopSenders $inn);
        fail_reasons = (TopPairs $fails 'reason');
        sources = (TopPairs $src 'ip');
        files = $files.Count; unreadable = $badFiles
    }}
    """


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
    if data.get("track_error"):
        raise Exception(data["track_error"])

    def number(key):
        value = data.get(key)
        return int(value) if str(value).lstrip("-").isdigit() else None

    return {
        "messages_in": number("messages_in") or 0,
        "messages_out": number("messages_out") or 0,
        "recipients": number("recipients") or 0,
        "failed": number("failed") or 0,
        # None, а не 0: счётчики могли не сняться, и «очередь пуста» здесь
        # означало бы обратное тому, что произошло.
        "queue": number("queue"),
        "poison": number("poison"),
        "senders_out": _rows(data.get("senders_out")),
        "senders_in": _rows(data.get("senders_in")),
        "fail_reasons": _rows(data.get("fail_reasons")),
        "sources": _rows(data.get("sources")),
        "files": number("files") or 0,
        "unreadable": _rows(data.get("unreadable")),
    }
