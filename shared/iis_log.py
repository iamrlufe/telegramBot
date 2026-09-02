"""
shared/iis_log.py

Сводка логов IIS: сканирование извне, входы в 1С, ошибки, медленные запросы.

Читается **по смещению**. Суточный файл на живой публикации 1С — это 67 МБ
и полмиллиона строк, полный проход занимает десятки секунд; раз в час так
делать нельзя. Поэтому для каждого файла запоминается позиция, до которой
дочитали, и при следующем проходе читается только новое — тысячи строк
вместо полумиллиона.

Три случая, на которых наивное смещение врёт, и что с ними делается:

* **полночь** — появляется новый `u_ex*.log`, у старого остаётся хвост.
  Обходятся все файлы за последние 36 часов, поэтому хвост вчерашнего
  дочитывается, а не теряется;
* **файл короче запомненного смещения** — его подменили или ротировали
  иначе, читаем с начала;
* **первый запуск** — истории здесь на 20 ГБ, читать её незачем: с нуля
  берётся только самый свежий файл, остальные пропускаются.

Строка `#Fields:` лежит в начале файла, а читать надо с середины, поэтому
заголовок вычитывается до перемотки: набор колонок в логе IIS настраивается,
и разбор по позициям на другом сервере молча подставит чужие значения.

Считает всё сам сервер: в бот приезжают счётчики, а не строки.
"""
import json

from winrm_client import run_ps, ps_json, ps_fits, PS_OUT_B64_HELPER

# Запрос дольше этого — медленный. 10 секунд: обычный вызов 1С укладывается
# в сотни миллисекунд, а на этой границе жалобы «тормозит» уже реальны.
SLOW_MS = 10000

# Сколько групп отдавать в каждом списке. Это сводка, а не выгрузка.
TOP = 25

# Файлы старше этого не трогаем: за 36 часов покрываются и текущие сутки,
# и хвост предыдущих после полуночи.
WINDOW_HOURS = 36

# Пути, которые любой нормальный сайт отдаёт кому угодно. Находкой сканера
# они быть не могут: за ними приходят поисковые роботы, а не взломщики.
# iisstart — картинка и страница-заглушка IIS по умолчанию: сервер отдаёт их
# на пустом сайте, и содержимого за ними нет никакого.
INNOCENT = r"^/(robots|sitemap|favicon|apple-touch|index\.|iisstart|\.well-known)"

# Долгие соединения по замыслу протокола: уведомления OWA, RPC-over-HTTP и
# MAPI держатся минутами. Считать их «медленными запросами» бессмысленно —
# на Exchange они дают десятки тысяч ложных срабатываний в сутки.
LONG_POLL = r"(ev\.owa2|rpcproxy|emsmdb|PushNotif|ActiveSync|subscri|notific)"

# Имя поля с реальным адресом клиента. Появляется в логе, только если в
# настройках сайта заведено пользовательское поле для заголовка
# X-Forwarded-For: за обратным прокси (Cloudflare, ARR, nginx) в c-ip лежит
# адрес прокси, а не посетителя, и разбор по адресам слепнет.
XFF = "x-forwarded-for"


# Сколько файлов имеет смысл передавать в скрипт. В окно попадают текущий
# и вчерашний, третий — запас на почасовую ротацию.
#
# Все три влезают в командную строку WinRM впритык: скрипт разбора стоит у
# самого потолка, и смещения режутся первыми. Потерянное смещение здесь
# дороже, чем кажется: файл, который уже не самый свежий, не перечитывается,
# а пропускается — после полуночи это молча теряет хвост вчерашнего лога.
# Поэтому следующее, что появится в разборе, придётся уносить во второй
# вызов (`_extra_script`), а не дописывать сюда. Запас стережёт
# test_offsets_for_three_files_still_fit.
STATE_FILES = 3


def _trim_state(state: dict, keep: int = STATE_FILES) -> str:
    """Свежие смещения первыми: у файлов имена вида u_exГГММДД.log, поэтому
    сортировка по имени — это сортировка по дате.

    Разделители без пробелов: скрипт стоит у самого потолка командной строки
    WinRM, и смещения режутся первыми — каждый сэкономленный символ это плюс
    один файл, чьё смещение доедет до сервера.
    """
    items = sorted((state or {}).items())[-keep:] if keep else []
    return json.dumps({k: int(v) for k, v in items}, separators=(",", ":"))


def _fit(build, state: dict) -> str:
    """Собирает скрипт, ужимая состояние, пока он не влезет в командную
    строку WinRM (8192 символа).

    Ужимать безопасно: потерянное смещение означает лишь, что файл прочтётся
    заново или будет пропущен как старый, а не влезший скрипт не выполнится
    вовсе.
    """
    for keep in range(STATE_FILES, -1, -1):
        script = build(_trim_state(state, keep))
        if ps_fits(script):
            return script
    return script


def _script(state: dict, slow_ms: int, top: int) -> str:
    return _fit(lambda state_json: _site_script(state_json, slow_ms, top), state)


def _site_script(state_json: str, slow_ms: int, top: int) -> str:
    """Разбор логов сайтов.

    Про два списка путей, `$ap` и `$loc`. Публикации (`$ap`) — это только
    приложения IIS: за ними считается трафик и по ним ловится подбор пароля
    1С. Но «не приложение» ещё не значит «посторонний путь»: виртуальный
    каталог и обычная папка в корне сайта приложениями не являются, а
    содержимое по ним сервер отдаёт совершенно законно. Раньше такой путь
    попадал в посторонние и первый же заход сотрудника давал находку
    «сервер отдал» — красную, с требованием разобрать вручную.

    Поэтому `$loc` — свои пути, которых нет среди публикаций: они не
    считаются ни публикацией, ни сканированием. Обратная сторона: файл,
    подброшенный в существующую папку сайта, находкой уже не станет —
    находки остаются только для путей, которых на сервере нет вовсе.
    """
    return PS_OUT_B64_HELPER + f"""
$ErrorActionPreference='SilentlyContinue'
Import-Module WebAdministration
function M($l){{$n=($l -replace '^#Fields:\\s*','') -split ' ';$h=@{{}};for($i=0;$i -lt $n.Count;$i++){{$h[$n[$i]]=$i}};$h}}
function X($p){{[Environment]::ExpandEnvironmentVariables([string]$p)}}
$ap=@(Get-WebApplication|%{{$_.path.Trim('/')}})
$loc=@(Get-WebVirtualDirectory|%{{$_.path.Trim('/')}})
$st=@{{}}
(ConvertFrom-Json '{state_json}').PSObject.Properties|%{{$st[$_.Name]=[int64]$_.Value}}
$au=@{{}};$pb=@{{}};$al=@{{}};$hit=@{{}};$lg=@{{}};$ips=@{{}};$e5=@{{}};$sl=@{{}};$hr=@{{}}
$tot=$alt=$slt=0;$ns=@{{}};$dirs=@()
foreach($s in gci IIS:\\Sites){{
$d=Join-Path (X $s.logFile.directory) ('W3SVC'+$s.id)
if(Test-Path $d){{$dirs+=$d}}
$loc+=@(gci (X $s.physicalPath) -Directory -Name)}}
foreach($dir in $dirs){{
$fl=@(gci $dir u_ex*.log|?{{$_.LastWriteTime -gt (Get-Date).AddHours(-{WINDOW_HOURS})}}|sort LastWriteTime)
for($j=0;$j -lt $fl.Count;$j++){{
$f=$fl[$j];$k=$f.Name;$off=$st[$k]
if($null -eq $off){{$off=$f.Length;if($j -eq $fl.Count-1){{$off=0}}}}
if($off -gt $f.Length){{$off=0}}
$fs=[IO.File]::Open($f.FullName,'Open','Read','ReadWrite');$sr=New-Object IO.StreamReader $fs
$map=@{{}}
while(!$map.Count -and ($l=$sr.ReadLine()) -ne $null){{
if($l.StartsWith('#Fields:')){{$map=M $l}}}}
if(!$map.Count){{$sr.Close();$fs.Close();continue}}
if($off -gt 0){{$fs.Position=$off;$sr.DiscardBufferedData()}}
while(($l=$sr.ReadLine()) -ne $null){{
if($l.StartsWith('#')){{if($l.StartsWith('#Fields:')){{$map=M $l}};continue}}
$p=$l -split ' ';$tot++
$s2=$p[$map['sc-status']];$c=$p[$map['c-ip']];$u=$p[$map['cs-uri-stem']];$a=$p[$map['cs(User-Agent)']]
$xi=$map['{XFF}'];if($null -ne $xi){{$x=$p[$xi];if($x -and $x -ne '-'){{$c=($x -split ',')[0].Trim()}}}}
$ips[$c]=1+$ips[$c]
$q=$p[$map['time']].Substring(0,2);$hr[$q]=1+$hr[$q]
$g=($u -split '/')[1];if($g){{$g=$g.ToLower()}}
if($g -and $ap -contains $g){{
$pb[$g]=1+$pb[$g]
if($u -like '*/e1cib/login' -and $s2 -eq '402'){{$lg[$g+'|'+$c]=1+$lg[$g+'|'+$c]}}
}}elseif(!($g -and $loc -contains $g)){{
$alt++;$al[$c+'|'+$a]=1+$al[$c+'|'+$a]
$au[$u]=1+$au[$u]
if($s2 -eq '200' -and $u -ne '/' -and $u -notmatch '{INNOCENT}'){{
$hit[$u+'|'+$c+'|'+$a]=1+$hit[$u+'|'+$c+'|'+$a]}}}}
if($s2 -like '5*'){{$e5[$u+'|'+$c]=1+$e5[$u+'|'+$c]}}
$t=0;[void][int]::TryParse($p[$map['time-taken']],[ref]$t)
if($t -gt {slow_ms} -and $u -notmatch '{LONG_POLL}'){{$slt++;$sl[$u+'|'+$c]=1+$sl[$u+'|'+$c]}}
}}
$ns[$k]=$fs.Position;$sr.Close();$fs.Close()}}}}
function T($h){{@($h.GetEnumerator()|sort Value -Descending|select -First {top}|%{{@{{k=$_.Key;n=$_.Value}}}})}}
Out-B64 @{{total=$tot;alien=$alt;slow=$slt;uniq=$ips.Count;state=$ns;
alienuris=(T $au);pubs=(T $pb);scan=(T $al);hits=(T $hit);logins=(T $lg);
ips=(T $ips);errors=(T $e5);slows=(T $sl);hours=(T $hr)}}
"""


def read_site_logs(server: dict, state: dict = None, slow_ms: int = SLOW_MS,
                   top: int = TOP) -> dict:
    """Новые строки логов сайта с прошлого раза → счётчики + новое состояние."""
    raw = run_ps(server["host"], _script(state or {}, slow_ms, top),
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=300, read_timeout_sec=360)
    data = ps_json(raw) or {}
    if isinstance(data, list):
        data = data[0] if data else {}
    for key in ("alienuris", "pubs", "scan", "hits", "logins", "ips",
                "errors", "slows", "hours"):
        rows = data.get(key) or []
        if isinstance(rows, dict):
            rows = [rows]
        data[key] = rows
    state_out = data.get("state") or {}
    if not isinstance(state_out, dict):
        state_out = {}
    data["state"] = {k: int(v) for k, v in state_out.items()}
    return data


# ─── HTTPERR и конфигурация ──────────────────────────────────

# Штатное закрытие простаивающих keep-alive соединений. Клиент 1С держит их
# постоянно, и на живом сервере это 10 тысяч записей в сутки — если не
# отделить, они похоронят десяток настоящих.
IDLE_REASON = "Timer_ConnectionIdle"

HTTPERR_DIR = r"C:\Windows\System32\LogFiles\HTTPERR"


def _extra_script(state: dict, top: int) -> str:
    return _fit(lambda state_json: _httperr_script(state_json, top), state)


def _httperr_script(state_json: str, top: int) -> str:
    return PS_OUT_B64_HELPER + f"""
$ErrorActionPreference='SilentlyContinue'
Import-Module WebAdministration
function M($l){{$n=($l -replace '^#Fields:\\s*','') -split ' ';$h=@{{}};for($i=0;$i -lt $n.Count;$i++){{$h[$n[$i]]=$i}};$h}}
$ap=@(Get-WebApplication|%{{@{{p=$_.path.Trim('/');pool=$_.applicationPool}}}})
$pl=@(Get-ChildItem IIS:\\AppPools|%{{@{{n=$_.name;s=[string]$_.state}}}})
$st=@{{}}
(ConvertFrom-Json '{state_json}').PSObject.Properties|%{{$st[$_.Name]=[int64]$_.Value}}
$rs=@{{}};$dt=@{{}};$ns=@{{}};$tot=0
$fl=@(Get-ChildItem '{HTTPERR_DIR}' -Filter *.log|?{{$_.LastWriteTime -gt (Get-Date).AddHours(-{WINDOW_HOURS})}}|Sort-Object LastWriteTime)
for($j=0;$j -lt $fl.Count;$j++){{
$f=$fl[$j];$k=$f.Name;$off=$st[$k]
if($null -eq $off){{$off=$f.Length;if($j -eq $fl.Count-1){{$off=0}}}}
if($off -gt $f.Length){{$off=0}}
$fs=[IO.File]::Open($f.FullName,'Open','Read','ReadWrite');$sr=New-Object IO.StreamReader $fs
$map=@{{}}
while(!$map.Count -and ($l=$sr.ReadLine()) -ne $null){{
if($l.StartsWith('#Fields:')){{$map=M $l}}}}
if(!$map.Count){{$sr.Close();$fs.Close();continue}}
if($off -gt 0){{$fs.Position=$off;$sr.DiscardBufferedData()}}
while(($l=$sr.ReadLine()) -ne $null){{
if($l.StartsWith('#')){{if($l.StartsWith('#Fields:')){{$map=M $l}};continue}}
$p=$l -split ' ';$tot++
$r=$p[$map['s-reason']];$rs[$r]=1+$rs[$r]
if($r -ne '{IDLE_REASON}'){{
$key=$r+'|'+$p[$map['cs-method']]+'|'+$p[$map['cs-uri']]+'|'+$p[$map['c-ip']]
$dt[$key]=1+$dt[$key]}}}}
$ns[$k]=$fs.Position;$sr.Close();$fs.Close()}}
$sz=0;$old=$null
foreach($s in Get-ChildItem IIS:\\Sites){{
$b=[Environment]::ExpandEnvironmentVariables($s.logFile.directory)
$d=Join-Path $b ('W3SVC'+$s.id)
if(Test-Path $d){{
$g=@(Get-ChildItem $d -Filter u_ex*.log)
$sz+=($g|Measure-Object Length -Sum).Sum
$o=($g|Sort-Object LastWriteTime|Select-Object -First 1)
if($o -and (-not $old -or $o.LastWriteTime -lt $old)){{$old=$o.LastWriteTime}}}}}}
function T($h){{@($h.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First {top}|%{{@{{k=$_.Key;n=$_.Value}}}})}}
Out-B64 @{{apps=$ap;pools=$pl;reasons=(T $rs);details=(T $dt);state=$ns;total=$tot;
logs_mb=[math]::Round($sz/1MB,1);oldest=$(if($old){{$old.ToString('yyyy-MM-dd')}}else{{''}})}}
"""


def read_httperr_and_config(server: dict, state: dict = None,
                            top: int = TOP) -> dict:
    """HTTPERR, список публикаций, пулы и объём каталога логов.

    Отдельным вызовом от логов сайта: командная строка WinRM ограничена
    8192 символами, и один скрипт на всё в неё не влезает.
    """
    raw = run_ps(server["host"], _extra_script(state or {}, top),
                 server.get("username"), server.get("password"),
                 operation_timeout_sec=180, read_timeout_sec=240)
    data = ps_json(raw) or {}
    if isinstance(data, list):
        data = data[0] if data else {}
    for key in ("apps", "pools", "reasons", "details"):
        rows = data.get(key) or []
        if isinstance(rows, dict):
            rows = [rows]
        data[key] = rows
    state_out = data.get("state") or {}
    if not isinstance(state_out, dict):
        state_out = {}
    data["state"] = {k: int(v) for k, v in state_out.items()}
    return data


# ─── Правило перебора паролей ────────────────────────────────

# Перебор паролей 1С. Измеренная норма живого сервера — до 26 входов
# в СУТКИ с адреса, поэтому 25 за ЧАС это двадцатикратное превышение.
LOGIN_BRUTE_PER_HOUR = 25

# Столько же входов даст и сломавшийся клиент, который переподключается по
# кругу. Отличие простое: у настоящего клиента после входов идёт работа, а у
# подбирающего пароль — только login. Если запросов с адреса не больше чем
# втрое от числа входов, работы за ними нет.
LOGIN_BRUTE_RATIO = 3


def detect_brute_force(logins: list, requests: list) -> list:
    """Подбор пароля 1С по входам за последний час.

    Порог взят с живого сервера: там до 26 входов в СУТКИ с адреса, значит
    25 за ЧАС — двадцатикратное превышение.

    Столько же входов даёт и сломавшийся клиент, который переподключается по
    кругу, поэтому мало превышения. У настоящего клиента после входа идёт
    работа — обычные запросы к базе; у подбирающего пароль нет ничего, кроме
    login. Это и разделяет случаи.
    """
    by_ip = {row["parts"][0]: row["count"] for row in requests or []}
    found = []
    for row in logins or []:
        base, ip = row["parts"][0], row["parts"][1]
        if row["count"] < LOGIN_BRUTE_PER_HOUR:
            continue
        total = by_ip.get(ip, 0)
        found.append({"base": base, "ip": ip, "count": row["count"],
                      "requests": total,
                      "working": total > row["count"] * LOGIN_BRUTE_RATIO})
    return found


# ─── Обратные прокси ─────────────────────────────────────────

# Сети Cloudflare (ipv4 и ipv6, https://www.cloudflare.com/ips/). Если домен
# проксируется через них, IIS видит адрес узла Cloudflare, а не посетителя:
# разбор «кто стучится» по такому адресу бессмыслен, и об этом надо сказать,
# а не выдавать узел прокси за источник.
#
# Список статичный намеренно: ходить за ним в интернет ради подписи в отчёте
# незачем, а меняется он раз в несколько лет. Устаревание не ломает ничего —
# просто пропадёт пометка.
CLOUDFLARE_NETS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

_CF_NETWORKS = None


def is_cloudflare(address: str) -> bool:
    """Адрес принадлежит сети Cloudflare — значит это узел прокси."""
    global _CF_NETWORKS
    import ipaddress

    if _CF_NETWORKS is None:
        _CF_NETWORKS = [ipaddress.ip_network(net) for net in CLOUDFLARE_NETS]
    try:
        parsed = ipaddress.ip_address((address or "").strip())
    except ValueError:
        return False
    return any(parsed in net for net in _CF_NETWORKS)
