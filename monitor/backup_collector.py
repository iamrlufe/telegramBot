"""
monitor/backup_collector.py

Сборщик метрик бэкапов. Запускается из monitor.py в отдельном потоке.
Период: каждые 5 минут (совпадает с основным циклом).
"""
import json
import os
import statistics
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from winrm_client import ps_fits, run_ps
from linux_check import run_ssh
from server_check import server_type
from alerts import (
    alert_due,
    alert_level,
    mark_alert_sent,
    send_or_defer, load_json, save_json, is_muted, check_backup_failure_alerts,
)
from backup_schedule import (
    ALMATY,
    most_recent_weekly_deadline,
    path_schedule,
    weekday_label,
    weekly_backup_missed,
)

SERVERS_FILE = "/app/config/servers.json"
BACKUP_ALERT_STATE_FILE = "/app/data/backup_alert_state.json"


def _fmt_local(dt) -> str:
    """naive-UTC время файла бэкапа → строка в местном времени (Алматы),
    как и всё остальное в боте. Без конвертации показывалось UTC."""
    return dt.replace(tzinfo=timezone.utc).astimezone(ALMATY).strftime("%d.%m.%Y %H:%M")

# Расширения по типу бэкапа
EXTENSIONS = {
    "sql":  [".bak", ".trn"],
    "veeam": [],          # не фильтруем, но и не удаляем
    "1c":   [".dt", ".zip"],
}

# Журналы транзакций MSSQL. Их делают каждые 15–60 минут, полную копию —
# раз в сутки, и в одном каталоге они лежат вперемешку. Общий newest_file
# берёт максимум по всем расширениям, поэтому свежий .trn маскирует
# пропавшую полную копию и алерт «БЭКАП УСТАРЕЛ» не срабатывает.
# Для путей с "ignore_logs": true журналы из учёта исключаются полностью:
# возраст, наличие файлов и проверка размера считаются только по .bak.
LOG_EXTENSIONS = {".trn"}

# Алерт: бэкап старше N часов. По умолчанию 25 (сутки + 1 час запаса), чтобы
# алерт не срабатывал, пока сегодняшний бэкап ещё делается (на серверах с
# многими базами окно бэкапа длится час-два).
# Приоритет настройки: своё время у конкретного пути (backups.<type>[i].alert_hours)
# > "backup_alert_hours" у сервера > глобальный BACKUP_ALERT_HOURS (.env).
# Всё, кроме глобального, редактируется через ⚙️ Настройка в боте.
def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        print(f"[backup] Некорректный {name}, использую {default}", flush=True)
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        print(f"[backup] Некорректный {name}, использую {default}", flush=True)
        return default


BACKUP_ALERT_HOURS = _int_env("BACKUP_ALERT_HOURS", 25)
# Алерт: размер журнала регистрации 1С
ONEC_LOG_WARN_GB = 5
ONEC_LOG_CRIT_GB = 10

# Проверка «бэкап подозрительно маленький» (например, обрыв копирования по FTP):
# новый файл сравнивается с медианой размеров последних N успешных бэкапов
# этого же пути. Включается опционально на сервере ("backup_size_check": true)
# и/или на конкретном пути (backups.<type>[i].size_check: true/false — приоритет
# выше, чем у сервера). Порог и минимальная история — общие настройки в .env,
# т.к. это грубая эвристика, а не точный порог под каждый путь.
BACKUP_SIZE_CHECK_MIN_RATIO = _float_env("BACKUP_SIZE_CHECK_MIN_RATIO", 0.97)
BACKUP_SIZE_CHECK_MIN_HISTORY = _int_env("BACKUP_SIZE_CHECK_MIN_HISTORY", 1)
BACKUP_SIZE_CHECK_MIN_AGE_HOURS = _int_env("BACKUP_SIZE_CHECK_MIN_AGE_HOURS", 2)


# ─── PostgreSQL ───────────────────────────────────────────────

from psycopg2 import errors

from pgconn import get_conn


# ─── WinRM: метрики папки бэкапов ────────────────────────────

def _ps_scan_script(items_json: str) -> str:
    """PowerShell, считающий метрики сразу нескольких каталогов за один вызов.

    items_json — [{"Index": 0, "Path": "...", "Exts": [".bak"]}, ...].
    Пути и расширения передаются данными, а не подстановкой в код: путь
    может содержать кавычки, а скрипт от этого не должен разъезжаться.

    Скрипт нарочно короткий: командная строка WinRM ограничена 8000
    символами после кодирования, и каждая сотня символов тела — это
    минус один каталог в пачке (комментарии не в счёт, их снимает
    compact_ps). Отсюда функции-сокращения и одна общая заготовка ответа
    вместо двух почти одинаковых.
    """
    payload = items_json.replace("'", "''")
    return f"""
    $items = '{payload}' | ConvertFrom-Json
    $drives = @(Get-PSDrive -PSProvider FileSystem)
    function U($f) {{ if ($f) {{ $f.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }} }}
    function GB($n) {{ [math]::Round($n / 1GB, 3) }}
    $out = @()

    foreach ($item in $items) {{
        $path = $item.Path
        $r = @{{ Index = $item.Index; FileCount = 0; TotalGB = 0; OldestFile = $null;
                NewestFile = $null; NewestFileGB = $null; LogCount = 0; LogNewest = $null;
                FullCount = 0; FullNewest = $null; FullNewestGB = $null;
                DiskTotalGB = 0; DiskFreeGB = 0 }}
        try {{
            if (-not (Test-Path -LiteralPath $path)) {{
                $out += @{{ Index = $item.Index; Error = "Path not found" }}
                continue
            }}
            $disk = $drives | Where-Object {{ $path.StartsWith($_.Root, "OrdinalIgnoreCase") }} | Select-Object -First 1
            if ($disk) {{
                $r.DiskTotalGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
                $r.DiskFreeGB = [math]::Round($disk.Free / 1GB, 2)
            }}
            $files = @(Get-ChildItem -LiteralPath $path -Recurse -Force -File -ErrorAction SilentlyContinue)
            if ($item.Exts) {{ $files = @($files | Where-Object {{ $item.Exts -contains $_.Extension }}) }}
            if ($files) {{
                $sorted = $files | Sort-Object LastWriteTime
                $newest = $sorted | Select-Object -Last 1
                # Журналы транзакций и полные копии считаем раздельно: иначе свежий
                # .trn маскирует пропавшую полную копию — общий newest берёт максимум
                $logs = @($files | Where-Object {{ $_.Extension -eq ".trn" }})
                $fulls = @($files | Where-Object {{ $_.Extension -ne ".trn" }})
                $fullNewest = $fulls | Sort-Object LastWriteTime | Select-Object -Last 1
                $r.FileCount = $files.Count
                $r.TotalGB = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
                $r.OldestFile = U ($sorted | Select-Object -First 1)
                $r.NewestFile = U $newest
                $r.NewestFileGB = GB $newest.Length
                $r.LogCount = $logs.Count
                $r.LogNewest = U ($logs | Sort-Object LastWriteTime | Select-Object -Last 1)
                $r.FullCount = $fulls.Count
                $r.FullNewest = U $fullNewest
                $r.FullNewestGB = $(if ($fullNewest) {{ GB $fullNewest.Length }} else {{ $null }})
            }}
            $out += $r
        }} catch {{
            # Ошибка одного каталога (нет прав, отвалилась шара) не должна
            # отменять остальные: они в этом же вызове
            $out += @{{ Index = $item.Index; Error = "$($_.Exception.Message)" }}
        }}
    }}

    ConvertTo-Json @($out) -Depth 4 -Compress
    """


def _ps_items_json(targets: list) -> str:
    return json.dumps([
        {"Index": index, "Path": path, "Exts": EXTENSIONS.get(backup_type, [])}
        for index, (backup_type, path) in enumerate(targets)
    ], ensure_ascii=False)


def _ps_scan_chunks(targets: list) -> list:
    """Режет список каталогов так, чтобы каждый скрипт влезал в командную
    строку WinRM (8000 символов после кодирования)."""
    chunks = []
    current = []
    for target in targets:
        candidate = current + [target]
        if current and not ps_fits(_ps_scan_script(_ps_items_json(candidate))):
            chunks.append(current)
            current = [target]
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def _parse_ps_metrics(data: dict) -> dict:
    if data.get("Error"):
        raise RuntimeError(data["Error"])

    def parse_dt(s):
        if not s:
            return None
        # PowerShell отдаёт LastWriteTime.ToUniversalTime() — значение уже в UTC
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")

    newest_gb = data.get("NewestFileGB")

    return {
        "file_count":    int(data.get("FileCount", 0)),
        "total_size_gb": float(data.get("TotalGB", 0)),
        "oldest_file":   parse_dt(data.get("OldestFile")),
        "newest_file":   parse_dt(data.get("NewestFile")),
        "newest_file_gb": float(newest_gb) if newest_gb is not None else None,
        "log_count":      int(data.get("LogCount", 0) or 0),
        "log_newest":     parse_dt(data.get("LogNewest")),
        "full_count":     int(data.get("FullCount", 0) or 0),
        "full_newest":    parse_dt(data.get("FullNewest")),
        "full_newest_gb": (float(data["FullNewestGB"])
                           if data.get("FullNewestGB") is not None else None),
        "disk_total_gb": float(data.get("DiskTotalGB", 0)),
        "disk_free_gb":  float(data.get("DiskFreeGB", 0)),
    }


def collect_backup_paths(host: str, targets: list, username: str = None,
                         password: str = None) -> dict:
    """Метрики сразу всех каталогов сервера — одной сессией WinRM.

    targets — [(backup_type, backup_path), ...]. Возвращает
    {(type, path): метрики | Exception}.

    Раньше на каждый каталог открывалась своя сессия: рукопожатие, NTLM,
    запуск powershell.exe. На сервере с десятком путей постоянные расходы
    занимали больше времени, чем сам обход каталогов.
    """
    results = {}
    for chunk in _ps_scan_chunks(targets):
        try:
            raw = run_ps(host, _ps_scan_script(_ps_items_json(chunk)),
                         username, password)
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                # ConvertTo-Json разворачивает массив из одного элемента
                data = [data]
        except Exception as e:
            # Не достучались вообще — ошибка общая для всей пачки
            for target in chunk:
                results[target] = e
            continue

        by_index = {int(row.get("Index", -1)): row for row in data}
        for index, target in enumerate(chunk):
            row = by_index.get(index)
            if row is None:
                results[target] = RuntimeError("Сервер не вернул метрики каталога")
                continue
            try:
                results[target] = _parse_ps_metrics(row)
            except Exception as e:
                results[target] = e
    return results


def collect_backup_path(host: str, backup_path: str, backup_type: str,
                         username: str = None, password: str = None) -> dict:
    """Метрики одного каталога бэкапов через PowerShell."""
    key = (backup_type, backup_path)
    result = collect_backup_paths(host, [key], username, password)[key]
    if isinstance(result, Exception):
        raise result
    return result


# ─── SSH: метрики папки бэкапов (Linux / Synology NAS) ───────

def _sh_quote(value: str) -> str:
    """Путь в одинарных кавычках для sh: пробелы и кириллица не ломают команду."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def _ssh_scan_block(backup_path: str, backup_type: str) -> str:
    """Кусок shell-скрипта, считающий метрики одного каталога.

    Вынесен отдельно, потому что используется дважды: сам по себе (один
    путь — один вызов) и склеенным в пакет, когда у сервера каталогов
    много и открывать SSH-сессию на каждый расточительно.

    Считаем прямо в shell (find + stat + awk), наружу отдаём одну
    JSON-строку — не тащим список файлов целиком, каталог может быть
    большим."""
    exts = EXTENSIONS.get(backup_type, [])
    if exts:
        conditions = " -o ".join(f"-iname '*{e}'" for e in exts)
        ext_filter = f"\\( {conditions} \\)"
    else:
        ext_filter = ""

    path_q = _sh_quote(backup_path)
    # stat -c есть и в GNU coreutils, и в busybox (DSM); df -Pk не переносит строки.
    # @eaDir — служебные метаданные Synology, #recycle — корзина шары: без
    # -prune туда бы заходил find, и удалённый бэкап из корзины считался бы
    # живым (завышенный объём и ложно свежий newest_file).
    # Ветка else вместо `exit 0`: в пакете из нескольких каталогов выход
    # оборвал бы обход на первом же отсутствующем пути.
    return f"""
P={path_q}
if [ ! -d "$P" ]; then echo '{{"Error":"Path not found"}}'; else
DISK=$(df -Pk "$P" 2>/dev/null | awk 'NR==2 {{print $2" "$4}}')
find "$P" \\( -name '@eaDir' -o -name '#recycle' -o -name '.snapshot' \\) -prune \\
    -o -type f {ext_filter} -exec stat -c '%Y %s %n' {{}} + 2>/dev/null | awk -v disk="$DISK" '
BEGIN {{ c=0; sum=0; oldest=""; newest=""; nsize=0; lc=0; lnewest=""; fc=0; fnewest=""; fnsize=0 }}
{{
    c++; sum += $2
    if (oldest == "" || $1 < oldest) oldest = $1
    if (newest == "" || $1 > newest) {{ newest = $1; nsize = $2 }}
    # Расширение берём по концу всей строки: путь может содержать пробелы,
    # поэтому по номеру поля его не достать
    if ($0 ~ /\\.[Tt][Rr][Nn]$/) {{
        lc++; if (lnewest == "" || $1 > lnewest) lnewest = $1
    }} else {{
        fc++; if (fnewest == "" || $1 > fnewest) {{ fnewest = $1; fnsize = $2 }}
    }}
}}
END {{
    split(disk, d, " ")
    printf "{{\\"FileCount\\":%d,\\"TotalBytes\\":%.0f,\\"Oldest\\":%s,\\"Newest\\":%s,\\"NewestBytes\\":%.0f,\\"LogCount\\":%d,\\"LogNewest\\":%s,\\"FullCount\\":%d,\\"FullNewest\\":%s,\\"FullNewestBytes\\":%.0f,\\"DiskTotalKB\\":%.0f,\\"DiskFreeKB\\":%.0f}}",
        c, sum, (oldest == "" ? 0 : oldest), (newest == "" ? 0 : newest), nsize,
        lc, (lnewest == "" ? 0 : lnewest), fc, (fnewest == "" ? 0 : fnewest), fnsize, d[1], d[2]
}}'
fi
"""


def _parse_ssh_metrics(output: str) -> dict:
    """JSON от _ssh_scan_block → те же ключи, что отдаёт WinRM-ветка."""
    output = (output or "").strip()
    if not output:
        # find не нашёл ни одного файла — awk не печатает ничего
        raise RuntimeError("Пустой ответ от сервера")

    data = json.loads(output)
    if data.get("Error"):
        raise RuntimeError(data["Error"])

    def to_dt(epoch):
        epoch = int(epoch or 0)
        if not epoch:
            return None
        # naive UTC — как отдаёт PowerShell в Windows-ветке
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)

    gb = 1024 ** 3
    newest_bytes = float(data.get("NewestBytes") or 0)
    return {
        "file_count":     int(data.get("FileCount", 0)),
        "total_size_gb":  round(float(data.get("TotalBytes") or 0) / gb, 2),
        "oldest_file":    to_dt(data.get("Oldest")),
        "newest_file":    to_dt(data.get("Newest")),
        "newest_file_gb": round(newest_bytes / gb, 3) if newest_bytes else None,
        "log_count":      int(data.get("LogCount", 0) or 0),
        "log_newest":     to_dt(data.get("LogNewest")),
        "full_count":     int(data.get("FullCount", 0) or 0),
        "full_newest":    to_dt(data.get("FullNewest")),
        "full_newest_gb": (round(float(data["FullNewestBytes"]) / gb, 3)
                           if data.get("FullNewestBytes") else None),
        "disk_total_gb":  round(float(data.get("DiskTotalKB") or 0) / 1024 / 1024, 2),
        "disk_free_gb":   round(float(data.get("DiskFreeKB") or 0) / 1024 / 1024, 2),
    }


def _run_ssh_on_server(server: dict, script: str) -> str:
    return run_ssh(
        server["host"], script,
        server.get("username"), server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
    )


def collect_backup_path_ssh(server: dict, backup_path: str, backup_type: str) -> dict:
    """Те же метрики, что collect_backup_path, но по SSH — для каталогов,
    лежащих на Linux/NAS (например, Synology, куда копии приезжают по FTP).

    Сетевую шару правильнее опрашивать на самом хранилище: подключённый на
    Windows сетевой диск (Y:, Z:) виден только в сессии того пользователя,
    который его подключил, и через WinRM недоступен в принципе."""
    output = _run_ssh_on_server(server, _ssh_scan_block(backup_path, backup_type))
    return _parse_ssh_metrics(output)


# Маркер между ответами в пакетном обходе. Одна строка на каталог: сам ответ
# awk печатает без перевода строки, поэтому границы нужны явные.
SSH_BATCH_MARKER = "###AGENTMON"


def collect_backup_paths_ssh(server: dict, targets: list) -> dict:
    """Метрики сразу всех каталогов сервера за одну SSH-сессию.

    targets — [(backup_type, backup_path), ...]. Возвращает
    {(type, path): метрики | Exception}: ошибка одного каталога не должна
    отменять остальные.

    Зачем: на хранилище бэкапов путей бывает полтора десятка, а каждая
    сессия — это TCP, обмен ключами и аутентификация. Сам обход каталога
    от этого не ускоряется, но постоянные накладные расходы исчезают.
    """
    if not targets:
        return {}

    blocks = []
    for index, (backup_type, backup_path) in enumerate(targets):
        blocks.append(f'echo "{SSH_BATCH_MARKER} {index}"')
        blocks.append(_ssh_scan_block(backup_path, backup_type))
        blocks.append("echo")
    output = _run_ssh_on_server(server, "\n".join(blocks))

    chunks = {}
    current = None
    for line in (output or "").splitlines():
        if line.startswith(SSH_BATCH_MARKER):
            try:
                current = int(line.split()[-1])
            except ValueError:
                current = None
            if current is not None:
                chunks[current] = []
            continue
        if current is not None:
            chunks[current].append(line)

    results = {}
    for index, (backup_type, backup_path) in enumerate(targets):
        key = (backup_type, backup_path)
        raw = "\n".join(chunks.get(index, []))
        try:
            results[key] = _parse_ssh_metrics(raw)
        except Exception as e:
            results[key] = e
    return results


# ─── Сбои резервного копирования по данным SQL ───────────────

# Окно поиска: сутки. Больше не нужно — алерт шлётся один раз на событие,
# а старые сбои уже разобраны.
BACKUP_FAIL_WINDOW_HOURS = 24


def check_mssql_backup_failures(server: dict, data: dict = None):
    """Читает ошибки бэкапа из ERRORLOG и истории джоб, шлёт алерт на новые.

    Отдельная проверка нужна потому, что файловый мониторинг видит только
    отсутствие свежей копии и срабатывает через backup_alert_hours — то
    есть на сутки позже. SQL знает о сбое сразу и называет причину.
    """
    from mssql_log import (
        read_backup_errors, summarize_job_message, explain_backup_error,
        JOB_MESSAGE_TRUNCATED,
    )

    name = server["name"]
    # data передают, когда чтение уже сделано заранее — сбор с серверов идёт
    # параллельно, а разбор и алерты остаются в один поток
    if data is None:
        data = read_backup_errors(server, hours=BACKUP_FAIL_WINDOW_HOURS)
    events = []

    for row in data.get("engine", []):
        when = row.get("d") or ""
        text = " ".join((row.get("t") or "").split())[:300]
        if text:
            events.append({"key": f"e|{when}|{text[:80]}", "when": when,
                           "text": text,
                           "why": explain_backup_error(row.get("t") or "")})

    for row in data.get("jobs", []):
        when = row.get("when") or ""
        job = row.get("job") or ""
        step = row.get("stepname") or f"шаг {row.get('step')}"
        # Вывод шага плана обслуживания начинается с шапки dtexec, а сама
        # ошибка лежит дальше — обрезка по первым символам показывала шапку.
        raw = row.get("msg") or ""
        message = summarize_job_message(raw, limit=250)
        events.append({
            "key": f"j|{when}|{job}|{row.get('step')}",
            "when": when,
            "text": f"джоб «{job}», {step}: {message}" if message
                    else f"джоб «{job}», {step}",
            # Причина есть в тексте — объясняем её. Если в истории осталась
            # одна шапка dtexec, вместо молчания говорим, где смотреть.
            "why": (explain_backup_error(raw)
                    or (JOB_MESSAGE_TRUNCATED if raw and not message else "")),
        })

    if events:
        print(f"  ❌ Сбоев бэкапа по данным SQL: {len(events)}", flush=True)
    check_backup_failure_alerts(name, events)

    # Недоступность источника (нет прав, недоступен msdb) молчаливо не
    # прячем: иначе «алертов нет» будет означать «мы просто не смотрели».
    for problem in data.get("errors", []):
        print(f"  ⚠️ Проверка сбоев бэкапа: {problem}", flush=True)


# ─── WinRM: размеры MSSQL баз ────────────────────────────────

def collect_mssql_sizes(host: str, username: str = None, password: str = None) -> list:
    """
    Возвращает список (db_name, size_gb) для пользовательских баз MSSQL.
    """
    script = r"""
    $result = Invoke-Sqlcmd -Query "
        SELECT
            d.name AS dbname,
            CAST(SUM(mf.size) * 8.0 / 1024.0 / 1024.0 AS DECIMAL(18,2)) AS size_gb
        FROM sys.master_files mf
        JOIN sys.databases d ON d.database_id = mf.database_id
        WHERE d.database_id > 4
          AND d.source_database_id IS NULL
          AND LOWER(d.name) NOT LIKE '%copy%'
          AND LOWER(d.name) NOT LIKE N'%коп%'
          AND LOWER(d.name) NOT LIKE '%backup%'
          AND LOWER(d.name) NOT LIKE '%bak%'
          AND LOWER(d.name) NOT LIKE '%old%'
        GROUP BY d.name
        ORDER BY size_gb DESC
    " -ServerInstance "localhost" -ErrorAction Stop
    $result | Select-Object dbname, size_gb | ConvertTo-Json -Depth 2
    """
    result = run_ps(host, script, username, password)
    if not result:
        return []
    data = json.loads(result)
    if isinstance(data, dict):
        data = [data]
    return [(row["dbname"], float(row["size_gb"])) for row in data]


# ─── WinRM: размер журнала регистрации 1С ────────────────────

def collect_onec_log_path(host: str, log_path: str,
                          username: str = None, password: str = None) -> dict:
    """
    Возвращает размер каталога журнала регистрации 1С через PowerShell.
    """
    path_json = json.dumps(log_path).replace("'", "''")
    script = f"""
    $path = '{path_json}' | ConvertFrom-Json

    if (-not (Test-Path -LiteralPath $path)) {{
        @{{ Error = "Path not found" }} | ConvertTo-Json
        return
    }}

    $files = Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction SilentlyContinue

    if (-not $files) {{
        @{{
            FileCount  = 0
            TotalGB    = 0
            OldestFile = $null
            NewestFile = $null
        }} | ConvertTo-Json
        return
    }}

    $sorted  = $files | Sort-Object LastWriteTime
    $oldest  = $sorted | Select-Object -First 1
    $newest  = $sorted | Select-Object -Last 1
    $totalGB = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1GB, 2)

    @{{
        FileCount  = $files.Count
        TotalGB    = $totalGB
        OldestFile = $oldest.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        NewestFile = $newest.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    }} | ConvertTo-Json
    """

    result = run_ps(host, script, username, password)
    data = json.loads(result)

    if data.get("Error"):
        raise RuntimeError(data["Error"])

    def parse_dt(s):
        if not s:
            return None
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")

    return {
        "file_count": int(data.get("FileCount", 0)),
        "total_size_gb": float(data.get("TotalGB", 0)),
        "oldest_file": parse_dt(data.get("OldestFile")),
        "newest_file": parse_dt(data.get("NewestFile")),
    }


# ─── Сохранение в БД ─────────────────────────────────────────

def save_backup_metric(server_name: str, backup_type: str, backup_path: str, metrics: dict,
                       status: str = "ok", error: str = None):
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO backup_metrics
                    (server_name, backup_type, backup_path, file_count,
                     oldest_file, newest_file, newest_file_gb, total_size_gb,
                     disk_total_gb, disk_free_gb, status, error)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                server_name, backup_type, backup_path,
                metrics["file_count"],
                metrics["oldest_file"],
                metrics["newest_file"],
                metrics.get("newest_file_gb"),
                metrics["total_size_gb"],
                metrics["disk_total_gb"],
                metrics["disk_free_gb"],
                status,
                error,
            ))
        except errors.UndefinedColumn:
            conn.rollback()
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO backup_metrics
                        (server_name, backup_type, backup_path, file_count,
                         oldest_file, newest_file, total_size_gb, disk_total_gb, disk_free_gb,
                         status, error)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    server_name, backup_type, backup_path,
                    metrics["file_count"],
                    metrics["oldest_file"],
                    metrics["newest_file"],
                    metrics["total_size_gb"],
                    metrics["disk_total_gb"],
                    metrics["disk_free_gb"],
                    status,
                    error,
                ))
            except errors.UndefinedColumn:
                conn.rollback()
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO backup_metrics
                        (server_name, backup_type, backup_path, file_count,
                         oldest_file, newest_file, total_size_gb, disk_total_gb, disk_free_gb)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    server_name, backup_type, backup_path,
                    metrics["file_count"],
                    metrics["oldest_file"],
                    metrics["newest_file"],
                    metrics["total_size_gb"],
                    metrics["disk_total_gb"],
                    metrics["disk_free_gb"],
                ))


def get_recent_newest_sizes(server_name: str, backup_type: str, backup_path: str,
                             exclude_newest_file, limit: int) -> list:
    """Размеры последних N успешных бэкапов этого пути (по одному значению на
    уникальный newest_file, без текущего файла) — база для проверки аномалии."""
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT MAX(newest_file_gb) AS gb
                FROM backup_metrics
                WHERE server_name = %s AND backup_type = %s AND backup_path = %s
                  AND newest_file_gb IS NOT NULL AND newest_file IS NOT NULL
                  AND newest_file != %s
                GROUP BY newest_file
                ORDER BY newest_file DESC
                LIMIT %s
            """, (server_name, backup_type, backup_path, exclude_newest_file, limit))
        except errors.UndefinedColumn:
            conn.rollback()
            return []
        return [float(row[0]) for row in cur.fetchall()]


def get_last_newest_file(server_name: str, backup_type: str, backup_path: str):
    """Самый свежий известный файл бэкапа этого пути по истории в БД — не
    зависит от текущего цикла, поэтому работает и когда сервер сейчас offline
    (для проверки недельного расписания важно не терять из виду последний
    успешный бэкап, даже если WinRM сейчас недоступен)."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT MAX(newest_file)
            FROM backup_metrics
            WHERE server_name = %s AND backup_type = %s AND backup_path = %s
              AND newest_file IS NOT NULL
        """, (server_name, backup_type, backup_path))
        row = cur.fetchone()
        return row[0] if row else None


def save_db_sizes(server_name: str, sizes: list):
    with get_conn() as conn:
        cur = conn.cursor()
        for db_name, size_gb in sizes:
            cur.execute("""
                INSERT INTO database_sizes (server_name, database_name, size_gb)
                VALUES (%s, %s, %s)
            """, (server_name, db_name, size_gb))


def save_onec_log_metric(server_name: str, log_name: str, log_path: str,
                         metrics: dict, status: str = "ok", error: str = None):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO onec_log_metrics
                (server_name, log_name, log_path, total_size_gb, file_count,
                 oldest_file, newest_file, status, error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            server_name,
            log_name,
            log_path,
            metrics.get("total_size_gb"),
            metrics.get("file_count"),
            metrics.get("oldest_file"),
            metrics.get("newest_file"),
            status,
            error,
        ))


# ─── Алерты ──────────────────────────────────────────────────

# Состояние алертов хранится в файле (как остальные алерты monitor), чтобы
# не дублировать уведомления после рестарта контейнера.
# { "server:type:path": "empty"|"old"|"crit"|"warn", "server:type:path:size": "<newest_file iso>" }


def _check_weekly_schedule_alert(server_name: str, backup_type: str, backup_path: str,
                                  weekday: str, by_hour: int, now: datetime = None):
    """Немедленный алерт, если к дедлайну (weekday+by_hour, Алматы) не
    появилось новой недельной копии — не дожидаясь общего alert_hours.
    Использует историю из БД, поэтому срабатывает и если сервер сейчас offline."""
    if is_muted(server_name):
        return

    now = now or datetime.now(ALMATY)
    newest_file = get_last_newest_file(server_name, backup_type, backup_path)
    key = f"{server_name}:{backup_type}:{backup_path}:weekly"
    state = load_json(BACKUP_ALERT_STATE_FILE)

    if weekly_backup_missed(newest_file, weekday, by_hour, now):
        if alert_due(state, key, "missed"):
            mark_alert_sent(state, key, "missed")
            save_json(BACKUP_ALERT_STATE_FILE, state)
            deadline = most_recent_weekly_deadline(weekday, by_hour, now)
            deadline_label = weekday_label(weekday)
            last_seen = _fmt_local(newest_file) if newest_file else "нет данных"
            send_or_defer(
                f"🆘🆘 НЕДЕЛЬНАЯ КОПИЯ ПРОПУЩЕНА 🆘🆘\n\n"
                f"🖥 {server_name}\n"
                f"📁 {backup_path} ({backup_type})\n\n"
                f"⏰ Ожидалась к {deadline_label} {deadline.strftime('%d.%m.%Y %H:%M')} — файла нет.\n"
                f"📅 Последний известный: {last_seen}\n\n"
                f"‼️ Проверьте задание недельного бэкапа немедленно!",
                ack_key=f"backup_weekly:{server_name}:{backup_path}",
            )
    elif key in state:
        state.pop(key, None)
        save_json(BACKUP_ALERT_STATE_FILE, state)


def _check_backup_alerts(server_name: str, backup_type: str,
                          backup_path: str, metrics: dict,
                          alert_hours: int = None,
                          size_check_enabled: bool = False,
                          weekly_scheduled: bool = False,
                          ignore_logs: bool = False):
    if is_muted(server_name):
        return

    if alert_hours is None:
        alert_hours = BACKUP_ALERT_HOURS

    # "ignore_logs": true — в каталоге рядом с полными копиями лежат журналы
    # транзакций (.trn). Их делают каждые 15–60 минут, поэтому общий
    # newest_file почти всегда свежий и маскирует пропавшую полную копию.
    # Считаем только .bak: отсутствие журналов при этом никого не волнует.
    if ignore_logs:
        metrics = dict(metrics)
        metrics["file_count"] = metrics.get("full_count") or 0
        metrics["newest_file"] = metrics.get("full_newest")
        metrics["newest_file_gb"] = metrics.get("full_newest_gb")

    key = f"{server_name}:{backup_type}:{backup_path}"
    state = load_json(BACKUP_ALERT_STATE_FILE)

    if metrics["file_count"] == 0:
        if alert_due(state, key, "empty"):
            mark_alert_sent(state, key, "empty")
            save_json(BACKUP_ALERT_STATE_FILE, state)
            send_or_defer(
                f"🆘🆘 БЭКАП НЕ СОЗДАЁТСЯ 🆘🆘\n\n"
                f"🖥 {server_name}\n"
                f"📁 {backup_path} ({backup_type})\n\n"
                f"‼️ Каталог ПУСТ — файлов бэкапа нет вообще.\n"
                f"❗️ Проверьте задание бэкапа немедленно!",
                ack_key=f"backup_empty:{server_name}:{backup_path}",
            )
        return

    # Возраст последнего бэкапа (newest_file — naive UTC из PowerShell).
    # У пути с недельным расписанием возраст не показатель: копия делается раз
    # в неделю и к следующему плановому дню законно «стареет» на ~7 суток.
    # Такой путь контролирует только _check_weekly_schedule_alert по дедлайну,
    # иначе alert_hours слал бы «БЭКАП УСТАРЕЛ» каждый раз на вторые сутки.
    if metrics["newest_file"] and not weekly_scheduled:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        age_hours = (now - metrics["newest_file"]).total_seconds() / 3600
        if age_hours > alert_hours:
            age_days = round(age_hours / 24, 1)
            if alert_due(state, key, "old"):
                mark_alert_sent(state, key, "old")
                save_json(BACKUP_ALERT_STATE_FILE, state)
                send_or_defer(
                    f"🆘🆘 БЭКАП УСТАРЕЛ 🆘🆘\n\n"
                    f"🖥 {server_name}\n"
                    f"📁 {backup_path} ({backup_type})\n\n"
                    f"⏰ Свежего бэкапа нет уже {round(age_hours)} ч ({age_days} дн)\n"
                    f"📅 Последний: {_fmt_local(metrics['newest_file'])}\n\n"
                    f"‼️ Бэкапы важны — проверьте задание немедленно!",
                    ack_key=f"backup_stale:{server_name}:{backup_path}",
                )
            return

    # Место на диске под бэкапы уже покрыто общим check_disk_alert()
    # в alerts.py (тот же диск виден в WinRM-опросе всех дисков сервера).

    # Всё хорошо — сбрасываем состояние
    if key in state:
        state.pop(key, None)
        save_json(BACKUP_ALERT_STATE_FILE, state)

    # Подозрительно маленький бэкап (например, обрыв копирования по FTP):
    # сравниваем размер нового файла с медианой истории. Не раньше, чем файл
    # "устаканится" (BACKUP_SIZE_CHECK_MIN_AGE_HOURS) — иначе можно поймать
    # ещё докачивающийся большой файл.
    size_key = f"{key}:size"
    if size_check_enabled and metrics.get("newest_file_gb") is not None and metrics["newest_file"]:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        age_hours = (now - metrics["newest_file"]).total_seconds() / 3600
        if age_hours >= BACKUP_SIZE_CHECK_MIN_AGE_HOURS:
            history = get_recent_newest_sizes(
                server_name, backup_type, backup_path,
                exclude_newest_file=metrics["newest_file"],
                limit=BACKUP_SIZE_CHECK_MIN_HISTORY,
            )
            if len(history) >= BACKUP_SIZE_CHECK_MIN_HISTORY:
                baseline = statistics.median(history)
                current_gb = metrics["newest_file_gb"]
                file_marker = metrics["newest_file"].isoformat()
                if baseline > 0 and current_gb < baseline * BACKUP_SIZE_CHECK_MIN_RATIO:
                    if state.get(size_key) != file_marker:
                        state[size_key] = file_marker
                        save_json(BACKUP_ALERT_STATE_FILE, state)
                        pct = round(current_gb / baseline * 100)
                        send_or_defer(
                            f"🆘🆘 БЭКАП ПОДОЗРИТЕЛЬНО МАЛЕНЬКИЙ 🆘🆘\n\n"
                            f"🖥 {server_name}\n"
                            f"📁 {backup_path} ({backup_type})\n\n"
                            f"📦 Размер: {round(current_gb, 2)} ГБ ({pct}% от обычного)\n"
                            f"📊 Обычно: ~{round(baseline, 2)} ГБ (медиана {len(history)} посл. бэкапов)\n"
                            f"📅 Файл: {_fmt_local(metrics['newest_file'])}\n\n"
                            f"‼️ Похоже, бэкап скопирован не до конца — проверьте вручную!",
                            ack_key=f"backup_small:{server_name}:{backup_path}",
                        )
                elif state.get(size_key) == file_marker or size_key in state:
                    state.pop(size_key, None)
                    save_json(BACKUP_ALERT_STATE_FILE, state)


def _check_onec_log_alerts(server_name: str, log_name: str, log_path: str,
                           metrics: dict, warn_gb: float, crit_gb: float):
    if is_muted(server_name):
        return

    key = f"{server_name}:onec_log:{log_path}"
    total_gb = float(metrics.get("total_size_gb") or 0)
    state = load_json(BACKUP_ALERT_STATE_FILE)

    if total_gb >= crit_gb:
        level = "crit"
    elif total_gb >= warn_gb:
        level = "warn"
    else:
        if key in state:
            state.pop(key, None)
            save_json(BACKUP_ALERT_STATE_FILE, state)
        return

    if not alert_due(state, key, level):
        return

    mark_alert_sent(state, key, level)
    save_json(BACKUP_ALERT_STATE_FILE, state)
    icon = "🚨" if level == "crit" else "🟠"
    send_or_defer(
        f"{icon} Журнал регистрации 1С\n\n"
        f"🖥 Сервер: {server_name}\n"
        f"📁 {log_name}: {log_path}\n"
        f"📦 Размер: {total_gb} ГБ\n"
        f"Порог: {'критично' if level == 'crit' else 'предупреждение'} "
        f"({crit_gb if level == 'crit' else warn_gb} ГБ)",
        ack_key=f"onec_log:{server_name}:{log_name}",
    )


# ─── Основной цикл сборщика ──────────────────────────────────

def load_servers() -> list:
    with open(SERVERS_FILE) as f:
        return json.load(f)


_legacy_disk_pruned = False


def _prune_legacy_disk_keys():
    """Однократно убирает ключи вида "server:type:path:disk" — остатки
    старого алерта «диск под backup заполнен», который теперь покрыт
    общим check_disk_alert() в alerts.py."""
    global _legacy_disk_pruned
    if _legacy_disk_pruned:
        return
    _legacy_disk_pruned = True
    state = load_json(BACKUP_ALERT_STATE_FILE)
    cleaned = {k: v for k, v in state.items() if not k.endswith(":disk")}
    if len(cleaned) != len(state):
        save_json(BACKUP_ALERT_STATE_FILE, cleaned)
        print(f"[backup] Убрано устаревших :disk ключей: {len(state) - len(cleaned)}",
              flush=True)


MAX_PARALLEL_BACKUP_SERVERS = 4


def _has_backup_work(server: dict) -> bool:
    """Есть ли что собирать. Сетевому устройству доступен только ping, а
    датастор VMware — не файловая система: каталогов с копиями там нет."""
    if server_type(server) in ("device", "vmware"):
        return False
    return bool(server.get("backups") or server.get("dbsize")
                or server.get("onec_logs"))


def _backup_targets(server: dict) -> list:
    """Пути бэкапов сервера в разобранном виде: путь + все настройки,
    которые к нему применяются.

    Приоритет: своё значение у пути > значение у сервера > глобальное.
    Разбор вынесен из цикла, чтобы сбор метрик (сеть) и разбор с алертами
    (БД, файлы состояния) могли идти в разных потоках.
    """
    server_alert_hours = server.get("backup_alert_hours", BACKUP_ALERT_HOURS)
    server_size_check = bool(server.get("backup_size_check", False))
    targets = []

    for backup_type, paths in (server.get("backups") or {}).items():
        if not isinstance(paths, list):
            paths = [paths]
        for path_spec in paths:
            # Путь — либо просто строка, либо {"path": ..., "alert_hours": ...}
            # для своего времени алерта на конкретную папку.
            if isinstance(path_spec, dict):
                backup_path = path_spec.get("path")
                path_alert_hours = path_spec.get("alert_hours")
                path_size_check = path_spec.get("size_check")
                # Каталог, где рядом с полными копиями лежат журналы .trn
                path_ignore_logs = bool(path_spec.get("ignore_logs"))
            else:
                backup_path = path_spec
                path_alert_hours = None
                path_size_check = None
                path_ignore_logs = False

            if not backup_path:
                # Путь без "path" (правка servers.json руками мимо валидации)
                # ронял весь цикл сбора на backup_path.lower() ниже
                targets.append({"type": backup_type, "path": None})
                continue

            size_check = (path_size_check if path_size_check is not None
                          else server_size_check)
            # DIFF-копии по природе растут неравномерно всю неделю (после
            # очередного FULL резко "сбрасываются") — сравнение размера
            # с историей там даёт ложные срабатывания, поэтому не проверяем
            # вообще, независимо от настройки size_check.
            if "diff" in backup_path.lower():
                size_check = False

            targets.append({
                "type": backup_type,
                "path": backup_path,
                "alert_hours": (path_alert_hours if path_alert_hours is not None
                                else server_alert_hours),
                "size_check": size_check,
                "ignore_logs": path_ignore_logs,
                "schedule": path_schedule(path_spec),
            })
    return targets


def _onec_targets(server: dict) -> list:
    logs = server.get("onec_logs") or []
    if isinstance(logs, dict):
        logs = [logs]
    targets = []
    for log_spec in logs:
        if isinstance(log_spec, str):
            targets.append({"name": "1C log", "path": log_spec,
                            "warn_gb": ONEC_LOG_WARN_GB, "crit_gb": ONEC_LOG_CRIT_GB})
            continue
        log_path = log_spec.get("path")
        if not log_path:
            continue
        targets.append({
            "name": log_spec.get("name") or "1C log",
            "path": log_path,
            "warn_gb": float(log_spec.get("warn_gb", ONEC_LOG_WARN_GB)),
            "crit_gb": float(log_spec.get("crit_gb", ONEC_LOG_CRIT_GB)),
        })
    return targets


def collect_server_backups(server: dict) -> dict:
    """Удалённая часть сбора: опрос сервера и ничего больше.

    Ни записи в БД, ни файлов состояния алертов здесь нет намеренно.
    Серверы опрашиваются параллельно, а состояние алертов — общий JSON,
    который читается и переписывается целиком: параллельная запись
    потеряла бы чужие ключи. Поэтому разбор идёт отдельным шагом,
    в один поток (apply_server_backups).
    """
    kind = server_type(server)
    host = server["host"]
    collected = {
        "server": server,
        "kind": kind,
        "targets": _backup_targets(server),
        "metrics": {},
        "db_sizes": None,
        "db_sizes_error": None,
        "backup_errors": None,
        "backup_errors_error": None,
        "onec": [],
    }

    pairs = [(t["type"], t["path"]) for t in collected["targets"] if t["path"]]
    if pairs:
        try:
            if kind == "linux":
                collected["metrics"] = collect_backup_paths_ssh(server, pairs)
            else:
                collected["metrics"] = collect_backup_paths(
                    host, pairs, server.get("username"), server.get("password")
                )
        except Exception as e:
            # Сервер не отвечает вовсе — ошибка общая для всех его каталогов
            collected["metrics"] = {pair: e for pair in pairs}

    # Размеры MSSQL баз и журналы 1С — только Windows (Invoke-Sqlcmd,
    # PowerShell). На Linux/NAS их просто нет.
    if kind == "linux":
        return collected

    if server.get("dbsize"):
        try:
            collected["db_sizes"] = collect_mssql_sizes(
                host, server.get("username"), server.get("password")
            )
        except Exception as e:
            collected["db_sizes_error"] = e

        # Сбои резервного копирования по данным самого SQL. Файловая
        # проверка ловит только отсутствие свежей копии — и лишь через
        # backup_alert_hours; здесь причина видна в ту же ночь.
        try:
            from mssql_log import read_backup_errors
            collected["backup_errors"] = read_backup_errors(
                server, hours=BACKUP_FAIL_WINDOW_HOURS
            )
        except Exception as e:
            collected["backup_errors_error"] = e

    for log in _onec_targets(server):
        try:
            metrics = collect_onec_log_path(
                host, log["path"], server.get("username"), server.get("password")
            )
            collected["onec"].append((log, metrics))
        except Exception as e:
            collected["onec"].append((log, e))

    return collected


def apply_server_backups(collected: dict):
    """Разбор собранного: запись в БД, алерты, вывод в лог. Один поток."""
    server = collected["server"]
    name = server["name"]
    kind = collected["kind"]

    print(f"[backup] Проверяю: {name} ({server['host']})", flush=True)

    for target in collected["targets"]:
        backup_type, backup_path = target["type"], target["path"]
        if not backup_path:
            print(f"  ⚠️ {name}: в backups.{backup_type} есть запись без пути "
                  f"— пропускаю", flush=True)
            continue

        # Недельное расписание — отдельная проверка по истории из БД,
        # не зависит от успеха текущего опроса (важно, если сервер offline).
        if target["schedule"]:
            try:
                _check_weekly_schedule_alert(
                    name, backup_type, backup_path,
                    target["schedule"][0], target["schedule"][1]
                )
            except Exception as e:
                print(f"  ❌ weekly schedule {backup_type} {backup_path}: {e}", flush=True)

        metrics = collected["metrics"].get((backup_type, backup_path))
        if metrics is None:
            metrics = RuntimeError("Метрики не собраны")

        if isinstance(metrics, Exception):
            save_backup_metric(
                name, backup_type, backup_path,
                {
                    "file_count": None,
                    "oldest_file": None,
                    "newest_file": None,
                    "total_size_gb": None,
                    "disk_total_gb": None,
                    "disk_free_gb": None,
                },
                status="error",
                error=str(metrics),
            )
            print(f"  ❌ {backup_type} {backup_path}: {metrics}", flush=True)
            continue

        save_backup_metric(name, backup_type, backup_path, metrics, status="ok")
        _check_backup_alerts(
            name, backup_type, backup_path, metrics,
            target["alert_hours"], target["size_check"],
            weekly_scheduled=bool(target["schedule"]),
            ignore_logs=target["ignore_logs"],
        )
        print(
            f"  [{backup_type}] {backup_path}: "
            f"{metrics['file_count']} файлов, "
            f"{metrics['total_size_gb']} ГБ, "
            f"диск свободно: {metrics['disk_free_gb']} ГБ",
            flush=True
        )

    if kind == "linux":
        if server.get("dbsize"):
            print(f"  ⏭ {name}: dbsize только для Windows, пропускаю", flush=True)
        if server.get("onec_logs"):
            print(f"  ⏭ {name}: журналы 1С только для Windows, пропускаю", flush=True)
        return

    if server.get("dbsize"):
        if collected["db_sizes_error"]:
            print(f"  ❌ MSSQL dbsize: {collected['db_sizes_error']}", flush=True)
        elif collected["db_sizes"] is not None:
            save_db_sizes(name, collected["db_sizes"])
            print(f"  🗄 MSSQL: {len(collected['db_sizes'])} баз", flush=True)

        if collected["backup_errors_error"]:
            print(f"  ❌ MSSQL backup errors: {collected['backup_errors_error']}",
                  flush=True)
        elif collected["backup_errors"] is not None:
            try:
                check_mssql_backup_failures(server, data=collected["backup_errors"])
            except Exception as e:
                print(f"  ❌ MSSQL backup errors: {e}", flush=True)

    for log, metrics in collected["onec"]:
        if isinstance(metrics, Exception):
            save_onec_log_metric(
                name, log["name"], log["path"],
                {"total_size_gb": None, "file_count": None,
                 "oldest_file": None, "newest_file": None},
                status="error", error=str(metrics),
            )
            print(f"  ❌ 1C log {log['path']}: {metrics}", flush=True)
            continue

        save_onec_log_metric(name, log["name"], log["path"], metrics)
        _check_onec_log_alerts(name, log["name"], log["path"], metrics,
                               log["warn_gb"], log["crit_gb"])
        print(
            f"  📒 1C log {log['path']}: "
            f"{metrics['total_size_gb']} ГБ, {metrics['file_count']} файлов",
            flush=True
        )


def _collect_safe(server: dict) -> dict:
    """Сбор одного сервера в потоке: своя авария не должна ронять пул."""
    try:
        return collect_server_backups(server)
    except Exception as e:
        print(f"[backup] ❌ {server.get('name')}: сбор не выполнен: {e}", flush=True)
        return {"server": server, "kind": server_type(server), "targets": [],
                "metrics": {}, "db_sizes": None, "db_sizes_error": e,
                "backup_errors": None, "backup_errors_error": e, "onec": []}


def run_backup_cycle(on_progress=None):
    """Обход каталогов бэкапов: серверы опрашиваются параллельно, разбор
    и алерты идут по очереди.

    Раньше цикл был полностью последовательным, и на каждый путь открывалась
    своя сессия WinRM/SSH: полсотни рукопожатий подряд занимали больше
    времени, чем сам обход каталогов.

    on_progress вызывается после каждого разобранного сервера — монитор
    обновляет им heartbeat, чтобы долгий обход не выглядел зависшим.
    """
    _prune_legacy_disk_keys()
    try:
        servers = load_servers()
    except Exception as e:
        print(f"[backup] Не могу прочитать {SERVERS_FILE}: {e}", flush=True)
        return

    work = [server for server in servers if _has_backup_work(server)]
    if not work:
        print("[backup] Цикл завершён", flush=True)
        return

    with ThreadPoolExecutor(
        max_workers=min(MAX_PARALLEL_BACKUP_SERVERS, len(work))
    ) as pool:
        for collected in pool.map(_collect_safe, work):
            try:
                apply_server_backups(collected)
            except Exception as e:
                print(f"[backup] ❌ {collected['server'].get('name')}: "
                      f"разбор не выполнен: {e}", flush=True)
            if on_progress:
                on_progress()

    print("[backup] Цикл завершён", flush=True)
