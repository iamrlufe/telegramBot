"""
shared/backup_verify.py

RESTORE VERIFYONLY для последнего .bak в каталоге — общая логика для monitor
(ежесуточный автозапуск, backup_maintenance.py) и bot (ручной запуск по
кнопке, backup_bot_db.py).
"""
import json
from datetime import datetime

from pgconn import get_conn
from winrm_client import run_ps, ps_json, PS_OUT_B64_HELPER

# RESTORE VERIFYONLY читает весь файл бэкапа — на больших базах это долго
VERIFY_QUERY_TIMEOUT_SEC = 7200
VERIFY_READ_TIMEOUT_SEC = 7300
VERIFY_OPERATION_TIMEOUT_SEC = 7200


def path_str(item) -> str | None:
    """Путь из элемента backups.<type>: сам item (строка), либо item['path']
    для объектной формы {"path": ..., "alert_hours": ..., "size_check": ...}."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return item.get("path")
    return None


def verify_newest_bak(host: str, backup_path: str,
                      username: str = None, password: str = None) -> dict:
    """
    Находит самый новый .bak в каталоге и выполняет RESTORE VERIFYONLY.
    Возвращает {status, file, size_gb, modified, duration_sec, error}.
    """
    path_json = json.dumps(backup_path).replace("'", "''")
    script = f"""
    {PS_OUT_B64_HELPER}
    $path = '{path_json}' | ConvertFrom-Json
    if (-not (Test-Path -LiteralPath $path)) {{
        Out-B64 @{{ Status = "error"; Error = "Path not found" }}
        return
    }}
    $bak = Get-ChildItem -LiteralPath $path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Extension.ToLowerInvariant() -eq ".bak" }} |
        Sort-Object LastWriteTime |
        Select-Object -Last 1
    if (-not $bak) {{
        Out-B64 @{{ Status = "no_bak" }}
        return
    }}
    $file = $bak.FullName
    $escaped = $file -replace "'", "''"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {{
        Invoke-Sqlcmd -ServerInstance "localhost" `
            -Query "RESTORE VERIFYONLY FROM DISK = N'$escaped'" `
            -QueryTimeout {VERIFY_QUERY_TIMEOUT_SEC} -ErrorAction Stop | Out-Null
        $sw.Stop()
        Out-B64 @{{
            Status = "ok"
            File = $file
            SizeGB = [math]::Round($bak.Length / 1GB, 2)
            Modified = $bak.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            DurationSec = [math]::Round($sw.Elapsed.TotalSeconds, 0)
        }}
    }} catch {{
        $sw.Stop()
        Out-B64 @{{
            Status = "failed"
            File = $file
            SizeGB = [math]::Round($bak.Length / 1GB, 2)
            Modified = $bak.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            DurationSec = [math]::Round($sw.Elapsed.TotalSeconds, 0)
            Error = $_.Exception.Message
        }}
    }}
    """
    result = run_ps(
        host, script, username, password,
        operation_timeout_sec=VERIFY_OPERATION_TIMEOUT_SEC,
        read_timeout_sec=VERIFY_READ_TIMEOUT_SEC
    )
    data = ps_json(result)   # base64(UTF-8): русские ошибки SQL не теряются

    def parse_dt(s):
        if not s:
            return None
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")

    return {
        "status": data.get("Status", "error"),
        "file": data.get("File"),
        "size_gb": float(data["SizeGB"]) if data.get("SizeGB") is not None else None,
        "modified": parse_dt(data.get("Modified")),
        "duration_sec": int(data["DurationSec"]) if data.get("DurationSec") is not None else None,
        "error": data.get("Error"),
    }


def save_verification(server_name: str, backup_path: str, res: dict):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO backup_verifications
                (server_name, backup_path, file_path, file_size_gb,
                 file_modified, status, error, duration_sec)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            server_name,
            backup_path,
            res.get("file"),
            res.get("size_gb"),
            res.get("modified"),
            res.get("status"),
            res.get("error"),
            res.get("duration_sec"),
        ))
