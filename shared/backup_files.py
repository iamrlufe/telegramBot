"""
shared/backup_files.py

Листинг и безопасное удаление backup-файлов.

Windows — через WinRM/PowerShell, Linux и NAS (Synology) — по SSH.
Используется ботом (ручной Cleanup) и монитором (автоочистка по
retention_days; она остаётся только для Windows — см. backup_maintenance).
"""
import json
import os
from datetime import datetime, timezone

from server_check import server_type
from winrm_client import run_ps

# Расширения которые разрешено удалять
DELETABLE_EXTENSIONS = {".bak", ".trn", ".dt", ".zip"}
# Типы бэкапов которые нельзя удалять
NO_DELETE_TYPES = {"veeam"}


def deletable_backup_targets(server: dict) -> list[dict]:
    """
    Пути сервера, из которых разрешено удалять: [{"type", "path", "disk"}].

    Порядок стабильный (как в servers.json) — бот использует индекс в этом
    списке как компактный идентификатор в callback_data кнопок, чтобы не
    тащить длинный путь в ограниченные 64 байта Telegram.
    """
    targets = []
    for backup_type, paths in (server.get("backups") or {}).items():
        if backup_type in NO_DELETE_TYPES:
            continue
        if not isinstance(paths, list):
            paths = [paths]
        for raw_path in paths:
            backup_path = raw_path["path"] if isinstance(raw_path, dict) else raw_path
            if not backup_path:
                continue
            targets.append({
                "type": backup_type,
                "path": backup_path,
                "disk": disk_of_path(backup_path),
            })
    return targets


def disk_of_path(backup_path: str) -> str:
    """"E:\\Backups\\SQL" → "E:". UNC-путь (\\\\srv\\share) → "\\\\srv\\share".
    Linux/NAS "/volume1/1ast/Buh" → "/volume1" (том Synology).

    Без ветки для POSIX возвращался весь путь целиком, и в карточке сервера
    он печатался дважды — и как «диск», и как путь."""
    path = str(backup_path or "").strip()
    if path.startswith("\\\\"):
        parts = [p for p in path.strip("\\").split("\\") if p]
        return "\\\\" + "\\".join(parts[:2]) if len(parts) >= 2 else path
    if len(path) >= 2 and path[1] == ":":
        return path[:2].upper()
    if path.startswith("/"):
        parts = [p for p in path.split("/") if p]
        return "/" + parts[0] if parts else "/"
    return path


def _sh_quote(value: str) -> str:
    """Путь в одинарных кавычках для sh: пробелы и кириллица не ломают команду."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def _is_linux(server: dict) -> bool:
    return server_type(server) == "linux"


def _norm_win_path(path: str) -> str:
    """Windows-путь к сравнимому виду: единый разделитель, без хвостового
    слэша, регистр не важен (на Windows «E:\\Backups» == «e:/backups»)."""
    return str(path or "").replace("/", "\\").rstrip("\\").lower()


def inside_backup_roots(server: dict, path: str) -> bool:
    """True, если path лежит внутри одного из backup-каталогов конфига.

    Общая защита для обеих платформ: список файлов на удаление приходит из
    БД/предпросмотра, и без этой проверки протухшая или подменённая запись
    позволила бы стереть любой .bak на сервере. Раньше проверка была только
    в SSH-ветке, хотя справка и readme обещали её для всех серверов.
    """
    if _is_linux(server):
        roots = [t["path"].rstrip("/") for t in deletable_backup_targets(server)
                 if str(t["path"]).startswith("/")]
        return any(path == root or path.startswith(root + "/") for root in roots)

    target = _norm_win_path(path)
    for entry in deletable_backup_targets(server):
        root = _norm_win_path(entry["path"])
        if root and (target == root or target.startswith(root + "\\")):
            return True
    return False


def list_backup_files(server: dict, backup_path: str,
                      older_than: str = None,
                      extensions: set[str] = None) -> list:
    """
    Возвращает список файлов рекурсивно из backup_path.
    Каждый файл: {file_name, full_path, size_gb, modified}
    modified — naive UTC строкой "yyyy-MM-dd HH:mm:ss".
    """
    if _is_linux(server):
        return _list_backup_files_ssh(server, backup_path, older_than, extensions)
    return _list_backup_files_windows(server, backup_path, older_than, extensions)


def _list_backup_files_ssh(server: dict, backup_path: str,
                           older_than: str = None,
                           extensions: set[str] = None) -> list:
    """Листинг по SSH. Служебные каталоги Synology исключаются: без этого
    в предпросмотр очистки попали бы файлы из корзины шары (#recycle)."""
    from linux_check import run_ssh

    extensions = sorted(extensions or DELETABLE_EXTENSIONS)
    conditions = " -o ".join(f"-iname '*{e}'" for e in extensions)
    script = f"""
P={_sh_quote(backup_path)}
[ -d "$P" ] || exit 0
find "$P" \\( -name '@eaDir' -o -name '#recycle' -o -name '.snapshot' \\) -prune \\
    -o -type f \\( {conditions} \\) -exec stat -c '%Y %s %n' {{}} + 2>/dev/null
"""
    output = run_ssh(
        server["host"], script,
        server.get("username"), server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
    )

    cutoff = None
    if older_than:
        cutoff = datetime.strptime(older_than, "%Y-%m-%d %H:%M:%S")

    files = []
    for line in (output or "").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue                     # имя с переводом строки — пропускаем
        epoch, size, full_path = parts
        try:
            modified = datetime.fromtimestamp(int(epoch), tz=timezone.utc) \
                .replace(tzinfo=None)
            size_bytes = int(size)
        except ValueError:
            continue
        if cutoff and modified >= cutoff:
            continue
        files.append({
            "file_name": os.path.basename(full_path),
            "full_path": full_path,
            "size_gb": round(size_bytes / 1024 ** 3, 4),
            "modified": modified.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return files


def _list_backup_files_windows(server: dict, backup_path: str,
                               older_than: str = None,
                               extensions: set[str] = None) -> list:
    host = server["host"]
    username = server.get("username")
    password = server.get("password")
    extensions = sorted(extensions or DELETABLE_EXTENSIONS)
    extensions_json = json.dumps(extensions)
    # older_than приходит из Python как naive UTC — сравниваем
    # с LastWriteTime.ToUniversalTime(), т.к. на Windows-серверах локальное время
    cutoff_filter = ""
    if older_than:
        cutoff_filter = f"""
    $cutoff = [datetime]::ParseExact('{older_than}', 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    $files = $files | Where-Object {{ $_.LastWriteTime.ToUniversalTime() -lt $cutoff }}
"""

    path_json = json.dumps(backup_path).replace("'", "''")
    script = f"""
    $path = '{path_json}' | ConvertFrom-Json
    $extensions = '{extensions_json}' | ConvertFrom-Json
    if (-not (Test-Path -LiteralPath $path)) {{
        "[]"
        return
    }}
    $files = Get-ChildItem -LiteralPath $path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object {{ $extensions -contains $_.Extension.ToLowerInvariant() }}
{cutoff_filter}
    $files = $files |
        Select-Object Name, FullName,
            @{{N="SizeGB";  E={{[math]::Round($_.Length / 1GB, 4)}}}},
            @{{N="Modified"; E={{$_.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")}}}}
    if ($files) {{ $files | ConvertTo-Json -Depth 2 }} else {{ "[]" }}
    """
    result = run_ps(host, script, username, password)
    if not result or result.strip() == "[]":
        return []

    data = json.loads(result)
    if isinstance(data, dict):
        data = [data]

    return [
        {
            "file_name":  f["Name"],
            "full_path":  f["FullName"],
            "size_gb":    float(f["SizeGB"]),
            "modified":   f["Modified"],
        }
        for f in data
    ]


def delete_backup_files(server: dict, file_paths: list) -> list:
    """
    Удаляет файлы на удалённом хосте.
    Проверяет расширение перед удалением (защита).
    Возвращает список (full_path, ok, error).
    """
    if _is_linux(server):
        return _delete_backup_files_ssh(server, file_paths)
    return _delete_backup_files_windows(server, file_paths)


def _delete_backup_files_ssh(server: dict, file_paths: list) -> list:
    """Удаление по SSH.

    Кроме проверки расширения здесь есть и проверка вхождения: путь обязан
    лежать внутри одного из backup-каталогов конфига. На Windows это
    гарантируется тем, что список файлов строится из тех же каталогов, но
    здесь команда собирается в shell, и цена ошибки выше — поэтому
    подстраховываемся явно."""
    from linux_check import run_ssh

    results = []
    safe_paths = []
    for path in file_paths:
        if os.path.splitext(path)[1].lower() not in DELETABLE_EXTENSIONS:
            results.append((path, False, "Запрещённое расширение"))
        elif not inside_backup_roots(server, path):
            results.append((path, False, "Путь вне backup-каталогов конфига"))
        else:
            safe_paths.append(path)

    print(
        f"[backup] Удаление по SSH: host={server.get('host')}, "
        f"файлов={len(file_paths)}, разрешено={len(safe_paths)}",
        flush=True
    )
    if not safe_paths:
        return results

    # Пакетами — чтобы не упереться в предел длины командной строки
    if len(safe_paths) > 20:
        for i in range(0, len(safe_paths), 20):
            results.extend(_delete_backup_files_ssh(server, safe_paths[i:i + 20]))
        return results

    quoted = " ".join(_sh_quote(p) for p in safe_paths)
    # rm -f возвращает 0 и для несуществующего файла, поэтому факт удаления
    # проверяем отдельно через -e: иначе «успех» ничего не значил бы
    script = f"""
for p in {quoted}; do
  err=$(rm -f -- "$p" 2>&1)
  if [ -e "$p" ]; then
    printf 'ERR\\t%s\\t%s\\n' "$p" "${{err:-файл не удалён}}"
  else
    printf 'OK\\t%s\\n' "$p"
  fi
done
"""
    try:
        output = run_ssh(
            server["host"], script,
            server.get("username"), server.get("password"),
            port=int(server.get("ssh_port") or 22),
            key_path=server.get("ssh_key"),
        )
    except Exception as e:
        print(f"[backup] Ошибка удаления на {server.get('host')}: {e}", flush=True)
        return results + [(p, False, str(e)) for p in safe_paths]

    reported = {}
    for line in (output or "").splitlines():
        parts = line.rstrip("\n").split("\t")
        if parts[0] == "OK" and len(parts) >= 2:
            reported[parts[1]] = (True, "")
        elif parts[0] == "ERR" and len(parts) >= 3:
            reported[parts[1]] = (False, parts[2])

    for path in safe_paths:
        ok, err = reported.get(path, (False, "Нет ответа"))
        results.append((path, ok, err))
    return results


def _delete_backup_files_windows(server: dict, file_paths: list) -> list:
    host = server["host"]
    username = server.get("username")
    password = server.get("password")
    # Фильтруем: разрешённое расширение И путь внутри backup-каталогов конфига
    results = []
    safe_paths = []
    for p in file_paths:
        if os.path.splitext(p)[1].lower() not in DELETABLE_EXTENSIONS:
            results.append((p, False, "Запрещённое расширение"))
        elif not inside_backup_roots(server, p):
            results.append((p, False, "Путь вне backup-каталогов конфига"))
        else:
            safe_paths.append(p)

    print(
        f"[backup] Удаление: host={host}, файлов={len(file_paths)}, "
        f"разрешено={len(safe_paths)}",
        flush=True
    )

    if not safe_paths:
        return results
    # Разбиваем на пакеты по 20 файлов
    if len(safe_paths) > 20:
        final_results = results.copy()

        for i in range(0, len(safe_paths), 20):
            chunk = safe_paths[i:i + 20]

            final_results.extend(_delete_backup_files_windows(server, chunk))

        return final_results

    paths_json = json.dumps(safe_paths).replace("'", "''")
    script = f"""
    $paths = '{paths_json}' | ConvertFrom-Json
    $results = @()
    foreach ($path in $paths) {{
        try {{
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $results += [PSCustomObject]@{{ Path=$path; OK=$true; Error="" }}
        }} catch {{
            $results += [PSCustomObject]@{{ Path=$path; OK=$false; Error=$_.Exception.Message }}
        }}
    }}
    $results | ConvertTo-Json -Depth 2
    """

    try:
        result = run_ps(host, script, username, password)

        if not result:
            return results + [(p, False, "Нет ответа") for p in safe_paths]

        data = json.loads(result)
        if isinstance(data, dict):
            data = [data]

        results += [
            (row["Path"], bool(row["OK"]), row.get("Error", ""))
            for row in data
        ]
    except Exception as e:
        print(f"[backup] Ошибка удаления на {host}: {e}", flush=True)
        results += [(p, False, str(e)) for p in safe_paths]

    return results
