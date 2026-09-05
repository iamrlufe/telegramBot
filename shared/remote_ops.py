"""
shared/remote_ops.py

Разовые удалённые операции по запросу из бота (кнопки в алертах):
- get_top_dirs: самые тяжёлые каталоги диска («кто съел место»);
- restart_service: перезапуск Windows-службы / systemd-юнита;
- reboot_server: перезагрузка сервера (с опциональным импортом .reg).

Для systemctl restart на Linux пользователю мониторинга нужна
sudo-запись без пароля, например в /etc/sudoers.d/monitoring:
    monitoring ALL=(root) NOPASSWD: /usr/bin/systemctl restart *
Для перезагрузки Linux — дополнительно:
    monitoring ALL=(root) NOPASSWD: /sbin/shutdown
Чтобы get_top_dirs видел весь диск, а не только читаемое пользователем:
    monitoring ALL=(root) NOPASSWD: /usr/bin/du
"""
import shlex

from server_check import server_type
from winrm_client import run_ps, ps_json

TOP_DIRS_LIMIT = 10

# Каталоги корня (размер) + крупные файлы прямо в корне:
# на дисках под бэкапы/VHD файлы часто лежат в корне без подпапок.
#
# Размер папок считается через robocopy /L (только листинг, ничего не копирует):
# он перечисляет дерево в разы быстрее, чем Get-ChildItem -Recurse | Measure-Object,
# и не спотыкается на access-denied — критично для дисков под бэкапы с миллионами
# файлов, где рекурсивный подсчёт в PowerShell фактически зависает.
# Скрипт возвращает и диагностику (счётчики, первая ошибка), чтобы пустой
# результат превращался в понятную причину, а не в «не найдено».
_WIN_TOP_DIRS_TEMPLATE = r"""
    # Одинарные кавычки, а не двойные: в двойных PowerShell разворачивает
    # переменные, и стандартная папка C:\$Recycle.Bin превращалась в C:\.Bin.
    # Пока считался только корень диска, это не всплывало — при спуске
    # в произвольный каталог всплывает сразу.
    $root = '__ROOT__'
    $errs = @()
    $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable +errs)
    $files = @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue -ErrorVariable +errs)
    $items = @()
    foreach ($d in $dirs) {
        # /L — только листинг; несуществующий dest с /L не создаётся и ничего не копируется
        $dest = Join-Path $env:TEMP ("rcnull_" + [guid]::NewGuid().ToString("N"))
        $bytes = [int64]0
        try {
            $out = robocopy $d.FullName $dest /L /E /BYTES /NFL /NDL /NJH /NC /NS /NP /XJ 2>$null
            foreach ($line in $out) {
                if ($line -match 'Bytes\s*:\s*(\d+)') { $bytes = [int64]$Matches[1]; break }
            }
        } catch { }
        $items += [PSCustomObject]@{ Path = $d.FullName; Bytes = [int64]$bytes }
    }
    foreach ($f in $files) {
        $items += [PSCustomObject]@{ Path = $f.FullName; Bytes = [int64]$f.Length }
    }
    $top = @($items | Sort-Object Bytes -Descending | Select-Object -First __LIMIT__)
    # JSON отдаём как base64(UTF-8): имена папок бывают кириллицей, а OEM-кодировка
    # консоли сервера теряет их (превращает в «?»). Base64 — чистый ASCII,
    # транспорт его не искажает; Python распакует обратно из UTF-8.
    $json = (@{
        Items = $top
        DirCount = $dirs.Count
        FileCount = $files.Count
        FirstError = if ($errs.Count -gt 0) { "$($errs[0])" } else { $null }
    } | ConvertTo-Json -Depth 4)
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def get_top_dirs(server: dict, disk_name: str, limit: int = TOP_DIRS_LIMIT) -> list:
    """[(путь, размер_гб), ...] по убыванию. Может работать несколько минут."""
    if server_type(server) == "linux":
        return _linux_top_dirs(server, disk_name, limit)
    return _windows_top_dirs(server, disk_name, limit)


def _windows_top_dirs(server: dict, disk_name: str, limit: int) -> list:
    root = disk_name if ":" in disk_name else f"{disk_name}:\\"
    script = (_WIN_TOP_DIRS_TEMPLATE
              .replace("__ROOT__", root.replace("'", "''"))
              .replace("__LIMIT__", str(limit)))
    output = run_ps(
        server["host"], script,
        username=server.get("username"),
        password=server.get("password"),
        operation_timeout_sec=300,
        read_timeout_sec=330,
    )
    data = ps_json(output)
    if not isinstance(data, dict):
        data = {"Items": data}

    rows = data.get("Items")
    if isinstance(rows, dict):
        rows = [rows]   # ConvertTo-Json схлопывает список из одного элемента
    result = []
    norm_root = root.rstrip("\\").lower()
    for row in rows or []:
        path = row.get("Path")
        size_bytes = row.get("Bytes") or 0
        if not path:
            continue
        # Get-ChildItem по пути файла возвращает сам файл: если провалились
        # в файл, а не в каталог, показывать его же как «содержимое» нельзя —
        # ведём себя как Linux-ветка и отдаём пустой список.
        if str(path).rstrip("\\").lower() == norm_root:
            continue
        result.append((path, round(float(size_bytes) / 1024 ** 3, 2)))

    if not result:
        # Пустота — это диагноз, а не ответ: объясняем причину
        first_error = data.get("FirstError")
        if first_error:
            raise RuntimeError(f"PowerShell: {str(first_error)[:150]}")
        if not data.get("DirCount") and not data.get("FileCount"):
            raise RuntimeError(
                f"листинг {root} вернул 0 объектов — нет прав на чтение корня "
                f"диска у пользователя WinRM (нужно право List/Read на {root})"
            )
    return result


def _linux_top_dirs(server: dict, disk_name: str, limit: int) -> list:
    from linux_check import run_ssh
    mountpoint = disk_name or "/"
    # du -x — не пересекаем границы файловых систем (только этот диск);
    # -a при -d1 добавляет и файлы, лежащие прямо в корне.
    #
    # sudo -n обязателен: без root du не читает чужие каталоги (почтовые
    # хранилища, тома docker, /root) и молча их не считает — сумма выходит
    # в разы меньше занятого места по df. Если sudo без пароля не настроен,
    # считаем как есть: неполный ответ лучше отсутствия ответа, а расхождение
    # с df бот покажет отдельной строкой.
    quoted = shlex.quote(mountpoint)
    script = (
        # Проверяем доступность sudo именно через du: право обычно выдают
        # узко (NOPASSWD: /usr/bin/du), и проверка через `sudo -n true`
        # спрашивала бы пароль — sudo молча не применялся бы к самому du.
        f"if sudo -n du --version >/dev/null 2>&1; then SUDO='sudo -n'; else SUDO=''; fi; "
        f"$SUDO du -x -a -B1 -d1 {quoted} 2>/dev/null | sort -rn | head -n {limit + 1}"
    )
    output = run_ssh(
        server["host"], script,
        username=server.get("username"),
        password=server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
        timeout=300,
    )
    result = []
    for line in output.splitlines():
        parts = line.split("\t", 1) if "\t" in line else line.split(None, 1)
        if len(parts) != 2:
            continue
        size_raw, path = parts
        path = path.strip()
        if path == mountpoint:
            continue  # итоговая строка самого диска
        try:
            result.append((path, round(int(size_raw) / 1024 ** 3, 2)))
        except ValueError:
            continue
    return result[:limit]


def restart_service(server: dict, service_name: str) -> tuple:
    """(ok, статус-или-ошибка). Перезапуск и итоговый статус сервиса."""
    try:
        if server_type(server) == "linux":
            return _linux_restart(server, service_name)
        return _windows_restart(server, service_name)
    except Exception as e:
        return False, str(e)[:200]


def _windows_restart(server: dict, service_name: str) -> tuple:
    safe_name = service_name.replace("'", "''")
    # Имя экранируем как шаблон: -Name трактует *, ?, [ ] как wildcard,
    # а в именах служб 1С такие символы встречаются.
    script = (
        f"$n = [Management.Automation.WildcardPattern]::Escape('{safe_name}')\n"
        f"Restart-Service -Name $n -Force -ErrorAction Stop\n"
        f"Start-Sleep -Seconds 2\n"
        f"(Get-Service -Name $n).Status"
    )
    output = run_ps(
        server["host"], script,
        username=server.get("username"),
        password=server.get("password"),
        operation_timeout_sec=120,
        read_timeout_sec=150,
    ).strip()
    return output.lower() == "running", output or "нет ответа"


def import_reg_file(server: dict, reg_path: str) -> tuple:
    """(ok, сообщение). Импорт .reg в реестр Windows перед перезагрузкой."""
    safe_path = str(reg_path).replace("'", "''")
    script = f"""
    $reg = '{safe_path}'
    if (-not (Test-Path -LiteralPath $reg)) {{ "MISSING"; return }}
    & reg.exe import $reg 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {{ "OK" }} else {{ "FAIL:$LASTEXITCODE" }}
    """
    output = run_ps(
        server["host"], script,
        username=server.get("username"),
        password=server.get("password"),
        operation_timeout_sec=90,
        read_timeout_sec=120,
    ).strip()

    last = output.splitlines()[-1].strip() if output else ""
    if last == "OK":
        return True, f"✅ Reg-файл импортирован: {reg_path}"
    if last == "MISSING":
        return False, f"❌ Reg-файл не найден на сервере: {reg_path}"
    return False, f"❌ Не удалось импортировать reg-файл ({last or 'нет ответа'})"


def reboot_server(server: dict) -> tuple:
    """
    (ok, отчёт). Перезагрузка сервера.

    Если в конфиге сервера задан reg_file — сначала импортируем этот .reg
    в реестр и только при успешном импорте перезагружаем. Провал импорта
    отменяет перезагрузку (иначе машина уйдёт в ребут без нужных настроек).
    """
    try:
        kind = server_type(server)
        if kind == "device":
            return False, "Сетевое устройство — перезагрузка не поддерживается"
        if kind == "linux":
            return _linux_reboot(server)
        return _windows_reboot(server)
    except Exception as e:
        return False, str(e)[:200]


def _windows_reboot(server: dict) -> tuple:
    steps = []
    reg_path = (server.get("reg_file") or "").strip()
    if reg_path:
        ok, message = import_reg_file(server, reg_path)
        steps.append(message)
        if not ok:
            steps.append("⛔ Перезагрузка отменена.")
            return False, "\n".join(steps)

    # Отложенный на 5 секунд ребут: команда успевает вернуться до того,
    # как WinRM-сессия оборвётся вместе с сервером.
    run_ps(
        server["host"],
        'shutdown.exe /r /t 5 /f /c "AgentMonitor: перезагрузка по запросу из Telegram"',
        username=server.get("username"),
        password=server.get("password"),
        operation_timeout_sec=60,
        read_timeout_sec=90,
    )
    steps.append("🔄 Команда перезагрузки отправлена (сервер уйдёт в ребут через 5 сек)")
    return True, "\n".join(steps)


def _linux_reboot(server: dict) -> tuple:
    from linux_check import run_ssh
    if (server.get("reg_file") or "").strip():
        note = "ℹ️ reg-файл игнорируется: это Windows-настройка\n"
    else:
        note = ""
    output = run_ssh(
        server["host"],
        'sudo -n shutdown -r +0 "AgentMonitor: перезагрузка по запросу" 2>&1',
        username=server.get("username"),
        password=server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
        timeout=60,
    ).strip()

    if "password is required" in output.lower():
        return False, (note + "❌ нужны sudo-права: добавь в /etc/sudoers.d/monitoring "
                       "строку «user ALL=(root) NOPASSWD: /sbin/shutdown»")
    return True, note + "🔄 Команда перезагрузки отправлена"


def _linux_restart(server: dict, service_name: str) -> tuple:
    from linux_check import run_ssh
    unit = shlex.quote(service_name)
    script = (
        f'export PATH="$PATH:/usr/sbin:/sbin"\n'
        f"sudo -n systemctl restart {unit} 2>&1\n"
        f"sleep 2\n"
        f"systemctl is-active {unit} 2>&1 | tail -n 1"
    )
    output = run_ssh(
        server["host"], script,
        username=server.get("username"),
        password=server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
        timeout=120,
    ).strip()
    last_line = output.splitlines()[-1].strip() if output else ""
    if "password is required" in output.lower():
        return False, ("нужны sudo-права: добавь в /etc/sudoers.d/monitoring строку "
                       "«user ALL=(root) NOPASSWD: /usr/bin/systemctl restart *»")
    return last_line == "active", last_line or "нет ответа"
