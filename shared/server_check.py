"""
shared/server_check.py

Опрос сервера: Windows через WinRM, Linux через SSH (linux_check.py).
Тип задаётся полем "type" в servers.json: windows (по умолчанию) | linux |
device (сетевое устройство, только ping — полный опрос не выполняется).
Общий код для bot (принудительное обновление) и monitor.
"""
from winrm_client import PS_OUT_B64_HELPER, ps_json, run_ps


def server_type(server: dict) -> str:
    """Тип записи конфига: windows | linux | device."""
    return (server.get("type") or "windows").strip().lower()


def normalize_services(server: dict) -> list:
    service_specs = []
    for service in server.get("services", []):
        if isinstance(service, str):
            service_specs.append({
                "name": service,
                "display_name": service,
                "label": service
            })
        else:
            name = service.get("name") or service.get("service_name")
            display_name = service.get("display_name") or service.get("displayName") or name
            label = service.get("label") or display_name or name
            if name or display_name:
                service_specs.append({
                    "name": name,
                    "display_name": display_name,
                    "label": label
                })
    return service_specs


STATUS_SCRIPT = r"""
    $disks = Get-PSDrive -PSProvider FileSystem |
        Where-Object { $_.Free -gt 0 } |
        Select-Object Name,
            @{N="FreeGB"; E={[math]::Round($_.Free / 1GB, 2)}},
            @{N="UsedGB"; E={[math]::Round($_.Used / 1GB, 2)}}

    $cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
    $ram = Get-CimInstance Win32_OperatingSystem
    $ramTotal = [math]::Round($ram.TotalVisibleMemorySize / 1MB, 2)
    $ramFree  = [math]::Round($ram.FreePhysicalMemory / 1MB, 2)
    $uptimeSeconds = [math]::Round(((Get-Date) - $ram.LastBootUpTime).TotalSeconds, 0)

    $serverTimeUtc = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $unhealthyDisks = @()
    try {
        $unhealthyDisks = @(Get-PhysicalDisk -ErrorAction Stop |
            Where-Object { "$($_.HealthStatus)" -notin @("Healthy", "0") } |
            ForEach-Object { "$($_.FriendlyName): $($_.HealthStatus)" })
    } catch {}

    # Один снимок SCM через CIM: State здесь — источник правды, а ProcessId
    # подтверждает, что служба реально работает. Список отдаём целиком и
    # сопоставляем с конфигом уже на стороне Python: имена служб в скрипт не
    # подставляются, поэтому он не растёт и не упирается в лимит командной
    # строки WinRM.
    $allServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, State, ProcessId)

    Out-B64 @{
        Disks = $disks
        CpuLoad = $cpu
        RamTotal = $ramTotal
        RamFree = $ramFree
        UptimeSeconds = $uptimeSeconds
        AllServices = $allServices
        ServerTimeUtc = $serverTimeUtc
        UnhealthyDisks = $unhealthyDisks
    }
"""

VM_SCRIPT = r"""
    $vms = @()
    try {
        $vms = @(Get-VM -ErrorAction Stop | ForEach-Object {
            $integration = "n/a"
            if ($_.State -eq "Running") {
                $integration = "$($_.IntegrationServicesState)"
            }
            [PSCustomObject]@{
                Name = $_.Name
                State = "$($_.State)"
                CpuUsage = $_.CPUUsage
                MemoryMB = [math]::Round($_.MemoryAssigned / 1MB, 0)
                UptimeStr = "$($_.Uptime)"
                IntegrationState = $integration
            }
        })
    } catch {}
    Out-B64 @{ VMs = $vms }
"""

PROCESS_SCRIPT = r"""
    $n=[int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    if($n -lt 1){$n=1}
    $a=@{}
    Get-Process|%{$a[$_.Id]=if($null -eq $_.CPU){0}else{$_.CPU}}
    Start-Sleep -Seconds 1
    $p=Get-Process|%{
      $old=$a[$_.Id]
      $new=if($null -eq $_.CPU){0}else{$_.CPU}
      $d=if($null -eq $old){0}else{[math]::Max(0,$new-$old)}
      [pscustomobject]@{
        Name=$_.ProcessName
        Id=$_.Id
        CpuPercent=[math]::Round(($d/$n)*100,1)
        CpuSeconds=[math]::Round($new,1)
        MemoryMB=[math]::Round($_.WorkingSet64/1MB,1)
      }
    }
    Out-B64 @{
      TopCpu=($p|?{$_.Name -ne "Idle"}|sort CpuPercent -desc|select -first 5)
      TopMemory=($p|sort MemoryMB -desc|select -first 5)
    }
"""


def _is_x64(service: dict) -> bool:
    text = f"{service.get('Name') or ''} {service.get('DisplayName') or ''}".lower()
    return "x86-64" in text or "x86_64" in text


def _match_services(all_services: list, spec: dict) -> list:
    """Службы, подходящие под запись конфига: точное совпадение по имени или
    отображаемому имени плюс вариант с суффиксом в скобках. 1С ставит рядом
    две службы — "1C:Enterprise 8.3 Server Agent" (32 бита, обычно мёртвая) и
    "... (x86-64)" (рабочая), а в конфиге записано базовое имя."""
    found = {}
    for needle in (spec.get("name"), spec.get("display_name")):
        if not needle:
            continue
        needle = needle.lower()
        prefix = f"{needle} ("
        for service in all_services:
            name = str(service.get("Name") or "")
            display = str(service.get("DisplayName") or "")
            if (name.lower() == needle or display.lower() == needle
                    or name.lower().startswith(prefix)
                    or display.lower().startswith(prefix)):
                found.setdefault(name.lower(), service)
    return list(found.values())


def resolve_service(all_services: list, spec: dict) -> dict:
    """Запись о службе для алертов и БД: статус, реальное имя, признаки."""
    label = spec.get("label")
    found = _match_services(all_services, spec)
    if not found:
        return {
            "Name": spec.get("name") or spec.get("display_name"),
            "DisplayName": spec.get("display_name") or spec.get("name"),
            "Label": label,
            "Status": "not_found",
            "ProcessId": 0,
            "MatchCount": 0,
            "Ambiguous": False,
        }

    match_count = len(found)
    # Если есть 64-битный вариант — следим всегда за ним: 32-битная служба 1С
    # остаётся зарегистрированной, но не используется.
    x64 = [service for service in found if _is_x64(service)]
    candidates = x64 or found
    # Среди оставшихся одноимённых рабочей считаем запущенную,
    # а не первую попавшуюся.
    running = [c for c in candidates if str(c.get("State") or "").lower() == "running"]
    service = (running or candidates)[0]

    state = str(service.get("State") or "unknown")
    try:
        pid = int(service.get("ProcessId") or 0)
    except (TypeError, ValueError):
        pid = 0
    if state.lower() != "running" and pid > 0:
        # SCM отдаёт Stopped, но процесс живой — служба работает.
        state = "Running"

    return {
        "Name": service.get("Name"),
        "DisplayName": service.get("DisplayName"),
        "Label": label,
        "Status": state,
        "ProcessId": pid,
        "MatchCount": match_count,
        # Пара 32/64 бита — норма, выбор однозначен. Неоднозначно, когда
        # одноимённых служб несколько и разделить их по битности нельзя.
        "Ambiguous": match_count > 1 and len(x64) != 1,
    }


def _as_list(value):
    # ConvertTo-Json схлопывает список из одного элемента в объект/строку
    if isinstance(value, (dict, str)):
        return [value]
    return value or []


HYPERV_SERVICE_NAME = "vmms"  # Hyper-V Virtual Machine Management


def _format_vm_line(vm: dict) -> str:
    state = vm.get("State", "Unknown")
    icon = "🟢" if state == "Running" else "🔴" if state == "Off" else "🟡"
    line = f"{icon} {vm.get('Name')}: {state}"
    if state == "Running":
        cpu = vm.get("CpuUsage")
        ram = vm.get("MemoryMB")
        uptime = vm.get("UptimeStr")
        integration = vm.get("IntegrationState")
        line += f" | CPU {cpu}% | RAM {ram} MB | uptime {uptime} | интеграция: {integration}"
    return line


def check_server(server: dict) -> dict:
    kind = server_type(server)
    if kind == "linux":
        # Импорт по месту: paramiko нужен только при наличии Linux-серверов
        from linux_check import check_linux_server
        return check_linux_server(server)
    if kind == "vmware":
        # Импорт по месту: pyVmomi нужен только при наличии VMware в конфиге
        from vmware_check import check_vmware_server
        return check_vmware_server(server)

    service_specs = normalize_services(server)

    status_data = ps_json(run_ps(
        server["host"],
        PS_OUT_B64_HELPER + STATUS_SCRIPT,
        username=server.get("username"),
        password=server.get("password")
    ))
    process_data = ps_json(run_ps(
        server["host"],
        PS_OUT_B64_HELPER + PROCESS_SCRIPT,
        username=server.get("username"),
        password=server.get("password")
    ))

    server_time = status_data.get("ServerTimeUtc")
    all_services = _as_list(status_data.get("AllServices", []))
    services = [resolve_service(all_services, spec) for spec in service_specs]

    service_details = {}
    has_hyperv = any(spec.get("name") == HYPERV_SERVICE_NAME for spec in service_specs)
    if has_hyperv:
        vm_data = ps_json(run_ps(
            server["host"],
            PS_OUT_B64_HELPER + VM_SCRIPT,
            username=server.get("username"),
            password=server.get("password")
        ))
        vms = _as_list(vm_data.get("VMs", []))
        if vms:
            service_details[HYPERV_SERVICE_NAME] = [_format_vm_line(vm) for vm in vms]

    return {
        "disks": _as_list(status_data.get("Disks", [])),
        "cpu_load": float(status_data.get("CpuLoad", 0)),
        "ram_total": float(status_data.get("RamTotal", 0)),
        "ram_free": float(status_data.get("RamFree", 0)),
        "uptime_seconds": int(float(status_data.get("UptimeSeconds", 0))),
        "services": services,
        "top_cpu": _as_list(process_data.get("TopCpu", [])),
        "top_memory": _as_list(process_data.get("TopMemory", [])),
        "server_time_utc": int(server_time) if server_time else None,
        "unhealthy_disks": _as_list(status_data.get("UnhealthyDisks", [])),
        "service_details": service_details,
    }
