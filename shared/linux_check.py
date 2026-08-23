"""
shared/linux_check.py

Опрос Linux-сервера через SSH: диски, CPU, RAM, uptime, systemd-сервисы,
топ процессов. Формат результата совпадает с server_check.check_server
(Windows/WinRM), поэтому monitor и bot работают с Linux-серверами
теми же путями сохранения и алертов.

Аутентификация: username/password из конфига сервера, иначе общие
SSH_USERNAME / SSH_PASSWORD из .env. Вместо пароля можно указать путь
к приватному ключу: ssh_key в конфиге сервера или SSH_KEY_PATH в .env.
Порт: ssh_port в конфиге (по умолчанию 22).
"""
import os
import re
import shlex

import paramiko

from server_check import normalize_services

# Статусы systemd приводим к виду Windows-сервисов:
# alerts.check_service_alert считает сервис живым только при "Running".
_SYSTEMD_STATUS_MAP = {
    "active": "Running",
    "activating": "StartPending",
    "deactivating": "StopPending",
}

_SCRIPT_TEMPLATE = r"""
# /usr/sbin отсутствует в PATH неинтерактивной SSH-сессии обычного
# пользователя (Debian/Ubuntu), а там лежат nginx, apache2ctl и пр.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
echo '===STAT1==='
head -n1 /proc/stat
sleep 1
echo '===STAT2==='
head -n1 /proc/stat
echo '===MEMINFO==='
cat /proc/meminfo
echo '===UPTIME==='
cat /proc/uptime
echo '===TIMEUTC==='
date -u +%s
echo '===SMART==='
# Ищем smartctl по факту: в неинтерактивной SSH-сессии PATH урезан, а лежать
# он может по-разному (Synology DSM — /bin, Debian — /usr/sbin).
SMARTCTL=""
for p in "$(command -v smartctl 2>/dev/null)" /usr/sbin/smartctl /usr/bin/smartctl /bin/smartctl /sbin/smartctl; do
  if [ -n "$p" ] && [ -x "$p" ]; then SMARTCTL="$p"; break; fi
done
# Список физических дисков. Основной источник — /sys/block: он есть в любом
# Linux, тогда как lsblk на части систем (Synology DSM) не установлен вовсе,
# и раньше цикл молча не находил ни одного диска.
# Настоящий диск отличается от md/loop/ram наличием симлинка device.
DISKS=""
for b in /sys/block/*; do
  n=$(basename "$b")
  case "$n" in loop*|ram*|md*|dm-*|sr*|zram*|fd*|nbd*) continue ;; esac
  [ -e "$b/device" ] || continue
  DISKS="$DISKS $n"
done
if [ -z "$DISKS" ]; then
  DISKS=$(lsblk -ndo NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}')
fi
for d in $DISKS; do
  if [ -z "$SMARTCTL" ]; then printf '%s\t__NOSMARTCTL__\n' "$d"; continue; fi
  err=$(sudo -n "$SMARTCTL" -H "/dev/$d" 2>&1 >/dev/null)
  case "$err" in
    *password*|*"may not run"*|*"not allowed"*)
      # Без sudo без пароля SMART не прочитать. Раньше stderr глушился и
      # проблема выглядела как «дисков нет» — теперь причина видна.
      printf '%s\t__NOSUDO__\n' "$d"; continue ;;
    *"command not found"*|*"No such file"*)
      printf '%s\t__NOSMARTCTL__\n' "$d"; continue ;;
  esac
  r=$(sudo -n "$SMARTCTL" -H "/dev/$d" 2>/dev/null | grep -iE 'overall-health|SMART Health Status')
  [ -n "$r" ] && printf '%s\t%s\n' "$d" "$r"
done
true
echo '===DISKTEMP==='
for d in $DISKS; do
  [ -z "$SMARTCTL" ] && continue
  # Приоритет: 194 Temperature_Celsius (реальная температура диска).
  # 190 Airflow_Temperature — только запасной вариант: на части дисков он
  # показывает не температуру, а запас до порога.
  t=$(sudo -n "$SMARTCTL" -A "/dev/$d" 2>/dev/null | awk '
    /Temperature_Celsius/        { print $10; found=1; exit }
    /Current Drive Temperature/  { print $4;  found=1; exit }
    /^Temperature:/              { print $2;  found=1; exit }
    /Airflow_Temperature/        { if (!air) air=$10 }
    END { if (!found && air) print air }')
  [ -n "$t" ] && printf '%s\t%s\n' "$d" "$t"
done
true
echo '===MDSTAT==='
cat /proc/mdstat 2>/dev/null
true
echo '===DF==='
df -P -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null || df -P -B1
echo '===TOPCPU==='
ps -eo pid,pcpu,rss,comm --no-headers --sort=-pcpu 2>/dev/null | head -n 5
echo '===TOPMEM==='
ps -eo pid,pcpu,rss,comm --no-headers --sort=-rss 2>/dev/null | head -n 5
echo '===SERVICES==='
__SERVICES_LOOP__
"""

_SERVICES_LOOP_TEMPLATE = r"""
for unit in __UNITS__; do
  state=$(systemctl is-active -- "$unit" 2>/dev/null)
  printf '%s\t%s\n' "$unit" "${state:-unknown}"
done
"""

# Расширенные детали: включаются только для выбранных сервисов
# ps -a: остановленные и перезапускающиеся контейнеры нужны для алертов
_DOCKER_SECTION = r"""
echo '===DOCKERPS==='
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>&1 | head -n 30
"""

_NGINX_SECTION = r"""
echo '===NGINXCONF==='
{ nginx -T 2>/dev/null;
  cat /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null; } \
  | awk '/server[ \t]*\{/{print "#BLOCK#"} /server_name|listen/{print}' | head -n 160
"""

_APACHE_SECTION = r"""
echo '===APACHECONF==='
(apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null || apachectl -S 2>/dev/null) | head -n 60
grep -rhE '^[[:space:]]*(<VirtualHost|ServerName|ServerAlias)' \
  /etc/apache2/sites-enabled /etc/httpd/conf.d 2>/dev/null | head -n 60
"""

_APACHE_UNITS = ("apache2", "httpd", "apache")


def run_ssh(host: str, script: str, username: str = None, password: str = None,
            port: int = 22, key_path: str = None, timeout: int = 60) -> str:
    """
    Выполняет shell-скрипт на удалённом Linux-сервере по SSH.
    Если username/password не переданы — берёт из SSH_USERNAME / SSH_PASSWORD.
    """
    username = username or os.getenv("SSH_USERNAME")
    password = password or os.getenv("SSH_PASSWORD")
    key_path = key_path or os.getenv("SSH_KEY_PATH")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password or None,
            key_filename=key_path or None,
            timeout=10,
            auth_timeout=15,
            banner_timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, stderr = client.exec_command(script, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0 and not out.strip():
            raise Exception(err or f"SSH: команда завершилась с кодом {exit_code}")
        return out
    finally:
        client.close()


def _split_sections(output: str) -> dict:
    sections = {}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("===") and stripped.endswith("===") and len(stripped) > 6:
            current = stripped.strip("=")
            sections[current] = []
        elif current is not None:
            sections[current].append(line.rstrip())
    return sections


def _parse_cpu_percent(stat1_lines: list, stat2_lines: list) -> float:
    """CPU-загрузка по двум срезам /proc/stat с интервалом ~1 сек."""
    try:
        v1 = [int(x) for x in stat1_lines[0].split()[1:]]
        v2 = [int(x) for x in stat2_lines[0].split()[1:]]
        # idle = idle + iowait (поля 4 и 5 строки cpu)
        idle1 = v1[3] + (v1[4] if len(v1) > 4 else 0)
        idle2 = v2[3] + (v2[4] if len(v2) > 4 else 0)
        total1, total2 = sum(v1), sum(v2)
        d_total = total2 - total1
        d_idle = idle2 - idle1
        if d_total <= 0:
            return 0.0
        return round(100.0 * (d_total - d_idle) / d_total, 1)
    except (IndexError, ValueError):
        return 0.0


def _parse_meminfo(lines: list) -> tuple:
    """Возвращает (ram_total_gb, ram_free_gb); free = MemAvailable."""
    values = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            try:
                values[parts[0][:-1]] = int(parts[1])  # кБ
            except ValueError:
                pass
    total_kb = values.get("MemTotal", 0)
    avail_kb = values.get("MemAvailable", values.get("MemFree", 0))
    return round(total_kb / 1024 / 1024, 2), round(avail_kb / 1024 / 1024, 2)


def _parse_uptime(lines: list) -> int:
    try:
        return int(float(lines[0].split()[0]))
    except (IndexError, ValueError):
        return 0


def _parse_time_utc(lines: list):
    try:
        return int(lines[0].strip())
    except (IndexError, ValueError):
        return None


def _parse_smart(lines: list) -> list:
    """Диски с проваленным SMART-тестом: ['sda: FAILED!']."""
    unhealthy = []
    for line in lines:
        if "\t" not in line:
            continue
        device, result = line.split("\t", 1)
        if result.strip().startswith("__"):
            continue      # маркер недоступности, разбирается в _parse_smart_note
        if "fail" in result.lower():
            unhealthy.append(f"{device.strip()}: SMART FAILED")
    return unhealthy


def _parse_smart_note(lines: list) -> str | None:
    """Почему SMART не собрался. Пустая секция раньше выглядела как
    «дисков нет», хотя на деле не хватало прав — теперь причина видна
    в карточке сервера и в логе, но алертом не шумит."""
    markers = {result.strip() for line in lines if "\t" in line
               for _dev, result in [line.split("\t", 1)]}
    if "__NOSUDO__" in markers:
        return ("SMART недоступен: нужен sudo без пароля для smartctl "
                "(см. readme, раздел про Linux)")
    if "__NOSMARTCTL__" in markers:
        return "SMART недоступен: smartctl не установлен"
    return None


def _parse_disk_temps(lines: list) -> list:
    """[{'name': 'sda', 'temp_c': 41.0}] — температура дисков из smartctl -A."""
    temps = []
    for line in lines:
        if "\t" not in line:
            continue
        device, raw = line.split("\t", 1)
        try:
            temp = float(raw.strip().split()[0])
        except (ValueError, IndexError):
            continue
        # Значения вне физичного диапазона — мусор из нестандартного вывода
        if -20 <= temp <= 120:
            temps.append({"name": device.strip(), "temp_c": temp})
    return temps


# ─── RAID (/proc/mdstat) ─────────────────────────────────────
# Читается без root — в отличие от SMART. Для хранилища бэкапов это важнее
# всего остального: развалившийся массив не виден ни по свободному месту,
# ни по SMART отдельного диска, а второй выпавший диск означает потерю данных.
# Synology SHR тоже собран на md, поэтому формат тот же.

_MD_HEADER_RE = re.compile(
    r"^(md\d+)\s*:\s*(\S+)(?:\s+(raid\S+|linear|multipath|faulty))?\s*(.*)$"
)
_MD_COUNTS_RE = re.compile(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]")
_MD_PROGRESS_RE = re.compile(r"\b(recovery|resync|reshape|check)\s*=\s*([\d.]+)%")
_MD_FINISH_RE = re.compile(r"finish=(\S+)")
_MD_MEMBER_RE = re.compile(r"(\w+)\[\d+\](\([FS]\))?")


def _parse_mdstat(lines: list) -> list:
    """Массивы из /proc/mdstat.

    [{'name','level','state','total','active','flags','degraded',
      'failed','progress'}]

    degraded=True, если дисков в строю меньше, чем нужно ([4/3]), в карте
    есть «_» ([UU_U]) или участник помечен (F). Пометка (S) — это горячий
    резерв, а не сбой."""
    arrays = []
    current = None

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.lower().startswith(("personalities", "unused devices")):
            continue

        header = _MD_HEADER_RE.match(line.strip())
        if header and not line.startswith((" ", "\t")):
            name, state, level, members = header.groups()
            failed = [
                dev for dev, flag in _MD_MEMBER_RE.findall(members or "")
                if flag == "(F)"
            ]
            current = {
                "name": name,
                "state": state,
                "level": level or "?",
                "total": None,
                "active": None,
                "flags": None,
                "failed": failed,
                "progress": None,
                "degraded": state.lower() == "inactive" or bool(failed),
            }
            arrays.append(current)
            continue

        if current is None:
            continue

        counts = _MD_COUNTS_RE.search(line)
        if counts:
            total, active, flags = counts.groups()
            current["total"] = int(total)
            current["active"] = int(active)
            current["flags"] = flags
            if int(active) < int(total) or "_" in flags:
                current["degraded"] = True

        progress = _MD_PROGRESS_RE.search(line)
        if progress:
            action, percent = progress.groups()
            finish = _MD_FINISH_RE.search(line)
            current["progress"] = {
                "action": action,
                "percent": float(percent),
                "finish": finish.group(1) if finish else None,
            }

    return arrays


def _parse_df(lines: list) -> list:
    disks = []
    for line in lines:
        parts = line.split(None, 5)
        if len(parts) < 6 or parts[0] == "Filesystem":
            continue
        fs, total, used, avail, _, mountpoint = parts
        if fs.startswith("/dev/loop"):
            continue
        try:
            total_b, used_b, avail_b = int(total), int(used), int(avail)
        except ValueError:
            continue
        if total_b <= 0:
            continue
        disks.append({
            "Name": mountpoint,
            "FreeGB": round(avail_b / 1024 ** 3, 2),
            "UsedGB": round(used_b / 1024 ** 3, 2),
        })
    return disks


def _parse_processes(lines: list) -> list:
    processes = []
    for line in lines:
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        pid, pcpu, rss, comm = parts
        try:
            processes.append({
                "Name": comm.strip(),
                "Id": int(pid),
                "CpuPercent": round(float(pcpu), 1),
                "CpuSeconds": None,
                "MemoryMB": round(int(rss) / 1024, 1),
            })
        except ValueError:
            continue
    return processes


def _parse_services(lines: list, service_specs: list) -> list:
    states = {}
    for line in lines:
        if "\t" not in line:
            continue
        unit, state = line.split("\t", 1)
        states[unit.strip()] = state.strip() or "unknown"

    services = []
    for spec in service_specs:
        unit = spec["name"] or spec["display_name"]
        raw = states.get(unit, "not_found")
        services.append({
            "Name": unit,
            "DisplayName": spec["display_name"],
            "Label": spec["label"],
            "Status": _SYSTEMD_STATUS_MAP.get(raw, raw),
        })
    return services


def _unit_names(service_specs: list) -> list:
    units = [spec["name"] or spec["display_name"] for spec in service_specs]
    return [unit for unit in units if unit]


def build_script(service_specs: list) -> str:
    units = _unit_names(service_specs)
    if units:
        loop = _SERVICES_LOOP_TEMPLATE.replace(
            "__UNITS__", " ".join(shlex.quote(unit) for unit in units)
        )
    else:
        loop = "true"
    script = _SCRIPT_TEMPLATE.replace("__SERVICES_LOOP__", loop)

    # Детальные секции только для выбранных сервисов
    if "docker" in units:
        script += _DOCKER_SECTION
    if "nginx" in units:
        script += _NGINX_SECTION
    if any(unit in units for unit in _APACHE_UNITS):
        script += _APACHE_SECTION
    return script


def _short_ports(ports: str) -> str:
    """'0.0.0.0:80->80/tcp, :::443->443/tcp' → 'порты: 80, 443'."""
    host_ports = sorted({int(p) for p in re.findall(r":(\d+)->", ports)})
    if not host_ports:
        return ""
    return "порты: " + ", ".join(str(p) for p in host_ports)


def docker_problem(status: str) -> str:
    """Классификация статуса docker ps: '' = работает нормально."""
    low = (status or "").lower()
    if "unhealthy" in low:
        return "unhealthy"
    if low.startswith("restarting"):
        return "restarting"
    if low.startswith("exited") or low.startswith("dead"):
        return "exited"
    if low.startswith("paused"):
        return "paused"
    if low.startswith("created"):
        return "created"
    return ""


def _docker_rows(lines: list) -> tuple:
    """(контейнеры [{'name','status'}], текст ошибки | None)."""
    containers = []
    error = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if "permission denied" in low or "cannot connect" in low:
            error = "нет доступа к Docker: добавь пользователя мониторинга в группу docker"
            continue
        if "command not found" in low or ("not found" in low and "\t" not in stripped):
            error = "docker не установлен или недоступен"
            continue
        parts = stripped.split("\t")
        if len(parts) < 3:
            continue
        containers.append({
            "name": parts[0],
            "status": parts[2].strip(),
            "ports": parts[3] if len(parts) > 3 else "",
        })
    return containers, error


def _parse_docker_ps(lines: list) -> list:
    containers, error = _docker_rows(lines)
    if error and not containers:
        return [f"⚠️ {error}"]
    if not containers:
        return ["контейнеров нет"]

    running, problems = [], []
    for c in containers:
        # 'Up 2 weeks (healthy)' → 'Up 2 weeks'
        status = re.sub(r"\s*\(.*?\)", "", c["status"]).strip()
        problem = docker_problem(c["status"])
        entry = f"• {c['name']} · {status}"
        ports = _short_ports(c["ports"])
        if ports:
            entry += f" · {ports}"
        if problem:
            problems.append(f"⚠️ {c['name']} · {c['status']}")
        else:
            running.append(entry)
    return ([f"Контейнеры: {len(running)}"] + running[:10] + problems[:5])


def _listen_ports(tokens: list) -> set:
    ports = set()
    for token in tokens:
        token = token.strip().rstrip(";")
        if not token or "=" in token or token in ("ssl", "http2", "http3", "quic",
                                                  "default_server", "reuseport", "deferred"):
            continue
        tail = token.rsplit(":", 1)[-1]
        if tail.isdigit():
            ports.add(int(tail))
    return ports


def _parse_nginx_conf(lines: list) -> list:
    sites = {}
    current_names, current_ports = [], set()

    def flush():
        for name in current_names:
            sites.setdefault(name, set()).update(current_ports)

    for line in lines:
        stripped = line.strip().rstrip(";")
        if "#BLOCK#" in line:
            flush()
            current_names, current_ports = [], set()
        elif stripped.startswith("server_name"):
            current_names += [n for n in stripped.split()[1:] if n and n != "_"]
        elif stripped.startswith("listen"):
            current_ports |= _listen_ports(stripped.split()[1:])
    flush()

    if not sites:
        return ["⚠️ не удалось прочитать конфигурацию nginx (нет прав на nginx -T)"]
    result = ["Сайты:"]
    for name in sorted(sites)[:15]:
        ports = ", ".join(str(p) for p in sorted(sites[name])) or "80"
        result.append(f"• {name} — {ports}")
    return result


def _parse_apache_conf(lines: list) -> list:
    sites = {}
    current_ports = set()
    for line in lines:
        # Вывод apache2ctl -S
        m = re.search(r"port (\d+) namevhost (\S+)", line)
        if m:
            sites.setdefault(m.group(2), set()).add(int(m.group(1)))
            continue
        # Запасной разбор конфигов sites-enabled напрямую
        m = re.search(r"<VirtualHost[^>]*:(\d+)", line)
        if m:
            current_ports = {int(m.group(1))}
            continue
        m = re.search(r"^\s*Server(?:Name|Alias)\s+(\S+)", line)
        if m:
            sites.setdefault(m.group(1), set()).update(current_ports)
    if not sites:
        return ["⚠️ не удалось прочитать конфигурацию Apache "
                "(apache2ctl -S и /etc/apache2/sites-enabled недоступны)"]
    result = ["Сайты:"]
    for name in sorted(sites)[:15]:
        ports = ", ".join(str(p) for p in sorted(sites[name])) or "—"
        result.append(f"• {name} — {ports}")
    return result


def _collect_service_details(sections: dict, units: list) -> dict:
    """{unit: [строки]} — контейнеры Docker, сайты nginx/Apache."""
    details = {}
    if "docker" in units and "DOCKERPS" in sections:
        details["docker"] = _parse_docker_ps(sections["DOCKERPS"])
    if "nginx" in units and "NGINXCONF" in sections:
        details["nginx"] = _parse_nginx_conf(sections["NGINXCONF"])
    apache_unit = next((u for u in units if u in _APACHE_UNITS), None)
    if apache_unit and "APACHECONF" in sections:
        details[apache_unit] = _parse_apache_conf(sections["APACHECONF"])
    return details


def check_linux_server(server: dict) -> dict:
    service_specs = normalize_services(server)
    output = run_ssh(
        server["host"],
        build_script(service_specs),
        username=server.get("username"),
        password=server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
    )
    sections = _split_sections(output)
    units = _unit_names(service_specs)

    ram_total, ram_free = _parse_meminfo(sections.get("MEMINFO", []))
    result = {
        "disks": _parse_df(sections.get("DF", [])),
        "cpu_load": _parse_cpu_percent(sections.get("STAT1", []), sections.get("STAT2", [])),
        "ram_total": ram_total,
        "ram_free": ram_free,
        "uptime_seconds": _parse_uptime(sections.get("UPTIME", [])),
        "services": _parse_services(sections.get("SERVICES", []), service_specs),
        "top_cpu": _parse_processes(sections.get("TOPCPU", [])),
        "top_memory": _parse_processes(sections.get("TOPMEM", [])),
        "service_details": _collect_service_details(sections, units),
        "server_time_utc": _parse_time_utc(sections.get("TIMEUTC", [])),
        "unhealthy_disks": _parse_smart(sections.get("SMART", [])),
        "smart_note": _parse_smart_note(sections.get("SMART", [])),
        "disk_temps": _parse_disk_temps(sections.get("DISKTEMP", [])),
        "raid_arrays": _parse_mdstat(sections.get("MDSTAT", [])),
    }
    if "docker" in units and "DOCKERPS" in sections:
        containers, error = _docker_rows(sections["DOCKERPS"])
        # Структурированный список — для алертов по контейнерам в мониторе.
        # При ошибке доступа None: нет данных ≠ все контейнеры пропали.
        result["docker_containers"] = None if (error and not containers) else containers
    return result
