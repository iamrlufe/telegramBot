"""
shared/vmware_check.py

Опрос VMware vSphere: vCenter или отдельный ESXi-хост.

Транспорт — HTTPS/443 к /sdk (vSphere Web Services API, SOAP через pyVmomi).
Ни SSH, ни агента на хостах: API включён у ESXi и vCenter всегда, учётной
записи достаточно роли Read-only.

Модуль намеренно разделён на два слоя:

  _collect_raw()  — единственное место, которое говорит с vSphere. Сразу
                    превращает объекты pyVmomi в обычные словари и списки.
  всё остальное   — чистые функции над этими словарями: пересчёт в ГБ,
                    агрегация хостов, сопоставление ВМ со «службами»,
                    разбор снапшотов.

Так разбор данных покрывается тестами на зафиксированных ответах, без
живого vCenter — тем же приёмом, что и разбор JSON от PowerShell.

Одна запись конфига = одна точка подключения. Для vCenter это агрегат по
всей инфраструктуре: датасторы всех хостов, суммарная память, средняя
загрузка CPU. Для отдельного ESXi те же поля описывают один хост.
"""
import os
import ssl
from datetime import datetime, timezone

GB = 1024 ** 3

# Сколько ВМ показывать в топе по CPU и памяти (в таблицу process_metrics)
TOP_VM_LIMIT = 5

# Датчики железа с таким статусом считаем проблемой
BAD_SENSOR_STATES = {"red", "yellow"}


# ─── Пересчёт и мелкие помощники ─────────────────────────────

def _gb(value_bytes) -> float:
    try:
        return round(float(value_bytes) / GB, 2)
    except (TypeError, ValueError):
        return 0.0


def _num(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ─── Датасторы ───────────────────────────────────────────────

def map_datastores(datastores: list) -> list:
    """Датасторы в том же виде, что диски Windows/Linux: Name/FreeGB/UsedGB.

    Благодаря этому датастор без единой новой строки в мониторе получает
    пороги 15/10/5 %, гистерезис, прогноз заполнения и графики.

    Недоступный датастор пропускаем: vSphere отдаёт по нему нули, а нулевой
    объём check_disk_alert трактует как «нет данных» и молча выходит —
    зато сохранённый нулевой замер испортил бы прогноз заполнения.
    """
    result = []
    for store in datastores:
        if not store.get("accessible", True):
            continue
        capacity = _num(store.get("capacity_bytes"))
        free = _num(store.get("free_bytes"))
        if capacity <= 0:
            continue
        result.append({
            "Name": store.get("name") or "?",
            "FreeGB": _gb(free),
            "UsedGB": _gb(capacity - free),
        })
    return result


def overcommitted_datastores(datastores: list) -> list:
    """Датасторы, где тонкие диски выделены сверх ёмкости.

    uncommitted — сколько ещё могут занять тонкие диски, если вырастут до
    заявленного размера. capacity < used + uncommitted означает, что при
    полном разрастании места не хватит. Это не авария, но предупреждение
    задолго до того, как место кончится по факту.
    """
    result = []
    for store in datastores:
        if not store.get("accessible", True):
            continue
        capacity = _num(store.get("capacity_bytes"))
        free = _num(store.get("free_bytes"))
        uncommitted = _num(store.get("uncommitted_bytes"))
        if capacity <= 0 or uncommitted <= 0:
            continue
        provisioned = (capacity - free) + uncommitted
        if provisioned > capacity:
            result.append({
                "name": store.get("name") or "?",
                "capacity_gb": _gb(capacity),
                "provisioned_gb": _gb(provisioned),
                "overcommit_pct": round((provisioned / capacity - 1) * 100, 1),
            })
    return result


def inaccessible_datastores(datastores: list) -> list:
    return [store.get("name") or "?" for store in datastores
            if not store.get("accessible", True)]


# ─── Хосты ───────────────────────────────────────────────────

def aggregate_hosts(hosts: list) -> dict:
    """Сводка по хостам в поля обычного сервера.

    CPU — суммарно занятые мегагерцы к суммарной ёмкости, то есть загрузка
    всей платформы, а не среднее арифметическое по хостам: хост на 4 ядра и
    хост на 40 не должны весить одинаково.

    uptime берём минимальный: если один хост недавно перезагрузился, это
    и есть тот факт, который нужно увидеть, а не средний по больнице.
    Отключённые и находящиеся в обслуживании хосты в расчёт не идут —
    их нулевые счётчики занижали бы загрузку всей платформы.
    """
    cpu_total = cpu_used = 0.0
    ram_total = ram_used = 0.0
    uptimes = []

    for host in hosts:
        if host.get("connection_state") not in (None, "connected"):
            continue
        if host.get("in_maintenance"):
            continue
        cpu_total += _num(host.get("cpu_mhz_total"))
        cpu_used += _num(host.get("cpu_mhz_used"))
        ram_total += _num(host.get("memory_bytes_total"))
        ram_used += _num(host.get("memory_bytes_used"))
        uptime = host.get("uptime_seconds")
        if uptime:
            uptimes.append(int(_num(uptime)))

    return {
        "cpu_load": round(cpu_used / cpu_total * 100, 1) if cpu_total > 0 else 0.0,
        "ram_total": _gb(ram_total),
        "ram_free": _gb(ram_total - ram_used),
        "uptime_seconds": min(uptimes) if uptimes else 0,
    }


def host_problems(hosts: list) -> list:
    """Строки о хостах, которые требуют внимания: не в сети, в режиме
    обслуживания, красные и жёлтые датчики железа."""
    problems = []
    for host in hosts:
        name = host.get("name") or "?"
        state = host.get("connection_state")
        if state not in (None, "connected"):
            problems.append(f"{name}: хост {state}")
            continue
        if host.get("in_maintenance"):
            problems.append(f"{name}: режим обслуживания")
        for sensor in host.get("sensors") or []:
            status = str(sensor.get("status") or "").lower()
            if status in BAD_SENSOR_STATES:
                mark = "🔴" if status == "red" else "🟡"
                problems.append(f"{name}: {mark} {sensor.get('name') or 'датчик'}")
    return problems


# ─── Виртуальные машины ──────────────────────────────────────

# vSphere → словарь состояний, понятный check_service_alert: «running» для
# него означает норму, всё остальное — проблему. Поэтому включённая ВМ
# обязана называться именно running, иначе алерт о восстановлении никогда
# не придёт.
POWER_STATE_MAP = {
    "poweredOn": "running",
    "poweredOff": "stopped",
    "suspended": "suspended",
}


def map_vm_services(vms: list, specs: list) -> list:
    """ВМ из конфига → записи «служб» в той же форме, что WinRM-опрос.

    Имя ВМ сравнивается без учёта регистра: в vSphere оно как в инвентаре,
    а в конфиг его набирают руками.
    """
    by_name = {str(vm.get("name") or "").lower(): vm for vm in vms}
    result = []
    for spec in specs:
        wanted = spec.get("name") or spec.get("display_name")
        vm = by_name.get(str(wanted or "").lower())
        if vm is None:
            result.append({
                "Name": wanted,
                "DisplayName": spec.get("display_name") or wanted,
                "Label": spec.get("label"),
                "Status": "not_found",
                "ProcessId": 0,
                "MatchCount": 0,
                "Ambiguous": False,
            })
            continue
        power = str(vm.get("power_state") or "")
        result.append({
            "Name": vm.get("name"),
            "DisplayName": spec.get("display_name") or vm.get("name"),
            "Label": spec.get("label"),
            "Status": POWER_STATE_MAP.get(power, power or "unknown"),
            "ProcessId": 0,
            "MatchCount": 1,
            "Ambiguous": False,
            "ToolsStatus": vm.get("tools_status"),
        })
    return result


def top_vms(vms: list, by: str, limit: int = TOP_VM_LIMIT) -> list:
    """Топ включённых ВМ по CPU или памяти в форме process_metrics.

    Выключенные не учитываем: их нулевые счётчики только вытесняют
    из топа реальных потребителей.
    """
    key = "cpu_mhz_used" if by == "cpu" else "memory_mb_used"
    running = [vm for vm in vms if str(vm.get("power_state")) == "poweredOn"]
    ranked = sorted(running, key=lambda vm: _num(vm.get(key)), reverse=True)
    return [
        {
            "Name": vm.get("name"),
            "Id": 0,
            # Именно процент загрузки выделенных ВМ ядер: vSphere отдаёт
            # потребление в мегагерцах, и без пересчёта карточка сервера
            # показывала бы «1967% CPU» — колонка называется cpu_percent.
            "CpuPercent": round(_num(vm.get("cpu_percent")), 1),
            "CpuSeconds": None,
            "MemoryMB": round(_num(vm.get("memory_mb_used")), 1),
        }
        for vm in ranked[:limit]
    ]


def vm_cpu_percent(cpu_mhz_used, num_cpu, host_mhz) -> float:
    """Загрузка ВМ в процентах от выделенных ей ядер.

    Ёмкость ВМ = число её vCPU × частота ядра хоста, на котором она
    работает. Данных не хватает (ВМ выключена, хост неизвестен) — отдаём 0,
    а не выдумываем число.
    """
    capacity = _num(num_cpu) * _num(host_mhz)
    if capacity <= 0:
        return 0.0
    return round(_num(cpu_mhz_used) / capacity * 100, 1)


def host_detail_lines(hosts: list) -> list:
    """Строки по каждому ESXi-хосту для карточки сервера.

    Агрегат по vCenter отвечает на вопрос «хватает ли ресурсов платформе»,
    но не показывает перекос: один хост под завязку, другой пустой. Здесь
    видно каждый.
    """
    lines = []
    for host in sorted(hosts, key=lambda h: str(h.get("name") or "").lower()):
        name = host.get("name") or "?"
        state = host.get("connection_state")
        if state not in (None, "connected"):
            lines.append(f"🔴 {name} — {state}")
            continue

        cpu_total = _num(host.get("cpu_mhz_total"))
        cpu_used = _num(host.get("cpu_mhz_used"))
        cpu_pct = round(cpu_used / cpu_total * 100, 1) if cpu_total > 0 else 0.0
        ram_total = _num(host.get("memory_bytes_total"))
        ram_used = _num(host.get("memory_bytes_used"))
        ram_pct = round(ram_used / ram_total * 100, 1) if ram_total > 0 else 0.0

        mark = "🟠" if ram_pct >= 80 or cpu_pct >= 80 else "🟢"
        if host.get("in_maintenance"):
            mark = "🔧"
        line = (f"{mark} {name} — CPU {cpu_pct}% · "
                f"RAM {_gb(ram_used)}/{_gb(ram_total)} ГБ ({ram_pct}%)")
        uptime = int(_num(host.get("uptime_seconds")))
        if uptime:
            line += f" · uptime {uptime // 86400} д"
        if host.get("in_maintenance"):
            line += " · обслуживание"
        lines.append(line)
    return lines


def vm_overview_lines(vms: list, limit: int = 15) -> list:
    """Список ВМ для карточки сервера.

    Включённые идут первыми и по убыванию нагрузки на CPU — сверху то, что
    сейчас работает тяжелее всего. Выключенные не занимают по строке каждая:
    их имена собираются в одну строку, иначе на парке из двух десятков машин
    карточка превращается в простыню, где включённые теряются.

    Выравнивание колонок не используется намеренно: бот шлёт обычный текст,
    шрифт пропорциональный, и пробелы в колонки не сложатся.
    """
    lines = []
    running = [vm for vm in vms if str(vm.get("power_state")) == "poweredOn"]
    stopped = [vm for vm in vms if str(vm.get("power_state")) != "poweredOn"]

    running.sort(key=lambda vm: _num(vm.get("cpu_percent")), reverse=True)
    for vm in running[:limit]:
        cpu = round(_num(vm.get("cpu_percent")), 1)
        ram_gb = round(_num(vm.get("memory_mb_used")) / 1024, 1)
        mark = "🔥" if cpu >= 80 else "🟢"
        line = f"{mark} {vm.get('name')} — CPU {cpu}% · RAM {ram_gb} ГБ"
        tools = vm.get("tools_status")
        if tools and tools not in ("toolsOk", "toolsOld"):
            line += " · ⚠️ Tools"
        if vm.get("snapshots"):
            line += f" · 📸 {len(vm['snapshots'])}"
        lines.append(line)

    if len(running) > limit:
        # Без согласования по числу: «и ещё 1 включённых» читается как ошибка
        lines.append(f"…показаны первые {limit} из {len(running)} включённых")

    if stopped:
        names = ", ".join(str(vm.get("name")) for vm in stopped[:8])
        if len(stopped) > 8:
            names += f" и ещё {len(stopped) - 8}"
        lines.append(f"⚪ Выключены ({len(stopped)}): {names}")

    return lines


def vm_summary_line(vms: list) -> str:
    """Одна строка про парк ВМ: сколько включено, выключено, со снапшотами."""
    on = sum(1 for vm in vms if str(vm.get("power_state")) == "poweredOn")
    with_snapshots = sum(1 for vm in vms if vm.get("snapshots"))
    parts = [f"всего {len(vms)}", f"включено {on}", f"выключено {len(vms) - on}"]
    if with_snapshots:
        parts.append(f"со снапшотами {with_snapshots}")
    return " · ".join(parts)


# ─── Снапшоты ────────────────────────────────────────────────

def parse_snapshot_tree(root_list: list) -> list:
    """Плоский список снапшотов из дерева vSphere (снапшоты вложены друг
    в друга через childSnapshotList)."""
    found = []

    def walk(nodes):
        for node in nodes or []:
            found.append({
                "id": node.get("id"),
                "name": node.get("name"),
                "created_at": node.get("created_at"),
            })
            walk(node.get("children"))

    walk(root_list)
    return found


def snapshot_sizes(layout_ex: dict) -> dict:
    """{id снапшота: размер в байтах} из layoutEx виртуальной машины.

    Размер снапшота — это не один файл: к нему относятся файл состояния
    (dataKey) и дельта-диски, на которые ушли изменения после его создания.
    layoutEx.snapshot связывает снапшот с ключами файлов, layoutEx.file
    хранит размеры по этим ключам.
    """
    sizes_by_key = {}
    for entry in (layout_ex or {}).get("file") or []:
        key = entry.get("key")
        if key is not None:
            sizes_by_key[key] = _num(entry.get("size"))

    result = {}
    for snapshot in (layout_ex or {}).get("snapshot") or []:
        total = 0.0
        data_key = snapshot.get("dataKey")
        if data_key is not None and data_key in sizes_by_key:
            total += sizes_by_key[data_key]
        for disk in snapshot.get("disk") or []:
            for chain in disk.get("chain") or []:
                for file_key in chain.get("fileKey") or []:
                    total += sizes_by_key.get(file_key, 0.0)
        result[snapshot.get("key")] = total
    return result


def collect_snapshots(vms: list, now: datetime = None) -> list:
    """Все снапшоты всех ВМ с возрастом в сутках и размером в ГБ."""
    now = now or datetime.now(timezone.utc)
    result = []
    for vm in vms:
        for snapshot in vm.get("snapshots") or []:
            created = snapshot.get("created_at")
            age_days = None
            if isinstance(created, datetime):
                created_utc = (created if created.tzinfo
                               else created.replace(tzinfo=timezone.utc))
                age_days = max(0, (now - created_utc).days)
            result.append({
                "vm": vm.get("name"),
                "name": snapshot.get("name"),
                "created_at": created,
                "age_days": age_days,
                "size_gb": round(_num(snapshot.get("size_bytes")) / GB, 2),
            })
    return sorted(result, key=lambda s: s["age_days"] or 0, reverse=True)


def stale_snapshots(snapshots: list, max_age_days: int = None,
                    max_size_gb: float = None) -> list:
    """Снапшоты, вышедшие за порог по возрасту или по размеру.

    Оба порога необязательны: не задан — по нему не проверяем. Забытый
    снапшот месячной давности — самая частая причина внезапно кончившегося
    места на датасторе, поэтому проверок две, а не одна.
    """
    flagged = []
    for snapshot in snapshots:
        reasons = []
        age = snapshot.get("age_days")
        if max_age_days and age is not None and age >= max_age_days:
            reasons.append(f"возраст {age} дн")
        if max_size_gb and snapshot.get("size_gb", 0) >= max_size_gb:
            reasons.append(f"размер {snapshot['size_gb']} ГБ")
        if reasons:
            flagged.append({**snapshot, "reasons": reasons})
    return flagged


# ─── Сборка ответа в общий контракт ──────────────────────────

def build_status(raw: dict, server: dict) -> dict:
    """Ответ в той же форме, что отдают check_server (Windows) и
    check_linux_server — монитор не должен знать, что перед ним vSphere."""
    from server_check import normalize_services

    datastores = raw.get("datastores") or []
    hosts = raw.get("hosts") or []
    vms = raw.get("vms") or []

    aggregated = aggregate_hosts(hosts)
    snapshots = collect_snapshots(vms)

    unhealthy = host_problems(hosts)
    unhealthy += [f"датастор {name}: недоступен"
                  for name in inaccessible_datastores(datastores)]
    unhealthy += [
        f"датастор {item['name']}: выделено {item['provisioned_gb']} ГБ "
        f"при ёмкости {item['capacity_gb']} ГБ (+{item['overcommit_pct']}%)"
        for item in overcommitted_datastores(datastores)
    ]


    return {
        "disks": map_datastores(datastores),
        "cpu_load": aggregated["cpu_load"],
        "ram_total": aggregated["ram_total"],
        "ram_free": aggregated["ram_free"],
        "uptime_seconds": aggregated["uptime_seconds"],
        "services": map_vm_services(vms, normalize_services(server)),
        "top_cpu": top_vms(vms, "cpu"),
        "top_memory": top_vms(vms, "memory"),
        "server_time_utc": raw.get("server_time_utc"),
        "unhealthy_disks": unhealthy,
        # service_details — про службы сервера; ВМ и хосты живут в
        # platform_details, у карточки для них отдельные разделы
        "service_details": {},
        # Ниже — сверх общего контракта, для алертов по снапшотам.
        # Лишние ключи монитор игнорирует.
        "snapshots": snapshots,
        "vm_count": len(vms),
        "host_count": len(hosts),
        "platform_details": {
            "hosts": host_detail_lines(hosts),
            "vms": vm_overview_lines(vms),
            "summary": [vm_summary_line(vms)] if vms else [],
        },
    }


# ─── Обращение к vSphere ─────────────────────────────────────

def _ssl_context(verify: bool):
    if verify:
        return None          # pyVmomi возьмёт системные доверенные корни
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _verify_ssl(server: dict) -> bool:
    """По умолчанию проверяем сертификат. У vSphere он почти всегда
    самоподписанный, и отключение придётся задать явно в конфиге —
    молча ослаблять проверку в коде нельзя."""
    value = server.get("verify_ssl")
    if value is None:
        value = os.getenv("VMWARE_VERIFY_SSL", "true").strip().lower() not in (
            "0", "false", "no", "нет"
        )
    return bool(value)


def _retrieve(content, vim, vmodl, obj_type, path_set) -> list:
    """Свойства всех объектов типа obj_type одним запросом.

    Обычный обход (для каждой ВМ дёрнуть vm.runtime.powerState) делает по
    сетевому вызову на каждое свойство каждого объекта — на паре сотен ВМ
    цикл опроса встанет. PropertyCollector забирает всё за один раз.
    """
    view = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)
    try:
        traversal = vmodl.query.PropertyCollector.TraversalSpec(
            name="toView", path="view", skip=False, type=type(view)
        )
        object_spec = vmodl.query.PropertyCollector.ObjectSpec(
            obj=view, skip=True, selectSet=[traversal]
        )
        property_spec = vmodl.query.PropertyCollector.PropertySpec(
            type=obj_type, all=False, pathSet=list(path_set)
        )
        filter_spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[object_spec], propSet=[property_spec]
        )
        rows = []
        for result in content.propertyCollector.RetrieveContents([filter_spec]):
            row = {prop.name: prop.val for prop in result.propSet}
            # Ссылка на сам объект: по ней ВМ связывается со своим хостом,
            # без этого не посчитать процент загрузки CPU
            row["_ref"] = result.obj
            rows.append(row)
        return rows
    finally:
        view.Destroy()


def _snapshot_nodes(tree) -> list:
    """Дерево снапшотов pyVmomi → простые словари (рекурсивно)."""
    nodes = []
    for node in tree or []:
        nodes.append({
            "id": node.id,
            "name": node.name,
            "created_at": node.createTime,
            "children": _snapshot_nodes(getattr(node, "childSnapshotList", None)),
        })
    return nodes


def _layout_ex_to_dict(layout_ex) -> dict:
    if layout_ex is None:
        return {}
    return {
        "file": [{"key": f.key, "size": f.size, "type": f.type}
                 for f in (layout_ex.file or [])],
        "snapshot": [
            {
                "key": s.key.id if hasattr(s.key, "id") else s.key,
                "dataKey": s.dataKey,
                "disk": [{"chain": [{"fileKey": list(c.fileKey or [])}
                                    for c in (d.chain or [])]}
                         for d in (s.disk or [])],
            }
            for s in (layout_ex.snapshot or [])
        ],
    }


def _collect_raw(server: dict) -> dict:
    """Единственное место, которое обращается к vSphere.

    Всё, что уходит наружу, — обычные словари и списки: объекты pyVmomi
    дальше не живут, иначе разбор нельзя было бы протестировать.
    """
    # Импорт по месту: pyVmomi нужен только при наличии VMware в конфиге
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim, vmodl

    connection = SmartConnect(
        host=server["host"],
        user=server.get("username") or os.getenv("VMWARE_USERNAME"),
        pwd=server.get("password") or os.getenv("VMWARE_PASSWORD"),
        port=int(server.get("port") or 443),
        sslContext=_ssl_context(_verify_ssl(server)),
    )
    try:
        content = connection.RetrieveContent()

        datastores = [
            {
                "name": row.get("name"),
                "capacity_bytes": getattr(row.get("summary"), "capacity", 0),
                "free_bytes": getattr(row.get("summary"), "freeSpace", 0),
                "uncommitted_bytes": getattr(row.get("summary"), "uncommitted", 0) or 0,
                "accessible": bool(getattr(row.get("summary"), "accessible", True)),
                "type": getattr(row.get("summary"), "type", None),
            }
            for row in _retrieve(content, vim, vmodl, vim.Datastore, ["name", "summary"])
        ]

        hosts = []
        host_rows = _retrieve(content, vim, vmodl, vim.HostSystem, [
            "name", "summary.quickStats", "summary.hardware",
            "runtime.connectionState", "runtime.inMaintenanceMode",
            "runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo",
        ])
        for row in host_rows:
            quick = row.get("summary.quickStats")
            hardware = row.get("summary.hardware")
            cpu_total = 0
            if hardware is not None:
                cpu_total = (hardware.cpuMhz or 0) * (hardware.numCpuCores or 0)
            sensors = row.get(
                "runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo"
            ) or []
            hosts.append({
                "_ref": row.get("_ref"),
                "cpu_mhz_per_core": getattr(hardware, "cpuMhz", 0) or 0,
                "name": row.get("name"),
                "cpu_mhz_total": cpu_total,
                "cpu_mhz_used": getattr(quick, "overallCpuUsage", 0) or 0,
                "memory_bytes_total": getattr(hardware, "memorySize", 0) or 0,
                "memory_bytes_used": (getattr(quick, "overallMemoryUsage", 0) or 0) * 1024 ** 2,
                "uptime_seconds": getattr(quick, "uptime", 0) or 0,
                "connection_state": str(row.get("runtime.connectionState") or "connected"),
                "in_maintenance": bool(row.get("runtime.inMaintenanceMode")),
                "sensors": [
                    {"name": s.name, "status": getattr(s.healthState, "key", None)}
                    for s in sensors
                ],
            })

        vms = []
        # Частота ядра по каждому хосту: нужна, чтобы перевести потребление
        # ВМ из мегагерц в проценты от выделенных ей ядер
        mhz_by_host = {host["_ref"]: host["cpu_mhz_per_core"] for host in hosts}

        vm_rows = _retrieve(content, vim, vmodl, vim.VirtualMachine, [
            "name", "runtime.powerState", "runtime.host", "guest.toolsStatus",
            "summary.quickStats", "snapshot", "layoutEx", "config.template",
            "config.hardware.numCPU",
        ])
        for row in vm_rows:
            if row.get("config.template"):
                continue          # шаблоны — не работающие ВМ
            quick = row.get("summary.quickStats")
            snapshot_info = row.get("snapshot")
            nodes = _snapshot_nodes(
                getattr(snapshot_info, "rootSnapshotList", None) if snapshot_info else None
            )
            sizes = snapshot_sizes(_layout_ex_to_dict(row.get("layoutEx")))
            cpu_mhz_used = getattr(quick, "overallCpuUsage", 0) or 0
            vms.append({
                "name": row.get("name"),
                "power_state": str(row.get("runtime.powerState") or ""),
                "tools_status": str(row.get("guest.toolsStatus") or "") or None,
                "cpu_mhz_used": cpu_mhz_used,
                "cpu_percent": vm_cpu_percent(
                    cpu_mhz_used,
                    row.get("config.hardware.numCPU"),
                    mhz_by_host.get(row.get("runtime.host")),
                ),
                "memory_mb_used": getattr(quick, "guestMemoryUsage", 0) or 0,
                "snapshots": [
                    {**node, "size_bytes": sizes.get(node["id"], 0)}
                    for node in parse_snapshot_tree(nodes)
                ],
            })

        server_time = None
        try:
            server_time = int(content.serverClock.timestamp())
        except Exception:
            pass

        return {
            "datastores": datastores,
            "hosts": hosts,
            "vms": vms,
            "server_time_utc": server_time,
        }
    finally:
        # Сессии vCenter живут долго и упираются в лимит: при опросе раз в
        # пять минут незакрытые сессии копятся сутками. Закрываем всегда,
        # даже если разбор ответа упал.
        try:
            Disconnect(connection)
        except Exception:
            pass


def check_vmware_server(server: dict) -> dict:
    return build_status(_collect_raw(server), server)
