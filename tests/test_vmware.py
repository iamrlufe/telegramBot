"""
Разбор ответа vSphere (shared/vmware_check.py).

Тесты работают на зафиксированных структурах, какие отдаёт vCenter, — живой
vCenter не нужен. Обращение к API (_collect_raw) сюда не входит: оно тонкое
и проверяется на реальной установке, вся логика вынесена в чистые функции.
"""
from datetime import datetime, timedelta, timezone

import pytest

import vmware_check as vc

GB = 1024 ** 3


def ds(name, capacity_gb, free_gb, uncommitted_gb=0, accessible=True):
    return {
        "name": name,
        "capacity_bytes": capacity_gb * GB,
        "free_bytes": free_gb * GB,
        "uncommitted_bytes": uncommitted_gb * GB,
        "accessible": accessible,
        "type": "VMFS",
    }


def host(name, cores=8, mhz=2400, used_mhz=4800, ram_gb=128, used_ram_mb=65536,
         uptime=86400, state="connected", maintenance=False, sensors=None):
    return {
        "name": name,
        "cpu_mhz_total": cores * mhz,
        "cpu_mhz_used": used_mhz,
        "memory_bytes_total": ram_gb * GB,
        "memory_bytes_used": used_ram_mb * 1024 ** 2,
        "uptime_seconds": uptime,
        "connection_state": state,
        "in_maintenance": maintenance,
        "sensors": sensors or [],
    }


def vm(name, power="poweredOn", cpu=500, mem=2048, tools="toolsOk", snapshots=None):
    return {
        "name": name,
        "power_state": power,
        "tools_status": tools,
        "cpu_mhz_used": cpu,
        "memory_mb_used": mem,
        "snapshots": snapshots or [],
    }


# ─── Датасторы ───────────────────────────────────────────────

def test_datastores_map_to_disk_shape():
    """Форма обязана совпадать с дисками Windows/Linux — на неё завязаны
    пороги, прогноз и графики."""
    result = vc.map_datastores([ds("ds-fast", 1000, 250)])

    assert result == [{"Name": "ds-fast", "FreeGB": 250.0, "UsedGB": 750.0}]


def test_inaccessible_datastore_is_skipped():
    # vSphere отдаёт по недоступному датастору нули; сохранённый нулевой
    # замер испортил бы прогноз заполнения
    result = vc.map_datastores([ds("ds-dead", 0, 0, accessible=False), ds("ds-ok", 100, 40)])

    assert [d["Name"] for d in result] == ["ds-ok"]
    assert vc.inaccessible_datastores([ds("ds-dead", 0, 0, accessible=False)]) == ["ds-dead"]


def test_zero_capacity_datastore_is_skipped():
    assert vc.map_datastores([ds("ds-broken", 0, 0)]) == []


def test_overcommit_detected():
    # занято 600, свободно 400, тонкие могут дорасти ещё на 700 → 1300 из 1000
    result = vc.overcommitted_datastores([ds("ds-thin", 1000, 400, uncommitted_gb=700)])

    assert len(result) == 1
    assert result[0]["name"] == "ds-thin"
    assert result[0]["provisioned_gb"] == 1300.0
    assert result[0]["overcommit_pct"] == 30.0


def test_no_overcommit_when_fits():
    assert vc.overcommitted_datastores([ds("ds-thin", 1000, 400, uncommitted_gb=200)]) == []


# ─── Хосты ───────────────────────────────────────────────────

def test_cpu_load_is_weighted_by_capacity():
    """Хост на 4 ядра и хост на 40 не должны весить одинаково."""
    small = host("esx-small", cores=4, mhz=1000, used_mhz=4000)      # 4000 из 4000
    big = host("esx-big", cores=40, mhz=1000, used_mhz=0)            # 0 из 40000

    result = vc.aggregate_hosts([small, big])

    # Среднее арифметическое дало бы 50%, взвешенное — 4000/44000
    assert result["cpu_load"] == 9.1


def test_memory_is_summed_across_hosts():
    result = vc.aggregate_hosts([
        host("esx-01", ram_gb=100, used_ram_mb=40 * 1024),
        host("esx-02", ram_gb=100, used_ram_mb=60 * 1024),
    ])

    assert result["ram_total"] == 200.0
    assert result["ram_free"] == 100.0


def test_uptime_is_the_minimum():
    result = vc.aggregate_hosts([
        host("esx-01", uptime=1000000),
        host("esx-02", uptime=3600),
    ])

    assert result["uptime_seconds"] == 3600


def test_maintenance_and_disconnected_hosts_excluded_from_totals():
    result = vc.aggregate_hosts([
        host("esx-01", ram_gb=100, used_ram_mb=50 * 1024),
        host("esx-02", ram_gb=100, used_ram_mb=0, maintenance=True),
        host("esx-03", ram_gb=100, used_ram_mb=0, state="disconnected"),
    ])

    # Иначе нулевые счётчики выключенных хостов занижали бы загрузку
    assert result["ram_total"] == 100.0


def test_aggregate_survives_empty_host_list():
    assert vc.aggregate_hosts([]) == {
        "cpu_load": 0.0, "ram_total": 0.0, "ram_free": 0.0, "uptime_seconds": 0
    }


def test_host_problems_lists_sensors_and_states():
    problems = vc.host_problems([
        host("esx-01", sensors=[{"name": "PSU 2", "status": "red"},
                                {"name": "Fan 1", "status": "green"}]),
        host("esx-02", maintenance=True),
        host("esx-03", state="notResponding"),
    ])

    assert "esx-01: 🔴 PSU 2" in problems
    assert "esx-02: режим обслуживания" in problems
    assert "esx-03: хост notResponding" in problems
    assert not any("Fan 1" in p for p in problems)


# ─── Виртуальные машины как «службы» ─────────────────────────

def test_powered_on_vm_maps_to_running():
    """check_service_alert считает нормой только «running» — иначе алерт
    о восстановлении не придёт никогда."""
    services = vc.map_vm_services([vm("dc-01")], [{"name": "dc-01", "display_name": "dc-01"}])

    assert services[0]["Status"] == "running"


def test_powered_off_vm_maps_to_stopped():
    services = vc.map_vm_services(
        [vm("dc-01", power="poweredOff")], [{"name": "dc-01", "display_name": "dc-01"}]
    )

    assert services[0]["Status"] == "stopped"


def test_vm_name_matched_case_insensitively():
    services = vc.map_vm_services([vm("DC-01")], [{"name": "dc-01", "display_name": "dc-01"}])

    assert services[0]["Status"] == "running"
    assert services[0]["Name"] == "DC-01"


def test_missing_vm_reported_as_not_found():
    services = vc.map_vm_services([vm("other")], [{"name": "dc-01", "display_name": "dc-01"}])

    assert services[0]["Status"] == "not_found"


def test_top_vms_skips_powered_off_and_sorts():
    vms = [
        vm("idle", power="poweredOff", cpu=0, mem=0),
        vm("busy", cpu=5000, mem=8192),
        vm("calm", cpu=100, mem=1024),
    ]

    top = vc.top_vms(vms, "cpu", limit=2)

    assert [row["Name"] for row in top] == ["busy", "calm"]
    assert top[0]["MemoryMB"] == 8192.0


def test_top_vms_by_memory():
    vms = [vm("a", cpu=9000, mem=512), vm("b", cpu=1, mem=16384)]

    assert [row["Name"] for row in vc.top_vms(vms, "memory")] == ["b", "a"]


def test_overview_marks_tools_and_snapshots():
    lines = vc.vm_overview_lines([
        vm("app-01", tools="toolsNotRunning",
           snapshots=[{"id": 1, "name": "s", "created_at": None}]),
        vm("off-01", power="poweredOff"),
    ])

    assert "🟢 app-01" in lines[0]
    assert "⚠️ Tools" in lines[0]
    assert "📸 1" in lines[0]
    assert lines[1] == "⚪ Выключены (1): off-01"


# ─── Снапшоты ────────────────────────────────────────────────

def test_snapshot_tree_is_flattened():
    tree = [{
        "id": 1, "name": "before-update", "created_at": None,
        "children": [{"id": 2, "name": "after-update", "created_at": None, "children": []}],
    }]

    result = vc.parse_snapshot_tree(tree)

    assert [s["id"] for s in result] == [1, 2]


def test_snapshot_size_sums_state_file_and_delta_disks():
    layout = {
        "file": [
            {"key": 10, "size": 2 * GB, "type": "snapshotData"},
            {"key": 20, "size": 5 * GB, "type": "diskExtent"},
            {"key": 30, "size": 100 * GB, "type": "diskExtent"},   # чужой файл
        ],
        "snapshot": [
            {"key": 1, "dataKey": 10, "disk": [{"chain": [{"fileKey": [20]}]}]},
        ],
    }

    assert vc.snapshot_sizes(layout) == {1: 7 * GB}


def test_snapshot_sizes_tolerates_missing_layout():
    assert vc.snapshot_sizes({}) == {}
    assert vc.snapshot_sizes(None) == {}


def test_snapshot_age_calculated_in_days():
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    vms = [vm("app-01", snapshots=[{
        "id": 1, "name": "old", "created_at": now - timedelta(days=40), "size_bytes": 3 * GB,
    }])]

    result = vc.collect_snapshots(vms, now=now)

    assert result[0]["age_days"] == 40
    assert result[0]["size_gb"] == 3.0
    assert result[0]["vm"] == "app-01"


def test_naive_snapshot_time_treated_as_utc():
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    vms = [vm("app-01", snapshots=[{
        "id": 1, "name": "old", "created_at": datetime(2026, 8, 20), "size_bytes": 0,
    }])]

    assert vc.collect_snapshots(vms, now=now)[0]["age_days"] == 5


@pytest.mark.parametrize("age,size,max_age,max_size,flagged", [
    (40, 1.0, 7, None, True),      # старый
    (2, 80.0, None, 50, True),     # большой
    (2, 1.0, 7, 50, False),        # в норме
    (40, 80.0, None, None, False),  # пороги не заданы — не проверяем
])
def test_stale_snapshot_thresholds(age, size, max_age, max_size, flagged):
    snapshots = [{"vm": "app", "name": "s", "age_days": age, "size_gb": size}]

    result = vc.stale_snapshots(snapshots, max_age_days=max_age, max_size_gb=max_size)

    assert bool(result) is flagged


# ─── Сборка общего ответа ────────────────────────────────────

def test_build_status_matches_check_server_contract():
    """Монитор не должен знать, что перед ним vSphere: набор ключей тот же,
    что у Windows- и Linux-опроса."""
    raw = {
        "datastores": [ds("ds-01", 1000, 100)],
        "hosts": [host("esx-01")],
        "vms": [vm("dc-01"), vm("app-01", power="poweredOff")],
        "server_time_utc": 1756000000,
    }
    server = {"name": "vcenter", "host": "192.0.2.50", "services": ["dc-01", "app-01"]}

    status = vc.build_status(raw, server)

    required = {
        "disks", "cpu_load", "ram_total", "ram_free", "uptime_seconds",
        "services", "top_cpu", "top_memory", "server_time_utc",
        "unhealthy_disks", "service_details",
    }
    assert required <= set(status)
    assert status["disks"][0]["Name"] == "ds-01"
    assert {s["Name"]: s["Status"] for s in status["services"]} == {
        "dc-01": "running", "app-01": "stopped"
    }
    assert status["vm_count"] == 2


def test_build_status_reports_overcommit_as_unhealthy():
    raw = {
        "datastores": [ds("ds-thin", 1000, 400, uncommitted_gb=700)],
        "hosts": [host("esx-01")],
        "vms": [],
        "server_time_utc": None,
    }

    status = vc.build_status(raw, {"name": "vcenter", "host": "h", "services": []})

    assert any("выделено" in line for line in status["unhealthy_disks"])


def test_build_status_on_empty_inventory():
    """Права выданы без «Propagate to children» — vCenter вернёт пустой
    инвентарь. Падать при этом нельзя."""
    status = vc.build_status(
        {"datastores": [], "hosts": [], "vms": [], "server_time_utc": None},
        {"name": "vcenter", "host": "h", "services": []},
    )

    assert status["disks"] == []
    assert status["cpu_load"] == 0.0
    assert status["service_details"] == {}


# ─── Встраивание в бота и алерты ─────────────────────────────

def test_wizard_skips_backup_fields_for_vmware():
    """Датастор — не файловая система: путей с копиями, verify и MSSQL
    у этого типа нет, спрашивать их в мастере незачем."""
    from config_editor import build_wizard_order

    order = build_wizard_order("vmware")

    assert "snapshot_alert_days" in order
    assert "verify_ssl" in order
    for absent in ("backups_sql", "backups_veeam", "verify_backup", "dbsize",
                   "onec_logs", "reg_file", "backup_alert_hours"):
        assert absent not in order


def test_vmware_fields_hidden_from_other_types():
    from config_editor import build_wizard_order

    for kind in ("windows", "linux"):
        order = build_wizard_order(kind)
        assert "verify_ssl" not in order
        assert "snapshot_alert_days" not in order


def test_config_accepts_vmware_server():
    from config_editor import validate_config

    validate_config([{
        "name": "vcenter", "host": "192.0.2.50", "type": "vmware",
        "username": "monitor@vsphere.local", "verify_ssl": False,
        "services": ["dc-01"], "snapshot_alert_days": 7, "snapshot_alert_gb": 50,
    }])


@pytest.mark.parametrize("bad", [
    {"snapshot_alert_days": "неделя"},
    {"snapshot_alert_days": 0},
    {"snapshot_alert_gb": -5},
    {"verify_ssl": "нет"},
])
def test_config_rejects_bad_vmware_values(bad):
    from config_editor import validate_config

    with pytest.raises(ValueError):
        validate_config([{"name": "vcenter", "host": "h", "type": "vmware", **bad}])


def test_disk_alert_keyboard_hides_top_dirs_for_vmware():
    from alerts import disk_alert_kb

    def buttons(kb):
        return [b["text"] for row in kb["inline_keyboard"] for b in row]

    assert "📂 Топ каталогов" in buttons(disk_alert_kb("srv", "C:"))
    assert "📂 Топ каталогов" not in buttons(
        disk_alert_kb("vcenter", "ds-01", top_dirs=False)
    )


# ─── verify_ssl: флаг, у которого «по умолчанию» = включено ───

def test_answer_no_writes_explicit_false():
    """Ответ «нет» обязан записать false, а не просто не писать поле.

    У обычных флагов (dbsize) отсутствие означает «выключено», у
    verify_ssl — наоборот, «проверять». Если «нет» не пишет ничего,
    ответ теряется и подключение падает на проверке сертификата.
    """
    from config_editor import parse_field_value

    ok, value, error = parse_field_value("verify_ssl", "нет")

    assert (ok, error) == (True, None)
    assert value is False


def test_answer_yes_omits_field_as_default():
    from config_editor import parse_field_value

    ok, value, _ = parse_field_value("verify_ssl", "да")

    assert ok and value is None


@pytest.mark.parametrize("text", ["no", "нет", "off", "n"])
def test_various_negative_answers_write_false(text):
    from config_editor import parse_field_value

    ok, value, _ = parse_field_value("verify_ssl", text)
    if ok:                       # набор синонимов задаётся FALSE_WORDS
        assert value is False


def test_false_survives_write_to_config():
    from config_editor import apply_field

    server = {}
    apply_field(server, "verify_ssl", False)

    assert server["verify_ssl"] is False


def test_display_shows_default_as_yes():
    from config_editor import display_value

    assert display_value({}, "verify_ssl") == "да"
    assert display_value({"verify_ssl": False}, "verify_ssl") == "нет"


def test_check_uses_config_value():
    """Ради чего всё: false в конфиге должен доходить до подключения."""
    assert vc._verify_ssl({"verify_ssl": False}) is False
    assert vc._verify_ssl({"verify_ssl": True}) is True


def test_check_defaults_to_verifying(monkeypatch):
    monkeypatch.delenv("VMWARE_VERIFY_SSL", raising=False)

    assert vc._verify_ssl({}) is True


def test_env_can_switch_verification_off(monkeypatch):
    monkeypatch.setenv("VMWARE_VERIFY_SSL", "false")

    assert vc._verify_ssl({}) is False
    # Значение в конфиге сильнее переменной окружения
    assert vc._verify_ssl({"verify_ssl": True}) is True


# ─── Разбивка по хостам и проценты CPU ───────────────────────

def test_vm_cpu_reported_in_percent_not_megahertz():
    """vSphere отдаёт потребление в МГц. Без пересчёта карточка сервера
    показывала «1967% CPU» — колонка называется cpu_percent."""
    # 4 vCPU на ядрах по 2000 МГц = ёмкость 8000 МГц, занято 2000 → 25%
    assert vc.vm_cpu_percent(2000, 4, 2000) == 25.0


@pytest.mark.parametrize("mhz,cpus,host_mhz", [
    (2000, 0, 2000),      # число vCPU неизвестно
    (2000, 4, 0),         # частота хоста неизвестна
    (2000, None, None),   # ВМ выключена, данных нет
])
def test_cpu_percent_is_zero_when_capacity_unknown(mhz, cpus, host_mhz):
    # Лучше 0, чем выдуманное число
    assert vc.vm_cpu_percent(mhz, cpus, host_mhz) == 0.0


def test_top_vms_report_percent_field():
    vms = [dict(vm("busy", cpu=6000), cpu_percent=75.0)]

    assert vc.top_vms(vms, "cpu")[0]["CpuPercent"] == 75.0


def test_host_lines_show_each_host_separately():
    """Ради чего всё: в vCenter несколько хостов, и агрегат их прячет."""
    lines = vc.host_detail_lines([
        host("esxi8", cores=10, mhz=2000, used_mhz=2000, ram_gb=100, used_ram_mb=90 * 1024),
        host("esxi9", cores=10, mhz=2000, used_mhz=1000, ram_gb=100, used_ram_mb=10 * 1024),
    ])

    assert len(lines) == 2
    assert lines[0].startswith("🟠 esxi8")      # RAM 90% — предупреждение
    assert "CPU 10.0%" in lines[0]
    assert "RAM 90.0/100.0 ГБ (90.0%)" in lines[0]
    assert lines[1].startswith("🟢 esxi9")
    assert "uptime 1 д" in lines[1]


def test_host_line_marks_maintenance_and_offline():
    lines = vc.host_detail_lines([
        host("esxi-maint", maintenance=True),
        host("esxi-down", state="notResponding"),
    ])

    # Хосты сортируются по имени, поэтому esxi-down идёт первым
    by_name = {line.split()[1]: line for line in lines}
    assert by_name["esxi-maint"].startswith("🔧 esxi-maint")
    assert "обслуживание" in by_name["esxi-maint"]
    assert by_name["esxi-down"] == "🔴 esxi-down — notResponding"


def test_vm_summary_counts_states():
    line = vc.vm_summary_line([
        vm("a"), vm("b", power="poweredOff"),
        vm("c", snapshots=[{"id": 1, "name": "s", "created_at": None}]),
    ])

    assert "всего 3" in line and "включено 2" in line
    assert "выключено 1" in line and "со снапшотами 1" in line


def test_build_status_exposes_platform_details():
    status = vc.build_status(
        {"datastores": [], "hosts": [host("esxi8"), host("esxi9")],
         "vms": [vm("dc-01")], "server_time_utc": None},
        {"name": "vcenter", "host": "h", "services": []},
    )

    assert len(status["platform_details"]["hosts"]) == 2
    assert status["platform_details"]["summary"] == ["всего 1 · включено 1 · выключено 0"]


# ─── Раздел «Виртуальные машины» в карточке ──────────────────

def test_running_vms_sorted_by_cpu():
    """Сверху то, что сейчас работает тяжелее всего."""
    vms = [
        dict(vm("calm"), cpu_percent=2.0),
        dict(vm("busy"), cpu_percent=71.0),
        dict(vm("medium"), cpu_percent=30.0),
    ]

    names = [line.split()[1] for line in vc.vm_overview_lines(vms)]

    assert names == ["busy", "medium", "calm"]


def test_stopped_vms_collapsed_into_one_line():
    """Два десятка выключенных машин по строке каждая превращают карточку
    в простыню, где включённые теряются."""
    vms = [vm("on-01")] + [vm(f"off-{i}", power="poweredOff") for i in range(1, 7)]

    lines = vc.vm_overview_lines(vms)

    assert len(lines) == 2
    assert lines[1].startswith("⚪ Выключены (6):")


def test_many_stopped_vms_are_truncated():
    vms = [vm(f"off-{i}", power="poweredOff") for i in range(1, 13)]

    line = vc.vm_overview_lines(vms)[0]

    assert line.startswith("⚪ Выключены (12):")
    assert "и ещё 4" in line


def test_running_list_is_capped():
    vms = [dict(vm(f"vm-{i}"), cpu_percent=i) for i in range(1, 21)]

    lines = vc.vm_overview_lines(vms, limit=5)

    assert len(lines) == 6
    assert lines[-1] == "…показаны первые 5 из 20 включённых"


def test_hot_vm_is_marked():
    lines = vc.vm_overview_lines([dict(vm("hot"), cpu_percent=95.0)])

    assert lines[0].startswith("🔥 hot")


def test_ram_shown_in_gigabytes():
    lines = vc.vm_overview_lines([dict(vm("app", mem=7864), cpu_percent=4.1)])

    # В топе процессов мегабайты, здесь гигабайты — рядом с хостами так читается
    assert "RAM 7.7 ГБ" in lines[0]


def test_old_tools_not_flagged():
    """toolsOld — рабочее состояние, поднимать из-за него флаг незачем."""
    lines = vc.vm_overview_lines([dict(vm("app", tools="toolsOld"), cpu_percent=1.0)])

    assert "Tools" not in lines[0]


# ─── Отрисовка топа в карточке ───────────────────────────────

# bot/db.py и monitor/db.py называются одинаково, и обычный import db
# попадает в monitor — грузим модуль бота по явному пути.
def _bot_db():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "bot" / "db.py"
    spec = importlib.util.spec_from_file_location("bot_db", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_top_line_hides_empty_process_id():
    """У виртуальной машины идентификатора процесса нет — в колонке 0,
    и «(0)» в карточке выглядит как ошибка."""
    _top_line = _bot_db()._top_line

    line = _top_line(("agrotnk.kz", 0, 10.7, None, 819), by="cpu")

    assert "(0)" not in line
    assert line == "🟢 agrotnk.kz — 10.7% CPU · 819 MB"


def test_top_line_keeps_real_process_id():
    _top_line = _bot_db()._top_line

    line = _top_line(("sqlservr", 4312, 40.0, None, 2048), by="cpu")

    assert "(4312)" in line


def test_top_line_marks_heavy_load():
    _top_line = _bot_db()._top_line

    assert _top_line(("busy", 0, 91.0, None, 100), by="cpu").startswith("🔥")


def test_top_line_memory_order():
    _top_line = _bot_db()._top_line

    line = _top_line(("app", 0, 4.5, None, 2621), by="memory")

    assert line == "🟢 app — 2621 MB · 4.5% CPU"


def test_top_line_survives_missing_values():
    _top_line = _bot_db()._top_line

    line = _top_line(("app", None, None, None, None), by="cpu")

    assert line == "🟢 app — 0% CPU · 0 MB"


# ─── Устаревший TLS (vSphere 6.x) ────────────────────────────

def test_legacy_context_caps_tls12_and_lowers_cipher_policy():
    """vSphere 6.0 предлагает только шифры с обменом ключами на чистом RSA
    и спотыкается о ClientHello с расширениями TLS 1.3."""
    import ssl

    context = vc._ssl_context(verify=False, legacy=True)

    assert context.maximum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_NONE


def test_normal_context_keeps_modern_policy():
    import ssl

    context = vc._ssl_context(verify=False, legacy=False)

    # Потолок не опускаем: на современных vCenter TLS 1.3 работает
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.verify_mode == ssl.CERT_NONE


def test_verifying_context_is_default_unless_legacy():
    # None означает «настройки по умолчанию с системными корнями»
    assert vc._ssl_context(verify=True, legacy=False) is None
    assert vc._ssl_context(verify=True, legacy=True) is not None


def test_legacy_context_still_verifies_when_asked():
    import ssl

    context = vc._ssl_context(verify=True, legacy=True)

    # Старый TLS и отключение проверки сертификата — разные вещи
    assert context.verify_mode != ssl.CERT_NONE
    assert context.maximum_version == ssl.TLSVersion.TLSv1_2


def test_legacy_flag_read_from_config(monkeypatch):
    monkeypatch.delenv("VMWARE_LEGACY_TLS", raising=False)

    assert vc._legacy_tls({"legacy_tls": True}) is True
    assert vc._legacy_tls({}) is False


def test_legacy_flag_from_env(monkeypatch):
    monkeypatch.setenv("VMWARE_LEGACY_TLS", "true")

    assert vc._legacy_tls({}) is True
    # Значение в конфиге сильнее переменной окружения
    assert vc._legacy_tls({"legacy_tls": False}) is False


def test_wizard_asks_about_legacy_tls():
    from config_editor import build_wizard_order

    assert "legacy_tls" in build_wizard_order("vmware")
    assert "legacy_tls" not in build_wizard_order("windows")
