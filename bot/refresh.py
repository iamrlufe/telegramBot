import json

from ping_tools import ping_host
from server_check import check_server, server_type
from service_details import save_details_from_info
from winrm_errors import parse_status
from settings import SERVERS_FILE
from metrics_store import (
    save_disk_metrics,
    save_server_status,
    save_service_statuses,
    save_process_metrics,
)



def load_server(server_name: str) -> dict:
    try:
        with open(SERVERS_FILE) as f:
            servers = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"config/servers.json невалидный JSON: line {e.lineno} column {e.colno} ({e.msg})"
        ) from e

    for server in servers:
        if server.get("name") == server_name:
            return server
    raise ValueError(f"Сервер {server_name} не найден в config/servers.json")


def save_online(server_name: str, info: dict):
    """Замеры разового опроса — теми же функциями, что и цикл монитора
    (shared/metrics_store.py). Своя копия здесь писала каждый диск, службу и
    процесс отдельным INSERT: на сервере 1С это полтора десятка запросов
    вместо четырёх.

    Порядок тот же, что в цикле: сначала статус, потом наборы. Каждая
    функция пишет своей транзакцией — как и у монитора, отдельная кнопка
    атомарности всей пачки не требует."""
    save_server_status(
        server_name, "online",
        cpu_load=info["cpu_load"],
        ram_total=info["ram_total"],
        ram_free=info["ram_free"],
        uptime_seconds=info["uptime_seconds"],
    )
    save_disk_metrics(server_name, [
        (disk["Name"], float(disk["FreeGB"]), float(disk["UsedGB"]))
        for disk in info["disks"]
    ])
    save_service_statuses(server_name, [
        (
            service["Name"],
            service.get("Label") or service.get("DisplayName") or service["Name"],
            service.get("Status", "unknown"),
        )
        for service in info["services"] if service.get("Name")
    ])
    save_process_metrics(server_name, "cpu", info["top_cpu"])
    save_process_metrics(server_name, "memory", info["top_memory"])


def save_offline(server_name: str, status: str, error: str):
    save_server_status(server_name, status, error)


def save_ping_status(server_name: str, ok: bool):
    save_server_status(
        server_name,
        "online" if ok else "ping_down",
        None if ok else "Ping не отвечает",
    )


def refresh_server(server_name: str):
    try:
        server = load_server(server_name)

        if server_type(server) == "device":
            # Сетевое устройство: полного опроса нет, обновляем только ping-статус
            ok, output = ping_host(server["host"], count=1)
            save_ping_status(server_name, ok)
            return (True, None) if ok else (False, "Ping не отвечает")

        info = check_server(server)
        save_online(server_name, info)
        save_details_from_info(server_name, info)
        return True, None
    except Exception as e:
        error = str(e)
        try:
            save_offline(server_name, parse_status(error), error)
        except Exception:
            pass
        return False, error
