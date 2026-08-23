import json

from pgconn import get_conn
from ping_tools import ping_host
from server_check import check_server, server_type
from service_details import save_service_details
from winrm_errors import parse_status

SERVERS_FILE = "/app/config/servers.json"


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
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO server_status
                (server_name, status, error, cpu_load, ram_total, ram_free, uptime_seconds)
            VALUES (%s, 'online', NULL, %s, %s, %s, %s)
            """,
            (
                server_name,
                info["cpu_load"],
                info["ram_total"],
                info["ram_free"],
                info["uptime_seconds"]
            )
        )

        for disk in info["disks"]:
            cur.execute(
                """
                INSERT INTO disk_metrics (server_name, disk_name, free_gb, used_gb)
                VALUES (%s, %s, %s, %s)
                """,
                (server_name, disk["Name"], float(disk["FreeGB"]), float(disk["UsedGB"]))
            )

        for service in info["services"]:
            service_name = service.get("Name")
            if not service_name:
                continue
            cur.execute(
                """
                INSERT INTO service_status (server_name, service_name, display_name, status)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    server_name,
                    service_name,
                    service.get("Label") or service.get("DisplayName") or service_name,
                    service.get("Status", "unknown")
                )
            )

        for metric_type, processes in (("cpu", info["top_cpu"]), ("memory", info["top_memory"])):
            for process in processes:
                cur.execute(
                    """
                    INSERT INTO process_metrics
                        (server_name, metric_type, process_name, process_id,
                         cpu_percent, cpu_seconds, memory_mb)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        server_name,
                        metric_type,
                        process.get("Name"),
                        process.get("Id"),
                        process.get("CpuPercent"),
                        process.get("CpuSeconds"),
                        process.get("MemoryMB")
                    )
                )


def save_offline(server_name: str, status: str, error: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO server_status (server_name, status, error)
            VALUES (%s, %s, %s)
            """,
            (server_name, status, error)
        )


def save_ping_status(server_name: str, ok: bool):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO server_status (server_name, status, error)
            VALUES (%s, %s, %s)
            """,
            (
                server_name,
                "online" if ok else "ping_down",
                None if ok else "Ping не отвечает"
            )
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
        save_service_details(server_name, info.get("service_details") or {})
        return True, None
    except Exception as e:
        error = str(e)
        try:
            save_offline(server_name, parse_status(error), error)
        except Exception:
            pass
        return False, error
