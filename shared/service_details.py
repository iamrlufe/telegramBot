"""
shared/service_details.py

Расширенная информация о сервисах Linux-серверов (контейнеры Docker,
сайты веб-серверов). Монитор и бот пишут её в JSON на общем томе
/app/data, карточка сервера в боте читает оттуда — без изменения схемы БД.

Формат файла:
{
  "ServerName": {
    "updated": "2026-07-17T12:00:00+00:00",
    "services": { "docker": ["строка", ...], "nginx": [...] },
    "platform": { "hosts": ["строка", ...], "summary": [...] }
  }
}

Секция platform — про сам объект мониторинга, а не про его службы:
разбивка vCenter по ESXi-хостам. Агрегат в карточке отвечает на вопрос
«хватает ли ресурсов платформе», но не показывает перекос между хостами.
"""
import json
import os
import tempfile
import threading
from datetime import datetime, timezone

DETAILS_FILE = "/app/data/service_details.json"
_lock = threading.Lock()


def load_all() -> dict:
    try:
        with open(DETAILS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_service_details(server_name: str) -> dict:
    """{unit: [строки]} для сервера; пусто, если данных нет."""
    entry = load_all().get(server_name) or {}
    services = entry.get("services")
    return services if isinstance(services, dict) else {}


def load_platform_details(server_name: str) -> dict:
    """{раздел: [строки]} про саму платформу (хосты ESXi); пусто, если нет."""
    entry = load_all().get(server_name) or {}
    platform = entry.get("platform")
    return platform if isinstance(platform, dict) else {}


def save_service_details(server_name: str, details: dict, platform: dict = None):
    """Сохраняет детали сервера; пустые details и platform удаляют запись."""
    with _lock:
        data = load_all()
        if details or platform:
            data[server_name] = {
                "updated": datetime.now(timezone.utc).isoformat(),
                "services": details or {},
                "platform": platform or {},
            }
        elif server_name in data:
            del data[server_name]
        else:
            return

        directory = os.path.dirname(DETAILS_FILE)
        try:
            fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".svc_details_")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp_path, DETAILS_FILE)
        except OSError as e:
            print(f"[service_details] Не удалось сохранить {DETAILS_FILE}: {e}", flush=True)
