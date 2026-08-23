"""
shared/disk_health.py

Здоровье дисков Linux-серверов: состояние RAID (/proc/mdstat), температура
дисков и причина недоступности SMART. Монитор пишет в JSON на общем томе
/app/data, карточка сервера в боте читает оттуда — как и service_details,
без изменения схемы БД.

Зачем файл, а не таблица: данные всегда нужны только «на сейчас», история по
ним не строится, а схему БД на существующих инсталляциях пришлось бы
накатывать руками.

Формат:
{
  "nas.example.local": {
    "updated": "2026-08-02T12:00:00+00:00",
    "raid": [{"name": "md2", "level": "raid5", "total": 4, "active": 4,
              "flags": "UUUU", "degraded": false, "failed": [],
              "progress": null}],
    "temps": [{"name": "sda", "temp_c": 41.0}],
    "smart_note": "SMART недоступен: нужен sudo без пароля для smartctl"
  }
}
"""
import json
import os
import tempfile
import threading
from datetime import datetime, timezone

DISK_HEALTH_FILE = "/app/data/disk_health.json"
_lock = threading.Lock()


def load_all() -> dict:
    try:
        with open(DISK_HEALTH_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_disk_health(server_name: str) -> dict:
    """{"raid": [...], "temps": [...], "smart_note": str|None} для сервера."""
    entry = load_all().get(server_name) or {}
    return {
        "raid": entry.get("raid") or [],
        "temps": entry.get("temps") or [],
        "smart_note": entry.get("smart_note"),
        "updated": entry.get("updated"),
    }


def save_disk_health(server_name: str, raid: list = None,
                     temps: list = None, smart_note: str = None):
    """Сохраняет состояние дисков сервера; пустые данные удаляют запись,
    чтобы карточка не показывала протухшее «всё хорошо» после того, как
    сервер перестал отдавать эти сведения."""
    raid = raid or []
    temps = temps or []

    with _lock:
        data = load_all()
        if raid or temps or smart_note:
            data[server_name] = {
                "updated": datetime.now(timezone.utc).isoformat(),
                "raid": raid,
                "temps": temps,
                "smart_note": smart_note,
            }
        elif server_name in data:
            del data[server_name]
        else:
            return

        directory = os.path.dirname(DISK_HEALTH_FILE)
        try:
            fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".disk_health_")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp_path, DISK_HEALTH_FILE)
        except OSError as e:
            print(f"[disk_health] Не удалось сохранить {DISK_HEALTH_FILE}: {e}",
                  flush=True)


def purge_disk_health(server_name: str):
    """Убирает сервер из файла — при удалении его из конфига."""
    with _lock:
        data = load_all()
        if server_name not in data:
            return
        del data[server_name]
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=os.path.dirname(DISK_HEALTH_FILE), prefix=".disk_health_")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp_path, DISK_HEALTH_FILE)
        except OSError:
            pass


# ─── Отображение в карточке сервера ──────────────────────────

def format_disk_health(health: dict) -> str:
    """Блок для карточки сервера. Пустая строка, если сведений нет —
    на Windows их не бывает вовсе."""
    if not health:
        return ""

    lines = []
    raid = health.get("raid") or []
    if raid:
        lines.append("\n🧩 RAID\n")
        for array in raid:
            name = array.get("name", "?")
            level = array.get("level") or "?"
            total, active = array.get("total"), array.get("active")
            counts = f": {active}/{total}" if total is not None else ""
            flags = f" [{array['flags']}]" if array.get("flags") else ""
            progress = array.get("progress")

            if not array.get("degraded"):
                icon = "✅"
            elif progress:
                icon = "🔄"
            else:
                icon = "🚨"

            lines.append(f"   {icon} {name} ({level}){counts}{flags}\n")
            if array.get("failed"):
                lines.append(f"      ❌ выпали: {', '.join(array['failed'])}\n")
            if progress:
                finish = f", осталось ~{progress['finish']}" if progress.get("finish") else ""
                lines.append(
                    f"      ⏳ {progress.get('action', 'sync')}: "
                    f"{progress.get('percent')}%{finish}\n"
                )

    temps = health.get("temps") or []
    if temps:
        parts = []
        for disk in temps:
            temp = disk.get("temp_c")
            mark = "🔥" if temp is not None and temp >= 60 else \
                   "🌡" if temp is not None and temp >= 50 else ""
            parts.append(f"{disk.get('name')} {round(temp)}°C{mark}"
                         if temp is not None else str(disk.get("name")))
        lines.append("\n🌡 ТЕМПЕРАТУРА ДИСКОВ\n   " + " · ".join(parts) + "\n")

    note = health.get("smart_note")
    if note:
        lines.append(f"\n⚠️ {note}\n")

    return "".join(lines)
