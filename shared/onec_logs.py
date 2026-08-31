"""
shared/onec_logs.py

Разбор блока onec_logs из servers.json: путь, название и пороги размера.

Живёт в shared/, потому что читателей двое и они в разных контейнерах.
Монитор берёт отсюда пороги для алертов, бот — для сводки 🚨 Проблемы.
Пока разбор был продублирован, они разошлись: у пути стояли свои
150/180 ГБ, монитор молчал (правильно), а сводка красила журнал на 12 ГБ
в критичный по общим 5/10 — и настройка выглядела неработающей.
"""
import json

# Общие пороги: применяются, когда у пути не задано своё значение.
ONEC_LOG_WARN_GB = 5
ONEC_LOG_CRIT_GB = 10

DEFAULT_LOG_NAME = "1C log"


def _threshold(value, default: float) -> float:
    """Порог пути или общий. None встречается штатно: так бот записывает
    явный сброс к общим порогам (⚙️ Настройка → сбросить)."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def onec_targets(server: dict) -> list:
    """[{name, path, warn_gb, crit_gb}, ...] по одному серверу конфига.

    Принимает все формы записи: строка-путь, один объект, список из того
    и другого — руками конфиг правили и так, и так.
    """
    logs = server.get("onec_logs") or []
    if isinstance(logs, (str, dict)):
        logs = [logs]

    targets = []
    for spec in logs:
        if isinstance(spec, str):
            targets.append({
                "name": DEFAULT_LOG_NAME,
                "path": spec,
                "warn_gb": ONEC_LOG_WARN_GB,
                "crit_gb": ONEC_LOG_CRIT_GB,
            })
            continue

        if not isinstance(spec, dict):
            continue
        path = spec.get("path")
        if not path:
            continue

        targets.append({
            "name": spec.get("name") or DEFAULT_LOG_NAME,
            "path": path,
            "warn_gb": _threshold(spec.get("warn_gb"), ONEC_LOG_WARN_GB),
            "crit_gb": _threshold(spec.get("crit_gb"), ONEC_LOG_CRIT_GB),
        })
    return targets


def load_onec_thresholds(servers_file: str) -> dict:
    """{(имя сервера, путь): (warn_gb, crit_gb)} по всему конфигу.

    Нужна сводке проблем: она читает метрики из базы, где порогов нет, —
    они живут только в конфиге.
    """
    thresholds = {}
    try:
        with open(servers_file) as f:
            servers = json.load(f)
    except Exception as e:
        print(f"[onec] Не удалось прочитать {servers_file}: {e}", flush=True)
        return thresholds

    for server in servers:
        name = server.get("name")
        if not name:
            continue
        for target in onec_targets(server):
            thresholds[(name, target["path"])] = (
                target["warn_gb"], target["crit_gb"]
            )
    return thresholds
