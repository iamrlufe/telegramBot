"""
monitor/backup_maintenance.py

Ежесуточные задачи обслуживания бэкапов:

1. Ретеншн — автоочистка backup-файлов старше retention_days (servers.json).
   Правила безопасности:
   - retention_days < MIN_RETENTION_DAYS игнорируется (защита от опечатки);
   - самый новый файл в каталоге не удаляется никогда, даже если он старше
     порога (если бэкапы перестали делаться — последний экземпляр остаётся);
   - удаляются только разрешённые расширения, типы из NO_DELETE_TYPES не трогаются.

2. RESTORE VERIFYONLY — проверка восстановимости последнего .bak
   для серверов с "verify_backup": true. Результат пишется в backup_verifications,
   при ошибке отправляется Telegram-алерт. Час запуска — VERIFY_HOUR в .env
   (по Алматы); не задан — как раньше, на первом цикле после смены даты UTC.
"""
import json
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from backup_files import list_backup_files, delete_backup_files, NO_DELETE_TYPES
from backup_verify import verify_newest_bak, save_verification, path_str
from server_check import server_type
from alerts import send_or_defer

ALMATY = ZoneInfo("Asia/Almaty")

SERVERS_FILE = "/app/config/servers.json"
RETENTION_STATE_FILE = "/app/data/last_retention.txt"
VERIFY_STATE_FILE = "/app/data/last_verify.txt"
CLEANUP_LOG_FILE = "/app/data/cleanup_log.txt"

MIN_RETENTION_DAYS = 3


def _verify_hour_env() -> int | None:
    """VERIFY_HOUR в .env — час по Алматы, в который запускать RESTORE VERIFYONLY.
    Не задан — старое поведение: на первом цикле после смены даты по UTC
    (обычно это ~05:00 Алматы, но не гарантировано и не настраивается)."""
    val = os.getenv("VERIFY_HOUR")
    if val is None or val == "":
        return None
    try:
        hour = int(val)
    except ValueError:
        print("[maintenance] Некорректный VERIFY_HOUR, игнорирую (час не ограничен)", flush=True)
        return None
    if not (0 <= hour <= 23):
        print("[maintenance] VERIFY_HOUR вне диапазона 0-23, игнорирую", flush=True)
        return None
    return hour


VERIFY_HOUR = _verify_hour_env()


def _verify_hour_ok() -> bool:
    if VERIFY_HOUR is None:
        return True
    return datetime.now(ALMATY).hour == VERIFY_HOUR


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _due_today(state_file: str) -> bool:
    """True если задача сегодня (UTC) ещё не выполнялась."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        with open(state_file) as f:
            if f.read().strip() == today:
                return False
    except FileNotFoundError:
        pass
    return True


def _mark_done(state_file: str):
    with open(state_file, "w") as f:
        f.write(datetime.now(timezone.utc).strftime("%Y-%m-%d"))


def _log_cleanup(lines: list[str]):
    try:
        with open(CLEANUP_LOG_FILE, "a") as log:
            for line in lines:
                log.write(line + "\n")
    except OSError:
        pass


def _parent_dir(full_path: str) -> str:
    """Каталог файла — с учётом обоих разделителей: пути приходят и от
    PowerShell (E:\\Backups\\db1\\a.bak), и от POSIX-листинга."""
    normalized = str(full_path or "").replace("\\", "/")
    head, _, _tail = normalized.rpartition("/")
    return head


def _newest_per_directory(files: list) -> set:
    """full_path самого свежего файла в каждом подкаталоге листинга.

    Эти файлы ретеншн не удаляет никогда: «последний экземпляр остаётся»
    должно выполняться для каждой базы, а не для пути целиком."""
    newest_by_dir: dict[str, dict] = {}
    for f in files:
        directory = _parent_dir(f["full_path"])
        current = newest_by_dir.get(directory)
        if current is None or f["modified"] > current["modified"]:
            newest_by_dir[directory] = f
    return {f["full_path"] for f in newest_by_dir.values()}


# ─── Ретеншн ─────────────────────────────────────────────────

def retention_for_server(server: dict) -> dict | None:
    """
    Чистит backup-каталоги одного сервера по retention_days.
    Возвращает сводку {"deleted", "freed_gb", "failed", "errors": [..]} или None
    если ретеншн для сервера не настроен.
    """
    days = server.get("retention_days")
    if not days:
        return None

    name = server["name"]
    # Листинг и удаление идут через PowerShell — на Linux/NAS не сработают.
    # Ретеншем там занимается сам сервер (у Synology — свои задания).
    if server_type(server) != "windows":
        print(f"[retention] {name}: ретеншн только для Windows, пропускаю", flush=True)
        return None
    try:
        days = int(days)
    except (TypeError, ValueError):
        print(f"[retention] {name}: retention_days={days!r} не число — пропускаю", flush=True)
        return None

    if days < MIN_RETENTION_DAYS:
        print(
            f"[retention] {name}: retention_days={days} меньше минимума "
            f"{MIN_RETENTION_DAYS} — пропускаю (защита от опечатки)",
            flush=True
        )
        return None

    host = server["host"]
    username = server.get("username")
    password = server.get("password")
    backups = server.get("backups", {})
    cutoff = _utcnow_naive() - timedelta(days=days)

    summary = {"deleted": 0, "freed_gb": 0.0, "failed": 0, "errors": []}
    log_lines = [f"[{_utcnow_naive().strftime('%Y-%m-%d %H:%M:%S')} UTC] retention {name} (>{days} дн):"]

    for backup_type, paths in backups.items():
        if backup_type in NO_DELETE_TYPES:
            continue
        if not isinstance(paths, list):
            paths = [paths]

        for path_spec in paths:
            # Путь — либо строка, либо {"path": ..., "alert_hours": ..., "size_check": ...}
            backup_path = path_str(path_spec)
            if not backup_path:
                continue
            try:
                files = list_backup_files(server, backup_path)
            except Exception as e:
                summary["errors"].append(f"{backup_type} {backup_path}: листинг не удался: {str(e)[:80]}")
                continue

            if not files:
                continue

            # Самый новый файл не удаляем никогда — и не один на весь путь,
            # а в КАЖДОМ подкаталоге. Листинг рекурсивный, и типовая раскладка
            # «каталог на базу» (E:\Backups\db1, E:\Backups\db2) означала, что
            # уцелеет копия только одной базы: у остальных последний экземпляр
            # уходил под нож, если бэкапы перестали делаться.
            files.sort(key=lambda f: f["modified"])
            keep = _newest_per_directory(files)
            to_delete = [
                f for f in files
                if f["full_path"] not in keep
                and datetime.strptime(f["modified"], "%Y-%m-%d %H:%M:%S") < cutoff
            ]
            newest = files[-1]
            if not to_delete:
                continue

            results = delete_backup_files(
                server, [f["full_path"] for f in to_delete]
            )
            by_path = {f["full_path"]: f for f in to_delete}
            for full_path, ok, err in results:
                if ok:
                    summary["deleted"] += 1
                    summary["freed_gb"] += by_path.get(full_path, {}).get("size_gb", 0)
                    log_lines.append(f"  удалён {full_path}")
                else:
                    summary["failed"] += 1
                    summary["errors"].append(f"{os.path.basename(full_path)}: {str(err)[:60]}")
                    log_lines.append(f"  ОШИБКА {full_path}: {err}")

            print(
                f"[retention] {name} {backup_type} {backup_path}: "
                f"удалено {sum(1 for _, ok, _ in results if ok)}, "
                f"оставлен новейший {newest['file_name']}",
                flush=True
            )

    if summary["deleted"] or summary["failed"]:
        _log_cleanup(log_lines)
    return summary


def run_retention(servers: list):
    report_blocks = []

    for server in servers:
        try:
            summary = retention_for_server(server)
        except Exception as e:
            print(f"[retention] {server.get('name')}: ошибка: {e}", flush=True)
            report_blocks.append(f"🖥 {server.get('name')}\n   ❌ Ошибка: {str(e)[:80]}")
            continue

        if summary is None:
            continue
        if not summary["deleted"] and not summary["failed"] and not summary["errors"]:
            continue

        block = [f"🖥 {server['name']}"]
        block.append(f"   🗑 Удалено: {summary['deleted']} файлов ({summary['freed_gb']:.2f} ГБ)")
        if summary["failed"]:
            block.append(f"   ❌ Не удалось: {summary['failed']}")
        for err in summary["errors"][:5]:
            block.append(f"   ⚠️ {err}")
        report_blocks.append("\n".join(block))

    if report_blocks:
        send_or_defer(
            "🧹 АВТООЧИСТКА БЭКАПОВ (retention)\n\n" + "\n\n".join(report_blocks)
        )
    print("[retention] Цикл завершён", flush=True)


# ─── RESTORE VERIFYONLY ──────────────────────────────────────
# verify_newest_bak/save_verification — в shared/backup_verify.py, чтобы
# ими мог пользоваться и bot (ручной запуск по кнопке).


def run_verify(servers: list):
    for server in servers:
        if not server.get("verify_backup"):
            continue

        name = server["name"]
        # RESTORE VERIFYONLY выполняет MSSQL на самом сервере — на Linux/NAS
        # его нет, а бэкап там лежит уже скопированным с Windows-сервера.
        if server_type(server) != "windows":
            print(f"[verify] {name}: verify только для Windows, пропускаю", flush=True)
            continue
        sql_paths = server.get("backups", {}).get("sql", [])
        if not isinstance(sql_paths, list):
            sql_paths = [sql_paths]
        if not sql_paths:
            print(f"[verify] {name}: verify_backup=true, но нет backups.sql — пропускаю", flush=True)
            continue

        for path_spec in sql_paths:
            backup_path = path_str(path_spec)
            if not backup_path:
                continue
            print(f"[verify] {name}: проверяю {backup_path}...", flush=True)
            try:
                res = verify_newest_bak(
                    server["host"], backup_path,
                    server.get("username"), server.get("password")
                )
            except Exception as e:
                res = {"status": "error", "error": str(e), "file": None,
                       "size_gb": None, "modified": None, "duration_sec": None}

            try:
                save_verification(name, backup_path, res)
            except Exception as e:
                print(f"[verify] {name}: не удалось сохранить результат: {e}", flush=True)

            if res["status"] == "ok":
                print(
                    f"[verify] {name}: ✅ ok, {res['file']} "
                    f"({res['size_gb']} ГБ за {res['duration_sec']} сек)",
                    flush=True
                )
            else:
                detail = (res.get("error") or res["status"])
                print(f"[verify] {name}: ❌ {res['status']}: {detail}", flush=True)
                file_line = f"📄 {res['file']}\n" if res.get("file") else ""
                send_or_defer(
                    f"🚨 Backup Verify Alert\n\n"
                    f"🖥 {name}\n"
                    f"📁 {backup_path}\n"
                    f"{file_line}\n"
                    f"❌ RESTORE VERIFYONLY: {res['status']}\n"
                    f"{str(detail)[:200]}",
                    ack_key=f"verify:{name}:{backup_path}",
                )

    print("[verify] Цикл завершён", flush=True)


# ─── Точка входа из monitor.py ───────────────────────────────

def load_servers() -> list:
    with open(SERVERS_FILE) as f:
        return json.load(f)


def run_backup_maintenance():
    """Вызывается из своего фонового потока (maintenance_loop в monitor.py),
    не блокирует основной цикл мониторинга; сами задачи — раз в сутки."""
    retention_due = _due_today(RETENTION_STATE_FILE)
    verify_due = _due_today(VERIFY_STATE_FILE) and _verify_hour_ok()
    if not retention_due and not verify_due:
        return

    try:
        servers = load_servers()
    except Exception as e:
        print(f"[maintenance] Не могу прочитать {SERVERS_FILE}: {e}", flush=True)
        return

    if retention_due:
        # Помечаем до запуска, чтобы ошибка посреди цикла не приводила
        # к повторному удалению при каждом следующем цикле
        _mark_done(RETENTION_STATE_FILE)
        run_retention(servers)

    if verify_due:
        _mark_done(VERIFY_STATE_FILE)
        run_verify(servers)
