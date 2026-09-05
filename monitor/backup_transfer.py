"""
monitor/backup_transfer.py

Запуск копирования копий на приёмник вместо планировщика Windows.

Планировщик стартует по часам, а бэкап заканчивается когда придётся —
смысл замены и разбор сигнала «файл готов» описаны в shared/backup_copy.py.
Здесь всё, что требует внешнего мира: чтение msdb, запуск скрипта на
сервере-источнике по WinRM, наблюдение за процессом, состояние и алерты.

Состояние живёт в общем для бота и монитора файле (см. TRANSFER_STATE_FILE
в shared/backup_copy.py): бот запускает копирование кнопкой, монитор — по
готовности копии, и оба обязаны видеть одно и то же. Пока в состоянии есть
`run`, копирование считается идущим — по нему видно, что файл в дороге и
сколько он едет на самом деле.
"""
from datetime import datetime

from settings import SERVERS_FILE
from server_check import server_type
from mssql_log import read_backup_history, read_running_backups
from backup_copy import (
    TRANSFER_STATE_FILE,
    check_run,
    copy_settings,
    finish_run,
    launch_copy,
    load_servers,
    load_state,
    mark_sent,
    marker as _marker,
    pick_ready_backups,
    next_to_send,
    now_local as _now,
    run_verdict,
    save_state,
    script_for,
    type_label,
)
from alerts import (
    alert_due, mark_alert_sent, send_or_defer, load_json, save_json, is_muted,
)

# История msdb за сутки: копия, законченная раньше, уже никуда не поедет
# (see COPY_FRESH_MINUTES), а лишние строки только раздувают ответ WinRM.
HISTORY_DAYS = 1
HISTORY_LIMIT = 20


# ─── Шаги цикла ──────────────────────────────────────────────

def _alert(name: str, key_level: str, text: str, ack_key: str):
    """Тревога о копировании с обычной защитой от повторов."""
    if is_muted(name):
        return
    key = f"{name}:copy"
    alert_state = load_json(TRANSFER_STATE_FILE + ".alerts")
    if not alert_due(alert_state, key, key_level):
        return
    mark_alert_sent(alert_state, key, key_level)
    save_json(TRANSFER_STATE_FILE + ".alerts", alert_state)
    send_or_defer(text, ack_key=ack_key)


def _run_head(name: str, run: dict) -> str:
    return (f"🖥 {name}\n"
            f"💾 {run.get('db') or 'копия'} ({type_label(run.get('type'))})"
            + (f", {run['size_gb']} ГБ" if run.get("size_gb") else "") + "\n"
            f"📜 {run.get('script') or '?'}\n"
            f"▶️ Запущено: {run.get('started')}\n")


def _tail_block(tail: str) -> str:
    return f"\n📄 Конец журнала:\n{tail[-800:]}\n" if tail else ""


def _watch_run(server: dict, settings: dict, entry: dict, state_key: str,
               state: dict) -> bool:
    """Следит за идущим копированием. True — состояние изменилось."""
    name = server["name"]
    run = entry["run"]
    now = _now()

    try:
        outcome = check_run(server, run)
    except Exception as e:
        # Сервер не ответил: сам по себе это не авария копирования —
        # процесс может идти. Ждём следующего цикла, но не вечно: таймаут
        # ниже отработает и без связи.
        print(f"[copy] {name}: не проверить рейс {run.get('pid')}: {e}", flush=True)
        outcome = {"state": "running", "code": None, "tail": ""}

    if outcome["state"] == "running":
        if run_verdict(run, settings, now) == "timeout":
            minutes = round((now - datetime.strptime(
                run["started"], "%Y-%m-%d %H:%M:%S")).total_seconds() / 60)
            _alert(
                name, "timeout",
                "🆘🆘 КОПИРОВАНИЕ ЗАВИСЛО 🆘🆘\n\n"
                + _run_head(name, run)
                + f"⏰ Идёт уже {minutes} мин при пороге "
                  f"{settings['timeout_minutes']} мин\n"
                + _tail_block(outcome["tail"])
                + "\n‼️ Проверьте копирование на сервере вручную!",
                ack_key=f"backup_copy_stuck:{name}",
            )
        return False

    # Отметку «увезли» и перевод рейса в last_run делает finish_run: та же
    # функция закрывает рейс, когда его застаёт законченным бот.
    finish_run(entry, outcome, now)
    minutes = entry["last_run"]["minutes"]

    if outcome["state"] == "ok":
        # Скрипт отработал без ошибки. Доехал ли файл целиком — вопрос уже
        # к приёмнику: у SFTP оборванная загрузка выглядит успешной, это
        # ловит обычная проверка каталога.
        print(f"[copy] {name}: копирование закончилось за {minutes} мин",
              flush=True)
    else:
        reason = (f"скрипт вернул код {outcome['code']}"
                  if outcome["state"] == "failed" else
                  "процесс исчез, не дописав код возврата "
                  "(убит или сервер перезагрузился)")
        _alert(
            name, "failed",
            "🆘🆘 КОПИРОВАНИЕ НЕ УДАЛОСЬ 🆘🆘\n\n"
            + _run_head(name, run)
            + f"⛔ Закончилось за {minutes} мин: {reason}\n"
            + _tail_block(outcome["tail"])
            + "\n‼️ Копия осталась на сервере — проверьте скрипт "
              "и запустите копирование вручную!",
            ack_key=f"backup_copy_failed:{name}",
        )
        print(f"[copy] {name}: рейс не удался — {reason}", flush=True)

    state[state_key] = entry
    return True


def process_server_copy(server: dict, state: dict) -> bool:
    """Один сервер-источник: запустить копирование или последить за идущим.
    True — состояние изменилось и его надо сохранить."""
    settings = copy_settings(server)
    if not settings or server_type(server) != "windows":
        return False

    name = server["name"]
    entry = state.get(name) or {}
    changed = False

    if entry.get("run"):
        return _watch_run(server, settings, entry, name, state)

    # На сервере прямо сейчас делается копия? В msdb запись появляется,
    # как только закончилась ПЕРВАЯ база, а следом сервер может писать
    # вторую и третью. Утащить каталог в этот момент — значит увезти
    # файл, который ещё дописывается.
    try:
        running = read_running_backups(server)
    except Exception as e:
        # Не смогли спросить — не повод стоять: копию всё равно везти
        # надо, а от полуготового файла защищает пауза перед запуском.
        print(f"[copy] {name}: не проверить идущие копии: {e}", flush=True)
        running = []
    if running:
        where = ", ".join(f"{r.get('db')} {r.get('pct')}%" for r in running[:3])
        print(f"[copy] {name}: жду окончания копий ({where})", flush=True)
        return False

    try:
        rows = read_backup_history(server, days=HISTORY_DAYS, limit=HISTORY_LIMIT)
    except Exception as e:
        print(f"[copy] {name}: не прочитать msdb: {e}", flush=True)
        return False

    ready, reason = next_to_send(rows, entry, settings, _now())
    if not ready:
        # Первый раз видим эти копии, но везти их незачем (старые или
        # автозапуск выключен) — запоминаем, чтобы не думать о них снова.
        if not entry.get("last_finished"):
            for item in pick_ready_backups(rows, settings):
                mark_sent(entry, item["type"], _marker(item["finished"]))
                changed = True
            if changed:
                state[name] = entry
        print(f"[copy] {name}: не запускаю — {reason}", flush=True)
        return changed

    print(f"[copy] {name}: копия {ready['db']} "
          f"({type_label(ready['type'])}) готова {_marker(ready['finished'])} "
          f"— запускаю {script_for(settings, ready['type'])}", flush=True)
    try:
        entry["run"] = launch_copy(server, settings, ready)
    except Exception as e:
        if not is_muted(name):
            send_or_defer(
                f"🆘🆘 КОПИРОВАНИЕ НЕ ЗАПУСТИЛОСЬ 🆘🆘\n\n"
                f"🖥 {name}\n"
                f"💾 {ready.get('db')} ({type_label(ready.get('type'))}), "
                f"копия готова {_marker(ready['finished'])}\n"
                f"📜 {script_for(settings, ready.get('type'))}\n\n"
                f"❌ {str(e)[:200]}\n\n"
                f"‼️ Файл на месте, но никуда не поедет — запустите вручную!",
                ack_key=f"backup_copy_failed:{name}",
            )
        print(f"[copy] {name}: запуск не удался: {e}", flush=True)
        return False

    state[name] = entry
    return True


def run_transfer_cycle(servers: list = None):
    """Обход серверов-источников. Дешёвый: запрос к msdb и, если есть что
    везти, один запуск скрипта. Идёт каждый цикл монитора (5 минут), а не
    вместе с обходом каталогов: копию надо отправлять сразу, как она
    готова, иначе теряется весь смысл отказа от планировщика."""
    if servers is None:
        try:
            servers = load_servers()
        except Exception as e:
            print(f"[copy] Не могу прочитать {SERVERS_FILE}: {e}", flush=True)
            return

    work = [s for s in servers if copy_settings(s)]
    if not work:
        return

    state = load_state()
    changed = False
    for server in work:
        try:
            changed = process_server_copy(server, state) or changed
        except Exception as e:
            print(f"[copy] ❌ {server.get('name')}: {e}", flush=True)

    if changed:
        save_state(state)
