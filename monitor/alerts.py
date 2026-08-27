import os
import json
import tempfile
import threading
import time as time_module
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

import requests

from winrm_errors import error_to_status

ALMATY = ZoneInfo("Asia/Almaty")

DISK_STATE_FILE = "/app/data/disk_alert_state.json"
SERVER_STATE_FILE = "/app/data/server_alert_state.json"
ALERTS_DISABLED_FILE = "/app/data/alerts_disabled.json"
DEFERRED_FILE = "/app/data/deferred_alerts.json"
QUIET_NOTICE_STATE_FILE = "/app/data/quiet_notice_state.json"
DOCKER_STATE_FILE = "/app/data/docker_alert_state.json"
SMART_STATE_FILE = "/app/data/smart_alert_state.json"
TIME_DRIFT_STATE_FILE = "/app/data/time_drift_state.json"
SNAPSHOT_STATE_FILE = "/app/data/snapshot_alert_state.json"
BACKUP_FAIL_STATE_FILE = "/app/data/backup_fail_state.json"

TIME_DRIFT_ALERT_SEC = 120   # алерт при дрейфе больше 2 минут
TIME_DRIFT_OK_SEC = 60       # восстановление при дрейфе меньше минуты

# ping_loop (отдельный поток) и run_cycle (основной поток) оба читают/пишут
# файлы состояния алертов — без блокировки возможна гонка и потерянные записи.
_state_lock = threading.Lock()


# ─── Telegram ────────────────────────────────────────────────

def _get_notify_id() -> str:
    """Группа если задана, иначе личка."""
    group = os.getenv("TELEGRAM_GROUP_ID")
    if group:
        return group
    return os.getenv("TELEGRAM_ALLOWED_USER_ID")


# Telegram отклоняет сообщения длиннее 4096 символов. Обрезаем с запасом:
# алерт офлайна вкладывает полный текст исключения WinRM/paramiko, который
# легко переваливает за лимит — и такой алерт молча терялся целиком.
TELEGRAM_TEXT_LIMIT = 4000


def _hide_token(message: str, token: str) -> str:
    """Убирает токен бота из текста ошибки перед выводом в лог.

    requests вкладывает в исключение полный URL запроса, а токен — часть пути
    (/bot<TOKEN>/sendMessage). Без этой замены любой сетевой сбой печатал
    рабочий токен в stdout контейнера, откуда он уходит в docker logs и дальше
    в любой сборщик логов.
    """
    if token and token in message:
        message = message.replace(token, "<TOKEN>")
    return message


def _post_message(token: str, chat_id, text: str, reply_markup: dict = None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json=payload,
        timeout=10
    )


def send_telegram(text: str, reply_markup: dict = None):
    """Шлёт алерт в группу (если задана), иначе в личку.

    Отправка в группу — самое хрупкое место: ID супергруппы отличается от ID
    обычной группы, и после автоконвертации (бот стал админом, включены темы)
    старый TELEGRAM_GROUP_ID начинает отдавать 400, а алерты молча пропадают.
    Поэтому здесь два страховочных слоя: подхват migrate_to_chat_id из ответа
    Bot API и фолбэк в личку владельца, чтобы алерт дошёл в любом случае.
    """
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = _get_notify_id()
    owner_id = os.getenv("TELEGRAM_ALLOWED_USER_ID")
    if len(text) > TELEGRAM_TEXT_LIMIT:
        text = text[:TELEGRAM_TEXT_LIMIT - 20] + "\n… (обрезано)"

    try:
        response = _post_message(token, chat_id, text, reply_markup)

        # Группа сконвертирована в супергруппу: Bot API отдаёт новый ID.
        # Дошлём туда сразу и подскажем, что поправить в .env.
        migrated = None
        if not response.ok:
            try:
                migrated = (response.json().get("parameters") or {}).get("migrate_to_chat_id")
            except ValueError:
                migrated = None
        if migrated:
            print(
                f"[alerts] Группа {chat_id} стала супергруппой {migrated}. "
                f"Пропишите TELEGRAM_GROUP_ID={migrated} в .env и пересоберите.",
                flush=True
            )
            response = _post_message(token, migrated, text, reply_markup)

        # Ответ проверяем: HTTP 400 от Bot API (слишком длинный текст, битая
        # клавиатура, неверный chat_id) раньше выглядел как успешная отправка,
        # и потерянный алерт нигде не оставлял следа.
        if not response.ok:
            print(
                f"[alerts] Telegram отклонил сообщение в чат {chat_id} "
                f"({response.status_code}): {response.text[:200]}",
                flush=True
            )
            if owner_id and str(chat_id) != str(owner_id):
                fallback = _post_message(
                    token, owner_id,
                    "⚠️ Не удалось отправить алерт в группу "
                    f"{chat_id} — проверьте TELEGRAM_GROUP_ID и права бота.\n\n" + text,
                    reply_markup
                )
                if not fallback.ok:
                    print(
                        f"[alerts] Фолбэк в личку {owner_id} тоже не прошёл "
                        f"({fallback.status_code}): {fallback.text[:200]}",
                        flush=True
                    )
                else:
                    print(f"[alerts] Алерт доставлен в личку {owner_id} (фолбэк)", flush=True)
    except Exception as e:
        print(f"[alerts] Ошибка отправки в Telegram: {_hide_token(str(e), token)}", flush=True)


def server_alert_kb(server_name: str) -> dict:
    """Кнопки быстрых действий под алертом; callback-и обрабатывает бот."""
    return {"inline_keyboard": [
        [
            {"text": "🔄 Проверить сейчас", "callback_data": f"al_refresh:{server_name}"},
            {"text": "📈 График", "callback_data": f"chart:{server_name}"},
        ],
        [
            {"text": "🔇 Тихо на 1 час", "callback_data": f"al_mute:{server_name}"},
        ],
    ]}


def disk_alert_kb(server_name: str, disk_name: str, top_dirs: bool = True) -> dict:
    """top_dirs=False — для датасторов VMware: разбор занятого места идёт
    через robocopy или du, а датастор монитору как файловая система
    недоступен. Кнопка, которая гарантированно вернёт ошибку, хуже, чем
    её отсутствие."""
    kb = server_alert_kb(server_name)
    if top_dirs:
        kb["inline_keyboard"].insert(1, [
            {"text": "📂 Топ каталогов",
             "callback_data": f"al_topdirs:{server_name}:{disk_name}"},
        ])
    return kb


def service_alert_kb(server_name: str, service_name: str) -> dict:
    kb = server_alert_kb(server_name)
    kb["inline_keyboard"].insert(1, [
        {"text": "🔁 Перезапустить сервис",
         "callback_data": f"al_svcfix:{server_name}:{service_name}"},
    ])
    return kb


def is_muted(server_name: str) -> bool:
    """
    Mute навсегда (true, /mute) или до метки времени ISO
    (кнопка «Тихо на 1 час» в алерте).
    """
    value = load_json(ALERTS_DISABLED_FILE).get(server_name)
    if not value:
        return False
    if value is True:
        return True
    try:
        return datetime.now(timezone.utc) < datetime.fromisoformat(str(value))
    except ValueError:
        return True


# ─── Тихие часы ──────────────────────────────────────────────
# QUIET_HOURS="23:00-07:00" (время Алматы): ночью бот молчит полностью —
# все алерты копятся и утром приходят одной сводкой. Исключений нет:
# падение сервера, SMART и бэкапы тоже ждут утра. Пусто — выключено.

def _parse_quiet_hours():
    raw = os.getenv("QUIET_HOURS", "").strip()
    if not raw:
        return None
    try:
        start_raw, end_raw = raw.split("-", 1)

        def parse(part):
            part = part.strip()
            if ":" in part:
                hours, minutes = part.split(":", 1)
            else:
                hours, minutes = part, "0"
            return int(hours) % 24 * 60 + int(minutes) % 60

        return parse(start_raw), parse(end_raw)
    except (ValueError, AttributeError):
        print(f"[alerts] Непонятный QUIET_HOURS={raw!r}, тихие часы выключены", flush=True)
        return None


def in_quiet_hours(now: datetime = None) -> bool:
    quiet_range = _parse_quiet_hours()
    if not quiet_range:
        return False
    start, end = quiet_range
    if start == end:
        return False
    now = now or datetime.now(ALMATY)
    current = now.hour * 60 + now.minute
    if start < end:
        return start <= current < end
    return current >= start or current < end   # диапазон через полночь


QUIET_NOTICE_LEAD_MIN = 15   # предупреждение за N минут до начала тихих часов


def notify_quiet_hours_start(now: datetime = None):
    """Разово предупреждает не позже чем за QUIET_NOTICE_LEAD_MIN минут до
    начала тихих часов, чтобы тишина не была неожиданностью.

    Защита от повтора привязана к конкретному старту тихих часов
    (дата+время), а не к календарной дате — иначе окно, пересекающее
    полночь, дало бы два уведомления."""
    quiet_range = _parse_quiet_hours()
    if not quiet_range:
        return
    start, _end = quiet_range

    now = now or datetime.now(ALMATY)
    current = now.hour * 60 + now.minute
    minutes_left = (start - current) % (24 * 60)   # минут до ближайшего старта
    if not (0 < minutes_left <= QUIET_NOTICE_LEAD_MIN):
        return

    # Момент старта, о котором предупреждаем — стабилен на всё окно
    target_start = now + timedelta(minutes=minutes_left)
    session_key = target_start.strftime("%Y-%m-%d %H:%M")
    with _state_lock:
        state = load_json(QUIET_NOTICE_STATE_FILE)
        if state.get("session") == session_key:
            return
        save_json(QUIET_NOTICE_STATE_FILE, {"session": session_key})

    hh, mm = divmod(start, 60)
    send_telegram(
        f"🌙 Через {minutes_left} мин начнётся тихий режим ({hh:02d}:{mm:02d}).\n"
        "Некритичные алерты будут копиться и придут одной сводкой утром."
    )


def purge_server_state(server_name: str):
    """Убирает все следы сервера из файлов состояния алертов и mute —
    вызывается при удалении сервера из конфига, чтобы заново добавленный
    сервер с тем же именем не унаследовал старый mute/состояние."""
    state_files = [
        DISK_STATE_FILE, SERVER_STATE_FILE, DOCKER_STATE_FILE,
        SMART_STATE_FILE, TIME_DRIFT_STATE_FILE, ALERTS_DISABLED_FILE,
        CPU_STATE_FILE, RAM_STATE_FILE, SERVICE_STATE_FILE,
        DISK_FORECAST_STATE_FILE, DISK_TEMP_STATE_FILE, RAID_STATE_FILE,
        "/app/data/backup_alert_state.json",
        BACKUP_FAIL_STATE_FILE,
    ]
    prefix = f"{server_name}:"
    with _state_lock:
        for path in state_files:
            state = load_json(path)
            if not state:
                continue
            keys = [k for k in state if k == server_name or k.startswith(prefix)]
            if keys:
                for k in keys:
                    del state[k]
                save_json(path, state)


def send_or_defer(text: str, reply_markup: dict = None):
    """В тихие часы копим до утра, иначе отправляем сразу.

    Исключений нет: тихий режим глушит ВСЁ, включая падение сервера и SMART.
    Ночью ничего не пробивает — накопленное уходит утренней сводкой."""
    if not in_quiet_hours():
        send_telegram(text, reply_markup)
        return
    with _state_lock:
        queue = load_json(DEFERRED_FILE)
        items = queue.get("items", [])
        items.append({
            "time": datetime.now(ALMATY).strftime("%H:%M"),
            "text": text,
        })
        save_json(DEFERRED_FILE, {"items": items[-100:]})
    print(f"[alerts] Отложено до утра: {text.splitlines()[0]}", flush=True)


def flush_deferred():
    """Вызывается каждый цикл: вне тихих часов отправляет накопленное."""
    if in_quiet_hours():
        return
    with _state_lock:
        items = load_json(DEFERRED_FILE).get("items", [])
        if not items:
            return
        save_json(DEFERRED_FILE, {"items": []})

    header = f"🌙 За тихие часы накопилось уведомлений: {len(items)}\n"
    chunk = header
    for item in items:
        block = f"\n— {item.get('time', '?')} —\n{item.get('text', '')}\n"
        if len(chunk) + len(block) > 3800:
            send_telegram(chunk)
            chunk = "🌙 (продолжение)\n"   # без него вторая часть шла без контекста
        chunk += block
    if chunk.strip():
        send_telegram(chunk)


# ─── Состояние (JSON файлы) ──────────────────────────────────

def load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_json(path: str, data: dict):
    """Атомарная запись: сначала во временный файл рядом, потом os.replace.

    Прямая запись в открытый на "w" файл сначала обрезает его до нуля.
    Обрыв в этот момент (перезапуск контейнера, конец места на диске)
    оставлял битый JSON, а load_json молча возвращает {} на любой ошибке —
    то есть разом и незаметно терялись все заглушённые серверы и состояния
    алертов. os.replace внутри одной файловой системы атомарен: читатель
    видит либо прежний файл целиком, либо новый целиком.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ─── Провалившийся бэкап MSSQL ───────────────────────────────

# Сколько ключей событий помним на сервер: защита от разрастания файла
# состояния, при этом хватает, чтобы не повторить алерт по кругу.
BACKUP_FAIL_KEYS_KEPT = 60

# В одно сообщение больше не кладём: серия одинаковых сбоев за ночь всё
# равно читается по первым записям, а Telegram режет длинный текст.
BACKUP_FAIL_IN_MESSAGE = 5


def check_backup_failure_alerts(server_name: str, events: list):
    """Алерт о новых сбоях резервного копирования MSSQL.

    Событие опознаётся по ключу «время + суть»: ERRORLOG и история джоб
    отдают одни и те же записи при каждом опросе, и без запоминания алерт
    уходил бы каждые пять минут. Новыми считаются только те ключи,
    которых ещё не было в состоянии.
    """
    if is_muted(server_name) or not events:
        return

    with _state_lock:
        state = load_json(BACKUP_FAIL_STATE_FILE)
        seen = state.get(server_name) or []
        seen_set = set(seen)

        fresh = [e for e in events if e.get("key") and e["key"] not in seen_set]
        if not fresh:
            return

        state[server_name] = (seen + [e["key"] for e in fresh])[-BACKUP_FAIL_KEYS_KEPT:]
        save_json(BACKUP_FAIL_STATE_FILE, state)

    lines = [
        "❌ БЭКАП НЕ ВЫПОЛНЕН",
        f"🖥 Сервер: {server_name}",
        f"Новых сбоев: {len(fresh)}",
        "",
    ]
    for event in fresh[:BACKUP_FAIL_IN_MESSAGE]:
        when = (event.get("when") or "")[:16]
        lines.append(f"{when} — {event.get('text', '')}")
        # Причина отдельной строкой: сообщение шага почти всегда длинное и
        # техническое, а действие должно быть понятно без чтения целиком.
        if event.get("why"):
            lines.append(f"↳ {event['why']}")
    if len(fresh) > BACKUP_FAIL_IN_MESSAGE:
        lines.append(f"… и ещё {len(fresh) - BACKUP_FAIL_IN_MESSAGE}")

    send_or_defer("\n".join(lines), reply_markup=server_alert_kb(server_name))


# ─── Снапшоты VMware ─────────────────────────────────────────

def check_snapshot_alerts(server_name: str, snapshots: list,
                          max_age_days: int = None, max_size_gb: float = None):
    """Алерт о снапшотах, вышедших за порог по возрасту или размеру.

    Состояние храним, чтобы не повторять алерт каждые пять минут: пока
    набор проблемных снапшотов не изменился, молчим. Исчезли все — шлём
    одно сообщение о том, что снапшотов больше нет, и забываем сервер.
    """
    from vmware_check import stale_snapshots

    if is_muted(server_name):
        return
    if not max_age_days and not max_size_gb:
        return

    flagged = stale_snapshots(snapshots, max_age_days, max_size_gb)
    current = sorted(f"{item['vm']}/{item['name']}" for item in flagged)

    with _state_lock:
        state = load_json(SNAPSHOT_STATE_FILE)
        previous = state.get(server_name) or []

        if current == sorted(previous):
            return

        if not current:
            state.pop(server_name, None)
            save_json(SNAPSHOT_STATE_FILE, state)
            send_or_defer(
                f"✅ Снапшоты убраны\n"
                f"🖥 Сервер: {server_name}\n"
                f"Снапшотов сверх порога больше нет"
            )
            return

        state[server_name] = current
        save_json(SNAPSHOT_STATE_FILE, state)

    lines = [
        f"📸 СТАРЫЕ СНАПШОТЫ",
        f"🖥 Сервер: {server_name}",
        f"Найдено: {len(flagged)}",
        "",
    ]
    for item in flagged[:10]:
        lines.append(
            f"• {item['vm']} · {item['name']} — {', '.join(item['reasons'])}"
        )
    if len(flagged) > 10:
        lines.append(f"…и ещё {len(flagged) - 10}")
    lines.append("")
    lines.append("⚠️ Снапшот растёт, пока живёт, и съедает место на датасторе")

    send_or_defer("\n".join(lines), reply_markup=server_alert_kb(server_name))


# ─── Алерты по дискам ────────────────────────────────────────

DISK_LEVELS = (5, 10, 15)      # пороги «свободно меньше N %»
DISK_HYSTERESIS_PCT = 2.0      # запас, чтобы не дребезжало на границе порога


def _disk_level(free_pct: float):
    """Строгость проблемы: 5 (хуже всего) / 10 / 15 / None (норма)."""
    for level in DISK_LEVELS:
        if free_pct < level:
            return level
    return None


def check_disk_alert(server_name: str, disk: dict, kind: str = "windows"):
    """
    Алерт только при УХУДШЕНИИ: переход в более строгий порог или первое
    попадание в проблемную зону. Улучшение (место освободилось) состояние
    обновляет молча — иначе на бэкап-дисках, где место скачет вокруг порога,
    прилетала пачка тревожных «НИЗКОЕ СВОБОДНОЕ МЕСТО» на рост свободного места.
    Гистерезис не даёт дребезжать у самой границы.
    """
    if is_muted(server_name):
        return

    free = float(disk["FreeGB"])
    used = float(disk["UsedGB"])
    total = free + used
    if total <= 0:
        return

    free_pct = round((free / total) * 100, 1)
    key = f"{server_name}:{disk['Name']}"
    new_level = _disk_level(free_pct)

    with _state_lock:
        state = load_json(DISK_STATE_FILE)
        old_level = state.get(key)

        if new_level is None:
            # Вышли из проблемной зоны — сбрасываем, но только с запасом
            if old_level and free_pct >= DISK_LEVELS[-1] + DISK_HYSTERESIS_PCT:
                del state[key]
                save_json(DISK_STATE_FILE, state)
            return

        if old_level is not None:
            if new_level >= old_level:
                # Стало не хуже: тревогу не поднимаем. Состояние смягчаем
                # только если место выросло с запасом — иначе колебания
                # у границы порога снова дали бы «ухудшение» и новый алерт.
                if new_level > old_level and free_pct >= old_level + DISK_HYSTERESIS_PCT:
                    state[key] = new_level
                    save_json(DISK_STATE_FILE, state)
                return

        state[key] = new_level
        save_json(DISK_STATE_FILE, state)

    send_or_defer(
        f"🚨 НИЗКОЕ СВОБОДНОЕ МЕСТО\n"
        f"🖥 Сервер: {server_name}\n"
        f"💽 Диск: {disk['Name']}\n"
        f"🔓 Свободно: {free} ГБ ({free_pct}%)\n"
        f"📦 Занято: {used} ГБ\n"
        f"⚠️ Рекомендуется проверить диск",
        reply_markup=disk_alert_kb(server_name, disk["Name"],
                                   top_dirs=kind != "vmware")
    )


# ─── Алерты по серверам ──────────────────────────────────────

def alert_server_online(server: dict):
    name = server["name"]

    with _state_lock:
        state = load_json(SERVER_STATE_FILE)
        old_status = state.get(name)

        if old_status is None:
            state[name] = "online"
            save_json(SERVER_STATE_FILE, state)
            return

        if old_status == "online":
            return

        state[name] = "online"
        save_json(SERVER_STATE_FILE, state)

    send_or_defer(
        f"✅ Сервер восстановлен\n"
        f"🖥 {server['name']}\n"
        f"🌐 {server['host']}\n"
        f"Предыдущий статус: {old_status}"
    )


def alert_server_offline(server: dict, error: str):
    if is_muted(server["name"]):
        return

    name = server["name"]
    status, title = error_to_status(error)

    with _state_lock:
        state = load_json(SERVER_STATE_FILE)
        if state.get(name) == status:
            return

        state[name] = status
        save_json(SERVER_STATE_FILE, state)

    send_or_defer(
        f"{title}\n"
        f"🖥 Сервер: {server['name']}\n"
        f"🌐 Хост: {server['host']}\n"
        f"❌ Ошибка: {str(error)[:600]}",
        reply_markup=server_alert_kb(server["name"])
    )


def alert_server_down(server: dict):
    if is_muted(server["name"]):
        return

    name = server["name"]

    with _state_lock:
        state = load_json(SERVER_STATE_FILE)
        if state.get(name) == "ping_down":
            return

        state[name] = "ping_down"
        save_json(SERVER_STATE_FILE, state)

    send_or_defer(
        f"🚨 Сервер упал\n"
        f"🖥 Сервер: {server['name']}\n"
        f"🌐 Хост: {server['host']}\n"
        f"❌ Ping не отвечает",
        reply_markup=server_alert_kb(server["name"])
    )


# ─── Алерты по контейнерам Docker ────────────────────────────

_DOCKER_PROBLEM_TEXT = {
    "exited": "остановлен",
    "restarting": "перезапускается по кругу",
    "unhealthy": "нездоров (healthcheck)",
    "paused": "на паузе",
    "created": "создан, но не запущен",
}


def _docker_problem(status: str) -> str:
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
    return "ok"


def check_docker_alerts(server_name: str, containers: list):
    """
    Сравнивает контейнеры с прошлым циклом. Алерт на переход в проблему
    (остановлен/перезапуск/unhealthy) и на исчезновение, восстановление —
    когда контейнер снова Up. Первый цикл — только запоминание состояния.
    """
    if is_muted(server_name):
        return

    current = {c["name"]: _docker_problem(c.get("status", "")) for c in containers if c.get("name")}
    statuses = {c["name"]: c.get("status", "") for c in containers if c.get("name")}
    messages = []

    with _state_lock:
        state_all = load_json(DOCKER_STATE_FILE)
        prev = state_all.get(server_name)

        if prev is not None:
            for cname, problem in current.items():
                old = prev.get(cname)
                if problem != "ok" and old is not None and old != problem:
                    messages.append(
                        f"🐳 Контейнер {_DOCKER_PROBLEM_TEXT.get(problem, problem)}\n"
                        f"🖥 Сервер: {server_name}\n"
                        f"📦 Контейнер: {cname}\n"
                        f"Статус: {statuses.get(cname, '?')}"
                    )
                elif problem == "ok" and old not in (None, "ok"):
                    messages.append(
                        f"✅ Контейнер снова работает\n"
                        f"🖥 Сервер: {server_name}\n"
                        f"📦 Контейнер: {cname}\n"
                        f"Статус: {statuses.get(cname, '?')}"
                    )
            for cname, old in prev.items():
                if cname not in current and old == "ok":
                    messages.append(
                        f"ℹ️ Контейнер исчез (удалён?)\n"
                        f"🖥 Сервер: {server_name}\n"
                        f"📦 Контейнер: {cname}"
                    )

        state_all[server_name] = current
        save_json(DOCKER_STATE_FILE, state_all)

    for message in messages:
        send_or_defer(message, reply_markup=server_alert_kb(server_name))


# ─── Прогноз заполнения диска ────────────────────────────────
# Порог «свободно меньше N %» отвечает, плохо ли сейчас. Этот алерт — про
# «когда станет плохо»: хранилище может держать 20% свободного и упереться
# в потолок за неделю, если бэкапы выросли.

DISK_FORECAST_STATE_FILE = "/app/data/disk_forecast_state.json"
def _num_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name) or default)
    except ValueError:
        print(f"[alerts] Некорректный {name}, использую {default}", flush=True)
        return default


DISK_FORECAST_ALERT_DAYS = _num_env("DISK_FORECAST_ALERT_DAYS", 14)
DISK_FORECAST_OK_DAYS = DISK_FORECAST_ALERT_DAYS * 2   # запас против дребезга


def check_disk_forecast_alert(server_name: str, disk_name: str, trend: dict,
                              kind: str = "windows"):
    """Алерт, когда по тренду место кончится раньше DISK_FORECAST_ALERT_DAYS.
    Снимается только при двукратном запасе — иначе прогноз, гуляющий вокруг
    порога, слал бы «кончится/не кончится» каждый цикл."""
    if is_muted(server_name) or not trend:
        return

    key = f"{server_name}:{disk_name}"
    days_left = trend.get("days_left")
    with _state_lock:
        state = load_json(DISK_FORECAST_STATE_FILE)
        alerted = key in state

        if trend.get("shrinking") and days_left is not None \
                and days_left <= DISK_FORECAST_ALERT_DAYS:
            if alerted:
                return
            state[key] = round(days_left, 1)
            save_json(DISK_FORECAST_STATE_FILE, state)
            action = "send"
        elif alerted and (not trend.get("shrinking")
                          or (days_left or 0) >= DISK_FORECAST_OK_DAYS):
            state.pop(key, None)
            save_json(DISK_FORECAST_STATE_FILE, state)
            action = "recover"
        else:
            return

    if action == "send":
        per_day = abs(trend["slope_gb_per_day"])
        send_or_defer(
            f"📉 МЕСТО СКОРО КОНЧИТСЯ\n"
            f"🖥 Сервер: {server_name}\n"
            f"💽 Диск: {disk_name}\n"
            f"🔓 Свободно сейчас: {round(trend['free_gb'], 1)} ГБ\n"
            f"📊 Расход: ~{per_day:.1f} ГБ/сут "
            f"(по {trend['points']} замерам за {round(trend['span_days'])} дн)\n"
            f"⏳ При таком темпе места хватит на ~{round(days_left)} дн\n"
            f"⚠️ Успеть освободить заранее дешевле, чем разбирать аварию",
            reply_markup=disk_alert_kb(server_name, disk_name,
                                       top_dirs=kind != "vmware")
        )
    else:
        send_or_defer(
            f"✅ Диск больше не заканчивается\n"
            f"🖥 {server_name} · 💽 {disk_name}\n"
            f"Свободно: {round(trend['free_gb'], 1)} ГБ"
        )


# ─── RAID (/proc/mdstat) ─────────────────────────────────────
# Для хранилища бэкапов это самый важный алерт: развалившийся массив не
# виден ни по свободному месту, ни по SMART отдельного диска, а второй
# выпавший диск — это уже потеря данных.

RAID_STATE_FILE = "/app/data/raid_alert_state.json"


def _raid_level(array: dict) -> str | None:
    """degraded / rebuilding / None (норма)."""
    if not array.get("degraded"):
        return None
    return "rebuilding" if array.get("progress") else "degraded"


def check_raid_alert(server_name: str, arrays: list):
    """Алерт на деградацию массива, отдельное сообщение о старте
    восстановления и о возврате в норму. Повторов нет: состояние каждого
    массива хранится и сравнивается."""
    if is_muted(server_name) or not arrays:
        return

    messages = []
    with _state_lock:
        state = load_json(RAID_STATE_FILE)
        changed = False
        seen = set()

        for array in arrays:
            name = array.get("name")
            if not name:
                continue
            key = f"{server_name}:{name}"
            seen.add(key)
            level = _raid_level(array)
            old = state.get(key)

            if level == old:
                continue

            members = ""
            if array.get("total") is not None:
                members = f"\n📊 Дисков в строю: {array['active']} из {array['total']}"
                if array.get("flags"):
                    members += f"  [{array['flags']}]"
            failed = ""
            if array.get("failed"):
                failed = f"\n❌ Выпали: {', '.join(array['failed'])}"

            if level is None:
                state.pop(key, None)
                changed = True
                messages.append(
                    f"✅ RAID снова в норме\n"
                    f"🖥 Сервер: {server_name}\n"
                    f"💽 Массив: {name} ({array.get('level', '?')})"
                    f"{members}"
                )
                continue

            state[key] = level
            changed = True

            if level == "rebuilding":
                progress = array["progress"]
                finish = f", осталось ~{progress['finish']}" if progress.get("finish") else ""
                messages.append(
                    f"🔄 RAID ВОССТАНАВЛИВАЕТСЯ\n"
                    f"🖥 Сервер: {server_name}\n"
                    f"💽 Массив: {name} ({array.get('level', '?')})"
                    f"{members}{failed}\n"
                    f"⏳ {progress['action']}: {progress['percent']}%{finish}\n"
                    f"⚠️ Пока идёт пересборка, массив уязвим — не нагружай и "
                    f"не выключай сервер"
                )
            else:
                messages.append(
                    f"🚨 RAID ДЕГРАДИРОВАН\n"
                    f"🖥 Сервер: {server_name}\n"
                    f"💽 Массив: {name} ({array.get('level', '?')})"
                    f"{members}{failed}\n"
                    f"‼️ Массив без резерва: ещё один диск — и данные потеряны.\n"
                    f"Меняй диск немедленно."
                )

        # Массив исчез из mdstat (разобрали) — состояние не копим
        for key in [k for k in state if k.startswith(f"{server_name}:") and k not in seen]:
            state.pop(key, None)
            changed = True

        if changed:
            save_json(RAID_STATE_FILE, state)

    for message in messages:
        send_or_defer(message, reply_markup=server_alert_kb(server_name))


# ─── Температура дисков ──────────────────────────────────────

DISK_TEMP_STATE_FILE = "/app/data/disk_temp_state.json"
DISK_TEMP_WARN_C = _num_env("DISK_TEMP_WARN_C", 50)
DISK_TEMP_CRIT_C = _num_env("DISK_TEMP_CRIT_C", 60)
DISK_TEMP_HYSTERESIS_C = 3.0


def check_disk_temp_alert(server_name: str, disk_temps: list):
    """Перегрев диска: warn/crit с гистерезисом, чтобы дневные колебания
    вокруг порога не давали поток сообщений."""
    if is_muted(server_name) or not disk_temps:
        return

    messages = []
    with _state_lock:
        state = load_json(DISK_TEMP_STATE_FILE)
        changed = False

        for disk in disk_temps:
            name = disk.get("name")
            temp = disk.get("temp_c")
            if not name or temp is None:
                continue
            key = f"{server_name}:{name}"
            old = state.get(key)

            if temp >= DISK_TEMP_CRIT_C:
                level = "crit"
            elif temp >= DISK_TEMP_WARN_C:
                level = "warn"
            else:
                level = None

            if level == old:
                continue
            if level is None:
                # Остываем — снимаем только с запасом
                if old and temp <= DISK_TEMP_WARN_C - DISK_TEMP_HYSTERESIS_C:
                    state.pop(key, None)
                    changed = True
                    messages.append(
                        f"✅ Диск остыл\n🖥 {server_name} · 💽 {name}\n"
                        f"Сейчас {temp:.0f}°C"
                    )
                continue

            state[key] = level
            changed = True
            icon = "🔥" if level == "crit" else "🌡"
            limit = DISK_TEMP_CRIT_C if level == "crit" else DISK_TEMP_WARN_C
            messages.append(
                f"{icon} ПЕРЕГРЕВ ДИСКА\n"
                f"🖥 Сервер: {server_name}\n"
                f"💽 Диск: {name}\n"
                f"🌡 Температура: {temp:.0f}°C (порог {limit:.0f}°C)\n"
                f"⚠️ Проверь охлаждение — перегрев убивает диски"
            )

        if changed:
            save_json(DISK_TEMP_STATE_FILE, state)

    for message in messages:
        send_or_defer(message, reply_markup=server_alert_kb(server_name))


# ─── SMART и дрейф времени ───────────────────────────────────

def check_smart_alert(server_name: str, unhealthy: list):
    """Windows: Get-PhysicalDisk HealthStatus; Linux: smartctl -H."""
    if is_muted(server_name):
        return

    current = sorted(str(d) for d in unhealthy)
    with _state_lock:
        state = load_json(SMART_STATE_FILE)
        old = state.get(server_name, [])
        if current == old:
            return
        if current:
            state[server_name] = current
        else:
            state.pop(server_name, None)
        save_json(SMART_STATE_FILE, state)

    if current:
        disks = "\n".join(f"• {d}" for d in current)
        send_or_defer(
            f"🚨 ПРОБЛЕМА С ФИЗИЧЕСКИМ ДИСКОМ\n"
            f"🖥 Сервер: {server_name}\n"
            f"{disks}\n"
            f"⚠️ Проверь диск и бэкапы — возможен выход из строя",
            reply_markup=server_alert_kb(server_name)
        )
    else:
        send_or_defer(
            f"✅ Диски снова здоровы\n"
            f"🖥 Сервер: {server_name}\n"
            f"Ранее было: {', '.join(old)}"
        )


def check_time_drift(server_name: str, server_time_utc):
    """Сравнение часов сервера с часами монитора (NTP-рассинхрон)."""
    if not server_time_utc or is_muted(server_name):
        return

    drift = abs(time_module.time() - float(server_time_utc))
    with _state_lock:
        state = load_json(TIME_DRIFT_STATE_FILE)
        alerted = server_name in state

        if drift > TIME_DRIFT_ALERT_SEC and not alerted:
            state[server_name] = round(drift)
            save_json(TIME_DRIFT_STATE_FILE, state)
            action = "send"
        elif drift < TIME_DRIFT_OK_SEC and alerted:
            old_drift = state.pop(server_name)
            save_json(TIME_DRIFT_STATE_FILE, state)
            action = "recover"
        else:
            return

    minutes = round(drift / 60, 1)
    if action == "send":
        send_or_defer(
            f"⏰ ЧАСЫ СЕРВЕРА УБЕЖАЛИ\n"
            f"🖥 Сервер: {server_name}\n"
            f"Расхождение с монитором: ~{minutes} мин\n"
            f"⚠️ Проверь NTP: рассинхрон ломает 1С, Kerberos и время бэкапов",
            reply_markup=server_alert_kb(server_name)
        )
    else:
        send_or_defer(
            f"✅ Часы сервера снова в норме\n"
            f"🖥 Сервер: {server_name}\n"
            f"Было расхождение ~{round(old_drift / 60, 1)} мин"
        )


# ─── Алерты CPU / RAM ────────────────────────────────────────

CPU_STATE_FILE = "/app/data/cpu_alert_state.json"
RAM_STATE_FILE = "/app/data/ram_alert_state.json"
SERVICE_STATE_FILE = "/app/data/service_alert_state.json"


def check_cpu_alert(server_name: str, cpu_load: float):
    # CPU-алерты в Telegram отключены, чтобы не зашумлять канал.
    return


def check_ram_alert(server_name: str, ram_total: float, ram_free: float):
    # RAM-алерты в Telegram отключены, чтобы не зашумлять канал.
    return


# ─── Алерты Windows-сервисов ─────────────────────────────────

def check_service_alert(server_name: str, service: dict):
    if is_muted(server_name):
        return

    service_name = service.get("Name") or service.get("name")
    display_name = service.get("DisplayName") or service_name
    status = str(service.get("Status") or service.get("status") or "unknown")
    key = f"{server_name}:{service_name}"
    is_problem = False

    with _state_lock:
        state = load_json(SERVICE_STATE_FILE)

        if status.lower() == "running":
            if key not in state:
                return
            old_status = state.pop(key)
            save_json(SERVICE_STATE_FILE, state)
            message = (
                f"✅ Сервис восстановлен\n"
                f"🖥 Сервер: {server_name}\n"
                f"⚙️ Сервис: {display_name} ({service_name})\n"
                f"Предыдущий статус: {old_status}"
            )
        else:
            if state.get(key) == status:
                return
            state[key] = status
            save_json(SERVICE_STATE_FILE, state)
            is_problem = True
            hint = ""
            if service.get("Ambiguous"):
                hint = (
                    f"\n⚠️ На сервере несколько служб с таким именем "
                    f"({service.get('MatchCount')}) — проверь, не осталась ли "
                    f"старая версия"
                )
            message = (
                f"🚨 Сервис не запущен\n"
                f"🖥 Сервер: {server_name}\n"
                f"⚙️ Сервис: {display_name} ({service_name})\n"
                f"Статус: {status}{hint}"
            )

    send_or_defer(
        message,
        reply_markup=service_alert_kb(server_name, service_name) if is_problem else None
    )
