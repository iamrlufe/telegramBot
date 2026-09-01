"""
bot/dashboard_html.py

Дашборд одним автономным HTML-файлом вместо PNG.

Картинка от matplotlib весила 200–400 КБ, строилась секундами и не давала
ни фильтра, ни подробностей: восемь серверов в списке — это восемь строк,
в которые не заглянуть. HTML весит вчетверо меньше, собирается мгновенно и
разворачивается по тапу.

Файл самодостаточный: ни одного внешнего запроса — ни шрифтов, ни скриптов,
ни картинок. Telegram отдаёт его документом, он открывается во встроенном
браузере и работает без сети. Это же требование безопасности: у бота нет
и не должно быть публичного HTTPS-эндпоинта, иначе машина с учётками от
всей инфраструктуры начнёт слушать порт наружу.

Палитра совпадает с charts.py (проверена валидатором dataviz), тёмная тема
берётся из системной и переключается кнопкой.
"""
import html
import os
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from pgconn import get_conn
from db import (
    STALE_MINUTES, DISK_WARN_FREE, DISK_CRIT_FREE,
    is_pseudo_disk, get_problems,
)
from ping_tools import load_targets
from log_store import read_snapshot
from iis_store import read_events as read_iis_events, read_facts as read_iis_facts
from geoip import resolve as geo_resolve
from iis_log import detect_brute_force, is_cloudflare, LOGIN_BRUTE_PER_HOUR
from log_summary import WIN_CATEGORIES, SQL_CATEGORIES, count_by_category
from backup_bot_db import (
    get_latest_backup_metrics, classify_backup_row, load_schedule_map,
    BACKUP_STATUS_MISSING,
)
from backup_schedule import schedule_for, weekday_short

ALMATY = ZoneInfo("Asia/Almaty")

# ─── Палитра (та же, что в charts.py) ────────────────────────
STATUS_GOOD = "#0ca30c"
STATUS_WARN = "#fab219"
STATUS_SERIOUS = "#ec835a"
STATUS_CRIT = "#d03b3b"

# Порядок статусов в списке: сначала лежащие, потом молчащие, потом норма.
STATUSES = {
    "down":  {"color": STATUS_CRIT,    "icon": "✕", "label": "недоступен",        "rank": 0},
    "warn":  {"color": STATUS_SERIOUS, "icon": "!", "label": "замечания",         "rank": 1},
    "stale": {"color": STATUS_WARN,    "icon": "◷", "label": "нет свежих данных", "rank": 2},
    "ok":    {"color": STATUS_GOOD,    "icon": "✓", "label": "онлайн",            "rank": 3},
}


def _to_local(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ALMATY)


def _age_text(minutes: float) -> str:
    """Возраст данных словами: «12 мин», «3.5 ч», «2 дн»."""
    if minutes < 60:
        return f"{round(minutes)} мин"
    if minutes < 60 * 24:
        hours = minutes / 60
        return f"{hours:.1f} ч".replace(".0 ", " ")
    return f"{round(minutes / 60 / 24)} дн"


def disk_color(free_pct: float) -> str:
    if free_pct < DISK_CRIT_FREE:
        return STATUS_CRIT
    if free_pct < DISK_WARN_FREE:
        return STATUS_WARN
    return STATUS_GOOD


# ─── Сбор данных ─────────────────────────────────────────────

def collect_dashboard_data(hours: int = 24) -> dict:
    """Три запроса к базе + готовая сводка проблем.

    Проблемы не пересчитываются заново: get_problems() отдаёт тот же
    кешированный разбор, что и кнопка 🚨 Проблемы, — иначе дашборд и сводка
    расходились бы в пределах одной минуты.
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (server_name)
                   server_name, status, checked_at
            FROM server_status
            ORDER BY server_name, checked_at DESC
        """)
        latest_rows = cur.fetchall()

        cur.execute("""
            SELECT server_name, checked_at, cpu_load, ram_total, ram_free
            FROM server_status
            WHERE checked_at >= NOW() - make_interval(hours => %s)
            ORDER BY checked_at
        """, (hours,))
        history_rows = cur.fetchall()

        cur.execute("""
            SELECT DISTINCT ON (server_name, disk_name)
                   server_name, disk_name, free_gb, used_gb
            FROM disk_metrics
            ORDER BY server_name, disk_name, created_at DESC
        """)
        disk_rows = cur.fetchall()

    if not latest_rows:
        raise ValueError("Нет данных мониторинга — дашборд пуст")

    _, problem_servers = get_problems()
    problems = {s["name"]: s["items"] for s in problem_servers}

    try:
        hosts = {t["name"]: t["host"] for t in load_targets()}
    except (OSError, ValueError, KeyError):
        # Дашборд не обязан падать из-за конфига: адрес — украшение карточки
        hosts = {}

    history = defaultdict(lambda: {"cpu": [], "ram": []})
    for server_name, _checked_at, cpu_load, ram_total, ram_free in history_rows:
        entry = history[server_name]
        if cpu_load is not None:
            entry["cpu"].append(float(cpu_load))
        if ram_total and ram_free and float(ram_total) > 0:
            used = (float(ram_total) - float(ram_free)) / float(ram_total) * 100
            entry["ram"].append(round(used, 1))

    disks = defaultdict(list)
    for server_name, disk_name, free_gb, used_gb in disk_rows:
        if is_pseudo_disk(disk_name):
            continue
        free = float(free_gb)
        total = free + float(used_gb)
        if total <= 0:
            continue
        disks[server_name].append({
            "name": disk_name,
            "free_pct": round(free / total * 100, 1),
            "free_gb": round(free),
            "total_gb": round(total),
        })

    now_utc = datetime.now(timezone.utc)
    servers = []
    for server_name, status, checked_at in latest_rows:
        checked_utc = checked_at.replace(tzinfo=timezone.utc)
        age_min = (now_utc - checked_utc).total_seconds() / 60
        items = problems.get(server_name, [])

        if status != "online":
            state = "down"
        elif age_min > STALE_MINUTES:
            state = "stale"
        elif items:
            state = "warn"
        else:
            state = "ok"

        entry = history.get(server_name, {"cpu": [], "ram": []})
        servers.append({
            "name": server_name,
            "host": hosts.get(server_name, ""),
            "state": state,
            "raw_status": status,
            "age_min": age_min,
            "checked_at": _to_local(checked_at).strftime("%H:%M"),
            "cpu": entry["cpu"],
            "ram": entry["ram"],
            "disks": sorted(disks.get(server_name, []), key=lambda d: d["free_pct"]),
            "problems": items,
        })

    logs = collect_logs()
    for server in servers:
        server["logs"] = {
            source: [row for row in logs[source] if row["server"] == server["name"]]
            for source in ("win", "sql")
        }

    return {
        "servers": servers,
        "logs": logs,
        "backups": collect_backups(),
        "iis": collect_iis(),
        "hours": hours,
        "generated_at": datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M"),
    }


# ─── IIS ─────────────────────────────────────────────────────

def _geo(address: str, geo: dict) -> str:
    """« · 🇰🇿 Астана» для подстановки в строку карточки, уже экранированное."""
    label = (geo or {}).get(str(address or "").strip())
    return f" · {html.escape(label)}" if label else ""


# Где в разобранных ключах лежит адрес. У каждой категории своя позиция.
_IIS_IP_AT = (("scan", 0), ("hits", 1), ("logins", 1), ("errors", 1),
              ("slows", 1), ("herrd", 3))


def _iis_addresses(server: dict) -> list:
    found = [item["ip"] for item in server.get("brute") or []]
    for key, index in _IIS_IP_AT:
        for row in server.get(key) or []:
            parts = row.get("parts") or []
            if len(parts) > index:
                found.append(parts[index])
    return found


def _pairs(rows: list, parts: int) -> list:
    """Ключи вида 'ip|ua' → разобранные части плюс счётчик."""
    out = []
    for row in rows or []:
        chunks = str(row["item"]).split("|")
        chunks += [""] * (parts - len(chunks))
        out.append({"parts": chunks[:parts], "count": row["count"]})
    return out


def _total(events: dict, name: str) -> int:
    for row in events.get("total") or []:
        if row["item"] == name:
            return row["count"]
    return 0


def collect_iis() -> list:
    """Сводка IIS по серверам из базы. Живьём логи не читаются: их дочитывает
    монитор по смещению раз в IIS_SCAN_MINUTES."""
    try:
        day = read_iis_events(24)
        hour = read_iis_events(1)
        facts = read_iis_facts()
    except Exception as e:
        print(f"[dashboard] Сводка IIS недоступна: {e}", flush=True)
        return []

    servers = []
    for name in sorted(set(day) | set(facts)):
        events = day.get(name, {})
        own_facts = facts.get(name, {})
        # Публикацией считается путь первого уровня. Вложенные каталоги
        # (owa/Calendar, EWS/bin у Exchange) — часть приложения, а не
        # отдельная точка входа, и в «без трафика» им не место.
        apps = [str(a.get("p") or "").strip("/") for a in (own_facts.get("apps") or [])]
        apps = [a for a in apps if a and "/" not in a]
        pubs = _pairs(events.get("pub"), 1)
        seen = {p["parts"][0].lower() for p in pubs}
        dead = sorted(a for a in apps if a and a.lower() not in seen)

        # Перебор считается по последнему часу, а не по суткам: 25 входов за
        # день — норма, за час — уже подбор.
        brute = detect_brute_force(
            _pairs(hour.get(name, {}).get("login"), 2),
            _pairs(hour.get(name, {}).get("ip"), 1),
        )

        hits = _pairs(events.get("hit"), 3)
        herr = _pairs(events.get("herr"), 1)
        down_reasons = [h for h in herr
                        if h["parts"][0] in ("QueueFull", "AppOffline",
                                             "Connections_Refused")]
        alarms = []
        if hits:
            alarms.append("сканер получил успешный ответ")
        for item in brute:
            if not item["working"]:
                alarms.append(f"перебор паролей с {item['ip']}")
        if down_reasons:
            alarms.append("публикации были недоступны")

        servers.append({
            "name": name,
            "requests": _total(events, "requests"),
            "alien": _total(events, "alien"),
            "slow": _total(events, "slow"),
            # Считается по накопленным за сутки ключам, а не берётся из
            # последнего прохода: сразу после полуночи в файле десяток строк,
            # и «уникальных адресов: 6» было бы неправдой.
            "uniq": len(events.get("ip") or []),
            "alienuris": _pairs(events.get("alienuri"), 1),
            "pubs": pubs,
            "dead": dead,
            "scan": _pairs(events.get("scan"), 2),
            "hits": hits,
            "logins": _pairs(events.get("login"), 2),
            "errors": _pairs(events.get("error"), 2),
            "slows": _pairs(events.get("slowuri"), 2),
            "hours": sorted(_pairs(events.get("hour"), 1),
                            key=lambda h: h["parts"][0]),
            "herr": herr,
            "herrd": _pairs(events.get("herrd"), 4),
            "brute": brute,
            "pools": own_facts.get("pools") or [],
            "logs_mb": own_facts.get("logs_mb") or 0,
            "oldest_log": own_facts.get("oldest_log") or "",
            "error": own_facts.get("_error") or "",
            "alarms": alarms,
        })

    servers.sort(key=lambda s: (0 if s["alarms"] else 1, -s["requests"], s["name"]))

    # Страна и город — одним запросом на весь дашборд, а не по карточке:
    # адресов в сводке сканирования бывают сотни. Дашборд не должен падать
    # из-за геоданных, поэтому пустой словарь здесь — нормальный исход.
    try:
        addresses = [a for item in servers for a in _iis_addresses(item)]
        geo = geo_resolve(addresses)
    except Exception as e:
        print(f"[dashboard] Геоданные недоступны: {str(e)[:120]}", flush=True)
        geo = {}
    for item in servers:
        item["geo"] = geo
    return servers


def _log_group(events: list, scan: dict, source: str) -> dict:
    """Один сервер одного источника: счётчики по категориям плюс записи."""
    return {
        "categories": count_by_category(events, source),
        "events": sorted(events, key=lambda e: e["event_at"], reverse=True),
        "total": sum(e.get("count", 1) for e in events),
        # Неудачный сбор — тоже повод для жёлтого: «в журналах чисто» и
        # «журнал не прочитан» выглядели одинаково зелёными.
        "level": ("crit" if any(e["level"] == "crit" for e in events)
                  else "warn" if events or (scan or {}).get("error") else "ok"),
        "error": (scan or {}).get("error", ""),
        "collected_at": (scan or {}).get("collected_at"),
    }


def collect_logs() -> dict:
    """Сводка журналов из базы, разложенная по серверам.

    Читается готовое: журналы собирает монитор раз в LOG_SCAN_MINUTES.
    Живьём их тянуть нельзя — на десятке серверов это под сотню удалённых
    вызовов и минуты ожидания при каждой плановой рассылке.
    """
    try:
        events, scans = read_snapshot()
    except Exception as e:
        print(f"[dashboard] Сводка журналов недоступна: {e}", flush=True)
        return {"win": [], "sql": []}

    names = {name for name, _source in scans} | {e["server"] for e in events}
    result = {"win": [], "sql": []}
    for source in ("win", "sql"):
        for name in sorted(names):
            scan = scans.get((name, source))
            own = [e for e in events if e["server"] == name and e["source"] == source]
            if not scan and not own:
                continue
            group = _log_group(own, scan, source)
            group["server"] = name
            result[source].append(group)
        result[source].sort(
            key=lambda g: (0 if g["level"] == "crit" else 1 if g["level"] == "warn" else 2,
                           -g["total"], g["server"].lower())
        )
    return result


BACKUP_STATES = {
    "crit": {"color": STATUS_CRIT,  "icon": "✕", "label": "устарела",   "rank": 0},
    "warn": {"color": STATUS_WARN,  "icon": "!", "label": "на грани",   "rank": 1},
    "ok":   {"color": STATUS_GOOD,  "icon": "✓", "label": "свежая",     "rank": 2},
}


def collect_backups() -> dict:
    """Здоровье бэкапов по всем серверам — та же классификация, что в разделе
    💾 Бэкапы: classify_backup_row общий, иначе дашборд и бот расходились бы
    в оценке одного и того же пути."""
    try:
        rows = get_latest_backup_metrics(include_missing=True)
        schedule_map = load_schedule_map()
    except Exception as e:
        print(f"[dashboard] Метрики бэкапов недоступны: {e}", flush=True)
        return {"servers": [], "totals": {"crit": 0, "warn": 0, "ok": 0}, "size_gb": 0.0}

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    by_server = defaultdict(list)
    totals = {"crit": 0, "warn": 0, "ok": 0}
    size_gb = 0.0

    for row in rows:
        state = classify_backup_row(row, now_utc, schedule_map)
        totals[state] = totals.get(state, 0) + 1
        size_gb += float(row.get("total_size_gb") or 0)
        newest = row.get("newest_file")
        age_h = None
        if newest:
            if getattr(newest, "tzinfo", None):
                newest = newest.astimezone(timezone.utc).replace(tzinfo=None)
            age_h = (now_utc - newest).total_seconds() / 3600
        free_pct = None
        total_disk = float(row.get("disk_total_gb") or 0)
        if total_disk > 0 and row.get("disk_free_gb") is not None:
            free_pct = float(row["disk_free_gb"]) / total_disk * 100
        # Недельная копия оценивается по пропуску срока, а не по возрасту
        # файла: без расписания рядом красная строка «свежий 3 дн назад»
        # выглядит противоречащей настройке «порог возраста не применяется».
        weekly = schedule_for(schedule_map, row["server_name"],
                              row.get("backup_type"), row.get("backup_path"))
        by_server[row["server_name"]].append({
            "weekly": weekly,
            "type": (row.get("backup_type") or "").upper(),
            "path": row.get("backup_path") or "",
            "state": state,
            "files": row.get("file_count"),
            "age_h": age_h,
            "size_gb": float(row.get("total_size_gb") or 0),
            "free_pct": free_pct,
            "missing": row.get("status") == BACKUP_STATUS_MISSING,
            "error": (row.get("error") or "").splitlines()[0][:200] if row.get("error") else "",
        })

    servers = []
    for name, items in by_server.items():
        items.sort(key=lambda i: (BACKUP_STATES[i["state"]]["rank"], i["path"]))
        worst = items[0]["state"] if items else "ok"
        servers.append({
            "name": name, "items": items, "state": worst,
            "size_gb": sum(i["size_gb"] for i in items),
            "counts": {key: sum(1 for i in items if i["state"] == key)
                       for key in ("crit", "warn", "ok")},
        })
    servers.sort(key=lambda s: (BACKUP_STATES[s["state"]]["rank"],
                                -s["counts"]["crit"], s["name"].lower()))
    return {"servers": servers, "totals": totals, "size_gb": size_gb}


# Насколько старой должна быть сводка журналов, чтобы это стоило подписать.
# Монитор читает их раз в час, поэтому «час с небольшим» — норма.
LOG_STALE_MINUTES = 150


def _size_text(gb: float) -> str:
    gb = float(gb or 0)
    if gb >= 1024:
        return f"{gb / 1024:.2f} ТБ"
    if gb >= 1:
        return f"{gb:.1f} ГБ"
    return f"{gb * 1024:.0f} МБ" if gb else "—"


# ─── Отрисовка ───────────────────────────────────────────────

SPARK_W, SPARK_H = 240, 34


def sparkline_path(values: list, width: int = SPARK_W, height: int = SPARK_H) -> str:
    """Линия по точкам, растянутая на всю высоту: у ровных рядов свой масштаб,
    иначе спарклайн CPU 2–4 % выглядит прямой."""
    if not values:
        return ""
    if len(values) == 1:
        values = values * 2

    low, high = min(values), max(values)
    pad = max(4.0, (high - low) * 0.25)
    low, high = max(0.0, low - pad), min(100.0, high + pad)
    span = (high - low) or 1.0

    points = []
    for i, value in enumerate(values):
        x = i / (len(values) - 1) * width
        y = height - 2 - (value - low) / span * (height - 4)
        points.append(f"{'L' if i else 'M'}{x:.1f} {y:.1f}")
    return "".join(points)


def _spark(values: list, color: str) -> str:
    """Линия за сутки с точкой на последнем значении.

    Подсказки по наведению здесь нет и быть не может: просмотрщик Telegram
    открывает файл без JavaScript. Всё, что должно работать, работает на
    голой разметке и CSS."""
    if not values:
        return '<div class="nodata">нет данных</div>'

    path = sparkline_path(values)
    last_x, last_y = path.rsplit("L", 1)[-1].split(" ") if "L" in path else ("0", "0")
    return (
        f'<svg class="spark" viewBox="0 0 {SPARK_W + 4} {SPARK_H}" preserveAspectRatio="none">'
        f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2"'
        f' stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>'
        f'<circle cx="{last_x}" cy="{last_y}" r="2.6" fill="{color}"/></svg>'
    )


RING_R = 34
RING_C = 2 * 3.141592653589793 * RING_R


def _ring(disk: dict) -> str:
    """Кольцо свободного места на худшем диске. Пустое кольцо — если метрик
    по дискам ещё нет: у ESXi и части NAS их не бывает вовсе."""
    if not disk:
        return (
            f'<svg class="ring" viewBox="0 0 100 100">'
            f'<circle cx="50" cy="50" r="{RING_R}" class="track"/></svg>'
            f'<div class="ringtext"><b>—</b><span>нет данных</span></div>'
        )

    free = disk["free_pct"]
    color = disk_color(free)
    offset = RING_C - free / 100 * RING_C
    return (
        f'<svg class="ring" viewBox="0 0 100 100">'
        f'<circle cx="50" cy="50" r="{RING_R}" class="track"/>'
        f'<circle cx="50" cy="50" r="{RING_R}" class="value" stroke="{color}"'
        f' stroke-dasharray="{RING_C:.1f}" stroke-dashoffset="{offset:.1f}"'
        f' style="--from:{RING_C:.1f};--to:{offset:.1f}"'
        f' transform="rotate(-90 50 50)"/></svg>'
        f'<div class="ringtext" style="--ringc:{color}"><b>{free:.0f}%</b>'
        f'<span>своб. · {html.escape(disk["name"])}</span></div>'
    )


def _tint(color: str, alpha: str) -> str:
    """Цвет статуса с прозрачностью: color-mix() понимают не все WebView,
    а восьмизначный hex — все."""
    return f"{color}{alpha}"


SOURCE_TITLES = {"win": "📜 Windows", "sql": "🗄 SQL"}


def _log_badges(server: dict) -> str:
    """Строка «что в журналах» внутри карточки сервера: сколько и чего за
    сутки. Разбор по записям — на вкладках, здесь только повод туда пойти."""
    parts = []
    for source in ("win", "sql"):
        groups = (server.get("logs") or {}).get(source) or []
        if not groups:
            continue
        group = groups[0]
        if group.get("error") and not group["events"]:
            parts.append(
                f'<span class="lb" style="--c:{STATUS_WARN}">{SOURCE_TITLES[source]}: '
                f'<b>сбор не удался</b></span>')
            continue
        hot = [c for c in group["categories"] if c["count"]]
        if not hot:
            continue
        color = STATUS_CRIT if group["level"] == "crit" else STATUS_WARN
        listed = " · ".join(f'<b>{c["count"]}</b> {c["label"]}' for c in hot[:2])
        parts.append(f'<span class="lb" style="--c:{color}">'
                     f'{SOURCE_TITLES[source]}: {listed}</span>')
    return f'<div class="badges">{"".join(parts)}</div>' if parts else ""


def _card(server: dict) -> str:
    state = STATUSES[server["state"]]
    name = html.escape(server["name"])
    cpu = server["cpu"][-1] if server["cpu"] else None
    ram = server["ram"][-1] if server["ram"] else None
    worst = server["disks"][0] if server["disks"] else None

    meta = [html.escape(server["host"])] if server["host"] else []
    if server["state"] == "down":
        meta.append(f"{html.escape(server['raw_status'])} · {_age_text(server['age_min'])}")
    elif server["state"] == "stale":
        meta.append(f"молчит {_age_text(server['age_min'])}")
    else:
        meta.append(f"проверен в {server['checked_at']}")

    parts = [
        f'<details class="card" data-state="{server["state"]}" style="'
        f'--status:{state["color"]};--glow:{_tint(state["color"], "5c")};'
        f'--pillbg:{_tint(state["color"], "24")}">',
        '<summary>',
        '<div class="visual"><div class="glow"></div><div class="grid"></div>',
        f'<div class="ringbox">{_ring(worst)}</div>',
        '<div class="metrics">',
        f'<div class="metric"><div class="mhead">CPU'
        f'<span class="mval">{"—" if cpu is None else f"{cpu:.0f}%"}</span></div>'
        f'{_spark(server["cpu"], "var(--cpu)")}</div>',
        f'<div class="metric"><div class="mhead">RAM'
        f'<span class="mval">{"—" if ram is None else f"{ram:.0f}%"}</span></div>'
        f'{_spark(server["ram"], "var(--ram)")}</div>',
        '</div></div>',
        '<div class="body"><div class="titlerow">',
        f'<span class="chev">›</span><span class="name">{name}</span>',
        f'<span class="pill">{state["icon"]} {state["label"]}</span>',
        f'</div><div class="desc">{" · ".join(meta)}</div></div>',
        '</summary>',
        '<div class="more">',
        _log_badges(server),
    ]

    if server["problems"]:
        parts.append('<div class="issues">')
        for item in server["problems"]:
            color = STATUS_CRIT if item["level"] == "crit" else STATUS_WARN
            text = html.escape(item["text"]).replace("\n", "<br>")
            parts.append(f'<div class="issue" style="--c:{color}">{text}</div>')
        parts.append('</div>')

    for disk in server["disks"]:
        parts.append(
            f'<div class="disk"><span class="dn">{html.escape(disk["name"])}</span>'
            f'<span class="bar"><i style="width:{100 - disk["free_pct"]:.0f}%;'
            f'background:{disk_color(disk["free_pct"])}"></i></span>'
            f'<span class="dv">{disk["free_gb"]} из {disk["total_gb"]} ГБ своб.</span></div>'
        )

    if server["cpu"]:
        avg = sum(server["cpu"]) / len(server["cpu"])
        parts.append(f'<div class="kv">Средний CPU<b>{avg:.0f}%</b></div>')
        parts.append(f'<div class="kv">Пик CPU<b>{max(server["cpu"]):.0f}%</b></div>')
    if server["ram"]:
        parts.append(f'<div class="kv">Пик RAM<b>{max(server["ram"]):.0f}%</b></div>')
    parts.append(f'<div class="kv">Последняя проверка<b>{_age_text(server["age_min"])} назад</b></div>')

    parts.append('</div></details>')
    return "".join(parts)


STYLE = """
:root{
  color-scheme:light;
  --surface:#fcfcfb;--panel:#fff;--panel-2:#f6f5f1;
  --ink:#0b0b0b;--ink-2:#52514e;--ink-3:#898781;
  --line:#e1e0d9;--baseline:#c3c2b7;--gridline:#80808033;
  --cpu:#2a78d6;--ram:#4a3aa7;
  --panel-soft:rgba(255,255,255,.72);
  --shadow:0 1px 2px rgba(11,11,11,.06),0 4px 12px rgba(11,11,11,.05);
}
@media (prefers-color-scheme:dark){
  :root{
    color-scheme:dark;
    --surface:#131312;--panel:#1a1a19;--panel-2:#232322;
    --ink:#fff;--ink-2:#c3c2b7;--ink-3:#898781;
    --line:#2e2e2c;--baseline:#3d3d3a;--gridline:#ffffff1f;
    --cpu:#3987e5;--ram:#9085e9;
    --panel-soft:rgba(26,26,25,.72);
    --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.3);
  }
}
/* Выбор темы вручную бьёт системную: токены переопределяются на .wrap,
   которая идёт следом за переключателем. */
#t-light:checked~.wrap{
  color-scheme:light;
  --surface:#fcfcfb;--panel:#fff;--panel-2:#f6f5f1;
  --ink:#0b0b0b;--ink-2:#52514e;--ink-3:#898781;
  --line:#e1e0d9;--baseline:#c3c2b7;--gridline:#80808033;
  --cpu:#2a78d6;--ram:#4a3aa7;
  --panel-soft:rgba(255,255,255,.72);
  --shadow:0 1px 2px rgba(11,11,11,.06),0 4px 12px rgba(11,11,11,.05);
}
#t-dark:checked~.wrap{
  color-scheme:dark;
  --surface:#131312;--panel:#1a1a19;--panel-2:#232322;
  --ink:#fff;--ink-2:#c3c2b7;--ink-3:#898781;
  --line:#2e2e2c;--baseline:#3d3d3a;--gridline:#ffffff1f;
  --cpu:#3987e5;--ram:#9085e9;
  --panel-soft:rgba(26,26,25,.72);
  --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.3);
}
/* Цвет текста задаётся здесь, а не на body: при ручном выборе темы
   токены переопределяются на .wrap, и унаследованный от body ink
   остался бы от системной темы — тёмное по тёмному. */
.wrap{background:var(--surface);color:var(--ink);min-height:100vh}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--surface);color:var(--ink);-webkit-text-size-adjust:100%;
  font:15px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:14px 12px 40px}
b,.mval,.dv,.kv b,.ringtext b{font-variant-numeric:tabular-nums}
header{display:flex;align-items:flex-start;gap:10px;margin-bottom:12px}
header h1{margin:0 0 2px;font-size:19px;font-weight:700;letter-spacing:-.01em}
header .sub{font-size:12.5px;color:var(--ink-3)}
.theme{margin-left:auto;flex:none;display:flex;border:1px solid var(--line);
  background:var(--panel);border-radius:9px;overflow:hidden}
.theme label{cursor:pointer;font-size:12.5px;line-height:1;padding:9px 9px;color:var(--ink-3);
  border-right:1px solid var(--line);-webkit-user-select:none;user-select:none}
.theme label:last-child{border-right:0}
#t-auto:checked~.wrap label[for="t-auto"],
#t-light:checked~.wrap label[for="t-light"],
#t-dark:checked~.wrap label[for="t-dark"]{background:var(--ink);color:var(--surface)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 11px;box-shadow:var(--shadow)}
.kpi b{display:block;font-size:22px;font-weight:700;line-height:1.1;letter-spacing:-.02em;color:var(--c,var(--ink))}
.kpi span{font-size:11.5px;color:var(--ink-3)}
.chips{display:flex;gap:7px;margin-bottom:14px;overflow-x:auto;padding-bottom:2px}
.chip{flex:none;white-space:nowrap;cursor:pointer;font-size:13px;padding:7px 13px;
  border:1px solid var(--line);background:var(--panel);color:var(--ink-2);border-radius:999px;
  -webkit-user-select:none;user-select:none}
/* Переключатели держатся на radio + :checked: во встроенном браузере
   Telegram скриптов нет, а этот способ работает на голом CSS. */
.switch{position:absolute;opacity:0;pointer-events:none}
#f-bad:checked~.wrap label[for="f-bad"],
#f-all:checked~.wrap label[for="f-all"],
#f-ok:checked~.wrap label[for="f-ok"]{background:var(--ink);color:var(--surface);border-color:var(--ink)}
#f-bad:checked~.wrap .card[data-state="ok"]{display:none}
#f-ok:checked~.wrap .card:not([data-state="ok"]){display:none}
#f-ok:checked~.wrap .empty{display:block}
.empty{display:none;padding:22px 4px;text-align:center;font-size:13px;color:var(--ink-3)}
.card{position:relative;margin-bottom:12px;overflow:hidden;background:var(--panel);
  border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
.card>summary{display:block;list-style:none;cursor:pointer}
.card>summary::-webkit-details-marker{display:none}
.visual{position:relative;height:150px;overflow:hidden;background:var(--panel-2)}
.glow{position:absolute;inset:0;z-index:1;
  background:radial-gradient(ellipse 60% 70% at 50% 50%,var(--glow),transparent 70%)}
.grid{position:absolute;inset:0;z-index:2;pointer-events:none;
  background-image:linear-gradient(to right,var(--gridline) 1px,transparent 1px),
    linear-gradient(to bottom,var(--gridline) 1px,transparent 1px);
  background-size:20px 20px;background-position:center;
  -webkit-mask-image:radial-gradient(ellipse 55% 55% at 50% 50%,#000 55%,transparent 100%);
  mask-image:radial-gradient(ellipse 55% 55% at 50% 50%,#000 55%,transparent 100%)}
.ringbox{position:absolute;z-index:3;left:14px;top:50%;transform:translateY(-50%);
  width:104px;height:104px;display:flex;align-items:center;justify-content:center}
.ring{position:absolute;width:104px;height:104px}
.ring .track{fill:none;stroke:var(--ink);stroke-width:9;opacity:.11}
.ring .value{fill:none;stroke-width:11;stroke-linecap:round;
  animation:ringfill .7s cubic-bezier(.6,.6,0,1) both}
@keyframes ringfill{from{stroke-dashoffset:var(--from)}to{stroke-dashoffset:var(--to)}}
.ringtext{position:relative;text-align:center;line-height:1.15}
.ringtext b{display:block;font-size:20px;font-weight:700;letter-spacing:-.02em;color:var(--ringc,var(--ink))}
.ringtext span{display:block;max-width:92px;margin:0 auto;font-size:9.5px;color:var(--ink-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.metrics{position:absolute;z-index:3;left:130px;right:12px;top:50%;transform:translateY(-50%);
  display:flex;flex-direction:column;gap:8px}
.metric{background:var(--panel-soft);border:1px solid var(--line);
  border-radius:10px;padding:6px 8px 3px;backdrop-filter:blur(4px)}
.mhead{display:flex;align-items:baseline;font-size:11px;color:var(--ink-3)}
.mval{margin-left:auto;font-size:14px;font-weight:650;color:var(--ink)}
.spark{display:block;width:100%;height:28px;touch-action:pan-y}
.nodata{height:28px;display:flex;align-items:center;font-size:11px;color:var(--ink-3)}
.body{padding:11px 13px;border-top:1px solid var(--line)}
.titlerow{display:flex;align-items:center;gap:7px}
.chev{flex:none;color:var(--ink-3);font-size:12px;transition:transform .15s}
details[open] .chev{transform:rotate(90deg)}
.name{font-weight:650;font-size:15px;letter-spacing:-.01em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pill{margin-left:auto;flex:none;font-size:11.5px;font-weight:600;padding:4px 9px;border-radius:999px;
  color:var(--status);background:var(--pillbg)}
.desc{margin-top:2px;margin-left:19px;font-size:12px;color:var(--ink-3)}
.more{padding:0 13px 13px;border-top:1px solid var(--line)}
.issues{margin:11px 0 4px}
.issue{border-left:2px solid var(--c);padding:3px 0 3px 9px;margin-bottom:6px;font-size:12.5px;color:var(--ink-2)}
.disk{display:flex;align-items:center;gap:9px;font-size:12.5px;margin:7px 0}
.disk .dn{flex:none;width:78px;color:var(--ink-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{flex:1;height:8px;border-radius:4px;background:var(--panel-2);overflow:hidden}
.bar i{display:block;height:100%;border-radius:4px}
.dv{flex:none;width:118px;text-align:right;color:var(--ink-2)}
.kv{display:flex;gap:8px;padding:3px 0;font-size:12.5px;color:var(--ink-2)}
.kv b{margin-left:auto;font-weight:600;color:var(--ink)}
footer{margin-top:18px;text-align:center;font-size:11.5px;line-height:1.6;color:var(--ink-3)}

/* ─── Вкладки: те же radio + :checked, что у фильтра ─────────── */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin-bottom:14px;overflow-x:auto}
.tabs label{flex:none;cursor:pointer;font-size:13.5px;color:var(--ink-3);padding:9px 7px;
  border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap;
  -webkit-user-select:none;user-select:none}
#v-srv:checked~.wrap label[for="v-srv"],
#v-win:checked~.wrap label[for="v-win"],
#v-sql:checked~.wrap label[for="v-sql"],
#v-bak:checked~.wrap label[for="v-bak"]{color:var(--ink);font-weight:600;border-bottom-color:var(--ink)}
.pane{display:none}
#v-srv:checked~.wrap .pane-srv,
#v-win:checked~.wrap .pane-win,
#v-sql:checked~.wrap .pane-sql,
#v-bak:checked~.wrap .pane-bak{display:block}
.tabs .badge{display:inline-block;min-width:17px;margin-left:5px;padding:0 5px;border-radius:999px;
  background:var(--bg);color:#fff;font-size:10.5px;font-weight:700;line-height:17px;text-align:center}
.hint{font-size:11.5px;color:var(--ink-3);margin:-4px 2px 12px}
/* ─── Карточка журналов и бэкапов ────────────────────────────── */
.logcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;
  box-shadow:var(--shadow);margin-bottom:10px;overflow:hidden}
.logcard>summary{display:block;list-style:none;cursor:pointer;padding:12px 13px}
.logcard>summary::-webkit-details-marker{display:none}
.loghead{display:flex;align-items:center;gap:7px}
.loghead .name{font-weight:650;font-size:14.5px;letter-spacing:-.01em;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.loghead .tag{margin-left:auto;flex:none;font-size:11.5px;font-weight:600;padding:4px 9px;
  border-radius:999px;color:var(--c);background:var(--cbg)}
.dotc{flex:none;width:8px;height:8px;border-radius:50%;background:var(--c)}
.cats{display:flex;flex-wrap:wrap;gap:6px;margin:9px 0 0 19px}
.cat{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;padding:4px 9px;
  border-radius:8px;background:var(--panel-2);color:var(--ink-2)}
.cat b{font-weight:700;color:var(--c);font-variant-numeric:tabular-nums}
.cat.zero{opacity:.45}
.rows{padding:0 13px 12px;border-top:1px solid var(--line)}
.lrow{display:flex;gap:9px;padding:8px 0;border-bottom:1px solid var(--line);font-size:12.5px}
.lrow:last-child{border-bottom:0}
.lrow .t{flex:none;width:82px;color:var(--ink-3);font-variant-numeric:tabular-nums;font-size:11.5px}
.lrow .m{min-width:0}
.lrow .m b{display:block;font-weight:600}
.lrow .m span{display:block;color:var(--ink-3);font-size:11.5px;word-break:break-word}
.lrow .m i{font-style:normal;color:var(--ink-3);font-size:11px}
.stale{margin:8px 0 0 19px;font-size:11.5px;color:var(--warn)}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin:11px 0 4px}
.lb{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;font-size:11.5px;
  padding:4px 9px;border-radius:8px;background:var(--panel-2);color:var(--ink-2)}
.lb b{color:var(--c);font-weight:700}
.bpath{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--ink-3);
  word-break:break-all}

/* ─── Вкладка IIS ────────────────────────────────────────────── */
#v-iis:checked~.wrap label[for="v-iis"]{color:var(--ink);font-weight:600;border-bottom-color:var(--ink)}
#v-iis:checked~.wrap .pane-iis{display:block}
.srvchips{display:flex;gap:7px;margin-bottom:12px;overflow-x:auto;padding-bottom:2px}
.srvchips label{flex:none;white-space:nowrap;cursor:pointer;font-size:13px;padding:7px 12px;
  border:1px solid var(--line);background:var(--panel);color:var(--ink-2);border-radius:999px;
  display:inline-flex;align-items:center;gap:6px;-webkit-user-select:none;user-select:none}
.srvchips label i{width:7px;height:7px;border-radius:50%;background:var(--c)}
.iisbox{display:none}
.bars{margin:2px 0 0 19px}
.bar2{display:flex;align-items:center;gap:9px;font-size:12.5px;padding:3px 0}
.bar2 .nm2{flex:none;width:130px;color:var(--ink-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar2 .tr{flex:1;height:7px;border-radius:4px;background:var(--panel-2);overflow:hidden}
.bar2 .tr i{display:block;height:100%;border-radius:4px;background:var(--cpu)}
.bar2 .vv{flex:none;width:72px;text-align:right;color:var(--ink-2);font-variant-numeric:tabular-nums}
.hours{display:flex;align-items:flex-end;gap:2px;height:54px;margin:6px 0 0 19px}
.hours i{flex:1;background:var(--cpu);border-radius:2px 2px 0 0;min-height:2px;opacity:.85}
.hoursx{display:flex;justify-content:space-between;font-size:10px;color:var(--ink-3);margin:3px 0 0 19px}
.note{margin:9px 0 0 19px;font-size:11.5px;color:var(--ink-3)}
@media (max-width:430px){.kpis{grid-template-columns:repeat(2,1fr)}}
@media (prefers-reduced-motion:reduce){.ring .value{transition:none}}
"""

def _when(event_at: str) -> str:
    """2026-09-01 04:12:33 → 01.09 04:12. Секунды в списке не нужны, а дата
    нужна: сводка за сутки перешагивает полночь."""
    text = (event_at or "").strip()
    if len(text) < 16:
        return text or "—"
    return f"{text[8:10]}.{text[5:7]} {text[11:16]}"


def _age_since(collected_at) -> str:
    if not collected_at:
        return ""
    delta = datetime.now(timezone.utc) - collected_at
    return _age_text(max(0.0, delta.total_seconds() / 60))


def _log_card(group: dict, source: str) -> str:
    """Сервер на вкладке журналов: счётчики по категориям, внутри — записи."""
    color = (STATUS_CRIT if group["level"] == "crit"
             else STATUS_WARN if group["level"] == "warn" else STATUS_GOOD)
    tag = (f'{group["total"]} за сутки' if group["total"]
           else "сбор не удался" if group["error"] else "чисто")

    cats = "".join(
        f'<span class="cat{"" if c["count"] else " zero"}" '
        f'style="--c:{STATUS_CRIT if c["level"] == "crit" else STATUS_WARN if c["level"] == "warn" else STATUS_GOOD}">'
        f'{c["icon"]} {c["label"]} <b>{c["count"]}</b></span>'
        for c in group["categories"]
    )

    rows = []
    for event in group["events"]:
        row_color = (STATUS_CRIT if event["level"] == "crit"
                     else STATUS_GOOD if event["level"] == "ok" else STATUS_WARN)
        code = f' <i>код {html.escape(event["event_id"])}</i>' if event["event_id"] else ""
        detail = f'<span>{html.escape(event["detail"])}</span>' if event["detail"] else ""
        rows.append(
            f'<div class="lrow"><i class="dotc" style="--c:{row_color};margin-top:5px"></i>'
            f'<span class="t">{_when(event["event_at"])}</span>'
            f'<div class="m"><b>{html.escape(event["title"])}{code}</b>{detail}</div></div>'
        )
    if group["error"]:
        rows.insert(0, f'<div class="lrow"><i class="dotc" style="--c:{STATUS_WARN};margin-top:5px"></i>'
                       f'<span class="t">сбор</span><div class="m">'
                       f'<b>Журнал прочитан не полностью</b>'
                       f'<span>{html.escape(group["error"])}</span></div></div>')
    if not rows:
        rows.append('<div class="lrow"><div class="m">'
                    '<span>За сутки записей нет.</span></div></div>')
    rows.append('<div class="lrow"><div class="m"><span>Полный разбор — '
                'кнопка в карточке сервера в боте.</span></div></div>')

    stale = ""
    age = _age_since(group.get("collected_at"))
    if age and group.get("collected_at"):
        delta_min = (datetime.now(timezone.utc) - group["collected_at"]).total_seconds() / 60
        if delta_min > LOG_STALE_MINUTES:
            stale = f'<div class="stale">◷ данные журналов собраны {age} назад</div>'

    return (
        f'<details class="logcard"{" open" if group["level"] == "crit" else ""}>'
        f'<summary><div class="loghead"><i class="dotc" style="--c:{color}"></i>'
        f'<span class="name">{html.escape(group["server"])}</span>'
        f'<span class="tag" style="--c:{color};--cbg:{_tint(color, "24")}">{tag}</span></div>'
        f'<div class="cats">{cats}</div>{stale}</summary>'
        f'<div class="rows">{"".join(rows)}</div></details>'
    )


def _logs_pane(groups: list, source: str, hint: str) -> str:
    if not groups:
        return (f'<div class="pane pane-{source}"><div class="empty" style="display:block">'
                f'Сводка журналов ещё не собрана. Монитор читает их раз в час — '
                f'загляните после следующего цикла.</div></div>')
    body = "".join(_log_card(g, source) for g in groups)
    return f'<div class="pane pane-{source}"><div class="hint">{hint}</div>{body}</div>'


def _backup_card(server: dict) -> str:
    state = BACKUP_STATES[server["state"]]
    counts = server["counts"]
    cats = "".join(
        f'<span class="cat{"" if counts[key] else " zero"}" style="--c:{BACKUP_STATES[key]["color"]}">'
        f'{BACKUP_STATES[key]["icon"]} {BACKUP_STATES[key]["label"]} <b>{counts[key]}</b></span>'
        for key in ("crit", "warn", "ok")
    )

    rows = []
    for item in server["items"]:
        color = BACKUP_STATES[item["state"]]["color"]
        if item["missing"]:
            detail = "сбор ни разу не отработал по этому пути"
        elif item["error"]:
            detail = f'путь недоступен: {item["error"]}'
        elif not (item["files"] or 0):
            detail = "каталог пуст"
        else:
            bits = [f'{item["files"]} файлов']
            if item["age_h"] is not None:
                bits.append(f'свежий {_age_text(item["age_h"] * 60)} назад')
            if item["size_gb"]:
                bits.append(_size_text(item["size_gb"]))
            if item["free_pct"] is not None and item["free_pct"] < DISK_WARN_FREE:
                bits.append(f'на диске свободно {item["free_pct"]:.0f}%')
            detail = " · ".join(bits)
        if item["weekly"]:
            day, hour = item["weekly"]
            plan = f"{weekday_short(day)} {hour:02d}:00"
            detail += (f' · недельная копия {plan}: срок пропущен'
                       if item["state"] == "crit"
                       else f' · недельная копия {plan}')
        rows.append(
            f'<div class="lrow"><i class="dotc" style="--c:{color};margin-top:5px"></i>'
            f'<span class="t">{html.escape(item["type"])}</span>'
            f'<div class="m"><b>{html.escape(detail)}</b>'
            f'<span class="bpath">{html.escape(item["path"])}</span></div></div>'
        )

    return (
        f'<details class="logcard"{" open" if server["state"] == "crit" else ""}>'
        f'<summary><div class="loghead"><i class="dotc" style="--c:{state["color"]}"></i>'
        f'<span class="name">{html.escape(server["name"])}</span>'
        f'<span class="tag" style="--c:{state["color"]};--cbg:{_tint(state["color"], "24")}">'
        f'{_size_text(server["size_gb"]) if server["size_gb"] else "нет копий"}</span></div>'
        f'<div class="cats">{cats}</div></summary>'
        f'<div class="rows">{"".join(rows)}</div></details>'
    )


def _backups_pane(backups: dict) -> str:
    totals = backups["totals"]
    if not backups["servers"]:
        return ('<div class="pane pane-bak"><div class="empty" style="display:block">'
                'Метрик бэкапов пока нет — дождитесь первого обхода каталогов.</div></div>')

    tiles = "".join(
        f'<div class="kpi" style="--c:{BACKUP_STATES[key]["color"]}"><b>{totals.get(key, 0)}</b>'
        f'<span>{label}</span></div>'
        for key, label in (("crit", "устарели"), ("warn", "на грани"), ("ok", "свежие"))
    )
    tiles += (f'<div class="kpi"><b>{_size_text(backups["size_gb"])}</b>'
              f'<span>всего копий</span></div>')

    body = "".join(_backup_card(server) for server in backups["servers"])
    return (
        '<div class="pane pane-bak">'
        f'<div class="kpis">{tiles}</div>'
        '<div class="hint">Счётчики — по путям бэкапов, не по серверам. '
        'Тап по серверу разворачивает все его пути.</div>'
        f'{body}</div>'
    )


def _is_local(address: str) -> bool:
    """Свой же сервер: Managed Availability у Exchange проверяет себя с
    127.0.0.1, ::1 и link-local адресов, и его 500-е — штатный шум."""
    address = (address or "").strip().lower()
    return (address in ("127.0.0.1", "::1", "localhost")
            or address.startswith("fe80:") or address.startswith("::ffff:127."))


def _iis_card(color, title, tag, cats="", extra="", body="", open_=False) -> str:
    return (
        f'<details class="logcard"{" open" if open_ else ""}>'
        f'<summary><div class="loghead"><i class="dotc" style="--c:{color}"></i>'
        f'<span class="name">{title}</span>'
        f'<span class="tag" style="--c:{color};--cbg:{_tint(color, "24")}">{tag}</span></div>'
        f'{cats}{extra}</summary><div class="rows">{body}</div></details>'
    )


def _cat(icon: str, label: str, count: int, color: str) -> str:
    css = "cat" if count else "cat zero"
    return (f'<span class="{css}" style="--c:{color if count else STATUS_GOOD}">'
            f'{icon} {label} <b>{count}</b></span>')


def _lrow(color, left, title, detail="") -> str:
    tail = f'<span>{detail}</span>' if detail else ""
    return (f'<div class="lrow"><i class="dotc" style="--c:{color};margin-top:5px"></i>'
            f'<span class="t">{left}</span>'
            f'<div class="m"><b>{title}</b>{tail}</div></div>')


def _num(value) -> str:
    return f"{int(value or 0):,}".replace(",", " ")


def _bars(rows: list, limit: int = 8) -> str:
    rows = rows[:limit]
    if not rows:
        return ""
    top = max(r["count"] for r in rows) or 1
    body = "".join(
        f'<div class="bar2"><span class="nm2">{html.escape(r["parts"][0])}</span>'
        f'<span class="tr"><i style="width:{r["count"] / top * 100:.0f}%"></i></span>'
        f'<span class="vv">{_num(r["count"])}</span></div>'
        for r in rows
    )
    return f'<div class="bars">{body}</div>'


def _iis_server(server: dict) -> str:
    """Разделы одного IIS-сервера. Порядок задан вопросами, ради которых
    сюда заходят: сначала «нас атакуют?», потом «что сломано»."""
    cards = []

    # 1. Сканирование
    proxied = sum(r["count"] for r in server["scan"] if is_cloudflare(r["parts"][0]))
    body = "".join(
        _lrow(STATUS_CRIT if r["count"] > 40 else STATUS_WARN, _num(r["count"]),
              html.escape(r["parts"][0])
              + (" · узел Cloudflare" if is_cloudflare(r["parts"][0]) else "")
              + _geo(r["parts"][0], server.get("geo")),
              html.escape(r["parts"][1] or "—"))
        for r in server["scan"][:15]
    )
    if server["hits"]:
        for r in server["hits"][:10]:
            uri, ip, ua = r["parts"]
            body = _lrow(STATUS_CRIT, "200", f"Отдан {html.escape(uri)}",
                         f"{html.escape(ip)}{_geo(ip, server.get("geo"))} · "
                         f"{html.escape(ua)}") + body
        hit_note = "сервер отдал содержимое по постороннему пути — разобрать вручную"
    else:
        body += _lrow(STATUS_GOOD, "0", "Ничего не отдано",
                      "находкой считается только ответ 200 на посторонний путь; "
                      "редиректы и robots.txt со sitemap.xml сюда не идут")
        hit_note = "ничего не нашли"
    if server["alienuris"]:
        body += _lrow(STATUS_SERIOUS, "пути",
                      "Куда стучатся чаще всего",
                      " · ".join(f'{html.escape(r["parts"][0])} ({r["count"]})'
                                 for r in server["alienuris"][:10]))
    cards.append(_iis_card(
        STATUS_CRIT if server["hits"] else STATUS_SERIOUS if server["alien"] else STATUS_GOOD,
        "Сканирование извне", f'{_num(server["alien"])} запросов',
        cats='<div class="cats">'
             + _cat("🔎", "посторонних путей", server["alien"], STATUS_SERIOUS)
             + _cat("✓", "нашли", len(server["hits"]), STATUS_CRIT)
             + _cat("🌐", "адресов", len(server["scan"]), STATUS_WARN) + '</div>',
        extra=f'<div class="note">{hit_note}</div>' + (
            '<div class="note">часть трафика приходит через Cloudflare: в логе '
            'виден адрес узла прокси, а не посетителя. Настоящий адрес появится, '
            'если в логировании сайта завести поле для заголовка '
            'X-Forwarded-For</div>' if proxied else ""),
        body=body, open_=bool(server["hits"])))

    # 2. Вход в 1С
    if server["logins"] or server["brute"]:
        rows = []
        for item in server["brute"]:
            color = STATUS_WARN if item["working"] else STATUS_CRIT
            note = ("адрес при этом работает в базе — похоже на клиента, "
                    "который переподключается по кругу") if item["working"] else (
                    "с адреса идут только входы и ничего больше — это подбор пароля")
            rows.append(_lrow(color, f'{item["count"]}/ч',
                              f'{html.escape(item["base"])} ← '
                              f'{html.escape(item["ip"])}'
                              f'{_geo(item["ip"], server.get("geo"))}', note))
        for r in server["logins"][:12]:
            base, ip = r["parts"]
            rows.append(_lrow(STATUS_GOOD, _num(r["count"]),
                              f'/{html.escape(base)}/e1cib/login ← '
                              f'{html.escape(ip)}{_geo(ip, server.get("geo"))}',
                              "штатный шаг входа платформы 1С"))
        suspicious = sum(1 for i in server["brute"] if not i["working"])
        total_logins = sum(r["count"] for r in server["logins"])
        cards.append(_iis_card(
            STATUS_CRIT if suspicious else STATUS_GOOD, "Вход в 1С (ответы 402)",
            f"{_num(total_logins)} за сутки",
            cats='<div class="cats">'
                 + _cat("🔑", "входов", total_logins, STATUS_GOOD)
                 + _cat("🖥", "адресов", len(server["logins"]), STATUS_GOOD)
                 + _cat("⚠️", "подозрительных", suspicious, STATUS_CRIT) + '</div>',
            extra=f'<div class="note">перебором считается от {LOGIN_BRUTE_PER_HOUR} '
                  f'входов в час с одного адреса при отсутствии другой работы</div>',
            body="".join(rows), open_=bool(suspicious)))

    # 3. Ошибки приложения
    if server["errors"]:
        total = sum(r["count"] for r in server["errors"])
        inner = sum(r["count"] for r in server["errors"] if _is_local(r["parts"][1]))
        bases = {r["parts"][0].split("/")[1] for r in server["errors"] if "/" in r["parts"][0]}
        services = sum(r["count"] for r in server["errors"] if "/hs/" in r["parts"][0])
        body = "".join(
            _lrow(STATUS_WARN if _is_local(r["parts"][1]) else STATUS_CRIT,
                  _num(r["count"]), html.escape(r["parts"][0]),
                  f'← {html.escape(r["parts"][1])}'
                  + _geo(r["parts"][1], server.get("geo"))
                  + (" · внутренняя проверка сервера" if _is_local(r["parts"][1]) else ""))
            for r in server["errors"][:15]
        )
        cards.append(_iis_card(STATUS_WARN if inner == total else STATUS_CRIT,
            "Ошибки приложения (5xx)",
            f"{_num(total)} за сутки",
            cats='<div class="cats">'
                 + _cat("💥", "снаружи", total - inner, STATUS_CRIT)
                 + _cat("🏠", "свои проверки", inner, STATUS_WARN)
                 + _cat("🗄", "путей затронуто", len(bases), STATUS_WARN) + '</div>',
            extra=('<div class="note">запросы с 127.0.0.1, ::1 и fe80:: — это сам '
                   'сервер проверяет себя; у Exchange такие ошибки штатны</div>'
                   if inner else ""),
            body=body, open_=inner != total))

    # 4. Медленные
    if server["slow"]:
        body = "".join(
            _lrow(STATUS_WARN, _num(r["count"]), html.escape(r["parts"][0]),
                  f'← {html.escape(r["parts"][1])}'
                  + _geo(r["parts"][1], server.get("geo")))
            for r in server["slows"][:12]
        )
        cards.append(_iis_card(STATUS_WARN, "Медленные запросы",
            f'{_num(server["slow"])} запросов',
            cats='<div class="cats">'
                 + _cat("🐢", f"дольше {IIS_SLOW_SECONDS} с", server["slow"], STATUS_WARN)
                 + '</div>', body=body))

    # 5. Публикации
    pools = server["pools"] or []
    stopped = [p for p in pools if str(p.get("s") or "").lower() != "started"]
    body = ""
    if server["dead"]:
        body += _lrow(STATUS_CRIT, str(len(server["dead"])),
                      "Приложения без трафика за сутки",
                      " · ".join(html.escape(d) for d in server["dead"]))
    if pools:
        body += _lrow(STATUS_CRIT if stopped else STATUS_WARN, str(len(pools)),
                      "Пулы приложений",
                      " · ".join(f'{html.escape(str(p.get("n")))}: '
                                 f'{html.escape(str(p.get("s")))}' for p in pools))
    live = len(server["pubs"])
    total_pubs = live + len(server["dead"])
    cards.append(_iis_card(
        STATUS_CRIT if server["dead"] else STATUS_GOOD, "Приложения IIS",
        f"{live} с трафиком из {total_pubs}" if total_pubs else "нет данных",
        cats='<div class="cats">' + _cat("✓", "с трафиком", live, STATUS_GOOD)
             + _cat("✕", "без трафика", len(server["dead"]), STATUS_CRIT)
             + _cat("🧩", "пулов", len(pools), STATUS_WARN) + '</div>',
        extra=_bars(server["pubs"]), body=body, open_=bool(server["dead"])))

    # 6. HTTPERR
    if server["herr"]:
        idle = next((h["count"] for h in server["herr"]
                     if h["parts"][0] == "Timer_ConnectionIdle"), 0)
        rest = sum(h["count"] for h in server["herr"]) - idle
        scanners = sum(h["count"] for h in server["herr"]
                       if h["parts"][0] in ("Verb", "URL", "Hostname"))
        down = sum(h["count"] for h in server["herr"]
                   if h["parts"][0] in ("QueueFull", "AppOffline", "Connections_Refused"))
        body = "".join(
            _lrow(STATUS_GOOD if h["parts"][0] == "Timer_ConnectionIdle"
                  else STATUS_CRIT if h["parts"][0] in ("Verb", "URL", "Hostname",
                                                        "QueueFull", "AppOffline",
                                                        "Connections_Refused")
                  else STATUS_WARN,
                  _num(h["count"]), html.escape(h["parts"][0]),
                  HTTPERR_REASONS.get(h["parts"][0], ""))
            for h in server["herr"][:12]
        )
        for r in server["herrd"][:10]:
            reason, method, uri, ip = r["parts"]
            body += _lrow(STATUS_WARN, _num(r["count"]),
                          f'{html.escape(reason)} · {html.escape(method)} {html.escape(uri)}',
                          f'← {html.escape(ip)}')
        cards.append(_iis_card(STATUS_CRIT if down else STATUS_WARN,
            "HTTPERR — мимо лога сайта", f"{_num(rest)} записей",
            cats='<div class="cats">' + _cat("🚧", "сканеры", scanners, STATUS_CRIT)
                 + _cat("📉", "связь клиентов", rest - scanners - down, STATUS_WARN)
                 + _cat("🛑", "недоступность", down, STATUS_CRIT) + '</div>',
            extra='<div class="note">штатное закрытие простаивающих соединений '
                  f'({_num(idle)}) в счётчики не входит</div>',
            body=body, open_=bool(down)))

    # 7. Нагрузка и хозяйство
    hours = server["hours"]
    extra = ""
    if hours:
        peak = max(h["count"] for h in hours) or 1
        bars = "".join(f'<i style="height:{h["count"] / peak * 100:.0f}%"></i>'
                       for h in hours)
        extra = (f'<div class="hours">{bars}</div>'
                 '<div class="note">время по логу IIS — UTC; '
                 'по Алматы это на 5 часов позже</div>')
    body = _lrow(STATUS_GOOD, _num(server["uniq"]), "Уникальных адресов за сутки",
                 f'из них сканирующих: {len(server["scan"])}')
    if server["logs_mb"]:
        gb = server["logs_mb"] / 1024
        body += _lrow(STATUS_WARN if gb > 5 else STATUS_GOOD, f"{gb:.1f} ГБ",
                      "Каталог логов IIS",
                      f'старейший файл от {server["oldest_log"]} — автоочистки нет'
                      if server["oldest_log"] else "автоочистки нет")
    cards.append(_iis_card(STATUS_GOOD, "Нагрузка и хозяйство",
        f'{_num(server["requests"])} запросов', extra=extra, body=body))

    return "".join(cards)


HTTPERR_REASONS = {
    "Timer_ConnectionIdle": "штатное закрытие простаивающих keep-alive соединений",
    "Verb": "несуществующий HTTP-метод — почерк сканеров",
    "URL": "неразбираемый запрос, например префейс HTTP/2 «PRI *»",
    "Hostname": "обращение по адресу с неизвестным Host — сканер",
    "ClientCancel": "клиент оборвал запрос",
    "Client_Reset": "клиент сбросил соединение",
    "Connection_Dropped": "обрыв соединения — плохая связь у клиента",
    "Timer_MinBytesPerSecond": "клиент отдаёт данные медленнее порога",
    "QueueFull": "очередь пула переполнена — публикации недоступны",
    "AppOffline": "пул приложений остановлен",
    "Connections_Refused": "соединения отвергнуты http.sys",
}

IIS_SLOW_SECONDS = 10


def _iis_pane(servers: list) -> tuple:
    """Возвращает (переключатели, панель): radio обязаны стоять до .wrap,
    иначе селектор «~» до карточек не достанет."""
    if not servers:
        return "", ('<div class="pane pane-iis"><div class="empty" style="display:block">'
                    'Сводка IIS ещё не собрана. Монитор дочитывает логи раз в час — '
                    'загляните после следующего цикла.</div></div>')

    radios = "".join(
        f'<input class="switch" type="radio" name="s" id="s-{i}"'
        f'{" checked" if i == 0 else ""}>'
        for i in range(len(servers))
    )
    # Переключатель серверов — тот же приём, что вкладки: IIS-серверов может
    # быть много, а держать их все на одном экране нечитаемо.
    chips = ""
    rules = ""
    if len(servers) > 1:
        chips = '<div class="srvchips">' + "".join(
            f'<label for="s-{i}"><i style="--c:'
            f'{STATUS_CRIT if s["alarms"] else STATUS_GOOD}"></i>'
            f'{html.escape(s["name"].split(".")[0])}</label>'
            for i, s in enumerate(servers)
        ) + '</div>'
        rules = "<style>" + "".join(
            f'#s-{i}:checked~.wrap label[for="s-{i}"]{{background:var(--ink);'
            f'color:var(--surface);border-color:var(--ink)}}'
            f'#s-{i}:checked~.wrap .iis-{i}{{display:block}}'
            for i in range(len(servers))
        ) + "</style>"
    else:
        rules = "<style>.iis-0{display:block}</style>"

    boxes = []
    for i, server in enumerate(servers):
        tiles = "".join([
            f'<div class="kpi"><b>{_num(server["requests"])}</b>'
            f'<span>запросов за сутки</span></div>',
            f'<div class="kpi" style="--c:{STATUS_SERIOUS}"><b>{_num(server["alien"])}</b>'
            f'<span>посторонних</span></div>',
            f'<div class="kpi" style="--c:'
            f'{STATUS_CRIT if server["hits"] else STATUS_GOOD}">'
            f'<b>{len(server["hits"])}</b><span>найдено сканерами</span></div>',
            f'<div class="kpi" style="--c:{STATUS_CRIT}">'
            f'<b>{_num(sum(r["count"] for r in server["errors"]))}</b>'
            f'<span>ошибок 5xx</span></div>',
        ])
        note = f'{html.escape(server["name"])} · сводка за сутки, дочитывается по смещению'
        if server["error"]:
            note += f' · ⚠️ {html.escape(server["error"])}'
        boxes.append(
            f'<div class="iisbox iis-{i}"><div class="kpis">{tiles}</div>'
            f'<div class="hint">{note}</div>{_iis_server(server)}</div>'
        )

    return radios, ('<div class="pane pane-iis">' + rules + chips
                    + "".join(boxes) + '</div>')


def render_dashboard(data: dict) -> str:
    """Данные → готовый HTML. Отдельно от базы, чтобы тесты проверяли разметку
    без Postgres.

    Ни строчки JavaScript: просмотрщик файлов в Telegram открывает страницу
    со скриптами выключёнными — на кнопках это было видно сразу, они просто
    не нажимались. Фильтр и выбор темы держатся на radio + :checked, кольца
    рисуются готовыми, разворот карточки — на <details>."""
    # Порядок задаётся здесь, а не при выборке: сортировка — часть отчёта,
    # и её проверяют тесты, не поднимая базу.
    servers = sorted(data["servers"],
                     key=lambda s: (STATUSES[s["state"]]["rank"], s["name"].lower()))
    hours = data["hours"]
    down = sum(1 for s in servers if s["state"] == "down")
    stale = sum(1 for s in servers if s["state"] == "stale")
    warn = sum(1 for s in servers if s["state"] == "warn")
    good = sum(1 for s in servers if s["state"] == "ok")
    bad = len(servers) - good
    period = "24 часа" if hours == 24 else f"{hours} часов"

    kpis = [
        (down, "недоступны", STATUS_CRIT),
        (warn, "с замечаниями", STATUS_SERIOUS),
        (stale, "молчат", STATUS_WARN),
        (good, "в норме", STATUS_GOOD),
    ]
    kpi_html = "".join(
        f'<div class="kpi" style="--c:{color}"><b>{value}</b><span>{label}</span></div>'
        for value, label, color in kpis
    )

    # Открывается на проблемных: ради них отчёт и запрашивают. Если всё
    # хорошо — сразу общий список, иначе экран выглядел бы пустым.
    default_filter = "bad" if bad else "all"
    filters = [
        ("bad", f"Требуют внимания · {bad}"),
        ("all", f"Все · {len(servers)}"),
        ("ok", f"В норме · {good}"),
    ]
    radios = "".join(
        f'<input class="switch" type="radio" name="f" id="f-{key}"'
        f'{" checked" if key == default_filter else ""}>'
        for key, _label in filters
    )
    chips_html = "".join(
        f'<label class="chip" for="f-{key}">{label}</label>' for key, label in filters
    )
    themes = [("auto", "◐"), ("light", "☀"), ("dark", "☾")]
    radios += "".join(
        f'<input class="switch" type="radio" name="t" id="t-{key}"'
        f'{" checked" if key == "auto" else ""}>'
        for key, _icon in themes
    )
    theme_html = "".join(
        f'<label for="t-{key}" title="Тема: {key}">{icon}</label>' for key, icon in themes
    )

    empty = ('<div class="empty">Здоровых серверов нет — все требуют внимания.</div>'
             if not good else "")

    logs = data.get("logs") or {"win": [], "sql": []}
    backups = data.get("backups") or {"servers": [], "totals": {}, "size_gb": 0}
    iis = data.get("iis") or []
    iis_radios, iis_html = _iis_pane(iis)
    win_hot = sum(1 for g in logs["win"] if g["level"] == "crit")
    sql_hot = sum(1 for g in logs["sql"] if g["level"] == "crit")
    bak_hot = backups.get("totals", {}).get("crit", 0)
    iis_hot = sum(1 for s in iis if s["alarms"])

    tabs = [
        ("srv", "Серверы", 0, STATUS_CRIT),
        ("win", "Windows", win_hot, STATUS_CRIT),
        ("sql", "SQL", sql_hot, STATUS_CRIT),
        ("bak", "Бэкапы", bak_hot, STATUS_CRIT),
    ]
    if iis:
        tabs.append(("iis", "IIS", iis_hot, STATUS_CRIT))
    radios += "".join(
        f'<input class="switch" type="radio" name="v" id="v-{key}"'
        f'{" checked" if key == "srv" else ""}>'
        for key, _label, _count, _color in tabs
    ) + iis_radios
    tabs_html = "".join(
        f'<label for="v-{key}">{label}'
        + (f'<span class="badge" style="--bg:{color}">{count}</span>' if count else "")
        + '</label>'
        for key, label, count, color in tabs
    )

    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<title>Дашборд · AgentMonitor</title>'
        f'<style>{STYLE}</style></head><body>'
        f'{radios}<div class="wrap">'
        '<header><div><h1>Дашборд инфраструктуры</h1>'
        f'<div class="sub">{len(servers)} серверов · за {period} · '
        f'сформировано {data["generated_at"]}</div></div>'
        f'<div class="theme">{theme_html}</div></header>'
        f'<div class="tabs">{tabs_html}</div>'
        '<div class="pane pane-srv">'
        f'<div class="kpis">{kpi_html}</div>'
        f'<div class="chips">{chips_html}</div>'
        f'{"".join(_card(s) for s in servers)}{empty}</div>'
        + _logs_pane(logs["win"], "win",
                     "Event Log за сутки: перезагрузки и падения, службы, диски, "
                     "приложения, отказы входа.")
        + _logs_pane(logs["sql"], "sql",
                     "SQL Server за сутки: отказы входа, ошибки копирования "
                     "и движка, упавшие джобы Agent.")
        + _backups_pane(backups)
        + iis_html
        + '<footer>AgentMonitor · автономный HTML-отчёт, работает без сети<br>'
        'данные на момент формирования — обновить можно командой /dashboard</footer>'
        '</div></body></html>'
    )


def build_dashboard_html(hours: int = 24) -> str:
    """Готовый файл во временном каталоге; удаляет его вызывающая сторона."""
    html_text = render_dashboard(collect_dashboard_data(hours))
    stamp = datetime.now(ALMATY).strftime("%Y-%m-%d_%H-%M")
    directory = tempfile.mkdtemp(prefix="dashboard_")
    path = os.path.join(directory, f"Дашборд_{stamp}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_text)
    return path
