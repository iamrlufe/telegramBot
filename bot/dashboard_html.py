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

    return {
        "servers": servers,
        "hours": hours,
        "generated_at": datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M"),
    }


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
@media (max-width:430px){.kpis{grid-template-columns:repeat(2,1fr)}}
@media (prefers-reduced-motion:reduce){.ring .value{transition:none}}
"""

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
        f'<div class="kpis">{kpi_html}</div>'
        f'<div class="chips">{chips_html}</div>'
        f'{"".join(_card(s) for s in servers)}{empty}'
        '<footer>AgentMonitor · автономный HTML-отчёт, работает без сети<br>'
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
