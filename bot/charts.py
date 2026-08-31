import os
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import matplotlib.transforms as mtransforms

from pgconn import get_conn

ALMATY = ZoneInfo("Asia/Almaty")

# ─── Палитра (dataviz reference, проверена scripts/validate_palette.js) ──
SURFACE = "#fcfcfb"          # фон графика
INK = "#0b0b0b"              # основной текст
INK_SECONDARY = "#52514e"    # вторичный текст
INK_MUTED = "#898781"        # подписи осей
GRID = "#e1e0d9"             # сетка
BASELINE = "#c3c2b7"         # оси

# Категориальные цвета в фиксированном порядке (не перекрашивать при фильтрации)
SERIES = ["#2a78d6", "#1baf7a", "#eda100", "#008300",
          "#4a3aa7", "#e34948", "#e87ba4", "#eb6834"]
CPU_COLOR = SERIES[0]        # синий
RAM_COLOR = SERIES[4]        # фиолетовый

# Статусные цвета — только для состояния, не для серий
STATUS_GOOD = "#0ca30c"
STATUS_WARN = "#fab219"
STATUS_CRIT = "#d03b3b"


def _save_figure(fig, prefix: str) -> str:
    """Фигура → PNG во временный файл, путь наружу.

    plt.close(fig) обязательно в finally: matplotlib держит фигуры в глобальном
    реестре, и при сбое savefig они копились в долгоживущем процессе бота —
    утечка памяти, заметная только через недели аптайма."""
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".png")
    os.close(fd)
    try:
        fig.savefig(path, dpi=150, facecolor=fig.get_facecolor())
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    finally:
        plt.close(fig)
    return path


def _to_local(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc).astimezone(ALMATY)


def _style_axis(ax):
    """Ненавязчивые оси: без верхней/правой рамки, тонкая сетка."""
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(BASELINE)
        ax.spines[side].set_linewidth(0.8)
    ax.tick_params(colors=INK_MUTED, labelsize=9)
    ax.grid(True, color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)


def _setup_time_axis(ax, hours: int = 24):
    if hours <= 48:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=ALMATY))
        ax.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, hours // 8)))
    else:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m", tz=ALMATY))
        ax.xaxis.set_major_locator(mdates.DayLocator(interval=max(1, hours // 24 // 10)))
    _style_axis(ax)


def _danger_zones_high(ax, warn: float = 80, crit: float = 90):
    """Зоны опасности для метрик «выше — хуже» (CPU/RAM, %)."""
    ax.axhspan(warn, crit, color=STATUS_WARN, alpha=0.08, zorder=0)
    ax.axhspan(crit, 100, color=STATUS_CRIT, alpha=0.10, zorder=0)


def _danger_zones_low(ax, warn: float = 20, crit: float = 10):
    """Зоны опасности для метрик «ниже — хуже» (свободное место, %)."""
    ax.axhspan(crit, warn, color=STATUS_WARN, alpha=0.08, zorder=0)
    ax.axhspan(0, crit, color=STATUS_CRIT, alpha=0.10, zorder=0)


def _annotate_last(ax, times, values, color, label):
    """Маркер и значение на последней точке серии."""
    if not times:
        return
    ax.plot(times[-1], values[-1], "o", markersize=6, color=color,
            markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=5)
    ax.annotate(
        f"{label} {round(values[-1])}%",
        xy=(times[-1], values[-1]),
        xytext=(8, 0), textcoords="offset points",
        fontsize=9, fontweight="bold", color=color, va="center",
        bbox=dict(boxstyle="round,pad=0.25", facecolor=SURFACE,
                  edgecolor=color, linewidth=0.6, alpha=0.9),
        zorder=6,
    )


def _place_end_labels(ax, entries, fontsize=8.5):
    """Подписи серий в конце линий вместо легенды.

    Легенда поверх графика с 6-8+ сериями перекрывает сами линии и
    накладывается на них текстом — нечитаемо. Подписи сбоку с разведением
    по вертикали (если несколько серий заканчиваются близкими значениями)
    решают это: каждая линия подписана у своего конца, ничего не наложено.
    entries — список (time, value, color, label) по последней точке серии.
    """
    if not entries:
        return
    ylim = ax.get_ylim()
    span = (ylim[1] - ylim[0]) or 1
    n = len(entries)
    min_gap = span * 0.055

    # Если подписей много или значения сильно скучены, фиксированного
    # шага не хватает — упирается в край и подписи схлопываются обратно
    # друг в друга. Сжимаем шаг так, чтобы все n подписей гарантированно
    # разместились в пределах видимой области, без наложения.
    usable = span * 0.92
    if n > 1 and min_gap * (n - 1) > usable:
        min_gap = usable / (n - 1)

    ordered = sorted(entries, key=lambda e: e[1], reverse=True)
    positions = [e[1] for e in ordered]
    for i in range(1, len(positions)):
        if positions[i - 1] - positions[i] < min_gap:
            positions[i] = positions[i - 1] - min_gap

    # Блок подписей мог целиком уехать за нижний или верхний край — сдвигаем
    # его целиком обратно (не трогая эту же логику "снизу вверх" отдельно,
    # чтобы относительный порядок и зазоры не сломались).
    bottom_pad = ylim[0] + span * 0.02
    if positions[-1] < bottom_pad:
        shift = bottom_pad - positions[-1]
        positions = [p + shift for p in positions]
    top_pad = ylim[1] - span * 0.02
    if positions[0] > top_pad:
        shift = positions[0] - top_pad
        positions = [p - shift for p in positions]

    trans = mtransforms.blended_transform_factory(ax.transAxes, ax.transData)
    for (time, value, color, label), y in zip(ordered, positions):
        ax.plot(time, value, "o", markersize=4, color=color,
                markeredgecolor=SURFACE, markeredgewidth=1, zorder=4)
        # Соединительная линия от реальной точки до подписи — без неё, когда
        # несколько серий заканчиваются рядом, подписи разъезжаются в столбик
        # и непонятно, какая подпись к какой линии относится.
        ax.annotate(
            label, xy=(time, value), xycoords="data",
            xytext=(1.03, y), textcoords=trans,
            fontsize=fontsize, color=color, fontweight="bold",
            va="center", ha="left", annotation_clip=False,
            arrowprops=dict(arrowstyle="-", color=color, lw=0.7,
                             alpha=0.55, shrinkA=3, shrinkB=4),
        )


def _stats_text(values) -> str:
    if not values:
        return ""
    avg = sum(values) / len(values)
    return f"min {round(min(values))} · ср {round(avg)} · max {round(max(values))}"


def period_label(hours: int) -> str:
    if hours % 24 == 0 and hours >= 24:
        days = hours // 24
        return "24 часа" if days == 1 else f"{days} дней"
    return f"{hours} часов"


def build_server_chart(server_name: str, hours: int = 24) -> str:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT checked_at, status, cpu_load, ram_total, ram_free
            FROM server_status
            WHERE server_name = %s
              AND checked_at >= NOW() - make_interval(hours => %s)
            ORDER BY checked_at
        """, (server_name, hours))
        status_rows = cur.fetchall()

        cur.execute("""
            SELECT created_at, disk_name, free_gb, used_gb
            FROM disk_metrics
            WHERE server_name = %s
              AND created_at >= NOW() - make_interval(hours => %s)
            ORDER BY created_at
        """, (server_name, hours))
        disk_rows = cur.fetchall()

    label = period_label(hours)
    if not status_rows and not disk_rows:
        raise ValueError(f"Нет данных за {label} по серверу {server_name}")

    fig, axes = plt.subplots(3, 1, figsize=(12, 9), sharex=True)
    fig.patch.set_facecolor(SURFACE)
    fig.suptitle(f"{server_name} · {label}", fontsize=17, fontweight="bold", color=INK)

    # Доступность
    ax = axes[0]
    if status_rows:
        times = [_to_local(row[0]) for row in status_rows]
        values = [1 if row[1] == "online" else 0 for row in status_rows]
        availability = round(sum(values) / len(values) * 100, 1)
        ax.fill_between(times, values, step="post", color=STATUS_GOOD, alpha=0.15, zorder=1)
        ax.step(times, values, where="post", color=STATUS_GOOD, linewidth=1.8, zorder=2)
        down_times = [t for t, v in zip(times, values) if not v]
        if down_times:
            ax.scatter(down_times, [0] * len(down_times), color=STATUS_CRIT,
                       s=26, zorder=3, label="офлайн")
        ax.set_title(f"Доступность · {availability}%", loc="left",
                     fontsize=12, fontweight="bold", color=INK)
    else:
        ax.set_title("Доступность · нет данных", loc="left",
                     fontsize=12, fontweight="bold", color=INK)
    ax.set_ylim(-0.2, 1.2)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["down", "online"])
    _setup_time_axis(ax, hours)
    ax.grid(False)

    # CPU/RAM
    ax = axes[1]
    cpu_times, cpu_values = [], []
    ram_times, ram_values = [], []
    for checked_at, status, cpu_load, ram_total, ram_free in status_rows:
        t = _to_local(checked_at)
        if cpu_load is not None:
            cpu_times.append(t)
            cpu_values.append(float(cpu_load))
        if ram_total and ram_free:
            ram_total = float(ram_total)
            ram_free = float(ram_free)
            if ram_total > 0:
                ram_times.append(t)
                ram_values.append(round((ram_total - ram_free) / ram_total * 100, 1))

    _danger_zones_high(ax)
    if cpu_times:
        ax.plot(cpu_times, cpu_values, color=CPU_COLOR, linewidth=2, label="CPU", zorder=3)
        ax.fill_between(cpu_times, cpu_values, color=CPU_COLOR, alpha=0.12, zorder=2)
        _annotate_last(ax, cpu_times, cpu_values, CPU_COLOR, "CPU")
    if ram_times:
        ax.plot(ram_times, ram_values, color=RAM_COLOR, linewidth=2, label="RAM", zorder=3)
        ax.fill_between(ram_times, ram_values, color=RAM_COLOR, alpha=0.12, zorder=2)
        _annotate_last(ax, ram_times, ram_values, RAM_COLOR, "RAM")

    ax.set_title("CPU / RAM", loc="left", fontsize=12, fontweight="bold", color=INK)
    stats = " · ".join(part for part in (
        f"CPU: {_stats_text(cpu_values)}" if cpu_values else "",
        f"RAM: {_stats_text(ram_values)}" if ram_values else "",
    ) if part)
    if stats:
        ax.set_title(stats, loc="right", fontsize=8.5, color=INK_SECONDARY)
    ax.set_ylabel("%", color=INK_MUTED)
    ax.set_ylim(0, 100)
    if cpu_times or ram_times:
        legend = ax.legend(loc="upper left", fontsize=9, frameon=False)
        for text in legend.get_texts():
            text.set_color(INK_SECONDARY)
    _setup_time_axis(ax, hours)

    # Диски
    ax = axes[2]
    disks = defaultdict(lambda: {"times": [], "free_pct": []})
    for created_at, disk_name, free_gb, used_gb in disk_rows:
        free = float(free_gb)
        used = float(used_gb)
        total = free + used
        if total <= 0:
            continue
        disks[disk_name]["times"].append(_to_local(created_at))
        disks[disk_name]["free_pct"].append(round(free / total * 100, 1))

    _danger_zones_low(ax)
    for i, (disk_name, data) in enumerate(sorted(disks.items())):
        color = SERIES[i % len(SERIES)]
        ax.plot(data["times"], data["free_pct"], linewidth=2, color=color,
                label=f"{disk_name}: {round(data['free_pct'][-1])}%", zorder=3)
        ax.plot(data["times"][-1], data["free_pct"][-1], "o", markersize=5,
                color=color, markeredgecolor=SURFACE, markeredgewidth=1, zorder=4)
    ax.set_title("Свободное место на дисках", loc="left",
                 fontsize=12, fontweight="bold", color=INK)
    ax.set_ylabel("% свободно", color=INK_MUTED)
    ax.set_ylim(0, 100)
    if disks:
        legend = ax.legend(loc="upper right", ncol=2, fontsize=9, frameon=False)
        for text in legend.get_texts():
            text.set_color(INK_SECONDARY)
    _setup_time_axis(ax, hours)

    generated_at = datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M")
    fig.text(0.01, 0.01, f"AgentMonitor · сформировано {generated_at}",
             fontsize=9, color=INK_MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.95))

    return _save_figure(fig, f"{server_name}_chart_")


GROWTH_MAX_DB_LINES = 8
GROWTH_MAX_BACKUP_LINES = 8


def build_growth_chart(server_name: str, days: int = 30) -> str:
    """
    График роста: размеры MSSQL-баз и backup-каталогов за N дней.
    Отвечает на вопрос «когда закончится место» до срабатывания алерта.
    """
    from backup_bot_db import is_visible_database_name

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT collected_at, database_name, size_gb
            FROM database_sizes
            WHERE server_name = %s
              AND collected_at >= NOW() - make_interval(days => %s)
            ORDER BY collected_at
        """, (server_name, days))
        db_rows = [
            row for row in cur.fetchall()
            if is_visible_database_name(row[1]) and row[2] is not None
        ]

        cur.execute("""
            SELECT created_at, backup_type, backup_path, total_size_gb
            FROM backup_metrics
            WHERE server_name = %s
              AND created_at >= NOW() - make_interval(days => %s)
              AND total_size_gb IS NOT NULL
            ORDER BY created_at
        """, (server_name, days))
        backup_rows = cur.fetchall()

    if not db_rows and not backup_rows:
        raise ValueError(f"Нет истории размеров за {days} дней по серверу {server_name}")

    fig, axes = plt.subplots(2, 1, figsize=(13, 8.5), sharex=True)
    fig.patch.set_facecolor(SURFACE)
    fig.suptitle(f"{server_name} · рост за {days} дней",
                 fontsize=17, fontweight="bold", color=INK)
    hours = days * 24

    # Размеры баз
    ax = axes[0]
    db_series = defaultdict(lambda: {"times": [], "sizes": []})
    for collected_at, db_name, size_gb in db_rows:
        db_series[db_name]["times"].append(_to_local(collected_at))
        db_series[db_name]["sizes"].append(float(size_gb))

    # Не раздуваем подписи: только крупнейшие базы
    top_dbs = sorted(
        db_series.items(),
        key=lambda kv: kv[1]["sizes"][-1],
        reverse=True
    )[:GROWTH_MAX_DB_LINES]

    end_labels = []
    for i, (db_name, data) in enumerate(top_dbs):
        delta = data["sizes"][-1] - data["sizes"][0]
        sign = "+" if delta >= 0 else ""
        color = SERIES[i % len(SERIES)]
        ax.plot(data["times"], data["sizes"], linewidth=2, color=color)
        end_labels.append((
            data["times"][-1], data["sizes"][-1], color,
            f"{db_name} ({sign}{round(delta, 1)} ГБ)"
        ))
    if db_series:
        skipped = len(db_series) - len(top_dbs)
        title = "Размер баз MSSQL"
        if skipped > 0:
            title += f" (топ {GROWTH_MAX_DB_LINES}, ещё {skipped} скрыто)"
        ax.set_title(title, loc="left", fontsize=12, fontweight="bold", color=INK)
    else:
        ax.set_title("Размер баз MSSQL: нет данных", loc="left",
                     fontsize=12, fontweight="bold", color=INK)
    ax.set_ylabel("ГБ", color=INK_MUTED)
    _setup_time_axis(ax, hours)
    _place_end_labels(ax, end_labels)

    # Размеры backup-каталогов
    ax = axes[1]
    backup_series = defaultdict(lambda: {"times": [], "sizes": []})
    for created_at, backup_type, backup_path, total_size_gb in backup_rows:
        key = f"{backup_type.upper()} {backup_path}"
        backup_series[key]["times"].append(_to_local(created_at))
        backup_series[key]["sizes"].append(float(total_size_gb))

    # Не раздуваем подписи: только крупнейшие каталоги (как и с базами MSSQL)
    top_backups = sorted(
        backup_series.items(),
        key=lambda kv: kv[1]["sizes"][-1],
        reverse=True
    )[:GROWTH_MAX_BACKUP_LINES]

    end_labels = []
    for i, (key, data) in enumerate(top_backups):
        delta = data["sizes"][-1] - data["sizes"][0]
        sign = "+" if delta >= 0 else ""
        color = SERIES[i % len(SERIES)]
        ax.plot(data["times"], data["sizes"], linewidth=2, color=color)
        end_labels.append((
            data["times"][-1], data["sizes"][-1], color,
            f"{key} ({sign}{round(delta, 1)} ГБ)"
        ))
    if backup_series:
        skipped = len(backup_series) - len(top_backups)
        title = "Размер backup-каталогов"
        if skipped > 0:
            title += f" (топ {GROWTH_MAX_BACKUP_LINES}, ещё {skipped} скрыто)"
        ax.set_title(title, loc="left", fontsize=12, fontweight="bold", color=INK)
    else:
        ax.set_title("Backup-каталоги: нет данных", loc="left",
                     fontsize=12, fontweight="bold", color=INK)
    ax.set_ylabel("ГБ", color=INK_MUTED)
    _setup_time_axis(ax, hours)
    _place_end_labels(ax, end_labels)

    generated_at = datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M")
    fig.text(0.01, 0.01, f"AgentMonitor · сформировано {generated_at}",
             fontsize=9, color=INK_MUTED)
    # Правое поле оставлено под подписи серий, вынесенные за край графика
    fig.tight_layout(rect=(0, 0.03, 0.82, 0.95))

    return _save_figure(fig, f"{server_name}_growth_")


# ─── Топ каталогов диска ─────────────────────────────────────

def _basename(path: str) -> str:
    """Имя последнего сегмента пути (Windows или UNC): 'E:\\daily' → 'daily'."""
    clean = str(path or "").replace("\\", "/").rstrip("/")
    return clean.split("/")[-1] or clean or "?"


def build_top_dirs_chart(server_name: str, disk_name: str, dirs: list,
                         disk_used_gb: float = None, disk_free_gb: float = None) -> str:
    """
    Горизонтальная диаграмма «какая папка сколько занимает».
    dirs — [(путь, размер_гб)] по убыванию. Цвет от красного (самая большая)
    к зелёному (меньше); подпись — размер и % от общего размера диска.
    """
    dirs = [(p, float(s)) for p, s in dirs if s is not None]
    if not dirs:
        raise ValueError("нет данных для диаграммы")

    names = [_basename(p) for p, _ in dirs]
    sizes = [s for _, s in dirs]
    max_size = max(sizes) or 1.0

    total_disk = None
    if disk_used_gb is not None and disk_free_gb is not None:
        total_disk = float(disk_used_gb) + float(disk_free_gb)

    # Цвет по относительному размеру: самая большая — красная, дальше к зелёной
    cmap = matplotlib.colormaps["RdYlGn"]
    colors = [cmap(1.0 - (s / max_size)) for s in sizes]

    n = len(dirs)
    fig, ax = plt.subplots(figsize=(10, max(2.6, 0.62 * n + 1.7)))
    fig.patch.set_facecolor(SURFACE)

    y = list(range(n))
    ax.barh(y, sizes, color=colors, edgecolor=SURFACE, linewidth=0.8, zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=10, color=INK)
    ax.invert_yaxis()                     # самая большая — сверху
    _style_axis(ax)
    ax.grid(True, axis="x", color=GRID, linewidth=0.7)
    ax.grid(False, axis="y")
    ax.set_xlabel("ГБ", color=INK_MUTED)
    ax.set_xlim(0, max_size * 1.24)

    for i, s in enumerate(sizes):
        if total_disk and total_disk > 0:
            label = f"{s:.1f} ГБ · {s / total_disk * 100:.1f}%"
        else:
            label = f"{s:.1f} ГБ"
        ax.text(s + max_size * 0.012, i, label, va="center", ha="left",
                fontsize=9, fontweight="bold", color=INK_SECONDARY)

    title = f"{disk_name} на {server_name} — крупнейшие каталоги"
    if total_disk and total_disk > 0:
        used_pct = float(disk_used_gb) / total_disk * 100
        title += (f"\nДиск {total_disk:.0f} ГБ · занято {float(disk_used_gb):.0f} ГБ "
                  f"({used_pct:.0f}%) · свободно {float(disk_free_gb):.0f} ГБ ({100 - used_pct:.0f}%)")
    ax.set_title(title, loc="left", fontsize=12, fontweight="bold", color=INK, pad=12)

    generated_at = datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M")
    fig.text(0.01, 0.01, f"AgentMonitor · сформировано {generated_at}",
             fontsize=8, color=INK_MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.98))

    return _save_figure(fig, f"{server_name}_topdirs_")


# ─── Дайджест бэкапов: тепловая карта + общий объём ──────────

BACKUP_VOLUME_MAX_SERVERS = 8


def build_backup_freshness_chart() -> str:
    """Тепловая карта свежести: строка — сервер, квадрат — один путь
    бэкапа, цвет — статус (как в тексте еженедельного дайджеста).
    Серверы с критичными путями — сверху, чтобы проблемы бросались в глаза.
    """
    from backup_bot_db import classify_backup_row, get_latest_backup_metrics
    from backup_schedule import load_schedule_map

    # include_missing: настроенный, но ни разу не собранный путь должен быть
    # красным квадратом, а не отсутствовать на карте вместе со всем сервером
    rows = get_latest_backup_metrics(include_missing=True)
    if not rows:
        raise ValueError("Нет данных о бэкапах")

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    schedule_map = load_schedule_map()
    by_server = defaultdict(list)
    for row in sorted(rows, key=lambda r: (r["backup_type"], r["backup_path"])):
        by_server[row["server_name"]].append(
            classify_backup_row(row, now_utc, schedule_map)
        )

    def sort_key(item):
        _, statuses = item
        return (-statuses.count("crit"), -statuses.count("warn"), item[0])

    ordered = sorted(by_server.items(), key=sort_key)
    max_cols = max(len(statuses) for _, statuses in ordered)
    status_color = {"ok": STATUS_GOOD, "warn": STATUS_WARN, "crit": STATUS_CRIT}

    fig_height = max(2.2, 0.55 * len(ordered) + 1.1)
    fig_width = max(8, min(16, 3 + max_cols * 0.55))
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    cell, gap = 0.82, 0.18
    for row_i, (name, statuses) in enumerate(ordered):
        y = len(ordered) - row_i - 1
        for col, status in enumerate(statuses):
            ax.add_patch(mpatches.Rectangle(
                (col, y), cell, cell,
                facecolor=status_color[status], edgecolor=SURFACE, linewidth=2
            ))
        ax.text(-0.3, y + cell / 2, name, ha="right", va="center",
                fontsize=10, color=INK, fontweight="bold")

    ax.set_xlim(-max(3.5, max_cols * 0.28), max_cols + gap)
    ax.set_ylim(-0.3, len(ordered) + 0.3)
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_title("Свежесть бэкапов по серверам", loc="left", fontsize=13,
                fontweight="bold", color=INK, pad=16)

    legend_items = [
        mpatches.Patch(color=STATUS_GOOD, label="Свежий (<24ч)"),
        mpatches.Patch(color=STATUS_WARN, label="Устарел (>24ч)"),
        mpatches.Patch(color=STATUS_CRIT, label="Пусто/ошибка"),
    ]
    legend = ax.legend(handles=legend_items, loc="upper right", frameon=False,
                       fontsize=9, bbox_to_anchor=(1.0, 1.18), ncol=3)
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)

    generated_at = datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M")
    fig.text(0.01, 0.01, f"AgentMonitor · сформировано {generated_at}",
             fontsize=8, color=INK_MUTED)
    fig.tight_layout(rect=(0, 0.02, 1, 0.94))

    return _save_figure(fig, "backup_freshness_")


def build_backup_volume_chart(days: int = 30) -> str:
    """Общий объём бэкапов по инфраструктуре во времени, стек по серверам.
    Показывает суммарный рост занятого места, не только по одному серверу.
    """
    from backup_bot_db import get_backup_volume_history

    rows = get_backup_volume_history(days)
    if not rows:
        raise ValueError(f"Нет истории объёма бэкапов за {days} дней")

    by_server = defaultdict(dict)
    all_days = sorted({row["day"] for row in rows})
    for row in rows:
        by_server[row["server_name"]][row["day"]] = float(row["total_gb"])

    # Не раздуваем стек: крупнейшие серверы отдельно, остальные — одной суммой
    totals_last = {
        name: days_map.get(all_days[-1], list(days_map.values())[-1])
        for name, days_map in by_server.items()
    }
    top_servers = sorted(totals_last, key=totals_last.get, reverse=True)[:BACKUP_VOLUME_MAX_SERVERS]
    rest_servers = [s for s in by_server if s not in top_servers]

    def series_for(name):
        days_map = by_server[name]
        vals = []
        last = 0.0
        for day in all_days:
            if day in days_map:
                last = days_map[day]
            vals.append(last)
        return vals

    labels, stacks, colors = [], [], []
    for i, name in enumerate(top_servers):
        labels.append(name)
        stacks.append(series_for(name))
        colors.append(SERIES[i % len(SERIES)])
    if rest_servers:
        rest_vals = [0.0] * len(all_days)
        for name in rest_servers:
            for i, v in enumerate(series_for(name)):
                rest_vals[i] += v
        labels.append(f"Остальные ({len(rest_servers)})")
        stacks.append(rest_vals)
        colors.append(INK_MUTED)

    times = [_to_local(datetime.combine(d, datetime.min.time())) for d in all_days]

    fig, ax = plt.subplots(figsize=(12, 5.5))
    fig.patch.set_facecolor(SURFACE)
    _style_axis(ax)

    ax.stackplot(times, *stacks, labels=labels, colors=colors, alpha=0.88,
                edgecolor=SURFACE, linewidth=0.6)

    total_now = sum(s[-1] for s in stacks)
    ax.set_title(f"Общий объём бэкапов по инфраструктуре · {round(total_now)} ГБ сейчас",
                loc="left", fontsize=13, fontweight="bold", color=INK)
    ax.set_ylabel("ГБ", color=INK_MUTED)
    _setup_time_axis(ax, days * 24)

    ymax = max(sum(vals) for vals in zip(*stacks)) if stacks else 1
    ax.set_ylim(0, ymax * 1.22)
    legend = ax.legend(loc="upper left", fontsize=9, frameon=False, ncol=3)
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)

    generated_at = datetime.now(ALMATY).strftime("%d.%m.%Y %H:%M")
    fig.text(0.01, 0.01, f"AgentMonitor · сформировано {generated_at}",
             fontsize=8, color=INK_MUTED)
    fig.tight_layout(rect=(0, 0.02, 1, 0.96))

    return _save_figure(fig, "backup_volume_")
