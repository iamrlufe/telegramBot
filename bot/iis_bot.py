"""
bot/iis_bot.py

Раздел «🌐 IIS» в карточке сервера: сканирование извне, вход в 1С, ошибки,
медленные запросы, публикации, HTTPERR.

В отличие от 📜 Логов Windows и 🗄 SQL-логов здесь ничего не читается по
нажатию: суточный лог публикации — полмиллиона строк, ждать столько нельзя.
Данные берутся готовыми из базы, их дочитывает монитор по смещению раз в
IIS_SCAN_MINUTES. Отсюда и разница в поведении: раздел открывается мгновенно,
но показывает состояние на момент последнего сбора, а не «прямо сейчас».

Кнопка появляется у серверов, где среди `services` есть W3SVC.
"""
import itertools
from collections import OrderedDict

from telegram import InlineKeyboardMarkup, InlineKeyboardButton

from iis_log import detect_brute_force
from iis_store import read_events, read_facts
from tg_utils import safe_edit_message

IIS_TOKENS: "OrderedDict[str, tuple]" = OrderedDict()
IIS_TOKENS_MAX = 500
_SEQ = itertools.count(1)

PERIOD_SHORT_HOURS = 24
PERIOD_LONG_HOURS = 24 * 7

# Строк на экран: Telegram режет длинное сообщение, а глазами читают верхушку.
SHOW_LIMIT = 15

IIS_SERVICE = "w3svc"


def iis_token(server_name: str, hours: int) -> str:
    token = f"i{next(_SEQ)}"
    IIS_TOKENS[token] = (server_name, hours)
    while len(IIS_TOKENS) > IIS_TOKENS_MAX:
        IIS_TOKENS.popitem(last=False)
    return token


def has_iis(server: dict) -> bool:
    services = [str(s).lower() for s in (server.get("services") or [])]
    return IIS_SERVICE in services


def period_name(hours: int) -> str:
    return "24 часа" if hours <= PERIOD_SHORT_HOURS else "7 дней"


def iis_menu_kb(server_name: str, hours: int) -> InlineKeyboardMarkup:
    def cb(section: str) -> str:
        return f"iis_{section}:{iis_token(server_name, hours)}"

    other = PERIOD_LONG_HOURS if hours <= PERIOD_SHORT_HOURS else PERIOD_SHORT_HOURS
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔎 Сканирование", callback_data=cb("scan")),
            InlineKeyboardButton("🔑 Вход в 1С", callback_data=cb("login")),
        ],
        [
            InlineKeyboardButton("💥 Ошибки 5xx", callback_data=cb("errors")),
            InlineKeyboardButton("🐢 Медленные", callback_data=cb("slow")),
        ],
        [
            InlineKeyboardButton("📚 Публикации", callback_data=cb("pubs")),
            InlineKeyboardButton("🚧 HTTPERR", callback_data=cb("herr")),
        ],
        [InlineKeyboardButton(
            f"🕒 Период: {period_name(other)}",
            callback_data=f"iis_menu:{iis_token(server_name, other)}",
        )],
        [InlineKeyboardButton("⬅️ Назад", callback_data=f"server:{server_name}")],
    ])


# ─── Разбор данных ───────────────────────────────────────────

def _rows(events: dict, category: str, parts: int = 1) -> list:
    out = []
    for row in events.get(category) or []:
        chunks = str(row["item"]).split("|")
        chunks += [""] * (parts - len(chunks))
        out.append((chunks[:parts], row["count"]))
    return out


def _total(events: dict, name: str) -> int:
    for row in events.get("total") or []:
        if row["item"] == name:
            return row["count"]
    return 0


def _empty(title: str, hours: int) -> str:
    return (f"{title} за {period_name(hours)}\n\n"
            "Данных нет. Монитор дочитывает логи IIS раз в час — если сервер "
            "добавили только что, загляните после следующего цикла.")


# ─── Разделы ─────────────────────────────────────────────────

def format_scan(events: dict, hours: int) -> str:
    alien = _total(events, "alien")
    hits = _rows(events, "hit", 4)
    scan = _rows(events, "scan", 2)
    if not alien and not scan:
        return _empty("🔎 Сканирование извне", hours)

    lines = [f"🔎 Сканирование извне за {period_name(hours)}",
             f"Посторонних запросов: {alien} · адресов: {len(scan)}", ""]
    if hits:
        lines.append("🔴 СЕРВЕР ОТВЕТИЛ УСПЕХОМ — разобрать вручную:")
        for (status, uri, ip, ua), count in hits[:SHOW_LIMIT]:
            lines.append(f"{status} {uri}")
            lines.append(f"   ← {ip} · {ua} · {count} раз")
        lines.append("")
    else:
        lines.append("✅ Успешных ответов на посторонние пути нет.")
        lines.append("Ответы 200 на «/» и 301 с порта 80 сюда не считаются: "
                     "это стартовая страница IIS и редирект на HTTPS, они "
                     "отдаются на любой путь.")
        lines.append("")

    lines.append("Кто стучится:")
    for (ip, ua), count in scan[:SHOW_LIMIT]:
        lines.append(f"{count:>6}  {ip}  {ua or '—'}")
    return "\n".join(lines)


def format_login(events: dict, hours: int, brute: list = None) -> str:
    logins = _rows(events, "login", 2)
    if not logins:
        return _empty("🔑 Вход в 1С", hours)

    total = sum(count for _parts, count in logins)
    lines = [f"🔑 Вход в 1С за {period_name(hours)}",
             f"Входов: {total} · адресов: {len(logins)}",
             "Платформа отвечает 402 на /<база>/e1cib/login — по этим "
             "ответам и виден подбор пароля.", ""]

    for item in brute or []:
        mark = "🟠" if item["working"] else "🔴"
        lines.append(f"{mark} {item['ip']} → {item['base']}: "
                     f"{item['count']} входов за час")
        lines.append("   адрес работает в базе — похоже на клиента, который "
                     "переподключается по кругу"
                     if item["working"] else
                     "   с адреса идут только входы и ничего больше — "
                     "это подбор пароля")
    if brute:
        lines.append("")

    for (base, ip), count in logins[:SHOW_LIMIT]:
        lines.append(f"{count:>5}  {base}  ← {ip}")
    return "\n".join(lines)


def format_errors(events: dict, hours: int) -> str:
    errors = _rows(events, "error", 2)
    if not errors:
        return (f"💥 Ошибки 5xx за {period_name(hours)}\n\n"
                "Ошибок приложения нет.")

    total = sum(count for _parts, count in errors)
    lines = [f"💥 Ошибки 5xx за {period_name(hours)} — {total}",
             "Это ошибки самого приложения, а не IIS.", ""]
    for (uri, ip), count in errors[:SHOW_LIMIT]:
        lines.append(f"{count:>4}  {uri}")
        lines.append(f"      ← {ip}")
    return "\n".join(lines)


def format_slow(events: dict, hours: int) -> str:
    slow = _total(events, "slow")
    rows = _rows(events, "slowuri", 2)
    if not rows:
        return (f"🐢 Медленные запросы за {period_name(hours)}\n\n"
                "Запросов дольше порога нет.")

    lines = [f"🐢 Медленные запросы за {period_name(hours)} — {slow}", ""]
    for (uri, ip), count in rows[:SHOW_LIMIT]:
        lines.append(f"{count:>4}  {uri}")
        lines.append(f"      ← {ip}")
    return "\n".join(lines)


def format_pubs(events: dict, facts: dict, hours: int) -> str:
    pubs = _rows(events, "pub", 1)
    apps = [str(a.get("p") or "").strip("/") for a in (facts.get("apps") or [])]
    seen = {parts[0].lower() for parts, _count in pubs}
    dead = sorted(a for a in apps if a and a.lower() not in seen)

    lines = [f"📚 Публикации за {period_name(hours)}",
             f"Всего в конфигурации: {len(apps)} · с трафиком: {len(pubs)}", ""]
    for parts, count in pubs[:SHOW_LIMIT]:
        lines.append(f"{count:>8}  {parts[0]}")

    if dead:
        lines.append("")
        lines.append(f"🔴 Без трафика: {len(dead)}")
        lines.append("Каждая такая публикация — открытая наружу точка входа "
                     "без присмотра.")
        lines.append(", ".join(dead))

    pools = facts.get("pools") or []
    if pools:
        lines.append("")
        lines.append("Пулы приложений:")
        for pool in pools:
            lines.append(f"   {pool.get('n')} — {pool.get('s')}")

    logs_mb = facts.get("logs_mb") or 0
    if logs_mb:
        lines.append("")
        lines.append(f"Каталог логов IIS: {logs_mb / 1024:.1f} ГБ"
                     + (f", старейший файл от {facts['oldest_log']}"
                        if facts.get("oldest_log") else ""))
    return "\n".join(lines)


HTTPERR_REASONS = {
    "Timer_ConnectionIdle": "штатное закрытие простаивающих соединений",
    "Verb": "несуществующий HTTP-метод — почерк сканеров",
    "URL": "неразбираемый запрос, например префейс HTTP/2",
    "Hostname": "обращение по адресу с неизвестным Host — сканер",
    "ClientCancel": "клиент оборвал запрос",
    "Client_Reset": "клиент сбросил соединение",
    "Connection_Dropped": "обрыв соединения — плохая связь у клиента",
    "Timer_MinBytesPerSecond": "клиент отдаёт данные медленнее порога",
    "QueueFull": "очередь пула переполнена — публикации недоступны",
    "AppOffline": "пул приложений остановлен",
    "Connections_Refused": "соединения отвергнуты http.sys",
}


def format_herr(events: dict, hours: int) -> str:
    reasons = _rows(events, "herr", 1)
    if not reasons:
        return _empty("🚧 HTTPERR", hours)

    lines = [f"🚧 HTTPERR за {period_name(hours)}",
             "Сюда попадает то, чего в логе сайта нет вовсе: запрос "
             "отбракован ещё до IIS.", ""]
    for parts, count in reasons[:SHOW_LIMIT]:
        note = HTTPERR_REASONS.get(parts[0], "")
        lines.append(f"{count:>6}  {parts[0]}")
        if note:
            lines.append(f"        {note}")

    details = _rows(events, "herrd", 4)
    if details:
        lines.append("")
        lines.append("Подробности (без штатного простоя соединений):")
        for (reason, method, uri, ip), count in details[:SHOW_LIMIT]:
            lines.append(f"{count:>4}  {reason} · {method} {uri}")
            lines.append(f"      ← {ip}")
    return "\n".join(lines)


SECTIONS = {
    "scan": format_scan,
    "login": format_login,
    "errors": format_errors,
    "slow": format_slow,
    "herr": format_herr,
}


# ─── Обработчик ──────────────────────────────────────────────

async def iis_callback(query, context):
    section, _, token = query.data[len("iis_"):].partition(":")

    state = IIS_TOKENS.get(token)
    if state is None:
        await query.message.reply_text(
            "Кнопка устарела (бот перезапускался). Откройте карточку сервера заново."
        )
        return
    server_name, hours = state

    if section == "menu":
        await safe_edit_message(
            query,
            f"🌐 IIS — {server_name}\nПериод: {period_name(hours)}\n\n"
            "Данные собирает монитор раз в час, читая логи по смещению.",
            reply_markup=iis_menu_kb(server_name, hours),
        )
        return

    if section not in SECTIONS and section != "pubs":
        return

    try:
        events = (read_events(hours) or {}).get(server_name, {})
        facts = (read_facts() or {}).get(server_name, {})
    except Exception as e:
        await safe_edit_message(
            query, f"⚠️ Сводка IIS недоступна: {e}",
            reply_markup=iis_menu_kb(server_name, hours))
        return

    if section == "pubs":
        text = format_pubs(events, facts, hours)
    elif section == "login":
        hour_events = {}
        try:
            hour_events = (read_events(1) or {}).get(server_name, {})
        except Exception:
            pass
        brute = detect_brute_force(
            [{"parts": parts, "count": count}
             for parts, count in _rows(hour_events, "login", 2)],
            [{"parts": parts, "count": count}
             for parts, count in _rows(hour_events, "ip", 1)],
        )
        text = format_login(events, hours, brute)
    else:
        text = SECTIONS[section](events, hours)

    await safe_edit_message(query, text,
                            reply_markup=iis_menu_kb(server_name, hours))
