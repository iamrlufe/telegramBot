"""
shared/zimbra_log.py

Почтовый сервер Zimbra: кто отправляет, кто заходит, что не доставлено.

Два источника, и это не прихоть. Про входы postfix-лог не знает почти
ничего: люди работают через mailboxd (веб, IMAP, ActiveSync), а postfix
получает уже готовое письмо, и `sasl_username=` встречается там
редко — только когда почту сдают прямой SMTP-сессией. Кто и откуда заходил,
знает `/opt/zimbra/log/audit.log` — там `account=`, `oip=` и причина отказа.

Но редкость `sasl_username=` не делает его бесполезным: наоборот, его
ОТСУТСТВИЕ — единственное, чем входящее письмо отличается от отправленного.
Один и тот же smtpd принимает почту из интернета на 25-й порт и сдачу от
пользователя на 587-й, строка `client=` у них одинаковая, а отправитель в
конверте у входящего письма любой — свой домен подделывается свободно.
Правило, которое смотрит только на адрес, объявляет угнанной учёткой каждое
такое письмо.

Счёт писем — по уникальным `message-id`, а не по строкам `from=`. Одно
письмо проходит через амавис двумя очередями:

    pickup   88B25A009C: uid=0 from=<root>
    cleanup  88B25A009C: message-id=<X>
    qmgr     88B25A009C: from=<...>, nrcpt=1
    cleanup  F1216A0087: message-id=<X>        ← та же почта, новая очередь
    smtp     88B25A009C: ... status=sent (queued as F1216A0087)

На живом сервере это даёт троекратное расхождение: 15628 строк `from=`
против 5338 очередей и вдвое меньшего числа настоящих писем. Ключ
`message-id` не зависит от того, как настроен обвес: сменится топология —
счёт останется верным.

Считает сам сервер одним проходом awk: суточный mail.log это 25 МБ, и
тянуть его в бота незачем.
"""
import os

from linux_check import run_ssh
from settings import int_env

# Где искать. Первый существующий и непустой и берётся: на Zimbra
# /var/log/zimbra.log обычно пустышка, оставшаяся с установки, а живой лог —
# обычный mail.log. Пустой файл вместо живого означал бы отчёт «проблем нет»
# на пустом месте.
MAIL_LOGS = ("/var/log/mail.log", "/var/log/maillog", "/var/log/zimbra.log")
AUDIT_LOGS = ("/opt/zimbra/log/audit.log",)

# postqueue у Zimbra не в PATH: он лежит в своём префиксе, и у root его
# без полного пути нет. Отсюда «в очереди 0 писем» там, где их сотни.
POSTQUEUE_PATHS = ("/opt/zimbra/common/sbin/postqueue",
                   "/usr/sbin/postqueue", "postqueue")

# Сколько групп отдавать в каждом списке: сводка, а не выгрузка.
TOP = 20


# Порог всплеска отправки. Считается в письмах, а не в строках лога,
# поэтому число меньше привычного втрое.
SEND_ALERT = int_env("ZIMBRA_SEND_ALERT", 2000)

# Писем в очереди. Здоровая очередь на живом сервере — единицы.
QUEUE_ALERT = int_env("ZIMBRA_QUEUE_ALERT", 300)

# Неудачных входов с одного адреса за сутки.
AUTH_FAIL_ALERT = int_env("ZIMBRA_AUTH_FAIL_ALERT", 50)

# Разных адресов, с которых за сутки перебирают одну учётку.
#
# Порог по одному адресу обходится тривиально и обходится на практике: по
# одной попытке с полусотни адресов из разных стран не берёт ни одно
# правило, считающее пару «учётка + адрес». Признак здесь другой — не
# настойчивость с одного места, а сама разбросанность: живой человек,
# забывший пароль, ошибается со своего компьютера, а не из шести стран за
# ночь.
SPRAY_ADDRESSES_ALERT = int_env("ZIMBRA_SPRAY_ADDRESSES_ALERT", 3)

# Страна, из которой входы считаются штатными.
HOME_COUNTRY = os.getenv("ZIMBRA_HOME_COUNTRY", "KZ").strip().upper()

# Писем с подделанным своим отправителем за сутки, после которых стоит
# сказать вслух. Единичные приходят на любой сервер в интернете, и будить
# из-за них незачем; десятки означают, что адресами домена уже пользуются
# для фишинга по своим же сотрудникам.
SPOOF_ALERT = int_env("ZIMBRA_SPOOF_ALERT", 5)

# Отказов «отправитель запрещён» за сутки.
#
# Правило нужно там, где подделку своего домена режет сам Postfix: письмо с
# вашим доменом в конверте, пришедшее с чужого IP, отбивается на RCPT, и
# spoofed_senders замолкает — считать нечего, такие письма больше не
# доходят. Наблюдение при этом исчезать не должно, оно меняет источник:
# было «N писем подделки дошло», стало «N писем отбито по отправителю».
#
# Двадцать, а не полсотни: на живом сервере с включённой защитой таких
# отказов единицы в сутки, и порог в полсотни не сработал бы никогда.
SENDER_REJECT_ALERT = int_env("ZIMBRA_SENDER_REJECT_ALERT", 20)

# По этой подстроке узнаётся отказ по отправителю.
#
# Это текст Postfix ПО УМОЛЧАНИЮ для check_sender_access с действием REJECT
# без своего сообщения — то есть одинаковый у всех карт сразу: и у
# антиспуфинга своего домена, и у чёрного списка отправителей. Отличить их
# по логу нельзя, поэтому находка говорит «отправитель запрещён», а не
# «подделка»: врать в тексте тревоги нельзя, а причина отказа в ней есть.
#
# Разделить их можно только на сервере — дав своим записям собственное
# сообщение (`REJECT Spoofed sender of local domain`), и тогда подставить
# его сюда через .env. Пока этого нет, умолчание считает обе карты.
# Сравнение регистронезависимое: регистр в чужой формулировке не гарантирован.
SENDER_REJECT_MARK = os.getenv(
    "ZIMBRA_SENDER_REJECT_MARK", "sender address rejected").strip().lower()


def _reader(path: str) -> str:
    """Читалка файла с повышением прав, только если оно нужно.

    mail.log принадлежит syslog:adm, audit.log — zimbra:zimbra, и учётка
    мониторинга обычно не в этих группах. `sudo -n` не спрашивает пароль:
    если правила нет, команда честно падает, и текст ошибки скажет, чего
    не хватает, вместо пустого отчёта.
    """
    return (f'if [ -r "{path}" ]; then cat "{path}"; '
            f'else sudo -n cat "{path}"; fi')


def _pick_script(paths) -> str:
    """Первый существующий непустой файл из списка."""
    items = " ".join(f'"{p}"' for p in paths)
    return (f'for f in {items}; do '
            f'if [ -s "$f" ]; then echo "$f"; break; fi; done')


# ─── Разбор mail.log ─────────────────────────────────────────

# Awk без mktime и systime: на Ubuntu по умолчанию стоит mawk, а этих
# функций там нет — скрипт с ними падает на живом сервере, хотя локально
# на gawk проходит. Поэтому начало каждых суток окна считает shell (`date`)
# и передаёт таблицей, а awk только складывает часы, минуты и секунды.
#
# Метка syslog — «Aug 30 06:26:23», без года. Разбирать её в awk и гадать
# год не нужно: ключ «Aug 30» ищется в готовой таблице, и всё, чего в
# таблице нет, к окну не относится по определению.
_MAIL_AWK = r'''
function grab(line, key, endch,   p, q, s) {
  p = index(line, key); if (p == 0) return ""
  s = substr(line, p + length(key)); q = index(s, endch)
  if (q > 0) s = substr(s, 1, q - 1)
  return s
}
function short(s) { return length(s) > 90 ? substr(s, 1, 90) : s }
NR == FNR { p = index($0, "|"); day[substr($0, 1, p - 1)] = substr($0, p + 1); next }
{
  k = substr($0, 1, 6)
  if (!(k in day)) next
  split($3, t, ":")
  ts = day[k] + t[1] * 3600 + t[2] * 60 + t[3]
  if (ts < cut) next
  prog = $5; qid = $6; sub(/:$/, "", qid)

  # Откуда письмо попало в очередь. smtpd видит клиента, pickup — локальную
  # сдачу через sendmail (крон и системные письма).
  if (index(prog, "/smtpd[") && index($0, ": client=")) {
    c = grab($0, "client=", "]"); b = index(c, "[")
    qip[qid] = (b > 0 ? substr(c, b + 1) : c)
    # Без sasl_username это НЕ сдача письма, а приём его из интернета:
    # smtpd обслуживает и 25-й порт, и 587-й, и в логе они неразличимы
    # ничем другим. Отправитель в конверте при этом любой — подделать
    # свой же домен ничто не мешает.
    qauth[qid] = index($0, "sasl_username=") ? 1 : 0
  }
  else if (index(prog, "/pickup[") && index($0, "uid=")) qip[qid] = "local"

  else if (index(prog, "/cleanup[") && index($0, "message-id=<"))
    qmid[qid] = grab($0, "message-id=<", ">")

  # Единица счёта — письмо, а не строка: клеймим message-id первой же
  # очередью, а переинжект амависа приходит позже и ничего не подменяет.
  else if (index(prog, "/qmgr[") && index($0, "from=<")) {
    mid = qmid[qid]
    if (mid != "" && !(mid in claimed)) {
      claimed[mid] = 1
      f = grab($0, "from=<", ">"); if (f == "") f = "<>"
      n = grab($0, "nrcpt=", " ") + 0; if (n < 1) n = 1
      ip = qip[qid]; if (ip == "") ip = "local"
      sent[f] += 1; rcpt[f] += n; origin[f "\t" ip "\t" (qauth[qid] + 0)] += 1
      msgs += 1; rcpts += n
    }
  }

  if (index($0, "status=deferred")) {
    defer += 1
    r = grab($0, "said: ", "(")
    if (r == "") { r = grab($0, "status=deferred (", ")") }
    if (r != "") dreason[short(r)] += 1
    to = grab($0, "to=<", ">"); if (to != "") dto[to] += 1
  }
  else if (index($0, "status=bounced")) {
    bounce += 1
    to = grab($0, "to=<", ">"); if (to != "") bto[to] += 1
  }
  else if (index($0, "status=sent") && index(prog, "/lmtp[")) {
    to = grab($0, "to=<", ">"); a = index(to, "@")
    if (a > 0) ldom[substr(to, a + 1)] += 1
  }

  if (index($0, "NOQUEUE: reject")) {
    reject += 1
    # Причина лежит ПОСЛЕ адреса клиента, а первая «]: » в строке — это
    # конец «postfix/smtpd[30468]: ». Отсчёт от «reject: » снимает
    # неоднозначность.
    p = index($0, "reject: ")
    r = substr($0, p + 8)
    q = index(r, "]: "); if (q > 0) r = substr(r, q + 3)
    sc = index(r, ";"); if (sc > 0) r = substr(r, 1, sc - 1)
    # Адрес получателя выкидывается: с ним каждая строка уникальна, и
    # группировка по причинам рассыпается на тысячи строк по одной.
    lt = index(r, "<"); g = index(r, ">: ")
    if (lt > 0 && g > lt) r = substr(r, 1, lt - 1) substr(r, g + 3)
    gsub(/  +/, " ", r)
    if (r != "") rreason[short(r)] += 1
    c = grab($0, " from ", "]"); b = index(c, "[")
    if (b > 0) rip[substr(c, b + 1)] += 1
  }
}
END {
  printf "T\t%d\t%d\t%d\t%d\t%d\n", msgs, rcpts, defer, bounce, reject
  for (k in sent)    printf "S\t%s\t%d\t%d\n", k, sent[k], rcpt[k]
  for (k in origin)  printf "X\t%s\t%d\n", k, origin[k]
  for (k in dreason) printf "DF\t%s\t%d\n", k, dreason[k]
  for (k in dto)     printf "DR\t%s\t%d\n", k, dto[k]
  for (k in bto)     printf "BR\t%s\t%d\n", k, bto[k]
  for (k in rreason) printf "RJ\t%s\t%d\n", k, rreason[k]
  for (k in rip)     printf "RI\t%s\t%d\n", k, rip[k]
  for (k in ldom)    printf "LD\t%s\t%d\n", k, ldom[k]
}
'''


_MAIL_SH = r'''
set -u
rd() { if [ -r "$1" ]; then cat "$1"; else sudo -n cat "$1"; fi; }
LOG=""
for f in __LOGS__; do if [ -s "$f" ]; then LOG="$f"; break; fi; done
if [ -z "$LOG" ]; then printf 'ERR\tЛог почты не найден: __LOGS__\n'; exit 0; fi
if [ ! -r "$LOG" ] && ! sudo -n true 2>/dev/null; then
  printf 'ERR\tНет прав на чтение %s. Добавь учётку в группу adm или разреши sudo -n cat\n' "$LOG"; exit 0
fi
printf 'LOG\t%s\n' "$LOG"
CUT=$(date -d "-__HOURS__ hours" +%s)
TMP=$(mktemp)
i=0
while [ "$i" -lt __DAYS__ ]; do
  printf '%s|%s\n' "$(date -d "-$i day" '+%b %e')" \
                   "$(date -d "$(date -d "-$i day" '+%Y-%m-%d') 00:00:00" +%s)"
  i=$((i + 1))
done > "$TMP"
FILES="$LOG"
if [ -f "$LOG.1" ] && [ "$(date -r "$LOG.1" +%s)" -gt "$CUT" ]; then FILES="$LOG.1 $LOG"; fi
Q=""
for q in __POSTQUEUE__; do
  if [ -x "$q" ] || command -v "$q" >/dev/null 2>&1; then
    Q=$( { "$q" -p 2>/dev/null || sudo -n "$q" -p 2>/dev/null; } | tail -1 \
         | sed -n 's/.* in \([0-9][0-9]*\) Request.*/\1/p' )
    if [ -n "$Q" ]; then break; fi
    if { "$q" -p 2>/dev/null || sudo -n "$q" -p 2>/dev/null; } | grep -q "is empty"; then Q=0; break; fi
  fi
done
printf 'Q\t%s\n' "${Q:-?}"
for f in $FILES; do rd "$f"; done | awk -v cut="$CUT" '__AWK__' "$TMP" -
rm -f "$TMP"
'''


def _mail_script(hours: int, logs=MAIL_LOGS) -> str:
    return (_MAIL_SH
            .replace("__LOGS__", " ".join(logs))
            .replace("__HOURS__", str(int(hours)))
            .replace("__DAYS__", str(int(hours) // 24 + 2))
            .replace("__POSTQUEUE__", " ".join(POSTQUEUE_PATHS))
            .replace("__AWK__", _MAIL_AWK))


def _rows(text: str) -> dict:
    """Помеченные строки вывода → словарь списков.

    Формат плоский намеренно: собирать JSON в awk — это ручное
    экранирование кавычек в адресах и текстах ошибок SMTP, где кавычки как
    раз встречаются.
    """
    out = {}
    for line in (text or "").splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 2:
            continue
        out.setdefault(parts[0], []).append(parts[1:])
    return out


def _top(rows, key_parts: int = 1, limit: int = TOP) -> list:
    """[(ключи…, число)] по убыванию."""
    items = []
    for row in rows or []:
        if len(row) < key_parts + 1:
            continue
        try:
            count = int(row[key_parts])
        except ValueError:
            continue
        items.append((row[:key_parts], count))
    items.sort(key=lambda i: -i[1])
    return items[:limit]


def _senders(rows) -> list:
    """[{sender, messages, recipients}] по убыванию писем.

    Получателей отдельной колонкой: письмо на пятьдесят адресов и
    пятьдесят писем — разные вещи, а по числу писем они неотличимы.
    """
    out = []
    for row in rows or []:
        if len(row) < 3:
            continue
        try:
            out.append({"sender": row[0], "messages": int(row[1]),
                        "recipients": int(row[2])})
        except ValueError:
            continue
    out.sort(key=lambda i: -i["messages"])
    return out[:TOP]


def read_mail(server: dict, hours: int = 24) -> dict:
    """Сводка mail.log за окно. Возвращает счётчики, а не строки."""
    output = run_ssh(
        server["host"], _mail_script(hours, _log_paths(server)),
        server.get("username"), server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
        timeout=300,
    )
    rows = _rows(output)
    if rows.get("ERR"):
        raise Exception(rows["ERR"][0][0])

    totals = (rows.get("T") or [["0", "0", "0", "0", "0"]])[0]
    queue = (rows.get("Q") or [["?"]])[0][0]
    return {
        "log": (rows.get("LOG") or [[""]])[0][0],
        "queue": int(queue) if str(queue).isdigit() else None,
        "messages": int(totals[0]), "recipients": int(totals[1]),
        "deferred": int(totals[2]), "bounced": int(totals[3]),
        "rejected": int(totals[4]),
        "senders": _senders(rows.get("S")),
        "origins": _top(rows.get("X"), 3, limit=200),
        "defer_reasons": _top(rows.get("DF"), 1),
        "defer_to": _top(rows.get("DR"), 1),
        "bounce_to": _top(rows.get("BR"), 1),
        "reject_reasons": _top(rows.get("RJ"), 1),
        "reject_ips": _top(rows.get("RI"), 1),
        "local_domains": [row[0][0] for row in _top(rows.get("LD"), 1, 50)],
    }


def _log_paths(server: dict, key: str = "mail_log", default=MAIL_LOGS):
    """Путь из конфига, если задан. Иначе — обычные места по порядку."""
    own = (server.get(key) or "").strip()
    return (own,) + tuple(default) if own else tuple(default)


# ─── Разбор audit.log ────────────────────────────────────────

# Здесь метка времени в ISO («2026-09-01 00:15:45,087»), поэтому окно
# режется обычным сравнением строк: ISO сортируется лексикографически, и
# ни mktime, ни таблицы суток не нужны.
#
# Ротация суточная, в 02:50, поэтому последние 24 часа почти всегда лежат в
# двух файлах: текущем и вчерашнем .gz. Читать только текущий значит терять
# всю ночь — ровно то время, когда идёт подбор пароля.
_AUDIT_AWK = r'''
function grab(line, key, endch,   p, q, s) {
  p = index(line, key); if (p == 0) return ""
  s = substr(line, p + length(key)); q = index(s, endch)
  if (q > 0) s = substr(s, 1, q - 1)
  return s
}
{
  if (substr($0, 1, 19) < cut) next
  if (index($0, "cmd=Auth") == 0) next
  acct = grab($0, "account=", ";")
  if (acct == "") acct = grab($0, "name=", ";")
  if (acct == "") next
  ip = grab($0, "oip=", ";")
  if (ip == "") ip = "?"
  # protocol= у этих записей почти всегда soap: mailboxd проверяет пароль
  # своим внутренним SOAP, кто бы ни спрашивал. Настоящий протокол клиента
  # лежит в oproto= — он появляется, когда пароль проверяют для SMTP или
  # IMAP-сессии, и именно он отвечает на вопрос «чем ломятся».
  proto = grab($0, "oproto=", ";")
  if (proto == "") proto = grab($0, "protocol=", ";")
  if (proto == "") proto = "?"
  # Админ-консоль — это 7071. Путь /service/admin/ сам по себе админ-входом
  # не делает: по нему же на 7073 идёт проверка пароля SMTP и IMAP, и
  # перебор паролей к ящикам выглядел из-за этого попыткой влезть в
  # админку — то есть тревога называла не то, что происходило.
  if (index($0, ":7071/service/admin/")) proto = proto "/admin"
  ok = index($0, "error=") ? 0 : 1
  k = acct "\t" ip "\t" proto "\t" ok
  n[k] += 1
  when = substr($0, 1, 19)
  if (when > last[k]) last[k] = when
  if (ok) { good += 1 } else { bad += 1 }
}
END {
  printf "T\t%d\t%d\n", good, bad
  for (k in n) printf "A\t%s\t%d\t%s\n", k, n[k], last[k]
}
'''

_AUDIT_SH = r'''
set -u
rd() {
  case "$1" in
    *.gz) if [ -r "$1" ]; then zcat "$1"; else sudo -n zcat "$1"; fi ;;
    *)    if [ -r "$1" ]; then cat "$1";  else sudo -n cat "$1";  fi ;;
  esac
}
LOG=""
for f in __LOGS__; do if [ -s "$f" ]; then LOG="$f"; break; fi; done
if [ -z "$LOG" ]; then printf 'ERR\tЖурнал входов Zimbra не найден: __LOGS__\n'; exit 0; fi
if [ ! -r "$LOG" ] && ! sudo -n true 2>/dev/null; then
  printf 'ERR\tНет прав на чтение %s. Нужна группа zimbra или sudo -n cat\n' "$LOG"; exit 0
fi
printf 'LOG\t%s\n' "$LOG"
CUT=$(date -d "-__HOURS__ hours" '+%Y-%m-%d %H:%M:%S')
FILES=""
i=1
while [ "$i" -le __DAYS__ ]; do
  g="$LOG.$(date -d "-$i day" '+%Y-%m-%d').gz"
  if [ -f "$g" ]; then FILES="$FILES $g"; fi
  i=$((i + 1))
done
FILES="$FILES $LOG"
for f in $FILES; do rd "$f"; done | awk -v cut="$CUT" '__AWK__'
'''


def _audit_script(hours: int, logs=AUDIT_LOGS) -> str:
    return (_AUDIT_SH
            .replace("__LOGS__", " ".join(logs))
            .replace("__HOURS__", str(int(hours)))
            .replace("__DAYS__", str(int(hours) // 24 + 1))
            .replace("__AWK__", _AUDIT_AWK))


def read_audit(server: dict, hours: int = 24) -> dict:
    """Входы в почту: учётка, адрес, протокол, успех, когда последний раз."""
    output = run_ssh(
        server["host"], _audit_script(hours, _log_paths(server, "audit_log",
                                                        AUDIT_LOGS)),
        server.get("username"), server.get("password"),
        port=int(server.get("ssh_port") or 22),
        key_path=server.get("ssh_key"),
        timeout=180,
    )
    rows = _rows(output)
    if rows.get("ERR"):
        raise Exception(rows["ERR"][0][0])

    totals = (rows.get("T") or [["0", "0"]])[0]
    events = []
    for row in rows.get("A") or []:
        if len(row) < 6:
            continue
        account, ip, proto, ok, count, last = row[:6]
        events.append({"account": account, "ip": ip, "protocol": proto,
                       "ok": ok == "1", "count": int(count), "last": last})
    events.sort(key=lambda e: -e["count"])
    return {
        "log": (rows.get("LOG") or [[""]])[0][0],
        "ok": int(totals[0]), "failed": int(totals[1]),
        "events": events,
    }


# ─── Правила ─────────────────────────────────────────────────

# Отправка через mailboxd приходит в postfix с петли, локальная сдача
# (крон, системные письма) — через pickup. И то и другое — «через веб» в
# том смысле, что письмо родилось на самом сервере.
WEB_ORIGINS = ("local", "127.0.0.1", "::1", "localhost")


def origin_kind(ip: str, authed: bool = False) -> str:
    """Откуда письмо попало в очередь: web | inside | outside | incoming.

    Разделение задано тем, как здесь работают: все пользователи пишут через
    веб, и только несколько учёток сдают почту напрямую — с внутренних
    узлов.

    Белый адрес сам по себе ничего не значит, и это стоило ложных тревог.
    Postfix обслуживает одним и тем же smtpd и сдачу письма пользователем
    (587-й порт), и приём почты из интернета (25-й), а в логе строка
    `client=` у них одинаковая. Отличает их только `sasl_username=`:
    сессия без него — не отправка, а входящее письмо, и адрес отправителя
    в конверте там любой, какой захотел приславший.

    Поэтому по умолчанию `authed=False`: неаутентифицированная сессия с
    белого адреса — это `incoming`, обычная входящая почта. Тревоги стоит
    только `outside` — сдача письма снаружи по паролю.
    """
    from geoip import is_private

    address = (ip or "").strip().lower()
    if address in WEB_ORIGINS:
        return "web"
    if is_private(address):
        return "inside"
    return "outside" if authed else "incoming"


def local_domain(address: str, domains) -> bool:
    at = (address or "").rfind("@")
    return at > 0 and address[at + 1:].lower() in {d.lower() for d in domains or []}


def letters(count: int) -> str:
    """«1 письмо», «2 письма», «5 писем».

    Мелочь, но находка с «1 писем» читается как недоделка и подрывает
    доверие к остальному тексту тревоги.
    """
    tail = count % 100
    if 11 <= tail <= 14:
        return f"{count} писем"
    last = count % 10
    if last == 1:
        return f"{count} письмо"
    if 2 <= last <= 4:
        return f"{count} письма"
    return f"{count} писем"


def attempts(count: int) -> str:
    """«1 попытка», «3 попытки», «5 попыток». Третья пара к letters()."""
    tail = count % 100
    if 11 <= tail <= 14:
        return f"{count} попыток"
    last = count % 10
    if last == 1:
        return f"{count} попытка"
    if 2 <= last <= 4:
        return f"{count} попытки"
    return f"{count} попыток"


def addresses(count: int) -> str:
    """«1 адрес», «2 адреса», «5 адресов». Пара к letters().

    В сводке стояло «на 22 адресов» — та же мелочь, что и «1 писем».
    """
    tail = count % 100
    if 11 <= tail <= 14:
        return f"{count} адресов"
    last = count % 10
    if last == 1:
        return f"{count} адрес"
    if 2 <= last <= 4:
        return f"{count} адреса"
    return f"{count} адресов"


# Отправители, за которыми нет человека. `<>` — пустой конверт: так postfix
# шлёт отчёты о недоставке, и в сводке эта строка стабильно входила в топ,
# занимая место живого отправителя. Остальные три — служебные ящики самой
# почты, писать из них человек не может.
SERVICE_SENDERS = ("<>", "mailer-daemon@", "double-bounce@", "postmaster@")


def is_service_sender(sender: str) -> bool:
    """Отправитель — служба, а не человек.

    Скрывается только из обзора на дашборде: там пятнадцать строк, и каждая
    занятая служебной рассылкой — минус один живой отправитель. В карточке
    бота (📤 Отправители) список остаётся полным, там и место есть, и
    отчёты о недоставке иногда как раз то, что ищут.
    """
    value = (sender or "").strip().lower()
    if not value:
        return True
    return value == "<>" or value.startswith(SERVICE_SENDERS[1:])


def split_senders(senders, origins, local_domains) -> dict:
    """Разделяет отправителей на своих и внешних: {"own": [...], "incoming": [...]}.

    Postfix считает всех, кто прошёл через сервер, поэтому в одном списке
    оказывались сотрудники и уведомления внешних сервисов — банки, налоговая,
    доски вакансий. Раздел назывался «Кто отправляет», а показывал «кто
    вообще слал почту через сервер», и первые строки топа стабильно
    занимали чужие рассылки.

    Разделение по адресу отправителя было бы наивным: свой домен в конверте
    подделывается свободно, и спам, притворяющийся вашим сотрудником, попал
    бы к своим. Поэтому «свой» — это адрес вашего домена И происхождение, не
    равное `incoming`: письмо родилось на сервере (веб) или сдано изнутри
    по паролю. Всё остальное — входящее, включая подделку.

    Отправитель, которого нет в origins вовсе (строка сдачи не попала в
    окно), решается по домену: это лучше, чем терять его из обоих списков.
    """
    kinds = {}
    for sender, ip, authed, _count in _origin_rows(origins):
        kinds.setdefault(sender, set()).add(origin_kind(ip, authed))

    own, incoming = [], []
    for item in senders or []:
        sender = item.get("sender") or ""
        seen = kinds.get(sender)
        mine = local_domain(sender, local_domains)
        if seen is not None:
            mine = mine and bool(seen - {"incoming"})
        (own if mine else incoming).append(item)
    return {"own": own, "incoming": incoming}


# Сколько разных учёток за одним внутренним адресом означает, что это не
# рабочее место, а общий выход сети наружу — маршрутизатор, прокси, шлюз.
# За рабочим местом сидит один человек, изредка двое.
GATEWAY_MIN_ACCOUNTS = int_env("ZIMBRA_GATEWAY_MIN_ACCOUNTS", 3)


def shared_gateways(events, min_accounts: int = None) -> set:
    """Внутренние адреса, за которыми стоит не человек, а выход целой сети.

    Zimbra пишет в audit.log адрес, с которого пришло соединение. Если
    пользователи ходят в почту через маршрутизатор, все они приходят с его
    адреса — и внешний сотрудник, и сидящий в соседней комнате выглядят
    одинаково, как «локальная сеть». Считать такой вход внутренним нельзя:
    настоящий адрес клиента до сервера просто не доезжает.

    Отличить шлюз от рабочего места по логу можно только так — по числу
    разных учёток за одним адресом.

    Честный вывод отсюда — не «все входы внутренние», а «адрес клиента не
    виден». Это разные утверждения, и второе не даёт повода успокоиться.
    """
    limit = GATEWAY_MIN_ACCOUNTS if min_accounts is None else min_accounts
    from geoip import is_private

    accounts = {}
    for event in events or []:
        ip = (event.get("ip") or "").strip()
        if not is_private(ip):
            continue
        accounts.setdefault(ip, set()).add(event.get("account") or "")
    return {ip for ip, names in accounts.items() if len(names) >= limit}


def is_local_login(event, gateways=()) -> bool:
    """Вход с рабочего места в локальной сети — такой из обзора убирается.

    Вход через шлюз (gateways) сюда НЕ попадает: за ним может стоять
    человек снаружи, и прятать его — значит прятать ровно то, ради чего
    раздел существует.

    Полный список входов, включая внутренние, никуда не делся: он в
    карточке сервера в боте, 🔑 Входы в почту.
    """
    from geoip import is_private

    ip = (event.get("ip") or "").strip()
    return is_private(ip) and ip not in set(gateways or ())


def _origin_rows(origins):
    """Строки происхождения в едином виде: (отправитель, адрес, вход был)."""
    for key, count in origins or []:
        sender, ip = key[0], key[1]
        authed = len(key) > 2 and str(key[2]) == "1"
        yield sender, ip, authed, count


def outside_senders(origins, local_domains) -> list:
    """Свои адреса, письма от которых СДАНЫ с белого IP по паролю.

    Ради этого правила и разбирается происхождение письма: угнанную учётку
    видно ровно так — почта от своего адреса, сдана снаружи, и сдана после
    аутентификации.

    Последнее условие появилось не сразу, и без него правило кричало на
    обычный спам: письмо от подделанного своего адреса приходит из
    интернета через тот же smtpd, и от настоящей отправки в логе оно
    отличается только отсутствием `sasl_username=`. Такие письма теперь
    считает spoofed_senders.
    """
    found = []
    for sender, ip, authed, count in _origin_rows(origins):
        if not local_domain(sender, local_domains):
            continue
        if origin_kind(ip, authed) != "outside":
            continue
        found.append({"sender": sender, "ip": ip, "count": count})
    found.sort(key=lambda i: -i["count"])
    return found


def spoofed_senders(origins, local_domains) -> dict:
    """Письма от своих адресов, пришедшие снаружи БЕЗ аутентификации.

    Это не угнанные учётки, а подделка отправителя: кто угодно в интернете
    может написать в конверте ваш адрес. Само по себе явление обычное, но
    знать о нём стоит по двум причинам: письмо от «коллеги» убедительнее
    любого другого фишинга, и сам факт, что такие письма доходят, означает
    что SPF/DMARC их не отбраковывают.

    Отдаётся одной сводкой, а не находкой на письмо: девять писем за сутки
    от девяти учёток — это девять одинаковых тревог и ноль пользы.
    """
    senders, addresses, total = set(), set(), 0
    for sender, ip, authed, count in _origin_rows(origins):
        if not local_domain(sender, local_domains):
            continue
        if origin_kind(ip, authed) != "incoming":
            continue
        senders.add(sender)
        addresses.add(ip)
        total += count
    return {"messages": total, "senders": sorted(senders),
            "ips": sorted(addresses)}


def sender_rejects(reject_reasons) -> dict:
    """Отказы «отправитель запрещён» за окно: сколько и с какими причинами.

    Это продолжение spoofed_senders для серверов, где подделку своего домена
    режет сам Postfix. Там правило считает дошедшие письма, здесь — отбитые
    попытки; вместе они покрывают обе настройки, и включение защиты не
    оставляет наблюдение слепым.

    С умолчанием SENDER_REJECT_MARK сюда попадают и отказы чёрного списка:
    текст в логе у них один и тот же, стандартный. Это не ошибка счёта, а
    предел того, что вообще видно из лога, — потому и в тексте находки
    сказано «отправитель запрещён», а не «подделка».

    Адресов источника здесь нет и быть не может: awk считает reject-IP по
    всем отказам сразу, а не по каждой причине, и приписать их этой
    конкретной означало бы соврать. Кто именно долбится, видно на экране
    «🚫 Отбито на входе».
    """
    total = 0
    reasons = []
    for parts, count in reject_reasons or []:
        reason = (parts[0] if parts else "").strip()
        if SENDER_REJECT_MARK not in reason.lower():
            continue
        total += count
        reasons.append({"reason": reason, "count": count})
    reasons.sort(key=lambda i: -i["count"])
    return {"messages": total, "reasons": reasons}


def is_service_login(event) -> bool:
    """Вход самого сервера, а не человека.

    У служебных обращений (zmconfigd, zmmailboxdmgr, проверки состояния)
    в audit.log нет `oip=` — обращение идёт с самой машины, — и парсер
    ставит «?». Такая запись честно попадает в топ по числу входов и
    вытесняет из обзора живого пользователя: одна учётка `zimbra` с
    админ-протоколом набирает за сутки больше, чем любой человек.

    Скрывается только из обзора успешных входов. Неудачные остаются: вход
    без адреса, который НЕ удался, — это уже не фоновая служба, а сломанный
    служебный пароль, и знать о нём нужно.
    """
    return (event.get("ip") or "?").strip() in ("", "?")


def foreign_logins(events, geo_codes, home: str = None) -> list:
    """Удачные входы не из домашней страны.

    Только удачные: неудачная попытка из-за границы — это перебор, у него
    своё правило. Удачный вход оттуда означает, что пароль уже знают.
    """
    home = (home or HOME_COUNTRY).upper()
    found = []
    for event in events or []:
        if not event.get("ok"):
            continue
        code = (geo_codes or {}).get(event["ip"], "")
        if not code or code.upper() == home:
            continue
        found.append(dict(event, country=code.upper()))
    found.sort(key=lambda e: -e["count"])
    return found


def brute_force(events, threshold: int = None) -> list:
    """Подбор пароля: неудачные попытки с одного адреса на одну учётку.

    Успешные входы с того же адреса учитываются: если человек в итоге
    вошёл, это забытый пароль, а не подбор.
    """
    threshold = threshold or AUTH_FAIL_ALERT
    good = {(e["account"], e["ip"]) for e in events or [] if e.get("ok")}
    found = []
    for event in events or []:
        if event.get("ok") or event["count"] < threshold:
            continue
        key = (event["account"], event["ip"])
        found.append(dict(event, guessed=key in good,
                          admin="/admin" in event.get("protocol", "")))
    found.sort(key=lambda e: -e["count"])
    return found


def spray_targets(events, min_addresses: int = None, skip=()) -> list:
    """Учётки, пароль к которым перебирают сразу с нескольких адресов.

    Дополняет brute_force, а не заменяет: то правило ловит настойчивость с
    одного адреса, это — разбросанность по многим. Вместе они закрывают обе
    формы перебора, поодиночке — ни одной полностью.

    skip — учётки, о которых уже сказал brute_force: две тревоги об одном и
    том же не добавляют знания.

    guessed повторяет логику соседнего правила: если с одного из тех же
    адресов вход в итоге удался, пароль подобран, и это уже не попытка.
    """
    limit = SPRAY_ADDRESSES_ALERT if min_addresses is None else min_addresses
    good = {(e["account"], e["ip"]) for e in events or [] if e.get("ok")}

    by_account = {}
    for event in events or []:
        if event.get("ok") or event.get("account") in set(skip or ()):
            continue
        item = by_account.setdefault(event["account"], {
            "account": event["account"], "count": 0,
            "addresses": set(), "protocols": set(), "guessed": False,
        })
        item["count"] += event.get("count") or 0
        item["addresses"].add(event.get("ip"))
        if event.get("protocol"):
            item["protocols"].add(event["protocol"])
        if (event["account"], event.get("ip")) in good:
            item["guessed"] = True

    found = [dict(item, addresses=sorted(item["addresses"]),
                  protocols=sorted(item["protocols"]))
             for item in by_account.values()
             if len(item["addresses"]) >= limit]
    found.sort(key=lambda i: (-len(i["addresses"]), -i["count"]))
    return found


def heavy_senders(senders, threshold: int = None) -> list:
    """Всплеск отправки. Порог в письмах, а не в строках лога: со строками
    он молча означал бы втрое меньше."""
    threshold = threshold or SEND_ALERT
    return [item for item in senders or []
            if item.get("messages", 0) >= threshold]


def has_zimbra(server: dict) -> bool:
    """Почтовый сервер: явный флаг zimbra или служба zimbra/postfix.

    Тот же принцип, что у Exchange: флаг не обязателен, если состав служб
    и так однозначен.
    """
    from server_check import server_type

    if server_type(server) != "linux":
        return False
    if server.get("zimbra"):
        return True
    services = {str(s).lower() for s in (server.get("services") or [])}
    return bool(services & {"zimbra", "postfix", "zmconfigd"})
