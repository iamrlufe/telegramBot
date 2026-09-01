"""
bot/config_editor.py

Раздел ⚙️ Настройка: добавление и изменение серверов в config/servers.json
прямо из Telegram.

- Мастер добавления спрашивает все поля по очереди; обязательны только
  имя и host, остальное пропускается кнопкой «Пропустить» или ответом «-».
- Редактирование — поштучно: выбрал сервер → выбрал поле → прислал значение
  («-» очищает поле).
- Права: только пользователи из TELEGRAM_DELETE_USERS (те же, что могут
  удалять бэкапы).
- Запись атомарная (temp-файл + rename), предыдущая версия сохраняется
  в servers.json.bak.
"""
import asyncio
import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from telegram import InlineKeyboardMarkup, InlineKeyboardButton, Update
from telegram.ext import ContextTypes

from alerts_ack import active_acks, unack_alert
from onec_logs import ONEC_LOG_CRIT_GB, ONEC_LOG_WARN_GB
from tg_utils import safe_edit_message, load_muted, save_muted, mute_expired, split_message
from ping_tools import is_valid_host
from backup_bot import load_delete_user_ids, build_paginated_server_keyboard
from backup_schedule import (WEEKDAY_NAMES, path_schedule, weekday_label,
                             weekday_short)
import pg_admin
import audit

ALMATY = ZoneInfo("Asia/Almaty")

SERVERS_FILE = "/app/config/servers.json"
STATE_KEY = "cfg"          # context.user_data[STATE_KEY]
EDIT_SERVER_KEY = "cfg_edit_server"
SKIP_INPUTS = {"-", "—"}

TRUE_WORDS = {"да", "д", "yes", "y", "true", "1", "+"}
FALSE_WORDS = {"нет", "н", "no", "n", "false", "0"}


# ─── Права ───────────────────────────────────────────────────

def can_configure(user) -> bool:
    return bool(user) and user.id in load_delete_user_ids()


# ─── Файл конфигурации ───────────────────────────────────────

def load_config() -> list:
    with open(SERVERS_FILE) as f:
        return json.load(f)


def validate_config(servers) -> None:
    """Проверяет структуру конфига перед записью. Бросает ValueError с понятным
    сообщением — чтобы битый конфиг никогда не попал на диск и не уронил монитор."""
    if not isinstance(servers, list):
        raise ValueError("Конфиг должен быть списком серверов")

    seen_names = {}
    seen_hosts = {}
    for i, server in enumerate(servers, 1):
        if not isinstance(server, dict):
            raise ValueError(f"Запись #{i} не является объектом сервера")

        name = server.get("name")
        if not name or not str(name).strip():
            raise ValueError(f"Запись #{i}: не задано имя сервера")
        name = str(name)
        if ":" in name:
            raise ValueError(f"Имя «{name}» не должно содержать двоеточие")
        if name in seen_names:
            raise ValueError(f"Дублируется имя сервера: «{name}»")
        seen_names[name] = True

        host = server.get("host")
        if not host or not str(host).strip():
            raise ValueError(f"Сервер «{name}»: не задан host")
        host_key = str(host).strip().lower()
        if host_key in seen_hosts:
            raise ValueError(
                f"host «{host}» повторяется у серверов «{seen_hosts[host_key]}» и «{name}»"
            )
        seen_hosts[host_key] = name

        stype = server.get("type")
        if stype is not None and stype not in ("windows", "linux", "device", "vmware"):
            raise ValueError(f"Сервер «{name}»: тип «{stype}» неизвестен")

        if "services" in server and not isinstance(server["services"], list):
            raise ValueError(f"Сервер «{name}»: services должно быть списком")

        backups = server.get("backups")
        if backups is not None:
            if not isinstance(backups, dict):
                raise ValueError(f"Сервер «{name}»: backups должно быть объектом")
            for btype, paths in backups.items():
                if not isinstance(paths, (str, list, dict)):
                    raise ValueError(
                        f"Сервер «{name}»: backups.{btype} — строка, объект или список путей"
                    )
                plist = paths if isinstance(paths, list) else [paths]
                for p in plist:
                    if isinstance(p, str):
                        continue
                    if not isinstance(p, dict):
                        raise ValueError(
                            f"Сервер «{name}»: backups.{btype} — путь должен быть строкой "
                            f"или объектом {{path, alert_hours}}"
                        )
                    if not p.get("path"):
                        raise ValueError(
                            f"Сервер «{name}»: backups.{btype} — у объекта пути не задано path"
                        )
                    path_hours = p.get("alert_hours")
                    if path_hours is not None:
                        try:
                            path_hours = int(path_hours)
                        except (TypeError, ValueError):
                            raise ValueError(
                                f"Сервер «{name}»: backups.{btype}.alert_hours должно быть числом"
                            )
                        if path_hours < 1 or path_hours > 720:
                            raise ValueError(
                                f"Сервер «{name}»: backups.{btype}.alert_hours должно быть от 1 до 720"
                            )
                    if "size_check" in p and not isinstance(p["size_check"], bool):
                        raise ValueError(
                            f"Сервер «{name}»: backups.{btype}.size_check должно быть true/false"
                        )

                    # Журналы транзакций .trn рядом с полными копиями
                    if "ignore_logs" in p and not isinstance(p["ignore_logs"], bool):
                        raise ValueError(
                            f"Сервер «{name}»: backups.{btype}.ignore_logs "
                            f"должно быть true/false"
                        )

                    # Недельное расписание задаётся только парой полей: одно без
                    # второго молча не работало бы, а опечатка в дне недели тихо
                    # вернула бы путь под обычный порог по возрасту.
                    has_weekday = "schedule_weekday" in p
                    has_hour = "schedule_by_hour" in p
                    if has_weekday != has_hour:
                        raise ValueError(
                            f"Сервер «{name}»: backups.{btype} — schedule_weekday и "
                            f"schedule_by_hour задаются только вместе"
                        )
                    if has_weekday:
                        if str(p["schedule_weekday"]).strip().lower() not in WEEKDAY_NAMES:
                            raise ValueError(
                                f"Сервер «{name}»: backups.{btype}.schedule_weekday — "
                                f"один из {', '.join(WEEKDAY_NAMES)}"
                            )
                        try:
                            by_hour = int(p["schedule_by_hour"])
                        except (TypeError, ValueError):
                            raise ValueError(
                                f"Сервер «{name}»: backups.{btype}.schedule_by_hour "
                                f"должно быть числом"
                            )
                        if not 0 <= by_hour <= 23:
                            raise ValueError(
                                f"Сервер «{name}»: backups.{btype}.schedule_by_hour "
                                f"должно быть от 0 до 23"
                            )

        if "onec_logs" in server:
            if not isinstance(server["onec_logs"], list):
                raise ValueError(f"Сервер «{name}»: onec_logs должно быть списком")
            for entry in server["onec_logs"]:
                if isinstance(entry, str):
                    continue
                if not isinstance(entry, dict) or not entry.get("path"):
                    raise ValueError(
                        f"Сервер «{name}»: в onec_logs нужен путь (path)"
                    )
                limits = {}
                for field in ("warn_gb", "crit_gb"):
                    if entry.get(field) is None:
                        continue
                    try:
                        limits[field] = float(entry[field])
                    except (TypeError, ValueError):
                        raise ValueError(
                            f"Сервер «{name}»: onec_logs.{field} "
                            f"({entry['path']}) должно быть числом"
                        )
                    if limits[field] <= 0:
                        raise ValueError(
                            f"Сервер «{name}»: onec_logs.{field} "
                            f"({entry['path']}) должно быть больше нуля"
                        )
                warn = limits.get("warn_gb", ONEC_DEFAULT_WARN_GB)
                crit = limits.get("crit_gb", ONEC_DEFAULT_CRIT_GB)
                if limits and warn >= crit:
                    # Незаданный порог берётся общий: warn 100 без своего crit
                    # означает crit 10, и предупреждение не сработает никогда
                    raise ValueError(
                        f"Сервер «{name}»: у {entry['path']} порог "
                        f"предупреждения ({warn} ГБ) должен быть меньше "
                        f"критичного ({crit} ГБ)"
                    )

        rd = server.get("retention_days")
        if rd is not None:
            try:
                rd = int(rd)
            except (TypeError, ValueError):
                raise ValueError(f"Сервер «{name}»: retention_days должно быть числом")
            if rd < 3:
                raise ValueError(f"Сервер «{name}»: retention_days минимум 3")

        bah = server.get("backup_alert_hours")
        if bah is not None:
            try:
                bah = int(bah)
            except (TypeError, ValueError):
                raise ValueError(f"Сервер «{name}»: backup_alert_hours должно быть числом")
            if bah < 1 or bah > 720:
                raise ValueError(f"Сервер «{name}»: backup_alert_hours должно быть от 1 до 720")

        for flag in ("dbsize", "exchange", "verify_backup", "backup_size_check",
                     "verify_ssl", "legacy_tls"):
            if flag in server and not isinstance(server[flag], bool):
                raise ValueError(f"Сервер «{name}»: {flag} должно быть true/false")

        for field in ("snapshot_alert_days", "snapshot_alert_gb"):
            if field not in server:
                continue
            try:
                value = int(server[field])
            except (TypeError, ValueError):
                raise ValueError(f"Сервер «{name}»: {field} должно быть числом")
            if value < 1:
                raise ValueError(f"Сервер «{name}»: {field} должно быть больше нуля")

        reg = server.get("reg_file")
        if reg is not None and not str(reg).lower().endswith(".reg"):
            raise ValueError(f"Сервер «{name}»: reg_file должен указывать на .reg")


CONFIG_FILE_MODE = 0o600      # в конфиге лежат пароли WinRM/SSH


def save_config(servers: list):
    """Атомарная запись + резервная копия предыдущей версии."""
    validate_config(servers)
    directory = os.path.dirname(SERVERS_FILE)
    backup_path = SERVERS_FILE + ".bak"
    try:
        with open(SERVERS_FILE) as f:
            previous = f.read()
        # Копия — такой же секрет, как и оригинал: в ней те же пароли серверов.
        # Обычный open() дал бы 0644 по umask, и учётные данные стали бы
        # читаемы любому пользователю хоста, хотя сам servers.json — 0600.
        fd = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     CONFIG_FILE_MODE)
        with os.fdopen(fd, "w") as f:
            f.write(previous)
        # Если файл уже существовал, режим при открытии не меняется — правим явно
        os.chmod(backup_path, CONFIG_FILE_MODE)
    except OSError:
        pass

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".servers_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(servers, f, ensure_ascii=False, indent=2)
            f.write("\n")
        # mkstemp даёт 0600, но задаём явно: os.replace переносит режим
        # временного файла на servers.json, и это не должно зависеть от umask
        os.chmod(tmp_path, CONFIG_FILE_MODE)
        os.replace(tmp_path, SERVERS_FILE)
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


# ─── Описание полей ──────────────────────────────────────────
# kind: name | host | text | secret | list | paths | bool | int

FIELD_DEFS = {
    "name": {
        "label": "Имя сервера",
        "prompt": "Имя сервера (как будет отображаться в боте).\n"
                  "Без двоеточий. ⚠️ История метрик привязана к имени — "
                  "при переименовании старая история удаляется.",
        "kind": "name",
    },
    "host": {
        "label": "IP / hostname",
        "prompt": "IP или hostname сервера.\nНапример: 192.0.2.50",
        "kind": "host",
    },
    "type": {
        "label": "Тип",
        "prompt": "Тип объекта мониторинга:\n"
                  "• windows — сервер Windows, опрос по WinRM\n"
                  "• linux — сервер Linux, опрос по SSH\n"
                  "• device — сетевое устройство (коммутатор, шлюз, "
                  "принтер, камера), только ping\n"
                  "• vmware — vCenter или отдельный ESXi, опрос по HTTPS\n"
                  "Пропусти — windows.",
        "kind": "type",
    },
    "username": {
        "label": "Логин WinRM/SSH",
        "prompt": "Логин WinRM (Windows) или SSH (Linux) для этого сервера.\n"
                  "Пропусти — будет использоваться общий из .env",
        "kind": "text",
    },
    "password": {
        "label": "Пароль WinRM/SSH",
        "prompt": "Пароль WinRM (Windows) или SSH (Linux) для этого сервера.\n"
                  "Пропусти — будет использоваться общий из .env\n"
                  "(сообщение с паролем бот удалит из чата)",
        "kind": "secret",
    },
    "services": {
        "label": "Сервисы",
        "prompt": "Сервисы для контроля, через запятую.\n"
                  "Windows: имя службы или её отображаемое имя, "
                  "например MSSQLSERVER, W3SVC\n"
                  "Linux: systemd-юниты, например nginx, postgresql",
        "kind": "list",
    },
    "backups_sql": {
        "label": "SQL backup",
        "prompt": "Пути к каталогам SQL backup, через запятую.\n"
                  "Например: E:\\Backups\n"
                  "Своё время алерта для конкретного пути: E:\\Backups=40 (часов).\n"
                  "Не указано у пути — берётся время сервера, не указано у сервера — общее из .env.\n\n"
                  "🗓 Копия раз в неделю: E:\\Full@пн:9 (день и час, можно mon:9).\n"
                  "Такой путь проверяется только по расписанию — «БЭКАП УСТАРЕЛ» по "
                  "возрасту для него не шлётся. Убрать расписание: E:\\Full@-\n\n"
                  "⚠️ Можно прислать только ОДИН путь, который меняешь (например, "
                  "только E:\\Backups=40) — остальные уже добавленные пути НЕ удалятся, "
                  "допишутся/обновятся только те, что назвал. Чтобы удалить путь целиком "
                  "или начать список заново — сначала пришли «-» (очистит поле), потом "
                  "новое сообщение со всеми путями, которые должны остаться.",
        "kind": "backup_paths",
    },
    "backups_1c": {
        "label": "1C backup",
        "prompt": "Пути к каталогам 1C backup, через запятую.\n"
                  "Например: D:\\1CBase\\Backup1C\n"
                  "Своё время алерта для конкретного пути: D:\\1CBase\\Backup1C=40 (часов).\n"
                  "Не указано у пути — берётся время сервера, не указано у сервера — общее из .env.\n\n"
                  "🗓 Копия раз в неделю: D:\\1CBase\\Full@пн:9 (день и час, можно mon:9).\n"
                  "Такой путь проверяется только по расписанию. Убрать: D:\\1CBase\\Full@-\n\n"
                  "⚠️ Можно прислать только ОДИН путь, который меняешь — остальные уже "
                  "добавленные пути НЕ удалятся, допишутся/обновятся только те, что назвал. "
                  "Чтобы удалить путь целиком или начать список заново — сначала пришли «-» "
                  "(очистит поле), потом новое сообщение со всеми путями, которые должны остаться.",
        "kind": "backup_paths",
    },
    "backups_veeam": {
        "label": "Veeam backup",
        "prompt": "Пути к каталогам Veeam backup, через запятую.\n"
                  "Своё время алерта для конкретного пути: F:\\Veeam=40 (часов).\n"
                  "Не указано у пути — берётся время сервера, не указано у сервера — общее из .env.\n\n"
                  "🗓 Копия раз в неделю: F:\\Veeam\\Full@пн:9 (день и час, можно mon:9).\n"
                  "Такой путь проверяется только по расписанию. Убрать: F:\\Veeam\\Full@-\n\n"
                  "⚠️ Можно прислать только ОДИН путь, который меняешь — остальные уже "
                  "добавленные пути НЕ удалятся, допишутся/обновятся только те, что назвал. "
                  "Чтобы удалить путь целиком или начать список заново — сначала пришли «-» "
                  "(очистит поле), потом новое сообщение со всеми путями, которые должны остаться.",
        "kind": "backup_paths",
    },
    "onec_logs": {
        "label": "Журналы 1С",
        "prompt": "Пути к журналам регистрации 1С, через запятую.\n"
                  "Например: C:\\Program Files\\1cv8\\srvinfo\\reg_1541\n\n"
                  "Свои пороги размера для пути — через «=» в гигабайтах, "
                  "предупреждение/критично:\n"
                  "C:\\1cv8\\srvinfo\\reg_1541=100/150\n"
                  "Один порог (=100) задаёт только предупреждение. "
                  "Без порогов действуют общие: 5 и 10 ГБ.\n"
                  "Вернуть путь к общим порогам: C:\\1cv8\\srvinfo\\reg_1541=-\n\n"
                  "Список задаётся целиком: пути, которых нет в сообщении, "
                  "удаляются. Пороги и названия уже известных путей "
                  "сохраняются, если не задать новые.",
        "kind": "onec_paths",
    },
    "dbsize": {
        "label": "DB Size",
        "prompt": "Есть ли на сервере MSSQL? (да/нет)\n"
                  "Включает сбор размеров баз и кнопку 🗄 SQL-логи "
                  "в карточке сервера.",
        "kind": "bool",
    },
    "exchange": {
        "label": "Exchange",
        "prompt": "Это почтовый сервер Exchange? (да/нет)\n"
                  "Открывает кнопку 📧 Почта в карточке: входы в OWA, "
                  "неудачные пароли, мобильные клиенты.\n"
                  "Если среди сервисов уже есть служба MSExchange*, "
                  "раздел появится и без этого флага.",
        "kind": "bool",
    },
    "retention_days": {
        "label": "Ретеншн (дней)",
        "prompt": "Автоочистка: хранить бэкапы N дней (число, минимум 3).\n"
                  "Пропусти — автоочистка выключена.",
        "kind": "int",
    },
    "backup_alert_hours": {
        "label": "Алерт бэкапа (часов)",
        "prompt": "Через сколько часов без нового бэкапа слать алерт «БЭКАП УСТАРЕЛ»?\n"
                  "Например: 30 — не уведомлять, пока бэкапу меньше 30 часов.\n"
                  f"Пропусти — используется общее значение по умолчанию "
                  f"({os.getenv('BACKUP_ALERT_HOURS', '25')} ч, из BACKUP_ALERT_HOURS в .env).\n\n"
                  "🗓 На пути с недельным расписанием (путь@пн:9) не действует — "
                  "они проверяются только по пропуску плановой копии.",
        "kind": "hours",
    },
    "verify_backup": {
        "label": "Verify backup",
        "prompt": "Проверять последний .bak через RESTORE VERIFYONLY? (да/нет)\n"
                  "Требуется MSSQL на этом же сервере.",
        "kind": "bool",
    },
    "backup_size_check": {
        "label": "Проверка размера",
        "prompt": "Сверять размер нового бэкапа с медианой последних бэкапов и "
                  "слать алерт, если он подозрительно маленький (например, "
                  "обрыв копирования по FTP)? (да/нет)\n"
                  "Включает проверку сразу для всех путей этого сервера. "
                  "Отключить/включить для отдельного пути можно только через "
                  "config/servers.json — полем \"size_check\": true/false у пути.",
        "kind": "bool",
    },
    "verify_ssl": {
        "label": "Проверять сертификат",
        "prompt": "Проверять TLS-сертификат vCenter/ESXi? (да/нет)\n"
                  "У vSphere сертификат почти всегда самоподписанный, и тогда "
                  "проверка не пройдёт — отвечай «нет».\n"
                  "Пропусти — проверять (безопасное значение по умолчанию).",
        "kind": "bool_on",
    },
    "legacy_tls": {
        "label": "Старый TLS",
        "prompt": "Разрешить устаревшие настройки TLS? (да/нет)\n"
                  "Нужно для vSphere 6.0/6.5: они не договариваются с "
                  "современным клиентом, и подключение обрывается с ошибкой "
                  "SSL: UNEXPECTED_EOF_WHILE_READING.\n"
                  "Пропусти — не разрешать (для vSphere 7 и новее менять "
                  "ничего не нужно).",
        "kind": "bool",
    },
    "snapshot_alert_days": {
        "label": "Снапшот: возраст (дней)",
        "prompt": "Алерт, если снапшот старше N дней. Например: 7\n"
                  "Забытый снапшот — самая частая причина внезапно кончившегося "
                  "места на датасторе.\n"
                  "Пропусти — по возрасту не проверять.",
        "kind": "int",
    },
    "snapshot_alert_gb": {
        "label": "Снапшот: размер (ГБ)",
        "prompt": "Алерт, если снапшот вырос больше N ГБ. Например: 50\n"
                  "Пропусти — по размеру не проверять.",
        "kind": "int",
    },
    "reg_file": {
        "label": "Reg-файл",
        "prompt": "Полный путь к .reg файлу НА САМОМ СЕРВЕРЕ. Бот импортирует его "
                  "в реестр перед перезагрузкой этого сервера.\n"
                  "Например: C:\\Scripts\\before_reboot.reg\n"
                  "Пропусти — перезагрузка без импорта в реестр.",
        "kind": "regpath",
    },
}

WIZARD_ORDER = [
    "name", "host", "type", "username", "password", "services",
    "backups_sql", "backups_1c", "backups_veeam", "onec_logs",
    "dbsize", "exchange", "retention_days", "backup_alert_hours",
    "backup_size_check",
    "verify_backup", "reg_file",
    "verify_ssl", "legacy_tls", "snapshot_alert_days", "snapshot_alert_gb",
]
REQUIRED_FIELDS = {"name", "host"}

# Поля, неприменимые к Linux (бэкапы/MSSQL/1С/реестр — только Windows)
# Поля, которые на Linux физически не с чем связать:
#   onec_logs / dbsize   — журналы 1С и MSSQL бывают только на Windows
#   retention_days       — удаление файлов идёт через PowerShell
#   verify_backup        — RESTORE VERIFYONLY выполняет MSSQL
#   reg_file             — реестр Windows
# Пути бэкапов и пороги сюда НЕ входят: каталоги на Linux/NAS (Synology)
# читаются по SSH, и задавать их из бота нужно так же, как на Windows.
WINDOWS_ONLY_FIELDS = {
    "onec_logs", "dbsize", "exchange", "retention_days", "verify_backup",
    "reg_file",
}

# Поля только для vmware: TLS до vCenter и пороги по снапшотам.
# На остальных типах их показывать незачем.
VMWARE_ONLY_FIELDS = {
    "verify_ssl", "legacy_tls", "snapshot_alert_days", "snapshot_alert_gb",
}

# Чего у VMware нет: бэкапы, MSSQL, журналы 1С и реестр Windows.
# Каталогов с копиями там тоже нет — датастор не файловая система,
# доступная монитору, поэтому пути бэкапов исключаются целиком.
VMWARE_EXCLUDED_FIELDS = WINDOWS_ONLY_FIELDS | {
    "backups_sql", "backups_1c", "backups_veeam",
    "backup_alert_hours", "backup_size_check",
}

# Шаги мастера для Linux: то же, что на Windows, минус Windows-only поля
LINUX_WIZARD_ORDER = [
    key for key in WIZARD_ORDER
    if key not in WINDOWS_ONLY_FIELDS and key not in VMWARE_ONLY_FIELDS
]

# Шаги мастера для VMware: адрес vCenter/ESXi, учётка, TLS, список ВМ
# под контролем и пороги по снапшотам
VMWARE_WIZARD_ORDER = [
    key for key in WIZARD_ORDER if key not in VMWARE_EXCLUDED_FIELDS
]


def build_wizard_order(type_value) -> list:
    """Шаги мастера в зависимости от типа: device — только ping,
    linux — без Windows-специфичных полей (но с бэкапами: NAS опрашивается
    по SSH, и его каталоги задаются здесь же)."""
    if type_value == "device":
        return ["name", "host", "type"]
    if type_value == "linux":
        return list(LINUX_WIZARD_ORDER)
    if type_value == "vmware":
        return list(VMWARE_WIZARD_ORDER)
    return [key for key in WIZARD_ORDER if key not in VMWARE_ONLY_FIELDS]


# Популярные systemd-юниты: выбор кнопками при типе linux
LINUX_SERVICE_PRESETS = [
    ("docker", "🐳 Docker"),
    ("nginx", "🌐 Nginx (веб)"),
    ("apache2", "🌐 Apache (веб)"),
    ("postgresql", "🐘 PostgreSQL"),
    ("mysql", "🗄 MySQL"),
    ("mariadb", "🗄 MariaDB"),
    ("redis-server", "⚡ Redis"),
    ("srv1cv83", "📒 Сервер 1С"),
    ("ssh", "🔑 SSH"),
    ("cron", "⏰ Cron"),
    ("smbd", "📁 Samba"),
    ("fail2ban", "🛡 Fail2ban"),
]

# Популярные службы Windows: выбор кнопками при типе windows
WINDOWS_SERVICE_PRESETS = [
    ("MSSQLSERVER", "🗄 MSSQL Server"),
    ("SQLSERVERAGENT", "🗄 SQL Server Agent"),
    ("W3SVC", "🌐 IIS (веб)"),
    ("VeeamBackupSvc", "💾 Veeam"),
    ("vmms", "🖥 Hyper-V"),
    ("1C:Enterprise 8.3 Server Agent", "📒 Сервер 1С"),
    ("Spooler", "🖨 Диспетчер печати"),
    ("TermService", "🖥 RDP"),
    ("LanmanServer", "📁 Общие папки (SMB)"),
    ("Schedule", "⏰ Планировщик заданий"),
]


# Службы Synology DSM 7: имена юнитов у неё свои, обычные Debian-названия
# (ssh, smbd, cron) там не существуют и вернули бы «unknown».
# ftpd — первый по важности, если копии приезжают на NAS по FTP.
SYNOLOGY_SERVICE_PRESETS = [
    ("ftpd", "📤 FTP (Synology)"),
    ("sshd", "🔑 SSH (Synology)"),
    ("pkg-synosamba-smbd", "📁 SMB (Synology)"),
    ("synostoraged", "💽 Хранилище (Synology)"),
    ("synocrond", "⏰ Задания (Synology)"),
    ("synoscgi", "⚙️ DSM (Synology)"),
]


def service_presets_for_type(type_value) -> list:
    if (type_value or "windows") == "linux":
        return LINUX_SERVICE_PRESETS + SYNOLOGY_SERVICE_PRESETS
    return WINDOWS_SERVICE_PRESETS


# Поля, редактируемые кнопками при изменении сервера
EDIT_FIELDS = [
    ["name", "host"],
    ["type"],
    ["username", "password"],
    ["services", "onec_logs"],
    ["backups_sql", "backups_1c"],
    ["backups_veeam", "retention_days"],
    ["backup_alert_hours"],
    ["reg_file"],
    ["snapshot_alert_days", "snapshot_alert_gb"],
]
TOGGLE_FIELDS = ["dbsize", "exchange", "verify_backup", "backup_size_check"]

# Флаги, отсутствие которых в конфиге означает «включено», а не «выключено».
# Для них выключение пишется явным false — иначе ответ «нет» бесследно
# исчезает при чтении конфига.
DEFAULT_ON_FIELDS = {"verify_ssl"}


# ─── Разбор значений (чистые функции) ────────────────────────

def parse_field_value(key: str, text: str, existing_names: set[str] = None):
    """
    Разбирает ответ пользователя. Возвращает (ok, value, error).
    value=None означает «поле не задано».
    """
    kind = FIELD_DEFS[key]["kind"]
    text = (text or "").strip()

    if not text or text in SKIP_INPUTS:
        return True, None, None

    if kind == "name":
        if ":" in text:
            return False, None, "Имя не должно содержать двоеточие"
        if existing_names and text in existing_names:
            return False, None, f"Сервер с именем {text} уже есть в конфиге"
        return True, text, None

    if kind == "host":
        if not is_valid_host(text):
            return False, None, "Некорректный IP или hostname"
        return True, text, None

    if kind == "type":
        low = text.lower()
        if low in {"windows", "win", "w"}:
            return True, None, None   # windows — тип по умолчанию, поле не пишем
        if low in {"linux", "lin", "l"}:
            return True, "linux", None
        if low in {"device", "dev", "d", "устройство", "сетевое", "network"}:
            return True, "device", None
        if low in {"vmware", "vm", "esxi", "vcenter", "vsphere", "вмваре"}:
            return True, "vmware", None
        return False, None, "Ответь windows, linux, device или vmware (или пропусти)"

    if kind in ("text", "secret"):
        return True, text, None

    if kind == "regpath":
        if not text.lower().endswith(".reg"):
            return False, None, "Путь должен указывать на .reg файл"
        return True, text, None

    if kind in ("list", "paths"):
        items = [item.strip() for item in text.replace(";", ",").split(",")]
        items = [item for item in items if item]
        return (True, items, None) if items else (True, None, None)

    if kind == "backup_paths":
        raw_items = [item.strip() for item in text.replace(";", ",").split(",")]
        raw_items = [item for item in raw_items if item]
        if not raw_items:
            return True, None, None
        items = []
        for raw in raw_items:
            # «путь@mon:9» — недельная копия, «путь@-» — снять расписание.
            # Путь может содержать «:» и «\», но не «@», поэтому режем по нему.
            schedule_part = None
            if "@" in raw:
                raw, schedule_part = raw.rsplit("@", 1)
                raw, schedule_part = raw.strip(), schedule_part.strip()
                if not raw:
                    return False, None, "Не указан путь перед «@»"

            hours = None
            if "=" in raw:
                path_part, hours_part = raw.rsplit("=", 1)
                path_part = path_part.strip()
                hours_part = hours_part.strip()
                if not path_part:
                    return False, None, f"Не указан путь перед «=» в «{raw}»"
                try:
                    hours = int(hours_part)
                except ValueError:
                    return False, None, f"Часы для «{path_part}» должны быть числом"
                if hours < 1 or hours > 720:
                    return False, None, f"Часы для «{path_part}» — от 1 до 720"
            else:
                path_part = raw

            entry = {"path": path_part}
            if hours is not None:
                entry["alert_hours"] = hours

            if schedule_part is not None:
                if schedule_part in SKIP_INPUTS:
                    # None — явное снятие, _merge_backup_paths уберёт поле
                    entry["schedule_weekday"] = None
                    entry["schedule_by_hour"] = None
                else:
                    schedule, err = _parse_schedule(schedule_part, path_part)
                    if err:
                        return False, None, err
                    if hours is not None:
                        return False, None, (
                            f"Для «{path_part}» заданы и часы, и недельное расписание. "
                            f"У недельной копии порог по возрасту не применяется — "
                            f"оставь что-то одно."
                        )
                    entry["schedule_weekday"], entry["schedule_by_hour"] = schedule

            items.append(path_part if len(entry) == 1 else entry)
        return True, items, None

    if kind == "onec_paths":
        raw_items = [item.strip() for item in text.replace(";", ",").split(",")]
        raw_items = [item for item in raw_items if item]
        if not raw_items:
            return True, None, None

        items = []
        for raw in raw_items:
            # Путь содержит «\» и «:», но не «=», поэтому режем по последнему.
            if "=" not in raw:
                items.append(raw)
                continue

            path_part, limits = raw.rsplit("=", 1)
            path_part, limits = path_part.strip(), limits.strip()
            if not path_part:
                return False, None, f"Не указан путь перед «=» в «{raw}»"
            if limits in SKIP_INPUTS:
                # Явный сброс к общим порогам: словарь без warn_gb/crit_gb
                items.append({"path": path_part, "warn_gb": None, "crit_gb": None})
                continue

            parts = [p.strip() for p in limits.split("/")]
            if len(parts) > 2:
                return False, None, (
                    f"Пороги для «{path_part}» задаются как "
                    f"предупреждение/критично, например 100/150"
                )
            try:
                values = [float(p.replace(",", ".")) for p in parts]
            except ValueError:
                return False, None, f"Пороги для «{path_part}» должны быть числами"
            if any(v <= 0 for v in values):
                return False, None, f"Пороги для «{path_part}» должны быть больше нуля"
            if len(values) == 2 and values[0] >= values[1]:
                return False, None, (
                    f"Для «{path_part}» предупреждение должно быть меньше "
                    f"критичного порога"
                )

            entry = {"path": path_part, "warn_gb": values[0]}
            if len(values) == 2:
                entry["crit_gb"] = values[1]
            conflict = onec_limits_conflict(entry)
            if conflict:
                return False, None, f"{path_part}: {conflict}"
            items.append(entry)
        return True, items, None

    if kind == "bool":
        low = text.lower()
        if low in TRUE_WORDS:
            return True, True, None
        if low in FALSE_WORDS:
            return True, None, None   # False = поле не пишем
        return False, None, "Ответь «да» или «нет» (или пропусти)"

    if kind == "bool_on":
        # Флаг, у которого значение по умолчанию — «включено» (verify_ssl).
        # Здесь «нет» обязано записать явный false: если поле просто не
        # писать, при чтении вернётся значение по умолчанию, то есть «да»,
        # и ответ пользователя потеряется.
        low = text.lower()
        if low in TRUE_WORDS:
            return True, None, None   # True = значение по умолчанию, поле не пишем
        if low in FALSE_WORDS:
            return True, False, None
        return False, None, "Ответь «да» или «нет» (или пропусти)"

    if kind == "int":
        try:
            value = int(text)
        except ValueError:
            return False, None, "Нужно число (или пропусти)"
        if value < 3:
            return False, None, "Минимум 3 дня (защита от случайного удаления)"
        return True, value, None

    if kind == "hours":
        try:
            value = int(text)
        except ValueError:
            return False, None, "Нужно число часов (или пропусти)"
        if value < 1:
            return False, None, "Минимум 1 час"
        if value > 720:
            return False, None, "Максимум 720 часов (30 дней)"
        return True, value, None

    return False, None, "Неизвестное поле"


_SCHEDULE_RE = re.compile(r"^([a-zа-я]+)[\s:\-.]*(\d{1,2})$")

# Русские сокращения дней — вводить «пн:9» привычнее, чем «mon:9»
_WEEKDAY_ALIASES = {
    "пн": "mon", "вт": "tue", "ср": "wed", "чт": "thu",
    "пт": "fri", "сб": "sat", "вс": "sun",
}


def _parse_schedule(text: str, path_label: str):
    """«mon:9» / «пн 9» / «mon9» → (weekday, hour). Возвращает (значение, ошибка)."""
    match = _SCHEDULE_RE.match(text.strip().lower())
    if not match:
        return None, (
            f"Расписание для «{path_label}» — вида mon:9 "
            f"(день недели и час, например пн:9)"
        )
    weekday, hour = match.group(1), int(match.group(2))
    weekday = _WEEKDAY_ALIASES.get(weekday, weekday)
    if weekday not in WEEKDAY_NAMES:
        return None, (
            f"День недели для «{path_label}» — один из "
            f"{', '.join(WEEKDAY_NAMES)} (или пн…вс)"
        )
    if not 0 <= hour <= 23:
        return None, f"Час для «{path_label}» — от 0 до 23"
    return (weekday, hour), None


def _path_str(item):
    """Строка пути из элемента backups.<type>: сам item, либо item['path']."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return item.get("path")
    return None


# Поля пути, которые мастер не редактирует: их нельзя терять при правке
# alert_hours, иначе недельное расписание молча исчезло бы из конфига и
# бэкап начал бы оцениваться по возрасту (см. shared/backup_schedule.py).
PRESERVED_PATH_KEYS = ("schedule_weekday", "schedule_by_hour", "size_check",
                       "ignore_logs")

# Поля, значение которых — список путей с настройками. У них своё меню:
# путь редактируется кнопками, а не строкой с «=» и «@».
PATH_FIELDS = ("backups_sql", "backups_1c", "backups_veeam", "onec_logs")


def normalize_path(path: str) -> str:
    """Ключ сравнения путей. `E:\\Backups`, `e:\\backups\\` и `E:/Backups` —
    один и тот же каталог, а в конфиге они жили как разные записи, и монитор
    опрашивал его дважды."""
    text = str(path or "").strip().replace("/", "\\")
    stripped = text.rstrip("\\")
    # У корня диска и корня Linux слэш — часть пути, а не хвост
    if not stripped or stripped.endswith(":"):
        return text.lower()
    return stripped.lower()


def dedupe_paths(items: list) -> list:
    """Схлопывает повторы пути, сливая настройки: побеждает последняя
    непустая. Дубли попадали в конфиг при правке руками и удваивали опрос."""
    result = []
    index_by_key = {}
    for item in items or []:
        path = _path_str(item)
        if not path:
            continue
        key = normalize_path(path)
        if key not in index_by_key:
            index_by_key[key] = len(result)
            result.append(item)
            continue

        position = index_by_key[key]
        old, new = result[position], item
        if isinstance(new, dict):
            merged = dict(old) if isinstance(old, dict) else {"path": path}
            merged.update({k: v for k, v in new.items() if v is not None})
            result[position] = merged
    return result


def _merge_onec_logs(existing: list, new_items: list) -> list:
    """Список журналов задаётся целиком, но название журнала и пороги уже
    известного пути переносятся: `name` мастер не спрашивает, а пороги
    незачем повторять при правке соседнего пути."""
    old_by_path = {}
    for item in existing or []:
        path = _path_str(item)
        if path:
            old_by_path[normalize_path(path)] = (
                dict(item) if isinstance(item, dict) else {}
            )

    merged = []
    for item in new_items:
        path = _path_str(item)
        if not path:
            continue
        entry = old_by_path.get(normalize_path(path), {})
        entry.pop("path", None)
        if isinstance(item, dict):
            for field in ("warn_gb", "crit_gb"):
                if field not in item:
                    continue
                if item[field] is None:
                    entry.pop(field, None)   # «=-» — вернуть общие пороги
                else:
                    entry[field] = item[field]
        merged.append({"path": path, **entry} if entry else path)
    return dedupe_paths(merged)


def _merge_backup_paths(existing: list, new_items: list) -> list:
    """Дозаписывает/обновляет пути по совпадению path, не стирая остальные.
    Иначе правка одного пути (например, добавление alert_hours) сносила бы
    весь список — юзер вводит только тот путь, который меняет, а не все сразу.

    Настройки, которых нет в мастере (PRESERVED_PATH_KEYS), переносятся из
    старого элемента в новый."""
    merged = list(existing)
    index_by_path = {}
    for i, item in enumerate(merged):
        p = _path_str(item)
        if p:
            index_by_path[normalize_path(p)] = i

    def _finalize(entry, path):
        """None у поля = снято явно («@-»); путь без настроек — снова строка."""
        cleaned = {k: v for k, v in entry.items() if v is not None}
        return cleaned if len(cleaned) > 1 else path

    for item in new_items:
        p = _path_str(item)
        if not p:
            continue
        key = normalize_path(p)
        entry = dict(item) if isinstance(item, dict) else {"path": p}
        if key in index_by_path:
            old = merged[index_by_path[key]]
            if isinstance(old, dict):
                for preserved in PRESERVED_PATH_KEYS:
                    if preserved in old and preserved not in entry:
                        entry[preserved] = old[preserved]
            merged[index_by_path[key]] = _finalize(entry, p)
        else:
            merged.append(_finalize(entry, p))
            index_by_path[key] = len(merged) - 1
    return dedupe_paths(merged)


# ─── Меню путей (бэкапы, журналы 1С) ─────────────────────────

# Раньше все пути поля правились одной строкой с «=» и «@»: список путей
# уезжал в неразборчивую простыню, удалить один путь было нельзя (только
# очистить поле целиком), а отсутствие расписания вообще ничем не выдавало
# себя. Теперь список — экран с кнопкой на каждый путь, а добавление
# осталось текстовым: залить пять путей одним сообщением быстрее, чем
# кнопками.

SIZE_CHECK_CYCLE = (None, True, False)


def field_items(server: dict, field: str, raw: bool = False) -> list:
    """Список путей поля. По умолчанию — без повторов: дубли попадали в
    конфиг при правке руками, и один каталог показывался (и опрашивался
    монитором) дважды. raw=True возвращает как есть — чтобы увидеть, что
    повторы в файле вообще были."""
    if field.startswith("backups_"):
        backup_type = field.split("_", 1)[1]
        value = (server.get("backups") or {}).get(backup_type)
    else:
        value = server.get(field)
    if isinstance(value, (str, dict)):
        value = [value]
    items = list(value or [])
    return items if raw else dedupe_paths(items)


def duplicate_paths_count(server: dict, field: str) -> int:
    """Сколько повторов лежит в конфиге сверх уникальных путей."""
    return len(field_items(server, field, raw=True)) - len(field_items(server, field))


def path_button_label(path: str, limit: int = 24) -> str:
    """На кнопке — хвост пути: у E:\\SQLBackup\\base_one\\FULL
    различается именно он, а начало у всех путей одинаковое."""
    parts = [part for part in str(path).replace("/", "\\").split("\\") if part]
    label = "\\".join(parts[-2:]) if len(parts) > 1 else (parts[0] if parts else path)
    return label if len(label) <= limit else "…" + label[-(limit - 1):]


def path_details(field: str, item) -> list:
    """Строки описания пути. Прочерк ставится и там, где настройки нет:
    «расписание: нет» отвечает на вопрос, почему копия проверяется по
    возрасту, — раньше отсутствие расписания было просто не видно."""
    data = item if isinstance(item, dict) else {}
    lines = []

    if field == "onec_logs":
        warn, crit = data.get("warn_gb"), data.get("crit_gb")
        if warn is None and crit is None:
            lines.append("   📏 пороги: общие (5 / 10 ГБ)")
        else:
            warn_text = f"{_gb(warn)} ГБ" if warn is not None else "общий (5 ГБ)"
            crit_text = f"{_gb(crit)} ГБ" if crit is not None else "общий (10 ГБ)"
            lines.append(f"   📏 пороги: {warn_text} / {crit_text}")
        if data.get("name"):
            lines.append(f"   🏷 название: {data['name']}")
        return lines

    schedule = path_schedule(item)
    if schedule:
        lines.append(
            f"   🗓 недельно: {weekday_short(schedule[0])} {schedule[1]:02d}:00"
        )
        # «Не применяется» без продолжения читалось как «возраст не
        # проверяется вовсе», и пропущенный дедлайн в карточке выглядел
        # необъяснимым красным.
        lines.append(
            f"   ⏱ порог возраста не применяется — вместо него проверяется "
            f"пропуск срока {weekday_short(schedule[0])} {schedule[1]:02d}:00"
        )
    else:
        hours = data.get("alert_hours")
        lines.append(
            f"   ⏱ порог возраста: {hours} ч" if hours
            else "   ⏱ порог возраста: общий"
        )
        lines.append("   🗓 расписание: нет")

    size_check = data.get("size_check")
    if size_check is True:
        lines.append("   🔍 проверка размера: включена")
    elif size_check is False:
        lines.append("   🔍 проверка размера: выключена")

    if data.get("ignore_logs"):
        lines.append("   📄 журналы .trn: не учитываются")
    return lines


def paths_menu_text(server_name: str, field: str, items: list,
                    duplicates: int = 0) -> str:
    label = FIELD_DEFS[field]["label"]
    lines = [f"✏️ {server_name} · {label}", "━" * 20, ""]
    if not items:
        lines.append("Путей пока нет. Добавь их кнопкой ниже.")
        return "\n".join(lines)

    for number, item in enumerate(items, start=1):
        lines.append(f"{number}. {_path_str(item)}")
        lines += path_details(field, item)
        lines.append("")

    if duplicates > 0:
        lines.append(
            f"⚠️ В servers.json те же пути записаны ещё {duplicates} раз(а) — "
            f"монитор опрашивает их повторно. Кнопка «Убрать дубли» приведёт "
            f"файл к этому списку."
        )
        lines.append("")
    lines.append("Нажми на путь, чтобы изменить его настройки.")
    return "\n".join(lines)


def paths_menu_kb(server_name: str, field: str, items: list,
                  duplicates: int = 0):
    buttons = [
        InlineKeyboardButton(
            f"{number}. {path_button_label(_path_str(item))}",
            callback_data=f"cfg_p:{field}:{number - 1}"
        )
        for number, item in enumerate(items, start=1)
    ]
    keyboard = [buttons[i:i + 2] for i in range(0, len(buttons), 2)]
    keyboard.append([
        InlineKeyboardButton("➕ Добавить пути", callback_data=f"cfg_padd:{field}")
    ])
    if duplicates > 0:
        keyboard.append([
            InlineKeyboardButton(f"🧹 Убрать дубли ({duplicates})",
                                 callback_data=f"cfg_pdedup:{field}")
        ])
    if items:
        keyboard.append([
            InlineKeyboardButton("🧹 Очистить всё", callback_data=f"cfg_pclear:{field}")
        ])
    keyboard.append([
        InlineKeyboardButton("◀️ К серверу", callback_data=f"cfg_editsrv:{server_name}")
    ])
    return InlineKeyboardMarkup(keyboard)


def path_card_text(server_name: str, field: str, item) -> str:
    lines = [f"📁 {_path_str(item)}", "━" * 20, ""]
    lines += [line.strip() for line in path_details(field, item)]
    lines.append("")
    lines.append(f"{server_name} · {FIELD_DEFS[field]['label']}")
    return "\n".join(lines)


def path_card_kb(field: str, index: int, item):
    data = item if isinstance(item, dict) else {}
    prefix = f"{field}:{index}"

    if field == "onec_logs":
        keyboard = [[
            InlineKeyboardButton("📏 Пороги", callback_data=f"cfg_plim:{prefix}"),
        ]]
    else:
        size_check = data.get("size_check")
        size_label = ("🔍 Размер: вкл" if size_check is True
                      else "🔍 Размер: выкл" if size_check is False
                      else "🔍 Размер: общий")
        logs_label = ("📄 .trn: не учитывать" if data.get("ignore_logs")
                      else "📄 .trn: учитывать")
        keyboard = [
            [
                InlineKeyboardButton("⏱ Порог часов", callback_data=f"cfg_ph:{prefix}"),
                InlineKeyboardButton("🗓 Расписание", callback_data=f"cfg_psch:{prefix}"),
            ],
            [
                InlineKeyboardButton(size_label, callback_data=f"cfg_psz:{prefix}"),
                InlineKeyboardButton(logs_label, callback_data=f"cfg_plog:{prefix}"),
            ],
        ]

    keyboard.append([
        InlineKeyboardButton("🗑 Удалить путь", callback_data=f"cfg_pdel:{prefix}")
    ])
    keyboard.append([
        InlineKeyboardButton("◀️ К списку", callback_data=f"cfg_plist:{field}")
    ])
    return InlineKeyboardMarkup(keyboard)


def schedule_days_kb(field: str, index: int, has_schedule: bool):
    prefix = f"{field}:{index}"
    buttons = [
        InlineKeyboardButton(weekday_short(day), callback_data=f"cfg_pday:{prefix}:{day}")
        for day in WEEKDAY_NAMES
    ]
    keyboard = [buttons[i:i + 4] for i in range(0, len(buttons), 4)]
    if has_schedule:
        keyboard.append([
            InlineKeyboardButton("🚫 Убрать расписание",
                                 callback_data=f"cfg_pday:{prefix}:-")
        ])
    keyboard.append([
        InlineKeyboardButton("◀️ Назад", callback_data=f"cfg_p:{prefix}")
    ])
    return InlineKeyboardMarkup(keyboard)


def schedule_hours_kb(field: str, index: int, day: str):
    prefix = f"{field}:{index}"
    buttons = [
        InlineKeyboardButton(f"{hour:02d}:00",
                             callback_data=f"cfg_phour:{prefix}:{day}:{hour}")
        for hour in range(24)
    ]
    keyboard = [buttons[i:i + 6] for i in range(0, len(buttons), 6)]
    keyboard.append([
        InlineKeyboardButton("◀️ Назад", callback_data=f"cfg_psch:{prefix}")
    ])
    return InlineKeyboardMarkup(keyboard)



def apply_field(server: dict, key: str, value, merge: bool = True):
    """Записывает значение в конфиг сервера; None удаляет поле.

    merge=False пишет список путей как есть — так сохраняются правки из
    меню путей, где пользователь уже видит итоговый список целиком.
    Текстовый ввод, наоборот, дозаписывает: там называют один путь."""
    if key.startswith("backups_"):
        backup_type = key.split("_", 1)[1]
        backups = server.get("backups") or {}
        if not value:
            backups.pop(backup_type, None)
        else:
            if merge and FIELD_DEFS[key]["kind"] == "backup_paths":
                existing = backups.get(backup_type) or []
                if not isinstance(existing, list):
                    existing = [existing]
                value = _merge_backup_paths(existing, value)
            backups[backup_type] = value
        if backups:
            server["backups"] = backups
        else:
            server.pop("backups", None)
        return

    if key == "onec_logs" and value:
        value = (_merge_onec_logs(server.get("onec_logs") or [], value)
                 if merge else dedupe_paths(value))

    if value is None:
        server.pop(key, None)
    else:
        server[key] = value


def _gb(value) -> str:
    """100.0 ГБ читается хуже, чем 100."""
    number = float(value)
    return str(int(number)) if number == int(number) else str(number)


def display_value(server: dict, key: str) -> str:
    if key.startswith("backups_"):
        backup_type = key.split("_", 1)[1]
        value = (server.get("backups") or {}).get(backup_type)
    else:
        value = server.get(key)

    if key == "type":
        return str(value or "windows")
    if key in DEFAULT_ON_FIELDS:
        return "да" if value is not False else "нет"
    if value is None or value == []:
        return "—"
    if key == "password":
        return "••••••"
    if key == "onec_logs":
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
                continue
            text = item.get("path") or "?"
            warn, crit = item.get("warn_gb"), item.get("crit_gb")
            if warn is not None and crit is not None:
                text += f" ({_gb(warn)}/{_gb(crit)} ГБ)"
            elif warn is not None:
                text += f" (предупреждение {_gb(warn)} ГБ)"
            elif crit is not None:
                text += f" (критично {_gb(crit)} ГБ)"
            if item.get("name"):
                text += f" [{item['name']}]"
            parts.append(text)
        return ", ".join(parts)
    if key.startswith("backups_"):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            else:
                path = item.get("path") or "?"
                hours = item.get("alert_hours")
                text = f"{path} ({hours}ч)" if hours else path
                schedule = path_schedule(item)
                if schedule:
                    # Видно, что порог по возрасту к этому пути не применяется
                    text += f" [недельно: {weekday_label(schedule[0])} {schedule[1]:02d}:00]"
                if "size_check" in item:
                    text += " [проверка размера: вкл]" if item["size_check"] else " [проверка размера: выкл]"
                if item.get("ignore_logs"):
                    text += " [журналы .trn не учитываются]"
                parts.append(text)
        return ", ".join(parts)
    if isinstance(value, bool):
        return "✅" if value else "—"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def build_summary(server: dict) -> str:
    server_type = (server.get("type") or "windows").lower()
    lines = [f"⚙️ {server.get('name', '?')}", "━" * 20]
    for key in WIZARD_ORDER:
        if key == "name":
            continue
        if server_type == "device" and key not in ("host", "type"):
            continue
        if server_type == "linux" and (key in WINDOWS_ONLY_FIELDS
                                       or key in VMWARE_ONLY_FIELDS):
            continue
        if server_type == "vmware" and key in VMWARE_EXCLUDED_FIELDS:
            continue
        if server_type != "vmware" and key in VMWARE_ONLY_FIELDS:
            continue
        lines.append(f"{FIELD_DEFS[key]['label']}: {display_value(server, key)}")
    return "\n".join(lines)


def build_server_dict(data: dict) -> dict:
    """Собирает итоговый конфиг сервера из ответов мастера."""
    server = {}
    for key in WIZARD_ORDER:
        apply_field(server, key, data.get(key))
    return server


# ─── Клавиатуры ──────────────────────────────────────────────

def menu_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Добавить сервер", callback_data="cfg_add")],
        [InlineKeyboardButton("✏️ Изменить сервер", callback_data="cfg_edit_list")],
        [InlineKeyboardButton("🔕 Mute алертов", callback_data="cfg_mute_menu")],
        [InlineKeyboardButton("✅ Принятые алерты", callback_data="cfg_acks")],
        [InlineKeyboardButton("🐘 База мониторинга", callback_data="cfg_pgsize")],
        [InlineKeyboardButton("🗑 Очистка истории", callback_data="cfg_pgclean_menu")],
        [InlineKeyboardButton("📜 Аудит изменений", callback_data="cfg_audit")],
        [InlineKeyboardButton("📖 Справка", callback_data="cfg_help")],
    ])


def wizard_kb(step_key: str):
    row = []
    if step_key not in REQUIRED_FIELDS:
        row.append(InlineKeyboardButton("➡️ Пропустить", callback_data="cfg_skip"))
    row.append(InlineKeyboardButton("❌ Отмена", callback_data="cfg_cancel"))
    return InlineKeyboardMarkup([row])


def services_kb(selected: list, presets: list, cancel_callback: str = "cfg_cancel"):
    keyboard = []
    row = []
    for unit, label in presets:
        mark = "✅ " if unit in selected else ""
        row.append(InlineKeyboardButton(f"{mark}{label}", callback_data=f"cfg_svc:{unit}"))
        if len(row) == 2:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([
        InlineKeyboardButton("✔️ Готово", callback_data="cfg_svc_done"),
        InlineKeyboardButton("❌ Отмена", callback_data=cancel_callback),
    ])
    return InlineKeyboardMarkup(keyboard)


def services_text(selected: list, header: str) -> str:
    chosen = ", ".join(selected) if selected else "ничего"
    return (
        f"{header}\n\n"
        "Отметь сервисы для контроля кнопками.\n"
        "Своих нет в списке — допиши текстом через запятую "
        "(имя службы/юнита или отображаемое имя).\n\n"
        f"Выбрано: {chosen}\n\n"
        "Когда закончишь — нажми «✔️ Готово» "
        "(ничего не выбрано = без контроля сервисов)."
    )


def service_names(server: dict) -> list:
    """Имена сервисов из конфига (строки или dict-спецификации)."""
    names = []
    for service in server.get("services", []):
        if isinstance(service, str):
            names.append(service)
        else:
            name = service.get("name") or service.get("display_name")
            if name:
                names.append(name)
    return names


def edit_fields_kb(server: dict):
    server_type = (server.get("type") or "windows").lower()
    keyboard = []
    for row_keys in EDIT_FIELDS:
        if server_type == "device":
            row_keys = [key for key in row_keys if key in ("name", "host", "type")]
        elif server_type == "linux":
            row_keys = [key for key in row_keys
                        if key not in WINDOWS_ONLY_FIELDS
                        and key not in VMWARE_ONLY_FIELDS]
        elif server_type == "vmware":
            row_keys = [key for key in row_keys if key not in VMWARE_EXCLUDED_FIELDS]
        else:
            row_keys = [key for key in row_keys if key not in VMWARE_ONLY_FIELDS]
        if not row_keys:
            continue
        keyboard.append([
            InlineKeyboardButton(FIELD_DEFS[key]["label"], callback_data=f"cfg_f:{key}")
            for key in row_keys
        ])
    if server_type == "windows":
        keyboard.append([
            InlineKeyboardButton(
                f"DB Size: {'✅' if server.get('dbsize') else '❌'}",
                callback_data="cfg_toggle:dbsize"
            ),
            InlineKeyboardButton(
                f"Verify: {'✅' if server.get('verify_backup') else '❌'}",
                callback_data="cfg_toggle:verify_backup"
            ),
        ])
        keyboard.append([
            InlineKeyboardButton(
                f"Exchange: {'✅' if server.get('exchange') else '❌'}",
                callback_data="cfg_toggle:exchange"
            ),
        ])
        keyboard.append([
            InlineKeyboardButton(
                f"Проверка размера: {'✅' if server.get('backup_size_check') else '❌'}",
                callback_data="cfg_toggle:backup_size_check"
            ),
        ])
    if server_type == "vmware":
        keyboard.append([
            InlineKeyboardButton(
                f"Проверять сертификат: "
                f"{'❌' if server.get('verify_ssl') is False else '✅'}",
                callback_data="cfg_toggle:verify_ssl"
            ),
            InlineKeyboardButton(
                f"Старый TLS: {'✅' if server.get('legacy_tls') else '❌'}",
                callback_data="cfg_toggle:legacy_tls"
            ),
        ])
    keyboard.append([
        InlineKeyboardButton("🗑 Удалить сервер", callback_data=f"cfg_delete:{server.get('name')}")
    ])
    keyboard.append([InlineKeyboardButton("◀️ К списку", callback_data="cfg_edit_list")])
    return InlineKeyboardMarkup(keyboard)


# ─── Мастер добавления ───────────────────────────────────────

def wizard_prompt_text(step_index: int, order: list) -> str:
    key = order[step_index]
    d = FIELD_DEFS[key]
    required = "обязательно" if key in REQUIRED_FIELDS else "можно пропустить"
    return (
        f"➕ Новый сервер · шаг {step_index + 1}/{len(order)}\n\n"
        f"{d['label']} ({required})\n\n{d['prompt']}"
    )


async def start_wizard(query, context):
    order = list(WIZARD_ORDER)
    context.user_data[STATE_KEY] = {"mode": "wizard", "step": 0, "data": {}, "order": order}
    await safe_edit_message(query, wizard_prompt_text(0, order), reply_markup=wizard_kb(order[0]))


async def send_wizard_step(state, send):
    """Шлёт вопрос текущего шага; для сервисов — кнопки-чекбоксы."""
    order = state["order"]
    key = order[state["step"]]
    if key == "services":
        state["svc"] = []
        header = f"➕ Новый сервер · шаг {state['step'] + 1}/{len(order)}\n\nСервисы (можно пропустить)"
        presets = service_presets_for_type(state["data"].get("type"))
        await send(services_text([], header), services_kb([], presets))
    else:
        await send(wizard_prompt_text(state["step"], order), wizard_kb(key))


async def wizard_advance(context, send, value):
    """Записывает значение текущего шага и шлёт следующий вопрос/предпросмотр."""
    state = context.user_data[STATE_KEY]
    order = state.get("order") or list(WIZARD_ORDER)
    key = order[state["step"]]
    state["data"][key] = value
    state["step"] += 1
    state.pop("svc", None)

    if key == "type":
        # Тип определяет дальнейшие шаги: device — только ping,
        # linux — без Windows-специфичных полей
        order = build_wizard_order(value)
        state["order"] = order

    if state["step"] < len(order):
        await send_wizard_step(state, send)
        return

    # Все шаги пройдены — предпросмотр
    server = build_server_dict(state["data"])
    state["mode"] = "confirm"
    text = (
        "➕ Проверь данные нового сервера:\n\n"
        + build_summary(server)
        + "\n\nСохранить в config/servers.json?"
    )
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Сохранить", callback_data="cfg_add_confirm"),
        InlineKeyboardButton("❌ Отмена", callback_data="cfg_cancel"),
    ]])
    await send(text, kb)


async def wizard_confirm(query, context):
    state = context.user_data.get(STATE_KEY)
    if not state or state.get("mode") != "confirm":
        await safe_edit_message(query, "❌ Мастер неактивен. Начни заново.", reply_markup=menu_kb())
        return

    server = build_server_dict(state["data"])
    try:
        servers = load_config()
        if any(s.get("name") == server["name"] for s in servers):
            await safe_edit_message(
                query,
                f"❌ Сервер {server['name']} уже появился в конфиге. Начни заново.",
                reply_markup=menu_kb()
            )
            context.user_data.pop(STATE_KEY, None)
            return
        servers.append(server)
        save_config(servers)
    except Exception as e:
        await safe_edit_message(
            query,
            f"❌ Не удалось сохранить конфиг: {str(e)[:150]}\n\n"
            "Проверь, что каталог config смонтирован с правом записи "
            "(docker-compose: ./config:/app/config без :ro).",
            reply_markup=menu_kb()
        )
        context.user_data.pop(STATE_KEY, None)
        return

    context.user_data.pop(STATE_KEY, None)
    audit.log_config_change(
        query.from_user, "add", server["name"],
        f"host={server.get('host')}, тип={server.get('type') or 'windows'}"
    )
    await safe_edit_message(
        query,
        f"✅ Сервер {server['name']} добавлен.\n"
        f"Мониторинг подхватит его в течение 5 минут.",
        reply_markup=menu_kb()
    )


# ─── Редактирование ──────────────────────────────────────────

async def show_edit_list(query, context, page: int = 0):
    try:
        servers = load_config()
    except Exception as e:
        await safe_edit_message(query, f"❌ Не удалось прочитать конфиг: {str(e)[:150]}",
                                reply_markup=menu_kb())
        return

    names = sorted(s.get("name", "?") for s in servers)
    if not names:
        await safe_edit_message(query, "Конфиг пуст. Добавь первый сервер.", reply_markup=menu_kb())
        return

    await safe_edit_message(
        query,
        "✏️ ИЗМЕНЕНИЕ СЕРВЕРА\n\nВыбери сервер:",
        reply_markup=build_paginated_server_keyboard(names, "cfg_editsrv", page, back_callback="cfg_menu")
    )


async def show_server_editor(query, context, server_name: str):
    servers = load_config()
    server = next((s for s in servers if s.get("name") == server_name), None)
    if not server:
        await safe_edit_message(query, f"❌ Сервер {server_name} не найден.", reply_markup=menu_kb())
        return

    context.user_data[EDIT_SERVER_KEY] = server_name
    await safe_edit_message(
        query,
        build_summary(server) + "\n\nНажми на поле чтобы изменить («-» очищает поле):",
        reply_markup=edit_fields_kb(server)
    )


async def ask_edit_field(query, context, field: str):
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    if not server_name:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return

    if field == "services":
        try:
            servers = load_config()
            server = next((s for s in servers if s.get("name") == server_name), None)
        except Exception:
            server = None
        if server is not None:
            selected = service_names(server)
            type_value = (server.get("type") or "windows").lower()
            context.user_data[STATE_KEY] = {
                "mode": "edit_field", "server": server_name,
                "field": "services", "svc": selected, "type": type_value,
            }
            await safe_edit_message(
                query,
                services_text(selected, f"✏️ {server_name} · Сервисы"),
                reply_markup=services_kb(
                    selected, service_presets_for_type(type_value),
                    cancel_callback=f"cfg_editsrv:{server_name}"
                )
            )
            return

    if field in PATH_FIELDS:
        await show_paths_menu(query, context, field)
        return

    context.user_data[STATE_KEY] = {"mode": "edit_field", "server": server_name, "field": field}
    d = FIELD_DEFS[field]
    await safe_edit_message(
        query,
        f"✏️ {server_name} · {d['label']}\n\n{d['prompt']}\n\n"
        f"Текущее значение: {display_value_for(server_name, field)}\n"
        f"Отправь новое значение («-» — очистить поле):",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("❌ Отмена", callback_data=f"cfg_editsrv:{server_name}")
        ]])
    )


def services_view(state: dict) -> tuple:
    """(текст, клавиатура) для текущего состояния выбора сервисов."""
    selected = state.get("svc") or []
    if state["mode"] == "wizard":
        order = state.get("order") or list(WIZARD_ORDER)
        header = (f"➕ Новый сервер · шаг {state['step'] + 1}/{len(order)}\n\n"
                  "Сервисы (можно пропустить)")
        cancel = "cfg_cancel"
        presets = service_presets_for_type(state["data"].get("type"))
    else:
        header = f"✏️ {state['server']} · Сервисы"
        cancel = f"cfg_editsrv:{state['server']}"
        presets = service_presets_for_type(state.get("type"))
    return services_text(selected, header), services_kb(selected, presets, cancel_callback=cancel)


def display_value_for(server_name: str, field: str) -> str:
    try:
        servers = load_config()
        server = next((s for s in servers if s.get("name") == server_name), None)
        return display_value(server, field) if server else "—"
    except Exception:
        return "—"


def update_server_field(server_name: str, field: str, value) -> tuple[bool, str]:
    """Применяет изменение поля к конфигу. Возвращает (ok, сообщение)."""
    servers = load_config()
    server = next((s for s in servers if s.get("name") == server_name), None)
    if not server:
        return False, f"Сервер {server_name} не найден в конфиге"

    if field == "name":
        if value is None:
            return False, "Имя нельзя очистить"
        if any(s.get("name") == value for s in servers if s is not server):
            return False, f"Сервер с именем {value} уже есть"
    if field == "host" and value is None:
        return False, "Host нельзя очистить"

    apply_field(server, field, value)
    save_config(servers)
    return True, server.get("name")


async def ask_delete_confirm(query, context, server_name: str):
    await safe_edit_message(
        query,
        f"⚠️ Удалить сервер {server_name} из конфига?\n\n"
        "Мониторинг перестанет опрашивать его в течение 5 минут. "
        "История метрик в базе не удаляется.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("🗑 Да, удалить", callback_data=f"cfg_delete_confirm:{server_name}"),
            InlineKeyboardButton("❌ Отмена", callback_data=f"cfg_editsrv:{server_name}"),
        ]])
    )


async def delete_server(query, context, server_name: str):
    try:
        servers = load_config()
        remaining = [s for s in servers if s.get("name") != server_name]
        if len(remaining) == len(servers):
            await safe_edit_message(query, f"❌ Сервер {server_name} не найден.", reply_markup=menu_kb())
            return
        save_config(remaining)
    except Exception as e:
        await safe_edit_message(
            query,
            f"❌ Не удалось сохранить конфиг: {str(e)[:150]}",
            reply_markup=menu_kb()
        )
        return

    context.user_data.pop(STATE_KEY, None)
    context.user_data.pop(EDIT_SERVER_KEY, None)
    audit.log_config_change(query.from_user, "delete", server_name)
    await safe_edit_message(query, f"✅ Сервер {server_name} удалён из конфига.", reply_markup=menu_kb())


async def toggle_field(query, context, field: str):
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    if not server_name:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return

    servers = load_config()
    server = next((s for s in servers if s.get("name") == server_name), None)
    if not server:
        await safe_edit_message(query, f"❌ Сервер {server_name} не найден.", reply_markup=menu_kb())
        return

    default = field in DEFAULT_ON_FIELDS
    new_value = not server.get(field, default)
    if default:
        # «включено» — значение по умолчанию, поле не пишем;
        # «выключено» — пишем явный false
        apply_field(server, field, None if new_value else False)
    else:
        apply_field(server, field, True if new_value else None)
    try:
        save_config(servers)
    except Exception as e:
        await safe_edit_message(query, f"❌ Не удалось сохранить: {str(e)[:150]}",
                                reply_markup=menu_kb())
        return
    audit.log_config_change(
        query.from_user, "toggle", server_name,
        f"{FIELD_DEFS.get(field, {}).get('label', field)} → {'вкл' if new_value else 'выкл'}"
    )
    await show_server_editor(query, context, server_name)


# ─── Mute алертов ────────────────────────────────────────────

def _mute_line(name: str, value) -> str:
    if value is True:
        return f"• {name} — насовсем"
    try:
        expires = datetime.fromisoformat(str(value))
        until = expires.astimezone(ALMATY).strftime("%H:%M")
        return f"• {name} — до {until}"
    except ValueError:
        return f"• {name}"


async def show_mute_menu(query, context):
    muted = load_muted()
    now = datetime.now(timezone.utc)
    active = {k: v for k, v in muted.items() if not mute_expired(v, now)}
    if active != muted:
        save_muted(active)   # подчищаем истёкшие временные mute

    if active:
        text = ("🔕 MUTE АЛЕРТОВ\n\nАлерты отключены:\n"
                + "\n".join(_mute_line(k, v) for k, v in sorted(active.items()))
                + "\n\nНажми на сервер, чтобы включить алерты обратно:")
    else:
        text = "🔕 MUTE АЛЕРТОВ\n\nВсе алерты включены."

    keyboard = [
        [InlineKeyboardButton(f"🔔 {name}", callback_data=f"cfg_unmute:{name}")]
        for name in sorted(active)
    ]
    keyboard.append([InlineKeyboardButton("➕ Замутить сервер", callback_data="cfg_mute_pick")])
    keyboard.append([InlineKeyboardButton("◀️ Меню", callback_data="cfg_menu")])
    await safe_edit_message(query, text, reply_markup=InlineKeyboardMarkup(keyboard))


async def show_mute_pick(query, context, page: int = 0):
    try:
        names = sorted(s.get("name", "?") for s in load_config())
    except Exception as e:
        await safe_edit_message(query, f"❌ Не удалось прочитать конфиг: {str(e)[:150]}",
                                reply_markup=menu_kb())
        return
    if not names:
        await safe_edit_message(query, "Конфиг пуст.", reply_markup=menu_kb())
        return
    await safe_edit_message(
        query,
        "🔕 Выбери сервер для отключения алертов:",
        reply_markup=build_paginated_server_keyboard(
            names, "cfg_mutesrv", page, back_callback="cfg_mute_menu")
    )


async def show_mute_duration(query, context, server_name: str):
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("1 час", callback_data=f"cfg_mutedo:1:{server_name}"),
            InlineKeyboardButton("8 часов", callback_data=f"cfg_mutedo:8:{server_name}"),
        ],
        [InlineKeyboardButton("Насовсем (до ручного включения)",
                              callback_data=f"cfg_mutedo:0:{server_name}")],
        [InlineKeyboardButton("❌ Отмена", callback_data="cfg_mute_menu")],
    ])
    await safe_edit_message(query, f"🔕 {server_name}\n\nНа сколько отключить алерты?",
                            reply_markup=keyboard)


async def apply_mute(query, context, hours: int, server_name: str):
    muted = load_muted()
    if hours <= 0:
        muted[server_name] = True
    else:
        muted[server_name] = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    save_muted(muted)
    print(f"[config] {query.from_user.id} замутил {server_name} "
          f"({'насовсем' if hours <= 0 else str(hours) + 'ч'})", flush=True)
    await show_mute_menu(query, context)


# ─── Справка ─────────────────────────────────────────────────

HELP_INTRO = """📖 СПРАВКА ПО AGENTMONITOR

Мониторинг серверов Windows (WinRM), Linux (SSH) и сетевых устройств (ping).
• Полный опрос — каждые 5 минут
• Ping — каждые 30 секунд
• История — 30 дней в PostgreSQL

Выбери раздел ⤵️"""


HELP_START = """🚀 С ЧЕГО НАЧАТЬ

Порядок простой: добавить сервер → дождаться первого цикла (до 5 минут) →
проверить, что он зелёный в 🖥 Серверы.

━━━━━━━━━━━━━━━━━━━━
➕ КАК ДОБАВИТЬ СЕРВЕР

⚙️ Настройка → ➕ Добавить сервер. Бот спросит поля по очереди.
Обязательны только два: Имя и Host. Всё остальное — кнопка
«➡️ Пропустить» или ответ «-». В любой момент — «❌ Отмена».

Шаги мастера:
1. Имя — как сервер зовётся в боте. Уникальное, без двоеточий.
   ⚠️ Вся история метрик привязана к имени: переименуешь — история
   начнётся с нуля.
2. Host — IP или DNS-имя, тоже уникальное.
3. Тип — windows (по умолчанию) / linux / device. От него зависит,
   какие шаги бот спросит дальше.
4. Логин и пароль — если у сервера свои. Пропустишь — возьмутся общие
   из .env. Сообщение с паролем бот удаляет из чата сразу после обработки.
5. Сервисы — выбираются кнопками из списка типовых (MSSQL, IIS, Veeam,
   Hyper-V, 1С, nginx, docker…), можно и вписать свои через запятую.
6. Бэкапы sql / 1c / veeam, журналы 1С — пути к каталогам.
7. Остальное: DB Size, ретеншн, время алерта бэкапа, проверка размера,
   verify, reg-файл.

Для типа device мастер спросит только имя, host и тип — такому
устройству доступен лишь ping. Для linux пропускаются поля, которых
на Linux не бывает: DB Size, журналы 1С, ретеншн, verify, reg-файл.

━━━━━━━━━━━━━━━━━━━━
📦 NAS (SYNOLOGY) — ТАК ЖЕ, ЧЕРЕЗ linux

Хранилище, куда копии приезжают по FTP, заводится обычным сервером
с типом linux — и его каталоги бэкапов бот читает по SSH.

1. В DSM: Панель управления → Терминал и SNMP → включить SSH.
2. Зайти по SSH и узнать реальные пути: ls /volume1 (шары бывают на
   разных томах — /volume1, /volume4 и т.д.).
3. Добавить сервер: тип linux, в SQL backup — пути вида
   /volume1/backup/база1, /volume4/base1/база2

⚠️ Регистр важен: /volume1/1ast/Buh и /volume1/1ast/buh — РАЗНЫЕ пути.
⚠️ Указывай каждую базу отдельным путём, а не корень шары: свежесть
   считается по самому новому файлу внутри пути, и одна живая база
   в корне замаскирует десяток мёртвых.

Служебные папки Synology (@eaDir, #recycle, .snapshot) бот пропускает
сам — иначе удалённая копия из корзины считалась бы живой.

━━━━━━━━━━━━━━━━━━━━
✏️ КАК ИЗМЕНИТЬ СЕРВЕР

⚙️ Настройка → ✏️ Изменить сервер → выбрать сервер → выбрать поле →
прислать новое значение. «-» очищает поле.

Правится по одному полю за раз — остальные не трогаются.
Отдельно про пути бэкапов: можно прислать ТОЛЬКО тот путь, который
меняешь, — остальные сохранённые пути не пропадут. Чтобы стереть путь
или пересобрать список, сначала пришли «-», потом полный новый список.

━━━━━━━━━━━━━━━━━━━━
🛟 ЕСЛИ ЧТО-ТО ПОШЛО НЕ ТАК

Конфиг проверяется ПЕРЕД записью (обязательные поля, типы, дубли имён
и host). Не прошло проверку — бот покажет ошибку и ничего не запишет.
Запись атомарная, прошлая версия остаётся в servers.json.bak.
Монитор подхватывает изменения в течение 5 минут — перезапускать
контейнеры не нужно."""


HELP_MENU = """📂 ГЛАВНОЕ МЕНЮ

🖥 Серверы — карточка сервера:
   • статус, CPU/RAM, диски
   • бэкапы: диск, путь, размер, дата свежего файла
   • сервисы (docker — контейнеры и порты, nginx/apache — сайты)
   • топ процессов по CPU и памяти
   • кнопки: 🔄 Обновить · 📈 График · ♻️ Перезагрузить

📊 Дашборд — вся инфраструктура одним HTML-файлом: кольцо свободного
   места на худшем диске, спарклайны CPU/RAM за сутки, статус.
   Проблемные серверы — сверху, они же показаны сразу; кнопки
   «Требуют внимания · Все · В норме» переключают список.
   Тап по карточке разворачивает замечания, все диски и пик CPU.
   Вкладки: Серверы · Windows · SQL · Бэкапы · IIS.
   • Windows и SQL — журналы за сутки: счётчики по категориям
     и записи с кодом и расшифровкой. Собирает монитор раз в час,
     живьём при открытии ничего не читается.
   • Бэкапы — сводка сверху, тап по серверу разворачивает пути.
   • IIS — сканирование извне, вход в 1С, ошибки 5xx, медленные
     запросы, публикации без трафика, HTTPERR. Если серверов с
     IIS несколько, вверху вкладки чипы для переключения.
   Красное число на вкладке — сколько там критичного.
   Файл открывается прямо в Telegram и работает без сети и без
   скриптов. Тема: ◐ системная · ☀ светлая · ☾ тёмная.

📡 Пинг — сервер из списка или произвольный IP. В карточке: IP,
   до которого дорезолвилось имя, статус, средний отклик с мин/макс,
   потери пакетов, оценка качества связи и таблица ответов
   со столбиком задержки. Имя сервера можно набрать и руками:
   /ping sql-01 — оно узнаётся по конфигу.

   Под карточкой — ряд «📡 Пинг · 🔌 Порты · 🌐 HTTP» по той же
   цели, текущая проверка помечена точкой:
   • 🔌 Порты — TCP-проверка (1433, 3389, 5985, 80/443, SSH —
     берутся из полей сервера). ❌ значит «служба не слушает»,
     ⏱ — «ответа нет, похоже на файрвол». Для непрошедших портов
     появляются кнопки 🔁 — перепроверка одного порта с большим
     таймаутом; ✏️ Свой порт — проверить любой номер.
   • 🌐 HTTP — код ответа, время, редиректы и срок TLS-сертификата,
     который сервер реально отдаёт клиенту.
   ◀️ К списку серверов — вернуться к выбору цели.

📋 Отчёт — по всем серверам, кнопками переключается вид:
   • 🔎 Кратко — не на связи и вышедшее за пороги; здоровые
     серверы одной строкой (открывается сразу этот вид)
   • 📋 Подробно — строка на сервер: CPU, память, худший диск
   • 📄 Полный — все метрики и все диски подряд
   Пороги: CPU и память 70/90% занято, диск — меньше 20/10%
   свободного. Только вручную: по расписанию вместо текста
   приходит сводка — дашборд и графики бэкапов (08:00 и 18:00).

🌐 IIS — в карточке сервера с IIS: сканирование извне, вход в 1С,
   ошибки 5xx, медленные запросы, публикации, HTTPERR. Данные уже
   собраны монитором, раздел открывается мгновенно. Период
   переключается: 24 часа или 7 дней.

🚨 Проблемы — сводка критичного без захода в каждую карточку:
   офлайн, устаревшие данные, мало места, упавшие сервисы,
   проблемы бэкапов (копия старше 72 ч — уже красная,
   порог BACKUP_CRIT_HOURS), журналы 1С. Сначала счётчики по категориям
   («💾 Бэкапы: 27 на 5 серверах · худший 10.5 дн»), под ними —
   кнопка на каждый сервер с числом замечаний. Нажатие
   раскрывает разбор по серверу, ◀️ К сводке возвращает назад.

💾 Бэкапы — Health, Report, DB Size, рост, очистка, verify, дайджест.

⚙️ Настройка — серверы, mute, база мониторинга, аудит, справка.

━━━━━━━━━━━━━━━━━━━━
⌨️ КОМАНДЫ

/start — меню
/servers · /dashboard · /report · /problems
/ping IP — пинг любого адреса
/graph SERVER 7d — график (12h, 24h, 7d… до 30 дней)
/mute SERVER · /unmute SERVER · /mutes
/pgsize — размер БД мониторинга
/pgcleanup — ручная очистка истории"""


HELP_SERVERS = """🖧 ТИПЫ СЕРВЕРОВ И ПОЛЯ

• windows — опрос по WinRM (порт 5985), логин/пароль из .env или свой.
  Нужен пользователь с правами админа и включённый WinRM
  (winrm quickconfig, NTLM).
• linux — опрос по SSH (paramiko): диски, CPU/RAM, systemd, docker,
  nginx/apache, SMART. Аутентификация паролем или ключом (ssh_key),
  порт — ssh_port (по умолчанию 22). Для перезапуска сервисов и
  перезагрузки нужен sudo без пароля.
  Сюда же заводится NAS (Synology и т.п.): бэкап-каталоги на нём
  читаются по SSH и задаются в мастере так же, как на Windows —
  путями вида /volume1/backup/... Не работают только Windows-вещи:
  DB Size, журналы 1С, ретеншн, verify и reg-файл — мастер их для
  linux не спрашивает, а монитор пропускает.
  Службы Synology есть в пресетах кнопками (ftpd, sshd, SMB,
  synostoraged, synocrond, synoscgi) — имена юнитов у DSM свои,
  обычные ssh/cron/smbd там не существуют.
  Для SMART и температуры дисков нужен sudo без пароля на smartctl —
  иначе они просто не собираются (в логе будет сказано, почему).
• device — коммутатор/шлюз/принтер/камера: только ping и алерт падения,
  полный опрос и перезагрузка не поддерживаются.
• vmware — vCenter или отдельный ESXi, опрос по HTTPS (порт 443).
  Датасторы идут как обычные диски, ВМ из списка «Сервисы» — как
  службы, плюс алерты по снапшотам. Подробнее — раздел 🖥 VMware.

━━━━━━━━━━━━━━━━━━━━
📋 ПОЛЯ СЕРВЕРА

Имя — уникальное, без двоеточий; к нему привязана история.
Host — IP или hostname, уникальный.
Логин / Пароль — свои для этого сервера, иначе общие из .env.
Сервисы — Windows-службы или systemd-юниты под контролем.
  Для 1С хватит базового имени: вариант «(x86-64)» подхватится сам,
  и следим именно за ним, а не за мёртвой 32-битной службой.
Бэкапы sql / 1c / veeam — каталоги с копиями (см. раздел 💾 Бэкапы).
Журналы 1С — каталоги журнала регистрации, контроль размера.
Пороги пути (📏 Пороги) действуют и на алерт, и на 🚨 Проблемы:
источник один. Без своих порогов берутся общие: 5 / 10 ГБ.
   Пороги правятся кнопкой 📏 Пороги в карточке пути; при
   добавлении их можно задать сразу: путь=100/150 (ГБ,
   предупреждение/критично), путь=100 — только предупреждение.
   Незаданный порог берётся общий (5 и 10 ГБ), и предупреждение
   обязано быть меньше действующего критичного: иначе критичный
   сработает первым и предупреждения не будет вовсе.

Бэкапы и журналы 1С открывают список путей: строка на путь со
   всеми его настройками и кнопка на каждый. В карточке пути —
   ⏱ Порог часов, 🗓 Расписание (день и час выбираются кнопками),
   🔍 Размер, 📄 .trn, 🗑 Удалить путь. Порог часов и расписание
   заменяют друг друга: у недельной копии возраст файла не
   проверяется вовсе. С экрана ввода часов есть кнопка
   🗓 Раз в неделю. Добавление осталось
   текстовым: несколько путей одним сообщением быстрее.
   Строка «🗓 расписание: нет» показывается всегда — видно, что
   путь проверяется по возрасту, а не по недельному дедлайну.
   Повторы одного пути (регистр и слэши не в счёт) показываются
   один раз; если они есть в servers.json, под списком
   появляется предупреждение и кнопка 🧹 Убрать дубли.
DB Size — на сервере есть MSSQL: собираются размеры баз и открывается
  кнопка 🗄 SQL-логи в карточке (см. раздел 🗄 SQL-логи).
Exchange — это почтовый сервер: открывает кнопку 📧 Почта (входы в OWA,
  неудачные пароли, мобильные клиенты).
Ретеншн (дней) — автоудаление старых копий, минимум 3.
Алерт бэкапа (часов) — через сколько часов без свежей копии слать алерт.
Проверка размера — ловить подозрительно маленький бэкап.
Verify backup — ежесуточный RESTORE VERIFYONLY последнего .bak.
Reg-файл — .reg на самом сервере, импортируется перед перезагрузкой.

━━━━━━━━━━━━━━━━━━━━
♻️ ПЕРЕЗАГРУЗКА СЕРВЕРА

Кнопка в карточке сервера, с подтверждением, только для тех, кому
разрешены опасные действия. Windows — shutdown /r, Linux — sudo
shutdown -r, device — не поддерживается.
Если задан reg-файл, бот сперва импортирует его в реестр и
перезагружает ТОЛЬКО при успешном импорте; иначе отменяет перезагрузку."""


HELP_ALERTS = """🔔 АЛЕРТЫ

Приходят сами, без запроса. О проблеме, которая никуда не делась,
бот напоминает каждые 3 часа (ALERT_REPEAT_HOURS в .env, 0 —
не напоминать). Смена уровня отправляется сразу. В тихие часы
повторы не поднимаются, восстановления не повторяются вовсе,
а принятые алерты молчат.

Кнопка ✅ Принято под алертом глушит именно его (проблема + объект)
на сутки, а не сервер целиком: причина устранена, а источник ещё
отдаёт старые записи. Срок — ALERT_ACK_HOURS.

Кнопка ✅ Принял в карточке сервера (🚨 Проблемы → сервер) — то же
для всех его замечаний и навсегда: они уходят из сводки и не приходят
алертами. Для того, что не чинится за сутки: диск списанной ВМ. Новое
замечание на этом сервере придёт как обычно.

Список принятых и возврат — ⚙️ Настройка → ✅ Принятые алерты.

Что ловится:
• падение и восстановление сервера: ping молчит 2 минуты подряд
  (PING_FAIL_SECONDS в .env). Пока сервер лежит, пинг идёт каждые
  10 секунд вместо 30 — возврат в строй виден почти сразу
• недоступность по WinRM/SSH с разбором причины
  (логин, доступ, таймаут, DNS, отказ соединения)
• мало места на диске: свободно < 15% / 10% / 5%
  (только на ухудшение, с запасом 2%, чтобы не дребезжало у границы).
  Разделы ядра Linux (/sys, /proc, /dev, /run) и всё меньше 1 ГБ
  дисками не считаются: efivars всегда заполнен. Диск без свежих
  метрик пропадает из отчёта через 2 часа
• Windows-служба или systemd-юнит не запущен / восстановлен
• Docker: контейнер остановлен, крутится в перезапуске, unhealthy,
  пропал или снова поднялся
• SMART: физический диск нездоров
• ❌ БЭКАП НЕ ВЫПОЛНЕН — сбой копирования по данным самого SQL
  (ошибка движка или упавший шаг джоба Agent). Приходит в ту же ночь,
  а проверка по файлам ждёт backup_alert_hours и причину не называет.
  Только для серверов с включённым DB Size
• 🚨 RAID деградирован (Linux/NAS): выпал диск из массива. Отдельно
  сообщается о начале пересборки (процент и оценка времени) и о
  возврате в норму. Читается из /proc/mdstat без root, в отличие от
  SMART. Для хранилища бэкапов это самый важный алерт: развал массива
  не виден ни по месту, ни по SMART отдельного диска
• 📉 место скоро кончится — по тренду за 2 недели: «−12 ГБ/сут, хватит
  на 9 дней». Обычный порог говорит «плохо сейчас», этот — «когда
  станет плохо»: 20% свободного и упор в потолок за неделю.
  Порог — DISK_FORECAST_ALERT_DAYS в .env
• 🌡 перегрев диска (Linux): 50°C предупреждение, 60°C критично
• часы сервера разошлись с монитором больше чем на 2 минуты (NTP)
• бэкапы: устарел, каталог пуст, подозрительно маленький, verify
• недельная копия не появилась к сроку — в тот же день, с допуском
  24 ч (BACKUP_WEEKLY_GRACE_HOURS). В расписании указывай время,
  к которому копия ГОТОВА, а не старт задания
• журнал регистрации 1С разросся сверх порога

CPU и RAM в Telegram НЕ шлются намеренно — иначе канал зашумляется.
Их видно в карточке сервера и на графиках.

Кнопки под алертом:
   🔄 Проверить сейчас · 📈 График · 🔇 Тихо на 1 час
   📂 Топ каталогов (список + диаграмма)
   🔁 Перезапустить сервис (с подтверждением)

Тишина, mute и куда приходят алерты — раздел 🔕 Тишина и доставка."""


HELP_QUIET = """🔕 ТИШИНА И ДОСТАВКА

🔕 MUTE (ЗАГЛУШИТЬ СЕРВЕР)

⚙️ Настройка → 🔕 Mute алертов: на 1 час, на 8 часов или насовсем.
Кнопка «🔇 Тихо на 1 час» прямо под алертом — то же самое.
Командами: /mute SERVER, /unmute SERVER, /mutes — список заглушённых.
Временный mute истекает сам.

━━━━━━━━━━━━━━━━━━━━
🌙 ТИХИЕ ЧАСЫ

Задаются QUIET_HOURS в .env (время Алматы), например 23:00-07:00.
Ночью бот молчит ПОЛНОСТЬЮ: все алерты копятся и приходят утром одной
сводкой. Исключений нет — падение сервера, SMART и бэкапы тоже ждут
утра. За 15 минут до начала бот предупредит, что уходит в тишину.
Пусто в .env — тихие часы выключены.

━━━━━━━━━━━━━━━━━━━━
📬 КУДА ПРИХОДЯТ АЛЕРТЫ

Задан TELEGRAM_GROUP_ID — всё уходит в группу, личка остаётся только
каналом команд. Не задан — всё приходит в личку владельца.

Если группа недоступна (неверный ID, бота удалили из чата), алерт не
теряется: он придёт в личку владельца с пометкой о проблеме. Если ID
сменился (группа стала супергруппой), бот подхватит новый ID из ответа
Telegram, дошлёт туда и напишет в лог, что прописать в .env."""


HELP_TIMING = """⏰ РАСПИСАНИЯ И ОТЧЁТЫ

Что происходит само, без твоего участия (время — Алматы):

• каждые 30 секунд — ping всех серверов (все разом, а не по очереди);
  пока кто-то не отвечает — каждые 10 секунд, чтобы не проспать ни
  падение, ни возврат в строй
• каждые 5 минут — полный опрос: диски, CPU/RAM, службы, процессы,
  Docker, SMART, часы. Сервер, не ответивший по WinRM/SSH, повторяется
  через 30 секунд отдельным проходом — очередь остальных он не держит
• каждые 30 минут — обход каталогов бэкапов, размеры баз и журналов 1С
  (BACKUP_SCAN_MINUTES в .env; 0 — каждый цикл). Копия появляется раз
  в сутки, а обход каталога на NAS — это десятки тысяч файлов в выдаче
• раз в час — сводка журналов Windows и SQL для дашборда
  (LOG_SCAN_MINUTES в .env). Живьём журналы читает только карточка
  сервера по кнопке, дашборд берёт готовое из базы
• раз в час — сводка IIS (IIS_SCAN_MINUTES): логи сайта дочитываются
  по смещению, поэтому шаг дешёвый. Признак сервера с IIS — служба
  W3SVC в списке services
• 08:00 и 18:00 — сводка: 📊 файл-дашборд по всей инфраструктуре и два
  графика бэкапов (🗂 свежесть по серверам, 📦 общий объём за 30 дней).
  Текстовый отчёт по расписанию НЕ шлётся — он длинный и читается редко;
  когда нужен, есть кнопка 📋 Отчёт и команда /report
• воскресенье 09:00 — недельный отчёт (вид «Подробно») + дайджест бэкапов
  (свежесть, прирост размеров, verify). Графики и дашборд туда не
  дублируются: они приходят утром и вечером
• раз в сутки — автоочистка бэкапов по ретеншу
• раз в сутки — RESTORE VERIFYONLY (час задаётся VERIFY_HOUR в .env)
• раз в сутки — удаление истории старше 30 дней из БД мониторинга.
  Списки служб и топ процессов чистятся через 3 дня: из них читается
  только последняя запись, а места они занимали больше всего
• раз в сутки — самоотчёт «монитор жив» (час — SELF_REPORT_HOUR),
  со сводкой: сколько серверов онлайн/офлайн

Долгие задачи (verify может идти до 2 часов на большой базе) крутятся
в отдельном потоке и не тормозят обычный опрос."""


HELP_VMWARE = """🖥 VMWARE (vCenter / ESXi)

Тип сервера vmware опрашивает vSphere по HTTPS, порт 443. Ни SSH,
ни агента на хостах не нужно — API включён всегда.

Одна запись = одна точка подключения. vCenter даёт сразу всю
инфраструктуру, отдельный ESXi — только себя.

━━━━━━━━━━━━━━━━━━━━
👤 УЧЁТНАЯ ЗАПИСЬ

Роль Read-only на корне vCenter и ОБЯЗАТЕЛЬНО галочка
«Propagate to children». Без неё права действуют только на сам
объект vCenter: подключение пройдёт, а список датасторов и ВМ
будет пустым — и это не выглядит как ошибка.

Завести можно в Administration → Single Sign On → Users and Groups,
домен vsphere.local. Для ESXi вне vCenter нужен локальный
пользователь на каждом хосте: доменные учётки там не работают.

Сертификат у vSphere почти всегда самоподписанный — тогда в мастере
на вопрос «Проверять сертификат» отвечай «нет».

Если подключение падает с SSL: UNEXPECTED_EOF_WHILE_READING — это
старый vCenter 6.0/6.5. Проверка сертификата тут ни при чём: включи
«Старый TLS» в карточке сервера.

━━━━━━━━━━━━━━━━━━━━
📊 ЧТО СОБИРАЕТСЯ

• датасторы — как обычные диски: пороги 15/10/5%, прогноз
  заполнения, графики
• хосты — память, загрузка CPU, uptime
• ВМ из списка «Сервисы» — погасшая ВМ даёт обычный алерт
• снапшоты — алерт по возрасту и размеру (пороги в мастере)
• проблемы платформы — недоступные датасторы, перевыделение
  тонких дисков, датчики железа, режим обслуживания

Бэкапов, verify, MSSQL и журналов 1С у этого типа нет — эти поля
мастер не спрашивает. Кнопки «Топ каталогов» под алертом датастора
тоже нет: датастор монитору не файловая система.

━━━━━━━━━━━━━━━━━━━━
📋 ЧТО ВИДНО В КАРТОЧКЕ

• 💽 ДИСКИ — датасторы
• 🖥 ХОСТЫ — каждый ESXi отдельно: CPU, RAM, uptime, режим
  обслуживания. Сверху карточки идёт агрегат по всей платформе,
  а здесь виден перекос между хостами
• 🧩 ВИРТУАЛЬНЫЕ МАШИНЫ — включённые по убыванию загрузки CPU,
  📸 у машин со снапшотами, ⚠️ Tools если гостевые утилиты не
  работают; выключенные собраны в одну строку
• 🖥 ТОП ВМ — топ по CPU и памяти"""


HELP_RIGHTS = """🔐 ПРАВА И БЕЗОПАСНОСТЬ

Кто вообще может пользоваться ботом:
• личка — только TELEGRAM_ALLOWED_USER_ID
• группа — TELEGRAM_GROUP_ID (туда же уходят алерты)

⚠️ Доступ в группе даётся по чату, а не по человеку: читать отчёты,
графики, список каталогов и глушить алерты может ЛЮБОЙ участник
группы. Держите в ней только тех, кому доверяете инфраструктуру.
Опасные действия так не открываются — см. ниже.

Опасные действия доступны ТОЛЬКО пользователям из
TELEGRAM_DELETE_USERS (задаётся в .env через запятую):
• удаление backup-файлов
• изменение конфига серверов
• перезапуск служб и перезагрузка сервера
• ручной запуск verify

Защиты, которые нельзя обойти из бота:
• удалять можно только файлы из backup-путей конфига и только
  расширения .bak, .trn, .dt, .zip
• Veeam не удаляется никогда
• подтверждение удаления привязано одноразовым токеном к конкретному
  предпросмотру и живёт 15 минут
• пароли серверов не пишутся в промежуточные файлы — берутся из
  конфига в момент действия
• сообщение с паролем бот удаляет из чата после обработки
• ретеншн не трогает самый свежий файл в каждом подкаталоге, даже
  если он старше порога, и игнорирует срок меньше 3 дней

📜 Аудит изменений (⚙️ Настройка) — кто и когда менял конфиг,
перезагружал серверы и запускал verify, с Telegram ID."""


HELP_DATA = """🗄 ДАННЫЕ И ОБСЛУЖИВАНИЕ

Всё хранится в PostgreSQL: статусы серверов, метрики дисков и
процессов, службы, метрики бэкапов, размеры баз, журналы 1С,
результаты verify, аудит конфига.

История — 30 дней, лишнее удаляется само раз в сутки. Это НЕ то же
самое, что ретеншн бэкапов: ретеншн удаляет файлы копий на самих
серверах, а тут чистится только база мониторинга.

⚙️ Настройка → 🐘 База мониторинга — размеры таблиц (/pgsize).
⚙️ Настройка → 🗑 Очистка истории — ручная чистка старше 20/25/30
дней, с предпросмотром и VACUUM ANALYZE (/pgcleanup).

━━━━━━━━━━━━━━━━━━━━
🗂 КОНФИГ

Конфиг серверов — config/servers.json. Правится из меню ⚙️ Настройка:
запись атомарная, с проверкой схемы и копией предыдущей версии в
servers.json.bak. Монитор перечитывает файл каждые 5 минут, так что
перезапускать контейнеры после правки не нужно.

Общие настройки (токен бота, доступы, WinRM/SSH, тихие часы, пороги
бэкапов) — в .env рядом с docker-compose.yml. Их правка требует
перезапуска контейнеров."""

HELP_BACKUPS = f"""💾 БЭКАПЫ

Бот не делает бэкапы сам — он следит за каталогами, куда их складывают
твои задания, и ругается, когда что-то пошло не так.

Каталоги читаются и на Windows (WinRM), и на Linux/NAS (SSH) — например
на Synology, куда копии приезжают по FTP.

⚠️ Сетевую папку, подключённую на Windows как диск (Y:, Z:), бот увидеть
НЕ может: подключённые диски живут только в сессии того пользователя,
который их подключил, а WinRM открывает свою. В проводнике диск виден, в
боте — «путь недоступен», и это не лечится переподключением. Правильно —
завести само хранилище отдельным сервером с type: linux и указать путь
на нём (/volume1/...). Для MSSQL то же самое: пишите бэкап по UNC
(\\\\сервер\\шара), а не по букве диска.

━━━━━━━━━━━━━━━━━━━━
📁 КАК ЗАДАТЬ ПУТИ

⚙️ Настройка → сервер → SQL / 1C / Veeam backup. Пути через запятую.

Форматы ввода:
• E:\\Backups — обычный путь, порог по возрасту общий
• E:\\Backups=40 — свой порог: алерт, если копии нет дольше 40 часов
• E:\\Full@пн:9 — копия раз в неделю, понедельник 09:00
  (можно и mon:9; дни: пн вт ср чт пт сб вс)
• E:\\Full@- — убрать недельное расписание

⚠️ Можно прислать ТОЛЬКО тот путь, который меняешь — остальные
сохранённые пути не пропадут. Стереть путь или пересобрать список:
сначала «-», потом полный новый список.

━━━━━━━━━━━━━━━━━━━━
⏰ КОГДА ПРИХОДИТ «БЭКАП УСТАРЕЛ»

Порог берётся по приоритету:
свой у пути (E:\\Backups=40) > «Алерт бэкапа» у сервера >
общий из .env (сейчас {os.getenv('BACKUP_ALERT_HOURS', '25')} ч)

🗓 У пути с недельным расписанием порог по возрасту НЕ применяется
вообще — иначе копия, которая делается раз в неделю, начинала бы
«устаревать» уже на вторые сутки. Такой путь оценивается только по
расписанию: если к плановому дню и часу новой копии не появилось,
придёт «ПРОПУЩЕНА НЕДЕЛЬНАЯ КОПИЯ».

Пустой каталог и недоступный путь — проблема при любых настройках.

━━━━━━━━━━━━━━━━━━━━
📊 РАЗДЕЛЫ МЕНЮ 💾 БЭКАПЫ

📊 Backup Health — светофор по всем серверам и путям: ✅ норма,
   🟠 предупреждение, 🔴 критично. У недельных путей подписано, когда
   ждём следующую копию.
📦 Backup Report — по серверу: путь, тип, файлы, размер, диапазон дат,
   свободное место на диске.
🗄 DB Size — размеры баз MSSQL (для серверов с включённым DB Size).
📈 Рост баз — график роста баз и backup-каталогов за 30 дней.
🧹 Cleanup — удаление старых файлов с предпросмотром и подтверждением.
🧪 Verify статус — результаты RESTORE VERIFYONLY за 7 дней и ручной
   запуск ▶️ Запустить сейчас (идёт в фоне, до 2 часов на большой базе;
   ботом можно пользоваться, не дожидаясь).
📋 Дайджест — сводка + тепловая карта свежести + график объёма.

━━━━━━━━━━━━━━━━━━━━
🔍 ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ

Проверка размера (переключатель у сервера) — сравнивает новый файл с
медианой предыдущих копий этого же пути. Заметно меньший файл — признак
обрыва копирования (например, по FTP), придёт «БЭКАП ПОДОЗРИТЕЛЬНО
МАЛЕНЬКИЙ». Включается сразу на все пути сервера; отключить для одного
пути — только через servers.json полем "size_check": false.
DIFF-каталоги не проверяются никогда: они растут неравномерно.

Verify backup — раз в сутки берётся самый свежий .bak и проверяется
RESTORE VERIFYONLY на MSSQL этого же сервера. Сбой — сразу алерт.

━━━━━━━━━━━━━━━━━━━━
🧹 РЕТЕНШН И ОЧИСТКА

Ретеншн (дней) у сервера — раз в сутки удаляет копии старше срока.
Только на Windows: на Linux/NAS этим занимается сам сервер.
Защиты: срок меньше 3 дней игнорируется, Veeam не трогается вообще,
и самый свежий файл не удаляется никогда — В КАЖДОМ подкаталоге, а не
один на весь путь (иначе при раскладке «папка на базу» уцелела бы копия
только одной базы).

Ручной 🧹 Cleanup: если каталогов несколько, бот спросит, где чистить,
и срок можно задать свой для каждого. Перед удалением — предпросмотр
со списком файлов. Подтверждение живёт 15 минут. Удалять могут только
пользователи с правами на опасные действия."""


# Разделы справки: порядок = порядок кнопок
HELP_SQLHEALTH = """🩺 СОСТОЯНИЕ БАЗ SQL

Разделы в меню 🗄 SQL под журналами. Показывают «сейчас», период к ним
не применяется.

📓 Журналы транзакций — размер LDF, модель восстановления и причина, по
  которой журнал не очищается. LOG_BACKUP означает Full без регулярного
  BACKUP LOG: самая частая причина внезапно кончившегося места.
🩺 CHECKDB — когда база последний раз проверялась на целостность. Дата
  1900-01-01 значит «ни разу». Требует прав sysadmin.
⏳ Что идёт сейчас — запросы дольше 5 секунд и блокировки: видно, какая
  сессия кого держит, из какой программы и с какого компьютера.
📦 Файлы БД — размеры и потолок роста. Отдельно те, что не смогут
  вырасти: автоприрост выключен или достигнут max_size. Такой файл
  встаёт, когда на диске ещё половина свободна.


Если прав нет, раздел пишет, какой роли не хватает; остальные разделы
продолжают работать.

━━━━━━━━━━━━━━━━━━━━
🔑 ПРАВА

Журналам транзакций и файлам БД хватает тех же прав, что и сбору
размеров баз. «Что идёт сейчас» требует VIEW SERVER STATE. CHECKDB
требует sysadmin: DBCC DBINFO иначе недоступен."""


HELP_EXCHANGE = """📧 ПОЧТА (EXCHANGE)

Кнопка в карточке сервера. Появляется, если в настройке сервера включён
флаг Exchange либо среди сервисов уже есть служба MSExchange* —
автоопределение работает само, флаг нужен, когда службы в конфиг не
заводили.

Данные читаются в момент нажатия, алертов отсюда не шлётся. Период
переключается кнопкой: 24 часа / 7 дней. Входов в почту сотни в сутки,
поэтому разделы показывают сводку со счётчиками, а не поток строк.

━━━━━━━━━━━━━━━━━━━━
📑 РАЗДЕЛЫ

🔓 Входы в OWA — кто заходил, с какого адреса и из какого браузера,
  сколько обращений и когда последнее.
🔒 Неверный пароль — кто ошибался, откуда и почему (неверный пароль,
  учётной записи нет, заблокирована).
📱 Мобильные — клиенты ActiveSync отдельно: телефон с устаревшим
  паролем стучится каждые пару минут и в общем списке зашумил бы всё.
🌍 Адреса — сводка по IP: откуда вообще ходят в почту.

━━━━━━━━━━━━━━━━━━━━
🗂 ОТКУДА ДАННЫЕ

Успешные входы — из журналов IIS сайта Default Web Site. Там есть путь
(/owa/, ActiveSync, EWS), адрес клиента и браузер. Каталог берётся из
настроек самого IIS, а не угадывается. Лог текущих суток IIS держит
открытым, поэтому файл читается с общим доступом; если какой-то файл
прочитать не удалось, в шапке будет сказано, что выборка неполная.

Неудачные — из журнала Security, событие 4625. Причина в том, что OWA
проверяет пароль сам, а не средствами IIS: при неудачной попытке поле
пользователя в логе IIS остаётся пустым, и имя есть только в Security.
Обратная сторона: там OWA, ActiveSync и EWS неразличимы — все они
приходят одним процессом w3wp.exe с типом входа 8.

━━━━━━━━━━━━━━━━━━━━
⚠️ ЕСЛИ ПУСТО

🔓 Входы пустые — скорее всего выключено ведение журналов IIS для сайта
  Default Web Site либо логи пишутся в другой каталог.
🔒 Неверный пароль пусто — не включён аудит входа. Команды и настройка
  через доменные политики — в разделе 📜 Логи Windows.

Чтение больших логов занимает до минуты: раздел заранее пишет об этом,
чтобы ожидание не выглядело зависанием.

Списки длинные, поэтому листаются кнопками ◀️ 2/3 ▶️ — внизу видно,
какие записи показаны и сколько всего. Листание берёт данные из памяти
и логи заново не читает; для свежих данных есть кнопка 🔄 Обновить.
После перезапуска бота старое сообщение листаться перестанет — раздел
нужно открыть заново."""


HELP_WINLOG = """📜 ЛОГИ WINDOWS

Кнопка в карточке любого Windows-сервера. Отвечает на вопрос, которого не
хватало мониторингу: сервер был офлайн — почему. Ping показывает факт,
журнал событий показывает причину.

Данные читаются в момент нажатия, алертов отсюда не шлётся. Период
переключается кнопкой: 24 часа / 7 дней. Каждое событие выводится с
расшифровкой кода, одинаковые записи схлопнуты со счётчиком.

━━━━━━━━━━━━━━━━━━━━
📑 РАЗДЕЛЫ

♻️ Перезагрузки — 6008 (прошлое завершение было неожиданным), 41
  (Kernel-Power: питание или зависание), 1074 (кто инициировал
  перезагрузку), 1076 (причина, указанная вручную), 6005/6006 (старт
  системы и штатное выключение).
🛠 Службы — 7031/7034 (служба завершилась неожиданно, с перезапуском и
  без), 7000/7009 (не смогла запуститься), 7011 (не ответила вовремя).
  Дополняет контроль служб: видно не только что служба лежит, но и что
  она падала и перезапускалась ночью.
💽 Диски — 7/11/51 (сбойные блоки, ошибки контроллера), 55 (повреждена
  структура NTFS, нужен chkdsk), 129/153 (хранилище не отвечает),
  52 (диск предупреждает об отказе). Ранние признаки того же, что ловят
  SMART и коды 823/825 в SQL, но с другой стороны.
🔐 Входы — неудачные входы в Windows (событие 4625): кто, с какого адреса
  или компьютера, каким способом (RDP, по сети, локально) и почему.
  Ловит перебор паролей по RDP: серия с одного адреса схлопывается в одну
  строку со счётчиком.
⚠️ Приложения — ошибки и критические события журнала Application.
🩺 Состояние — ждёт ли сервер перезагрузки после обновлений (частая
  причина «обновления ставятся, а толку нет»), истекающие сертификаты
  IIS/RDP за 60 дней и последние установленные обновления.

━━━━━━━━━━━━━━━━━━━━
🔑 ПРАВА

System и Application читаются той же учётной записью, что и остальной
опрос по WinRM. Для журнала Security (раздел 🔐 Входы) учётной записи
нужны права администратора или членство в группе Event Log Readers.

Если прав не хватает, раздел покажет ошибку, а не пустой список. Поэтому
пустой 🔐 Входы почти всегда означает другое: выключен аудит. Windows
пишет событие только при включённой политике.

Проверить, что сейчас:
auditpol /get /category:"Вход/выход"

Включить (cmd от администратора, действует сразу):
auditpol /set /subcategory:"Вход в систему" /success:enable /failure:enable
auditpol /set /subcategory:"Блокировка учетных записей" /failure:enable
auditpol /set /subcategory:"Другие события входа и выхода" /failure:enable

Первая строка — обязательная, она даёт событие 4625. Вторая — 4740,
блокировку учётной записи после серии попыток. Третья — отказы RDP,
которые не всегда попадают в основную подкатегорию.

Имена подкатегорий зависят от языка системы: на английской это
"Logon", "Account Lockout", "Other Logon/Logoff Events".

Если сервер в домене, локальный auditpol живёт до следующего обновления
политики — включать нужно в GPO: Конфигурация компьютера → Политики →
Конфигурация Windows → Параметры безопасности → Расширенная настройка
политики аудита → Вход/выход. Там же обязательно включить «Аудит:
принудительно переопределять параметры категории политики аудита
параметрами подкатегории» — без него расширенные настройки не
применяются. Полный набор подкатегорий и размер журнала — в readme."""


HELP_SQLLOG = """🗄 SQL-ЛОГИ

Кнопка в карточке сервера, у которого включён DB Size (он же признак
«здесь есть MSSQL»). Данные читаются в момент нажатия, ничего не
накапливается и алертов отсюда не шлётся.

Период общий для всех разделов, переключается кнопкой: 24 часа / 7 дней.

━━━━━━━━━━━━━━━━━━━━
🔐 ОШИБКИ ВХОДА

Кто, с какого адреса и на какую базу не смог войти. Коды состояния
расшифрованы: 5 — логина нет, 8 — неверный пароль, 7 — логин отключён,
18 — требуется смена пароля, 38/40 — нет доступа к базе, 58 — SQL-логин
при режиме «только Windows».

Серия схлопывается в строку со счётчиком по логину, адресу, базе и коду
сразу: один логин может ломиться в разные базы, и это разные проблемы.

Адрес берётся из [CLIENT] или [КЛИЕНТ] — на русской локали SQL пишет
второй вариант. Значение «local machine» означает подключение с самого
сервера: локальный процесс, задание или приложение, а не сеть. Если
адреса в записи нет вовсе, стоит «адрес не записан».

Если внизу предупреждение о пределе выборки — отказов за период больше,
чем показано, и число в шапке не полное.

━━━━━━━━━━━━━━━━━━━━
💾 ОШИБКИ БЭКАПА

Текст ошибки движка (включая ошибку ОС и путь) плюс упавший шаг джоба
Agent: что именно и где не сработало.

Из вывода шага вырезается служебная шапка: планы обслуживания идут через
dtexec и начинаются с полустраничного «Executed as user… Execute Package
Utility… Started… Progress…», а сама ошибка лежит дальше. Под записью
строкой с ↳ выводится причина: путь не найден, нет прав у службы SQL,
кончилось место, сетевой путь недоступен.

Если кроме шапки в истории ничего нет, так и написано: SQL Agent
сохраняет только первые ~1024 символа шага, и у длинного плана
обслуживания ошибка туда не помещается. Смотреть тогда в журнале плана
(Management → Maintenance Plans → View History) либо включить в шаге
джоба «Include step output in history».

Частый случай — путь на букве
сетевого диска (G:\\...): служба SQL работает под своей учётной записью
и подключённых в сессии дисков не видит, нужен UNC-путь \\\\сервер\\шара.

━━━━━━━━━━━━━━━━━━━━
⚠️ ОШИБКИ ДВИЖКА

Проверяются четыре вида записей, каждая выводится с пояснением:
• severity 17+ — не хватило ресурсов; 18 — внутренняя ошибка запроса;
  19 — исчерпан лимит SQL; 20-25 — фатально, соединение разорвано;
• 823 — диск не отдал страницу; 824 — страница повреждена (контрольная
  сумма не сошлась); 825 — прочиталась лишь с повтора, диск сыпется;
• ввод-вывод дольше 15 секунд — не успевает хранилище;
• взаимоблокировки — проблема в запросах приложения, не в сервере.
Также распознаются 9002 (журнал транзакций заполнен) и 1105 (кончилось
место в файловой группе). Одинаковые записи схлопнуты со счётчиком.

Пусто — не всегда «всё хорошо»: ERRORLOG обнуляется при перезапуске
службы SQL и по sp_cycle_errorlog, и тогда смотреть не в чем.

━━━━━━━━━━━━━━━━━━━━
🕒 ДЖОБЫ AGENT · 📼 КОПИИ ИЗ MSDB

Джобы — последние запуски с итогом и длительностью; видно и то, что джоб
вовсе не стартовал. Пустая история чаще означает не остановленный Agent,
а нехватку прав: без роли SQLAgentReaderRole в msdb учётная запись видит
только свои джобы, чужие молча не попадают в выборку. Раздел сам
подсказывает, какой из двух случаев произошёл. Копии из msdb — что сам SQL считает сделанным: база,
тип (Full/Diff/Log), размер, путь. Расхождение с файлами на диске значит,
что копию делал не SQL, и восстановление из неё не гарантировано.

━━━━━━━━━━━━━━━━━━━━
🔑 ПРАВА

Вход и Движок читают ERRORLOG — нужна роль securityadmin (или sysadmin).
Джобы требуют SQLAgentReaderRole в базе msdb, копиям хватает public.
CHECKDB требует sysadmin: DBCC DBINFO иначе недоступен."""


HELP_IIS = """🌐 IIS

Кнопка появляется у серверов, где среди services есть W3SVC.

Раздел ничего не читает по нажатию: суточный лог публикации 1С —
полмиллиона строк. Данные уже в базе, их дочитывает монитор раз в
час, читая логи ПО СМЕЩЕНИЮ — только то, что дописалось с прошлого
раза. Поэтому раздел открывается мгновенно, но показывает состояние
на момент последнего сбора.

━━━━━━━━━━━━━━━━━━━━
📑 РАЗДЕЛЫ

🔎 Сканирование — запросы мимо публикаций, кто и куда стучится и
  главное: отдал ли сервер содержимое. Находка — только ответ 200.
  Редиректы не считаются: сервер ничего не отдал, а на корень и на
  любой путь по 80-му порту редирект приходит всегда. robots.txt,
  sitemap.xml и favicon.ico тоже не находки — за ними ходят
  поисковые роботы.
🔑 Вход в 1С — платформа отвечает 402 на /<база>/e1cib/login, по этим
  ответам виден подбор пароля. Тревога: от 25 входов в час с адреса
  И отсутствие другой работы с него. Второе условие обязательно —
  столько же входов даёт сломавшийся клиент, который переподключается
  по кругу, но после входа он работает в базе.
💥 Ошибки 5xx — ошибки самого приложения, а не IIS. Запросы с
  127.0.0.1, ::1 и fe80:: считаются отдельно: это сервер проверяет
  сам себя, у Exchange такие ошибки штатны.
🐢 Медленные — запросы дольше IIS_SLOW_MS (10 секунд), кроме тех,
  что держат соединение по замыслу протокола: уведомления OWA,
  RPC-over-HTTP, MAPI, ActiveSync.
📚 Публикации — с трафиком и без. Публикация без трафика это открытая
  наружу точка входа без присмотра. Считаются пути первого уровня:
  owa/Calendar и EWS/bin — вложенные каталоги, а не публикации.
🚧 HTTPERR — то, чего в логе сайта нет вовсе: запрос отбракован ещё до
  IIS. Штатное закрытие простаивающих соединений в подробности не идёт.

━━━━━━━━━━━━━━━━━━━━
🔔 ЧТО ПОПАДАЕТ В АЛЕРТЫ

Три вещи и только они: сканер получил успешный ответ, идёт подбор
пароля, публикации были недоступны. Остальное — фон.

Сутки не рвутся о полночь: счётчики копятся в базе, и отчёт суммирует
последние 24 часа независимо от того, в каком файле лежали строки.

━━━━━━━━━━━━━━━━━━━━
🌍 ЕСЛИ САЙТ ЗА CLOUDFLARE

Тогда в логе виден адрес узла прокси, а не посетителя — такие адреса
помечаются «узел Cloudflare». Чтобы видеть настоящие, заведите в
логировании сайта пользовательское поле x-forwarded-for с источником
Request Header: X-Forwarded-For. Модуль подхватит его сам."""


HELP_SECTIONS = {
    "start":   ("🚀 С чего начать",        HELP_START),
    "menu":    ("📂 Меню и команды",       HELP_MENU),
    "servers": ("🖧 Серверы и поля",       HELP_SERVERS),
    "backups": ("💾 Бэкапы",               HELP_BACKUPS),
    "vmware":  ("🖥 VMware",               HELP_VMWARE),
    "alerts":  ("🔔 Алерты",               HELP_ALERTS),
    "quiet":   ("🔕 Тишина и доставка",    HELP_QUIET),
    "timing":  ("⏰ Расписания",            HELP_TIMING),
    "rights":  ("🔐 Права и защита",       HELP_RIGHTS),
    "sqllog":  ("🗄 SQL-логи",             HELP_SQLLOG),
    "sqlhealth": ("🩺 Состояние баз",      HELP_SQLHEALTH),
    "winlog":  ("📜 Логи Windows",         HELP_WINLOG),
    "exchange": ("📧 Почта",                HELP_EXCHANGE),
    "iis":     ("🌐 IIS",                  HELP_IIS),
    "data":    ("🗄 Данные и конфиг",      HELP_DATA),
}


async def show_acks(query):
    """Список принятых (подавленных) алертов с возможностью вернуть.

    Без такого списка подавление превращается в чёрную дыру: алерт молчит,
    и вспомнить, кто и что заглушил, негде.
    """
    items = await asyncio.to_thread(active_acks)
    if not items:
        text = ("✅ ПРИНЯТЫЕ АЛЕРТЫ\n\n"
                "Сейчас ничего не подавлено — все алерты приходят.\n\n"
                "Кнопка «Принято» появляется под каждым алертом и "
                "заглушает его на сутки. Кнопка «Принял» в карточке "
                "сервера (🚨 Проблемы) убирает его замечания навсегда — "
                "до возврата отсюда. И то и другое действует на конкретный "
                "алерт (сервер + объект), а не на весь сервер: для полной "
                "тишины есть mute.")
        keyboard = [[InlineKeyboardButton("◀️ Меню", callback_data="cfg_menu")]]
        await safe_edit_message(query, text, InlineKeyboardMarkup(keyboard))
        return

    lines = ["✅ ПРИНЯТЫЕ АЛЕРТЫ\n"]
    keyboard = []
    for item in items[:20]:
        if item.get("forever"):
            when = "навсегда (принято в карточке сервера)"
        else:
            until = datetime.fromisoformat(item["until"]).astimezone(ALMATY)
            when = f"до {until.strftime('%d.%m %H:%M')}"
        lines.append(f"• {item['key']}\n   {when}")
        keyboard.append([InlineKeyboardButton(
            f"🔔 Вернуть: {item['key'][:40]}",
            callback_data=f"cfg_unack:{item['digest']}")])
    keyboard.append([InlineKeyboardButton("◀️ Меню", callback_data="cfg_menu")])
    await safe_edit_message(query, "\n".join(lines),
                            InlineKeyboardMarkup(keyboard))


def help_menu_kb():
    keyboard, row = [], []
    for key, (title, _text) in HELP_SECTIONS.items():
        row.append(InlineKeyboardButton(title, callback_data=f"cfg_help:{key}"))
        if len(row) == 2:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([InlineKeyboardButton("◀️ Меню", callback_data="cfg_menu")])
    return InlineKeyboardMarkup(keyboard)


def help_section_kb():
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("◀️ К разделам", callback_data="cfg_help"),
        InlineKeyboardButton("🏠 Меню", callback_data="cfg_menu"),
    ]])


# ─── Входные точки для bot.py ────────────────────────────────

async def cmd_config_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not can_configure(update.effective_user):
        await update.message.reply_text(
            "⛔ Нет прав на изменение конфигурации.\n"
            "Доступ настраивается через TELEGRAM_DELETE_USERS."
        )
        return
    await update.message.reply_text(
        "⚙️ НАСТРОЙКА СЕРВЕРОВ\n\nВыбери действие:",
        reply_markup=menu_kb()
    )


# ─── Экраны меню путей ───────────────────────────────────────

def load_server_or_none(server_name: str):
    try:
        servers = load_config()
        return next((s for s in servers if s.get("name") == server_name), None)
    except Exception:
        return None


def update_path_items(server_name: str, field: str, items: list) -> tuple:
    """Пишет список путей целиком: в меню виден итоговый список, дозапись
    здесь только мешала бы удалять."""
    servers = load_config()
    server = next((s for s in servers if s.get("name") == server_name), None)
    if not server:
        return False, f"Сервер {server_name} не найден в конфиге"
    apply_field(server, field, items or None, merge=False)
    save_config(servers)
    return True, server.get("name")


async def show_paths_menu(query, context, field: str):
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    server = load_server_or_none(server_name)
    if not server:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return
    context.user_data.pop(STATE_KEY, None)
    items = field_items(server, field)
    duplicates = duplicate_paths_count(server, field)
    await safe_edit_message(
        query,
        paths_menu_text(server_name, field, items, duplicates),
        reply_markup=paths_menu_kb(server_name, field, items, duplicates)
    )


async def show_path_card(query, context, field: str, index: int):
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    server = load_server_or_none(server_name)
    if not server:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return
    items = field_items(server, field)
    if index >= len(items):
        await show_paths_menu(query, context, field)
        return
    context.user_data.pop(STATE_KEY, None)
    await safe_edit_message(
        query,
        path_card_text(server_name, field, items[index]),
        reply_markup=path_card_kb(field, index, items[index])
    )


# Общие пороги журналов 1С; те же значения — в monitor/backup_collector.py и
# bot/db.py, согласованность проверяется тестом.
# Общие пороги журнала 1С — из shared/onec_logs.py: мастер обязан проверять
# ровно то, по чему потом считают монитор и сводка проблем.
ONEC_DEFAULT_WARN_GB = ONEC_LOG_WARN_GB
ONEC_DEFAULT_CRIT_GB = ONEC_LOG_CRIT_GB


def onec_limits_conflict(entry) -> str:
    """Текст ошибки, если пороги журнала 1С противоречат друг другу.

    Проверяются действующие значения, а не заданные: незаданный порог берётся
    общий. Из-за этого «предупреждение 100 ГБ» без своего критичного было
    бессмысленным — критичный оставался общим (10 ГБ) и срабатывал первым.

    Ловится до записи: раньше конфликт всплывал в валидаторе конфига уже как
    «ошибка записи», без подсказки, что делать."""
    data = entry if isinstance(entry, dict) else {}
    warn, crit = data.get("warn_gb"), data.get("crit_gb")
    if warn is None and crit is None:
        return ""

    warn_value = float(warn) if warn is not None else ONEC_DEFAULT_WARN_GB
    crit_value = float(crit) if crit is not None else ONEC_DEFAULT_CRIT_GB
    if warn_value < crit_value:
        return ""

    warn_text = f"{_gb(warn_value)} ГБ" + ("" if warn is not None else " (общий)")
    crit_text = f"{_gb(crit_value)} ГБ" + ("" if crit is not None else " (общий)")
    return (
        f"⚠️ Предупреждение {warn_text} не меньше критичного {crit_text} — "
        f"критичный сработает первым, и предупреждение не появится никогда.\n"
        f"Пришли оба числа сразу, например "
        f"{_gb(warn_value)}/{_gb(round(warn_value * 1.5, 1))}, "
        f"или «-», чтобы вернуть общие пороги "
        f"({ONEC_DEFAULT_WARN_GB} и {ONEC_DEFAULT_CRIT_GB} ГБ)."
    )


def _entry_dict(item) -> dict:
    return dict(item) if isinstance(item, dict) else {"path": item}


def _pack_entry(entry: dict):
    """Путь без настроек снова хранится строкой — так конфиг читается легче."""
    cleaned = {k: v for k, v in entry.items() if v is not None}
    return cleaned if len(cleaned) > 1 else cleaned.get("path")


async def change_path_entry(query, context, field: str, index: int, changes: dict):
    """Точечная правка одной настройки пути: пришло None — ключ снимается."""
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    server = load_server_or_none(server_name)
    if not server:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return
    items = field_items(server, field)
    if index >= len(items):
        await show_paths_menu(query, context, field)
        return

    entry = _entry_dict(items[index])
    for key, value in changes.items():
        if value is None:
            entry.pop(key, None)
        else:
            entry[key] = value
    items[index] = _pack_entry(entry)

    try:
        ok, result = await asyncio.to_thread(
            update_path_items, server_name, field, items
        )
    except Exception as e:
        ok, result = False, f"ошибка записи: {str(e)[:120]}"
    if not ok:
        await safe_edit_message(query, f"❌ {result}", reply_markup=menu_kb())
        return

    audit.log_config_change(
        query.from_user, "edit", server_name,
        f"{FIELD_DEFS[field]['label']}: {_path_str(items[index])} — "
        + ", ".join(f"{k}={v}" for k, v in changes.items())
    )
    await show_path_card(query, context, field, index)


async def delete_path_entry(query, context, field: str, index: int):
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    server = load_server_or_none(server_name)
    if not server:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return
    items = field_items(server, field)
    if index >= len(items):
        await show_paths_menu(query, context, field)
        return

    removed = _path_str(items.pop(index))
    try:
        ok, result = await asyncio.to_thread(
            update_path_items, server_name, field, items
        )
    except Exception as e:
        ok, result = False, f"ошибка записи: {str(e)[:120]}"
    if not ok:
        await safe_edit_message(query, f"❌ {result}", reply_markup=menu_kb())
        return

    audit.log_config_change(
        query.from_user, "edit", server_name,
        f"{FIELD_DEFS[field]['label']}: удалён путь {removed}"
    )
    await show_paths_menu(query, context, field)


async def ask_path_value(query, context, field: str, index: int, mode: str):
    """Значение, которого кнопками не наберёшь (часы, пороги), спрашиваем
    текстом — но по одному, без синтаксиса «=» и «@»."""
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    server = load_server_or_none(server_name)
    if not server:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return
    items = field_items(server, field)
    if index >= len(items):
        await show_paths_menu(query, context, field)
        return

    context.user_data[STATE_KEY] = {
        "mode": mode, "server": server_name, "field": field, "idx": index,
    }
    if mode == "path_hours":
        prompt = ("⏱ Пришли порог возраста в часах (число от 1 до 720).\n"
                  "«-» — вернуть общий порог сервера.\n\n"
                  "Копия раз в неделю задаётся не здесь: у такого пути возраст "
                  "файла не проверяется вовсе, вместо него — день и час "
                  "плановой копии. Кнопка 🗓 Раз в неделю ниже.")
    else:
        prompt = ("📏 Пришли пороги размера в гигабайтах: "
                  "предупреждение/критично, например 100/150.\n"
                  "Одно число задаёт только предупреждение, "
                  "«-» — вернуть общие пороги (5 и 10 ГБ).")

    keyboard = []
    if mode == "path_hours":
        keyboard.append([
            InlineKeyboardButton("🗓 Раз в неделю",
                                 callback_data=f"cfg_psch:{field}:{index}")
        ])
    keyboard.append([
        InlineKeyboardButton("❌ Отмена", callback_data=f"cfg_p:{field}:{index}")
    ])
    await safe_edit_message(
        query,
        f"📁 {_path_str(items[index])}\n\n{prompt}",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def ask_path_add(query, context, field: str):
    server_name = context.user_data.get(EDIT_SERVER_KEY)
    if not server_name:
        await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
        return
    context.user_data[STATE_KEY] = {
        "mode": "path_add", "server": server_name, "field": field,
    }
    await safe_edit_message(
        query,
        f"➕ {server_name} · {FIELD_DEFS[field]['label']}\n\n"
        f"{FIELD_DEFS[field]['prompt']}\n\n"
        "Уже добавленные пути останутся: перечисленные допишутся или "
        "обновятся. Настройки каждого пути потом правятся кнопками.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("❌ Отмена", callback_data=f"cfg_plist:{field}")
        ]])
    )



async def config_callback(query, context: ContextTypes.DEFAULT_TYPE):
    if not can_configure(query.from_user):
        await safe_edit_message(query, "⛔ Нет прав на изменение конфигурации.")
        return

    data = query.data

    if data == "cfg_acks":
        await show_acks(query)
        return

    if data.startswith("cfg_unack:"):
        digest = data.split(":", 1)[1]
        key = await asyncio.to_thread(unack_alert, digest)
        await query.message.reply_text(
            f"🔔 Алерт снова включён: {key or 'неизвестный'}")
        await show_acks(query)
        return

    if data == "cfg_menu":
        context.user_data.pop(STATE_KEY, None)
        await safe_edit_message(query, "⚙️ НАСТРОЙКА СЕРВЕРОВ\n\nВыбери действие:",
                                reply_markup=menu_kb())

    elif data == "cfg_add":
        await start_wizard(query, context)

    elif data == "cfg_skip":
        state = context.user_data.get(STATE_KEY)
        if not state or state.get("mode") != "wizard":
            await safe_edit_message(query, "❌ Мастер неактивен.", reply_markup=menu_kb())
            return
        key = (state.get("order") or WIZARD_ORDER)[state["step"]]
        if key in REQUIRED_FIELDS:
            return

        async def send(text, kb):
            await safe_edit_message(query, text, reply_markup=kb)
        await wizard_advance(context, send, None)

    elif data == "cfg_cancel":
        context.user_data.pop(STATE_KEY, None)
        await safe_edit_message(query, "⚙️ НАСТРОЙКА СЕРВЕРОВ\n\nВыбери действие:",
                                reply_markup=menu_kb())

    elif data == "cfg_add_confirm":
        await wizard_confirm(query, context)

    elif data == "cfg_edit_list":
        context.user_data.pop(STATE_KEY, None)
        await show_edit_list(query, context)

    elif data.startswith("cfg_editsrv_servers:"):
        page = int(data.split(":", 1)[1])
        await show_edit_list(query, context, page=page)

    elif data.startswith("cfg_editsrv:"):
        context.user_data.pop(STATE_KEY, None)
        await show_server_editor(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_delete_confirm:"):
        await delete_server(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_delete:"):
        await ask_delete_confirm(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_svc:"):
        state = context.user_data.get(STATE_KEY)
        if not state or "svc" not in state:
            await safe_edit_message(query, "❌ Выбор сервисов неактивен.", reply_markup=menu_kb())
            return
        unit = data.split(":", 1)[1]
        if unit in state["svc"]:
            state["svc"].remove(unit)
        else:
            state["svc"].append(unit)
        text, kb = services_view(state)
        await safe_edit_message(query, text, reply_markup=kb)

    elif data == "cfg_svc_done":
        state = context.user_data.get(STATE_KEY)
        if not state or "svc" not in state:
            await safe_edit_message(query, "❌ Выбор сервисов неактивен.", reply_markup=menu_kb())
            return
        selected = list(state["svc"]) or None

        if state["mode"] == "wizard":
            async def send(text, kb):
                await safe_edit_message(query, text, reply_markup=kb)
            await wizard_advance(context, send, selected)
        else:
            server_name = state["server"]
            try:
                saved, result = update_server_field(server_name, "services", selected)
            except Exception as e:
                saved, result = False, f"ошибка записи: {str(e)[:120]}"
            context.user_data.pop(STATE_KEY, None)
            if not saved:
                await safe_edit_message(query, f"❌ {result}", reply_markup=menu_kb())
                return
            audit.log_config_change(
                query.from_user, "services", server_name,
                ", ".join(selected) if selected else "очищено"
            )
            await show_server_editor(query, context, server_name)

    elif data.startswith("cfg_f:"):
        await ask_edit_field(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_plist:"):
        await show_paths_menu(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_padd:"):
        await ask_path_add(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_pdedup:"):
        field = data.split(":", 1)[1]
        server_name = context.user_data.get(EDIT_SERVER_KEY)
        server = load_server_or_none(server_name)
        if not server:
            await safe_edit_message(query, "❌ Сервер не выбран.", reply_markup=menu_kb())
            return
        removed = duplicate_paths_count(server, field)
        try:
            ok, result = await asyncio.to_thread(
                update_path_items, server_name, field, field_items(server, field)
            )
        except Exception as e:
            ok, result = False, f"ошибка записи: {str(e)[:120]}"
        if not ok:
            await safe_edit_message(query, f"❌ {result}", reply_markup=menu_kb())
            return
        audit.log_config_change(
            query.from_user, "edit", server_name,
            f"{FIELD_DEFS[field]['label']}: убрано повторов — {removed}"
        )
        await show_paths_menu(query, context, field)

    elif data.startswith("cfg_pclear:"):
        field = data.split(":", 1)[1]
        server_name = context.user_data.get(EDIT_SERVER_KEY)
        try:
            ok, result = await asyncio.to_thread(
                update_path_items, server_name, field, []
            )
        except Exception as e:
            ok, result = False, f"ошибка записи: {str(e)[:120]}"
        if not ok:
            await safe_edit_message(query, f"❌ {result}", reply_markup=menu_kb())
            return
        audit.log_config_change(query.from_user, "edit", server_name,
                                f"{FIELD_DEFS[field]['label']}: очищено")
        await show_paths_menu(query, context, field)

    elif data.startswith("cfg_p:"):
        _, field, index = data.split(":", 2)
        await show_path_card(query, context, field, int(index))

    elif data.startswith("cfg_pdel:"):
        _, field, index = data.split(":", 2)
        await delete_path_entry(query, context, field, int(index))

    elif data.startswith("cfg_ph:"):
        _, field, index = data.split(":", 2)
        await ask_path_value(query, context, field, int(index), "path_hours")

    elif data.startswith("cfg_plim:"):
        _, field, index = data.split(":", 2)
        await ask_path_value(query, context, field, int(index), "path_limits")

    elif data.startswith("cfg_psz:"):
        _, field, index = data.split(":", 2)
        index = int(index)
        server = load_server_or_none(context.user_data.get(EDIT_SERVER_KEY))
        items = field_items(server, field) if server else []
        current = (items[index].get("size_check")
                   if index < len(items) and isinstance(items[index], dict) else None)
        # общий → включена → выключена → снова общий
        nxt = SIZE_CHECK_CYCLE[(SIZE_CHECK_CYCLE.index(current) + 1)
                               % len(SIZE_CHECK_CYCLE)]
        await change_path_entry(query, context, field, index, {"size_check": nxt})

    elif data.startswith("cfg_plog:"):
        _, field, index = data.split(":", 2)
        index = int(index)
        server = load_server_or_none(context.user_data.get(EDIT_SERVER_KEY))
        items = field_items(server, field) if server else []
        current = (items[index].get("ignore_logs")
                   if index < len(items) and isinstance(items[index], dict) else None)
        await change_path_entry(query, context, field, index,
                                {"ignore_logs": None if current else True})

    elif data.startswith("cfg_psch:"):
        _, field, index = data.split(":", 2)
        index = int(index)
        server = load_server_or_none(context.user_data.get(EDIT_SERVER_KEY))
        items = field_items(server, field) if server else []
        if index >= len(items):
            await show_paths_menu(query, context, field)
            return
        schedule = path_schedule(items[index])
        current = (f"Сейчас: {weekday_label(schedule[0])}, {schedule[1]:02d}:00"
                   if schedule else "Сейчас: расписания нет, "
                                    "путь проверяется по возрасту файла")
        await safe_edit_message(
            query,
            f"🗓 {_path_str(items[index])}\n\n{current}\n\n"
            "Копия раз в неделю: выбери день, потом час. Порог возраста к "
            "такому пути не применяется — между плановыми копиями бэкап "
            "законно стареет почти на неделю.",
            reply_markup=schedule_days_kb(field, index, bool(schedule))
        )

    elif data.startswith("cfg_pday:"):
        _, field, index, day = data.split(":", 3)
        index = int(index)
        if day == "-":
            await change_path_entry(query, context, field, index,
                                    {"schedule_weekday": None,
                                     "schedule_by_hour": None})
            return
        await safe_edit_message(
            query,
            f"🗓 {weekday_label(day)} — в котором часу проверять?",
            reply_markup=schedule_hours_kb(field, index, day)
        )

    elif data.startswith("cfg_phour:"):
        _, field, index, day, hour = data.split(":", 4)
        # Недельная копия и порог по возрасту исключают друг друга
        await change_path_entry(query, context, field, int(index),
                                {"schedule_weekday": day,
                                 "schedule_by_hour": int(hour),
                                 "alert_hours": None})

    elif data.startswith("cfg_toggle:"):
        await toggle_field(query, context, data.split(":", 1)[1])

    elif data == "cfg_mute_menu":
        context.user_data.pop(STATE_KEY, None)
        await show_mute_menu(query, context)

    elif data == "cfg_mute_pick":
        await show_mute_pick(query, context)

    elif data.startswith("cfg_mutesrv_servers:"):
        await show_mute_pick(query, context, page=int(data.split(":", 1)[1]))

    elif data.startswith("cfg_mutesrv:"):
        await show_mute_duration(query, context, data.split(":", 1)[1])

    elif data.startswith("cfg_mutedo:"):
        _, hours, server_name = data.split(":", 2)
        await apply_mute(query, context, int(hours), server_name)

    elif data.startswith("cfg_unmute:"):
        server_name = data.split(":", 1)[1]
        muted = load_muted()
        muted.pop(server_name, None)
        save_muted(muted)
        print(f"[config] {query.from_user.id} включил алерты для {server_name}", flush=True)
        await show_mute_menu(query, context)

    elif data == "cfg_help":
        await safe_edit_message(query, HELP_INTRO, reply_markup=help_menu_kb())

    elif data.startswith("cfg_help:"):
        key = data.split(":", 1)[1]
        section = HELP_SECTIONS.get(key)
        if not section:
            await safe_edit_message(query, HELP_INTRO, reply_markup=help_menu_kb())
            return
        # Длинные разделы Telegram одним сообщением не примет
        chunks = split_message(section[1])
        await safe_edit_message(
            query, chunks[0],
            reply_markup=help_section_kb() if len(chunks) == 1 else None
        )
        for i, chunk in enumerate(chunks[1:], start=2):
            await query.message.reply_text(
                chunk,
                reply_markup=help_section_kb() if i == len(chunks) else None
            )

    elif data == "cfg_pgsize":
        await safe_edit_message(query, "⏳ Считаю размеры...")
        await pg_admin.show_pg_stats(query)

    elif data == "cfg_audit":
        await safe_edit_message(query, "⏳ Читаю аудит...")
        rows = await asyncio.to_thread(audit.get_recent_audit, 20)
        await safe_edit_message(
            query, audit.format_audit(rows),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("◀️ Меню", callback_data="cfg_menu")
            ]])
        )

    elif data == "cfg_pgclean_menu":
        await pg_admin.show_cleanup_menu(query)

    elif data.startswith("cfg_pgclean_do:"):
        days = int(data.split(":", 1)[1])
        await pg_admin.do_cleanup(query, days)

    elif data.startswith("cfg_pgclean:"):
        days = int(data.split(":", 1)[1])
        await safe_edit_message(query, "⏳ Считаю записи...")
        await pg_admin.show_cleanup_preview(query, days)


async def handle_path_text(update, context, state: dict, text: str, send) -> bool:
    """Текстовый ввод из меню путей: добавление списком, часы и пороги —
    по одному значению, без синтаксиса."""
    field, server_name = state["field"], state["server"]
    mode = state["mode"]
    cancel_to = (f"cfg_plist:{field}" if mode == "path_add"
                 else f"cfg_p:{field}:{state.get('idx', 0)}")

    def back_kb():
        return InlineKeyboardMarkup([[
            InlineKeyboardButton("❌ Отмена", callback_data=cancel_to)
        ]])

    if mode == "path_add":
        ok, value, error = parse_field_value(field, text)
        if not ok:
            await send(f"⚠️ {error}\nПопробуй ещё раз:", back_kb())
            return True
        if value is None:
            await send("⚠️ Пришли хотя бы один путь.", back_kb())
            return True
        try:
            servers = load_config()
            server = next((s for s in servers if s.get("name") == server_name), None)
            if not server:
                raise ValueError(f"Сервер {server_name} не найден в конфиге")
            apply_field(server, field, value)      # дозапись к существующим
            for item in field_items(server, field):
                conflict = onec_limits_conflict(item)
                if conflict:
                    await send(f"{_path_str(item)}\n{conflict}", back_kb())
                    return True
            save_config(servers)
        except Exception as e:
            await send(f"❌ ошибка записи: {str(e)[:120]}", menu_kb())
            context.user_data.pop(STATE_KEY, None)
            return True
        audit.log_config_change(
            update.effective_user, "edit", server_name,
            f"{FIELD_DEFS[field]['label']}: добавлено "
            + ", ".join(_path_str(item) for item in value)
        )
    else:
        index = state.get("idx", 0)
        stripped = (text or "").strip()
        if mode == "path_hours":
            if stripped in SKIP_INPUTS:
                changes = {"alert_hours": None}
            else:
                try:
                    hours = int(stripped)
                except ValueError:
                    await send("⚠️ Часы — это число от 1 до 720.", back_kb())
                    return True
                if not 1 <= hours <= 720:
                    await send("⚠️ Часы — от 1 до 720.", back_kb())
                    return True
                # Недельная копия проверяется по расписанию, а не по возрасту
                changes = {"alert_hours": hours, "schedule_weekday": None,
                           "schedule_by_hour": None}
        else:
            if stripped in SKIP_INPUTS:
                changes = {"warn_gb": None, "crit_gb": None}
            else:
                ok, value, error = parse_field_value(
                    "onec_logs", f"x={stripped}"
                )
                if not ok:
                    await send(f"⚠️ {error.replace('«x»', 'пути')}\n"
                               "Например: 100/150", back_kb())
                    return True
                entry = value[0] if value else {}
                changes = {"warn_gb": entry.get("warn_gb"),
                           "crit_gb": entry.get("crit_gb")}

        try:
            servers = load_config()
            server = next((s for s in servers if s.get("name") == server_name), None)
            if not server:
                raise ValueError(f"Сервер {server_name} не найден в конфиге")
            items = field_items(server, field)
            if index >= len(items):
                raise ValueError("путь уже удалён")
            entry = _entry_dict(items[index])
            for key, val in changes.items():
                if val is None:
                    entry.pop(key, None)
                else:
                    entry[key] = val

            conflict = onec_limits_conflict(entry)
            if conflict:
                await send(conflict, back_kb())
                return True

            items[index] = _pack_entry(entry)
            apply_field(server, field, items, merge=False)
            save_config(servers)
        except Exception as e:
            await send(f"❌ ошибка записи: {str(e)[:120]}", menu_kb())
            context.user_data.pop(STATE_KEY, None)
            return True
        audit.log_config_change(
            update.effective_user, "edit", server_name,
            f"{FIELD_DEFS[field]['label']}: {_path_str(items[index])} — "
            + ", ".join(f"{k}={v}" for k, v in changes.items())
        )

    context.user_data.pop(STATE_KEY, None)
    server = load_server_or_none(server_name)
    items = field_items(server, field) if server else []
    duplicates = duplicate_paths_count(server, field) if server else 0
    await send(
        "✅ Сохранено. Мониторинг подхватит изменения в течение 5 минут.\n\n"
        + paths_menu_text(server_name, field, items, duplicates),
        paths_menu_kb(server_name, field, items, duplicates)
    )
    return True



async def handle_config_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    Обрабатывает текстовый ввод для мастера/редактора.
    Возвращает True если сообщение обработано.
    """
    state = context.user_data.get(STATE_KEY)
    if not state:
        return False

    if not can_configure(update.effective_user):
        context.user_data.pop(STATE_KEY, None)
        return False

    text = update.message.text

    async def send(msg_text, kb):
        await update.message.reply_text(msg_text, reply_markup=kb)

    # Активен выбор Linux-сервисов кнопками: текст добавляет свои юниты
    if "svc" in state:
        ok, value, _ = parse_field_value("services", text)
        if ok and value:
            for unit in value:
                if unit not in state["svc"]:
                    state["svc"].append(unit)
        msg_text, kb = services_view(state)
        await update.message.reply_text(msg_text, reply_markup=kb)
        return True

    if state["mode"] == "wizard":
        order = state.get("order") or list(WIZARD_ORDER)
        key = order[state["step"]]
        existing = None
        if key == "name":
            try:
                existing = {s.get("name") for s in load_config()}
            except Exception:
                existing = set()

        ok, value, error = parse_field_value(key, text, existing_names=existing)
        if ok and value is None and key in REQUIRED_FIELDS:
            ok, error = False, "Это поле обязательно"

        if key == "password":
            try:
                await update.message.delete()
            except Exception:
                pass

        if not ok:
            await send(f"⚠️ {error}\n\n{wizard_prompt_text(state['step'], order)}", wizard_kb(key))
            return True

        await wizard_advance(context, send, value)
        return True

    if state["mode"] in ("path_add", "path_hours", "path_limits"):
        return await handle_path_text(update, context, state, text, send)

    if state["mode"] == "edit_field":
        field = state["field"]
        server_name = state["server"]
        existing = None
        if field == "name":
            try:
                existing = {s.get("name") for s in load_config() if s.get("name") != server_name}
            except Exception:
                existing = set()

        ok, value, error = parse_field_value(field, text, existing_names=existing)

        if field == "password":
            try:
                await update.message.delete()
            except Exception:
                pass

        if not ok:
            await send(f"⚠️ {error}\nПопробуй ещё раз («-» — очистить):", InlineKeyboardMarkup([[
                InlineKeyboardButton("❌ Отмена", callback_data=f"cfg_editsrv:{server_name}")
            ]]))
            return True

        try:
            saved, result = update_server_field(server_name, field, value)
        except Exception as e:
            saved, result = False, f"ошибка записи: {str(e)[:120]}"

        context.user_data.pop(STATE_KEY, None)
        if not saved:
            await send(f"❌ {result}", menu_kb())
            return True

        # result — актуальное имя (могло измениться при переименовании)
        context.user_data[EDIT_SERVER_KEY] = result
        user = update.effective_user
        label = FIELD_DEFS.get(field, {}).get("label", field)
        if field == "name" and result != server_name:
            details = f"переименование: {server_name} → {result}"
        elif field in ("password",):
            details = f"{label}: изменён"
        elif value is None:
            details = f"{label}: очищено"
        else:
            details = f"{label} = {display_value_for(result, field)}"
        audit.log_config_change(user, "edit", result, details)

        servers = load_config()
        server = next((s for s in servers if s.get("name") == result), None)
        if server is None:
            # Конфиг изменился между записью и перечиткой — сводку строить не из чего
            await send("✅ Сохранено, но сервер уже не найден в конфиге. "
                       "Открой ⚙️ Настройка заново.", menu_kb())
            return True
        await send(
            "✅ Сохранено. Мониторинг подхватит изменения в течение 5 минут.\n\n"
            + build_summary(server)
            + "\n\nНажми на поле чтобы изменить:",
            edit_fields_kb(server)
        )
        return True

    return False
