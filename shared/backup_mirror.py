"""
shared/backup_mirror.py

Сверка каталога-приёмника с каталогом-источником: «файл на регионе есть,
а сюда не доехал».

Зачем отдельно от обычной проверки возраста. Приёмник (сервер, куда
регионы заливают копии по SFTP) контролируется порогом alert_hours — то
есть «свежего файла нет уже N часов». Порог по природе поздний: чтобы
не звенеть на каждой задержке копирования, N ставят с запасом, и о том,
что копия не приехала, узнаёшь через сутки.

Источник знает точнее. Файл на регионе создан в 00:34 — значит задание
отработало, и через разумное время копия обязана появиться на приёмнике.
Не появилась через mirror_lag_minutes — это уже сбой копирования, и
сказать об этом можно в тот же цикл монитора (5 минут), а не назавтра.

Вторая находка — обрыв. По SFTP оборванная загрузка неотличима от
успешной: сервер не знает ожидаемого размера файла и видит только
закрытие соединения. Зато размер оригинала известен — сравнение
«приёмник против источника» ловит огрызок сразу, не накапливая историю
и не завися от медианы (для DIFF-копий медиана бессмысленна: они растут
всю неделю и обнуляются после очередной полной).

Модуль чистый: ни БД, ни сети, только два набора метрик на входе.
"""
from datetime import timedelta

from settings import int_env, float_env


# Сколько ждать копию после появления файла на источнике. Значение
# заведомо щедрое: база на 70 ГБ едет часами, а момент старта копирования
# отсюда не виден — планировщик на источнике запускается по своим часам.
# Когда копированием управляет сам бот (shared/backup_copy.py), этот
# порог не нужен вовсе: там известен момент старта, и ожидание считается
# от него, а сверка на время копирования просто молчит.
MIRROR_LAG_MINUTES = int_env("BACKUP_MIRROR_LAG_MINUTES", 180)

# Доля размера оригинала, ниже которой копия считается огрызком. Не 1.0:
# сравниваются файлы, замеренные разными опросами, и «ровно столько же»
# бывает не всегда (докачался хвост между замерами).
MIRROR_SIZE_RATIO = float_env("BACKUP_MIRROR_SIZE_RATIO", 0.98)

# Насколько свежими должны быть метрики источника, чтобы им верить. Если
# регион недоступен и последний опрос был вчера, «на источнике новее»
# ничего не значит: копия могла приехать, а данные протухли.
MIRROR_SOURCE_MAX_AGE_MINUTES = int_env("BACKUP_MIRROR_SOURCE_MAX_AGE_MINUTES", 60)

# Допуск на расхождение часов между источником и приёмником. Время файла
# берётся с каждого хоста своё; при копировании WinSCP переносит и
# LastWriteTime, поэтому у доехавшего файла метки совпадают, но пара
# минут расхождения возможна.
CLOCK_SKEW_MINUTES = 3


def mirror_spec(path_spec, default_type: str) -> dict:
    """Настройки сверки из элемента backups.<type> конфига.

    Ждём {"mirror_of": {"server": ..., "path": ..., "type": ...}} и
    необязательные mirror_lag_minutes / mirror_size_ratio. Возвращает
    None, если сверка у пути не настроена.
    """
    if not isinstance(path_spec, dict):
        return None
    source = path_spec.get("mirror_of")
    if not isinstance(source, dict):
        return None
    if not source.get("server") or not source.get("path"):
        return None

    lag = path_spec.get("mirror_lag_minutes")
    ratio = path_spec.get("mirror_size_ratio")
    return {
        "server": str(source["server"]),
        "path": str(source["path"]),
        "type": str(source.get("type") or default_type),
        "lag_minutes": int(lag) if lag is not None else MIRROR_LAG_MINUTES,
        "size_ratio": float(ratio) if ratio is not None else MIRROR_SIZE_RATIO,
    }


def mirror_findings(source: dict, dest: dict, spec: dict, now):
    """Что не так с копией. source/dest — {"newest_file", "newest_file_gb",
    "collected_at"} в naive-UTC, now — naive-UTC.

    Возвращает список находок: {"kind": "late"|"small", ...}. Пустой
    список — либо всё доехало, либо судить пока не по чему.
    """
    findings = []
    if not spec or not source:
        return findings

    src_newest = source.get("newest_file")
    if not src_newest:
        # На источнике вообще нет копий — это его собственная проблема,
        # её ловит проверка возраста самого источника. Здесь молчим,
        # иначе одна авария звенела бы дважды.
        return findings

    collected_at = source.get("collected_at")
    if collected_at is not None:
        age = (now - collected_at).total_seconds() / 60
        if age > MIRROR_SOURCE_MAX_AGE_MINUTES:
            return findings

    lag_minutes = (now - src_newest).total_seconds() / 60
    if lag_minutes < spec["lag_minutes"]:
        # Файл только что создан — копирование законно ещё идёт.
        return findings

    dst_newest = (dest or {}).get("newest_file")
    skew = timedelta(minutes=CLOCK_SKEW_MINUTES)
    if dst_newest is None or dst_newest < src_newest - skew:
        findings.append({
            "kind": "late",
            "source_newest": src_newest,
            "dest_newest": dst_newest,
            "lag_minutes": int(lag_minutes),
        })
        return findings

    # Копия на месте — смотрим, целиком ли. Размер сравниваем с самим
    # оригиналом, а не с историей: это единственный способ поймать обрыв
    # SFTP, который для сервера выглядит успехом.
    src_gb = source.get("newest_file_gb")
    dst_gb = (dest or {}).get("newest_file_gb")
    if src_gb and dst_gb is not None and dst_gb < src_gb * spec["size_ratio"]:
        findings.append({
            "kind": "small",
            "source_newest": src_newest,
            "dest_newest": dst_newest,
            "source_gb": float(src_gb),
            "dest_gb": float(dst_gb),
            "percent": round(float(dst_gb) / float(src_gb) * 100),
        })

    return findings
