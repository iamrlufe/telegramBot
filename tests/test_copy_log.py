"""Разбор журнала, который ведёт сам скрипт копирования.

Он знает то, чего не знает бот: сколько баз обошли, что залито, что
пропущено и на чём споткнулись. Образец — настоящий журнал с боевого
сервера, поэтому в нём есть и строки WinSCP без отметки времени.
"""
from datetime import datetime

from copy_log import (
    common_log,
    database_log,
    log_dir,
    parse_common_log,
    summary_lines,
)

DAY = datetime(2026, 9, 5)

SAMPLE = """[05.09.2026 11:17:42,07] ============================================
[05.09.2026 11:17:42,07] START upload_common.cmd
[05.09.2026 11:17:42,07] TYPE=FULL
[05.09.2026 11:17:42,08] Поиск каталогов FULL в D:\\backup\\AKT1C8
[05.09.2026 11:17:42,08] [new_pro_akt] [FULL] Каталог: D:\\backup\\AKT1C8\\new_pro_akt\\FULL
[05.09.2026 11:17:42,10] [new_pro_akt] [FULL] Найден файл: AKT1C8_new_pro_akt_FULL_20260905_094515.bak
[05.09.2026 11:17:42,10] [new_pro_akt] [FULL] Локальный размер: 47713517568 bytes
[05.09.2026 11:17:47,15] [new_pro_akt] [FULL] Размер стабилен: 47713517568 bytes
[05.09.2026 11:17:47,15] [new_pro_akt] [FULL] Проверка remote-файла...
batch           abort
Searching for host...
Can't get attributes of file '/new_pro_akt/FULL/AKT1C8_new_pro_akt_FULL_20260905_094515.bak'.
No such file or directory.
Error code: 2
[05.09.2026 11:17:47,91] [new_pro_akt] [FULL] Режим: UPLOAD
[05.09.2026 11:17:47,94] [new_pro_akt] [FULL] Попытка 1/3
[05.09.2026 11:19:00,00] [new_pro_atr] [FULL] Найден файл: AKT1C8_new_pro_atr_FULL_20260905_101506.bak
[05.09.2026 11:19:00,01] [new_pro_atr] [FULL] Локальный размер: 1073741824 bytes
[05.09.2026 11:19:05,00] [new_pro_atr] [FULL] SKIP: AKT1C8_new_pro_atr_FULL_20260905_101506.bak
[05.09.2026 11:20:00,00] END upload_common.cmd
"""


# ─── Где лежат журналы ───────────────────────────────────────

def test_log_dir_is_derived_from_the_script():
    """Раскладку задаёт сам скрипт — настраивать её отдельно значит
    завести второе место, которое разъедется с первым."""
    assert log_dir("C:\\roman\\2026\\upload_full.cmd", DAY) == \
        "C:\\roman\\2026\\logs\\2026-09-05"


def test_common_and_database_logs():
    script = "C:\\roman\\2026\\upload_diff.cmd"
    assert common_log(script, "I", DAY).endswith("\\common_DIFF.log")
    assert database_log(script, "D", "new_pro_akt", DAY).endswith(
        "\\new_pro_akt\\FULL.log")


def test_type_letters_become_script_words():
    """msdb говорит D/I/L, скрипт — FULL/DIFF/LOG."""
    script = "C:\\s\\up.cmd"
    assert common_log(script, "D", DAY).endswith("common_FULL.log")
    assert common_log(script, "L", DAY).endswith("common_LOG.log")


# ─── Разбор ──────────────────────────────────────────────────

def test_databases_and_their_verdicts():
    summary = parse_common_log(SAMPLE)

    assert summary["type"] == "FULL"
    assert [d["name"] for d in summary["databases"]] == ["new_pro_akt", "new_pro_atr"]
    assert summary["databases"][0]["status"] == "upload"
    assert summary["databases"][1]["status"] == "skip"


def test_file_and_size_are_picked_up():
    entry = parse_common_log(SAMPLE)["databases"][0]
    assert entry["file"].endswith(".bak")
    assert entry["size_gb"] == 44.44


def test_probe_answer_is_not_an_error():
    """«Файла нет на приёмнике» — нормальный ответ на вопрос перед
    заливкой, а не авария. Иначе каждая новая копия помечалась бы
    ошибкой."""
    entry = parse_common_log(SAMPLE)["databases"][0]
    assert entry["errors"] == []
    assert entry["status"] == "upload"


def test_winscp_errors_during_upload_are_counted():
    """А вот те же слова во время самой заливки — уже беда, и относятся
    они к базе, которую в этот момент везли."""
    text = SAMPLE.replace(
        "[05.09.2026 11:19:00,00] [new_pro_atr]",
        "Connection failed\nNetwork error: Software caused connection abort\n"
        "[05.09.2026 11:19:00,00] [new_pro_atr]")

    entry = parse_common_log(text)["databases"][0]

    assert any("Connection failed" in e for e in entry["errors"])


def test_finished_flag():
    assert parse_common_log(SAMPLE)["finished"] is True
    assert parse_common_log(
        "[05.09.2026 11:17:42,07] START upload_common.cmd")["finished"] is False


def test_start_and_end_times():
    summary = parse_common_log(SAMPLE)
    assert summary["started"].hour == 11 and summary["started"].minute == 17
    assert summary["ended"].minute == 20


def test_unknown_lines_do_not_break_anything():
    assert parse_common_log("мусор\n\nещё мусор")["databases"] == []
    assert parse_common_log("")["databases"] == []


def test_skip_clears_probe_noise():
    entry = parse_common_log(SAMPLE)["databases"][1]
    assert entry["status"] == "skip" and entry["errors"] == []


def test_summary_is_readable():
    text = "\n".join(summary_lines(parse_common_log(SAMPLE)))
    assert "Баз: 2" in text
    assert "залито 1" in text
    assert "пропущено 1" in text
    assert "new_pro_akt" in text
