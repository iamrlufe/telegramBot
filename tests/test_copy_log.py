"""Разбор журнала, который ведёт сам скрипт копирования.

Он знает то, чего не знает бот: сколько баз обошли, что залито, что
пропущено и на чём споткнулись. Образец — настоящий журнал с боевого
сервера, поэтому в нём есть и строки WinSCP без отметки времени.
"""
from datetime import datetime

from copy_log import (
    common_log,
    eta_minutes,
    human_minutes,
    progress_bar,
    progress_percent,
    winscp_highlights,
    winscp_is_transferring,
    winscp_last_time,
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
[05.09.2026 11:17:47,15] [new_pro_akt] [FULL] Remote: /new_pro_akt/FULL/AKT1C8_new_pro_akt_FULL_20260905_094515.bak
[05.09.2026 11:17:47,15] [new_pro_akt] [FULL] Проверка remote-файла...
batch           abort
Searching for host...
Can't get attributes of file '/new_pro_akt/FULL/AKT1C8_new_pro_akt_FULL_20260905_094515.bak'.
No such file or directory.
Error code: 2
[05.09.2026 11:17:47,91] [new_pro_akt] [FULL] Режим: UPLOAD
[05.09.2026 11:17:47,94] [new_pro_akt] [FULL] Попытка 1/3
[05.09.2026 11:52:03,10] [new_pro_akt] [FULL] SUCCESS
[05.09.2026 11:52:03,11] [new_pro_akt] [FULL] WinSCP exit code=0
[05.09.2026 11:52:03,12] [new_pro_akt] [FULL] Файл успешно загружен: AKT1C8_new_pro_akt_FULL_20260905_094515.bak
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
    assert summary["databases"][0]["status"] == "done"
    assert summary["databases"][1]["status"] == "skip"


def test_upload_without_success_is_still_running():
    """Пока скрипт не сказал SUCCESS, база числится в пути — а не
    «залито»: иначе оборванная заливка выглядела бы удачной."""
    text = SAMPLE.split("[05.09.2026 11:52:03,10]")[0]
    entry = parse_common_log(text)["databases"][0]
    assert entry["status"] == "upload"


def test_failed_exit_code_is_a_failure():
    """Провальная ветка скрипта пишет FAILED и ненулевой код — строки
    «Файл успешно загружен» в ней нет."""
    text = SAMPLE.replace("WinSCP exit code=0", "WinSCP exit code=3")
    text = text.replace("[FULL] SUCCESS", "[FULL] FAILED")
    text = "\n".join(line for line in text.splitlines()
                     if "успешно загружен" not in line)
    entry = parse_common_log(text)["databases"][0]
    assert entry["status"] == "failed"
    assert entry["exit_code"] == "3"


def test_upload_duration_is_measured():
    """От первой строки базы до SUCCESS — это и есть «сколько ехала»."""
    entry = parse_common_log(SAMPLE)["databases"][0]
    assert entry["done_at"].hour == 11 and entry["done_at"].minute == 52


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
    assert entry["status"] == "done"


def test_winscp_errors_during_upload_are_counted():
    """А вот те же слова во время самой заливки — уже беда, и относятся
    они к базе, которую в этот момент везли."""
    text = SAMPLE.replace(
        "[05.09.2026 11:52:03,10] [new_pro_akt] [FULL] SUCCESS",
        "Connection failed\nNetwork error: Software caused connection abort\n"
        "[05.09.2026 11:52:03,10] [new_pro_akt] [FULL] SUCCESS")

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


def test_similar_lines_do_not_pass_for_the_remote_path():
    """Рядом в журнале есть «Remote dir:» и «Remote размер:» — они не
    должны подменять путь, по которому считается процент."""
    text = ("[05.09.2026 11:17:47,15] [db] [FULL] Remote: /db/FULL/f.bak\n"
            "[05.09.2026 11:17:47,93] [db] [FULL] Remote dir: /db/FULL\n"
            "[05.09.2026 11:17:50,98] [db] [FULL] Remote размер: 100 bytes")
    assert parse_common_log(text)["databases"][0]["remote"] == "/db/FULL/f.bak"


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
    assert "за 34 мин" in text     # 11:17 → 11:52


# ─── Протокольный лог WinSCP ─────────────────────────────────

WINSCP_TAIL = """. 2026-09-05 11:40:21.697 Read 17 bytes (0 pending)
< 2026-09-05 11:40:21.697 Type: SSH_FXP_STATUS, Size: 17, Number: 29413638
< 2026-09-05 11:40:21.697 Status code: 0
> 2026-09-05 11:40:21.728 Type: SSH_FXP_WRITE, Size: 32758, Number: 29418758
. 2026-09-05 11:40:21.728 Sent 32762 bytes
"""

WINSCP_END = """. 2026-09-05 11:52:03.100 Transfer done: 'D:\\backup\\a.bak' => '/a.bak'
! 2026-09-05 11:52:03.200 Error message from server: Permission denied
. 2026-09-05 11:52:04.000 Session started.
"""


def test_protocol_noise_is_dropped():
    """На 44 ГБ такого набегает под гигабайт — читать его глазами
    бессмысленно, в сводку такие строки не идут."""
    assert winscp_highlights(WINSCP_TAIL) == []


def test_important_lines_survive():
    kept = winscp_highlights(WINSCP_END)
    assert any("Transfer done" in line for line in kept)
    assert any("Permission denied" in line for line in kept)


def test_last_time_and_transfer_state():
    assert winscp_last_time(WINSCP_TAIL) == "2026-09-05 11:40:21"
    assert winscp_is_transferring(WINSCP_TAIL) is True
    assert winscp_is_transferring(WINSCP_END) is False


# ─── Процент готовности ──────────────────────────────────────

def test_remote_path_is_taken_from_the_log():
    """Путь на приёмнике скрипт пишет сам: по нему и считается процент."""
    entry = parse_common_log(SAMPLE)["databases"][0]
    assert entry["remote"] == "/new_pro_akt/FULL/AKT1C8_new_pro_akt_FULL_20260905_094515.bak"
    assert entry["bytes"] == 47713517568


def test_percent_from_sizes():
    assert progress_percent(100, 25) == 25
    assert progress_percent(47713517568, 23856758784) == 50


def test_percent_is_capped():
    """Докачка может сделать файл чуть длиннее — 103% выглядели бы
    ошибкой."""
    assert progress_percent(100, 103) == 100


def test_percent_needs_both_sizes():
    assert progress_percent(None, 10) is None
    assert progress_percent(100, None) is None
    assert progress_percent(0, 10) is None


def test_progress_bar_is_ten_wide():
    assert progress_bar(0) == "▱" * 10
    assert progress_bar(100) == "▰" * 10
    assert progress_bar(32) == "▰▰▰▱▱▱▱▱▱▱"
    assert progress_bar(None) == ""


def test_eta_by_average_speed():
    """Мгновенную скорость по двум замерам не измерить, да и у большого
    файла с докачкой она скачет — считаем среднюю с начала."""
    # 10 ГБ за 20 минут → осталось 30 ГБ → ещё 60 минут
    assert eta_minutes(10, 40, 20) == 60
    assert eta_minutes(40, 40, 20) == 0
    assert eta_minutes(0, 40, 20) is None
    assert eta_minutes(10, 40, 0) is None


def test_long_eta_is_human():
    assert human_minutes(45) == "45 мин"
    assert human_minutes(140) == "2 ч 20 мин"
    assert human_minutes(120) == "2 ч"


def test_percent_shows_up_in_the_summary():
    summary = parse_common_log(SAMPLE.split("[05.09.2026 11:52:03,10]")[0])
    entry = summary["databases"][0]
    entry["percent"], entry["remote_gb"] = 28, 12.4

    text = "\n".join(summary_lines(summary))

    assert "28%" in text and "12.4 ГБ" in text
    assert "▰" in text and "▱" in text


# ─── Ругань, которая не ошибка ───────────────────────────────

MKDIR_NOISE = """[05.09.2026 12:26:19,00] [new_pro_akt] [FULL] Режим: UPLOAD
Script: mkdir "/new_pro_akt/FULL"
Error creating folder '/new_pro_akt/FULL'.
Error code: 4
Error message from server: failure: mkdir Cannot create a file when that file already exists.
Copying "AKT1C8.bak" to remote directory started.
"""


def test_mkdir_on_existing_folder_is_not_an_error():
    """Скрипт на всякий случай делает mkdir; каталог уже есть, сервер
    отвечает отказом с «Error code: 4». Передаче это не мешает — иначе
    база помечалась бы аварийной на каждом рейсе."""
    entry = parse_common_log(MKDIR_NOISE)["databases"][0]
    assert entry["errors"] == []
    assert entry["status"] == "upload"


def test_real_error_after_benign_one_still_counts():
    text = MKDIR_NOISE + "Connection failed\n"
    entry = parse_common_log(text)["databases"][0]
    assert any("Connection failed" in e for e in entry["errors"])


def test_mkdir_noise_is_not_a_highlight():
    """В списке важного простыня про mkdir вытесняла бы то, ради чего
    этот список нужен."""
    kept = winscp_highlights(MKDIR_NOISE)
    assert not any("Error code: 4" in line for line in kept)
    assert any("Copying" in line for line in kept)


# ─── Огрызок на приёмнике ────────────────────────────────────

def _skipped(**over):
    entry = {"name": "new_pro_akt", "status": "skip", "file": "f.bak",
             "size_gb": 42.22, "attempts": 0, "errors": [], "bytes": 45330792448}
    entry.update(over)
    return entry


def test_truncated_file_shouts_over_the_scripts_verdict():
    """Скрипт сказал «SKIP: файл уже полностью загружен», а на приёмнике
    2.59 ГБ из 42.22. Верить надо приёмнику."""
    summary = {"type": "FULL", "finished": True,
               "databases": [_skipped(truncated=True, remote_gb=2.59)]}
    text = "\n".join(summary_lines(summary))

    assert "❗ new_pro_akt" in text
    assert "2.59 ГБ из 42.22" in text
    assert "ОГРЫЗКОВ 1" in text
    assert "Удалите файл на приёмнике" in text


def test_missing_file_on_target_is_named_as_such():
    summary = {"type": "FULL", "finished": True,
               "databases": [_skipped(truncated=True)]}
    text = "\n".join(summary_lines(summary))

    assert "НЕТ вовсе" in text


def test_honest_skip_stays_a_skip():
    """Файл действительно доехал — знак прежний, паники нет."""
    summary = {"type": "FULL", "finished": True, "databases": [_skipped()]}
    text = "\n".join(summary_lines(summary))

    assert "⏭ new_pro_akt" in text
    assert "ОГРЫЗК" not in text
