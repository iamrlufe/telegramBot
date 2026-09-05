"""Запуск копирования по готовности копии (вместо планировщика Windows).

Проверяется главное: бот везёт копию тогда, когда SQL её закончил, и ровно
один раз; не везёт вчерашнюю после перезапуска монитора; ждёт окончания
столько, сколько копирование реально идёт, а не сколько угадали.
"""
from datetime import datetime, timedelta

import pytest

from backup_copy import (
    check_run_ps,
    copy_settings,
    decode_log_tail,
    run_outcome,
    launch_script_ps,
    mark_sent,
    next_to_send,
    pick_ready_backup,
    pick_ready_backups,
    run_verdict,
    script_for,
    sent_marker,
    should_start,
    type_label,
)

NOW = datetime(2026, 9, 5, 4, 0, 0)


def _server(**over):
    server = {"name": "sql-region", "host": "h",
              "copy_script": "C:\\Scripts\\copy.ps1"}
    server.update(over)
    return server


def _rows():
    return [
        {"db": "base", "btype": "L", "finished": "2026-09-05 03:50:00", "size_gb": 0.2},
        {"db": "base", "btype": "I", "finished": "2026-09-05 03:30:00", "size_gb": 70.4},
        {"db": "base", "btype": "D", "finished": "2026-09-04 03:10:00", "size_gb": 210.0},
    ]


# ─── Настройки ───────────────────────────────────────────────

def test_settings_none_without_script():
    assert copy_settings({"name": "a", "host": "h"}) is None


def test_settings_defaults():
    s = copy_settings(_server())
    assert s["types"] == ("D", "I")     # журналы по умолчанию не возим
    assert s["auto"] is True
    assert s["timeout_minutes"] > 0


def test_settings_read_types_from_string():
    assert copy_settings(_server(copy_types="d, l"))["types"] == ("D", "L")


def test_auto_can_be_turned_off():
    assert copy_settings(_server(copy_after_backup=False))["auto"] is False


# ─── Выбор копии из msdb ─────────────────────────────────────

def test_journal_is_ignored_by_default():
    """Журналы делают каждые 15–60 минут: гонять на них скрипт — значит
    копировать непрерывно."""
    ready = pick_ready_backup(_rows(), copy_settings(_server()))
    assert ready["type"] == "I"
    assert ready["finished"] == datetime(2026, 9, 5, 3, 30)


def test_journal_taken_when_asked():
    ready = pick_ready_backup(_rows(), copy_settings(_server(copy_types="L")))
    assert ready["type"] == "L"


def test_no_matching_backup():
    rows = [{"db": "b", "btype": "L", "finished": "2026-09-05 03:50:00"}]
    assert pick_ready_backup(rows, copy_settings(_server())) is None


# ─── Свой скрипт на каждый тип копии ─────────────────────────

FULL_DIFF = {"D": "C:\\roman\\upload_full.cmd",
             "I": "C:\\roman\\upload_diff.cmd"}


def test_script_map_sets_types_by_itself():
    """Заданный скрипт и есть согласие возить копии этого типа — второй
    список (copy_types) с ним только разъехался бы."""
    s = copy_settings(_server(copy_script=dict(FULL_DIFF)))
    assert set(s["types"]) == {"D", "I"}
    assert script_for(s, "D").endswith("upload_full.cmd")
    assert script_for(s, "I").endswith("upload_diff.cmd")


def test_single_script_still_covers_default_types():
    s = copy_settings(_server())
    assert script_for(s, "D") == script_for(s, "I") == "C:\\Scripts\\copy.ps1"


def test_type_without_script_is_not_shipped():
    """Скрипт только для полной — разностную везти нечем, и молчать об
    этом нельзя: причина уходит в лог."""
    s = copy_settings(_server(copy_script={"D": "C:\\full.cmd"}))
    ready = {"db": "base", "type": "I", "finished": NOW - timedelta(minutes=30)}
    ok, reason = should_start(ready, {}, s, NOW)
    assert not ok and "скрипт не задан" in reason


def test_each_type_is_tracked_separately():
    """Свежая разностная не отменяет неотправленную полную."""
    s = copy_settings(_server(copy_script=dict(FULL_DIFF)))
    rows = [
        {"db": "base", "btype": "I", "finished": "2026-09-05 03:30:00"},
        {"db": "base", "btype": "D", "finished": "2026-09-05 03:00:00"},
    ]
    state = {}

    first, _ = next_to_send(rows, state, s, NOW)
    assert first["type"] == "I"          # самая свежая едет первой

    mark_sent(state, "I", "2026-09-05 03:30:00")
    second, _ = next_to_send(rows, state, s, NOW)
    assert second["type"] == "D"         # полная осталась в очереди

    mark_sent(state, "D", "2026-09-05 03:00:00")
    assert next_to_send(rows, state, s, NOW)[0] is None


def test_one_trip_at_a_time():
    """Копирование грузит сеть и диск: два рейса разом идут вдвое дольше
    каждый. Второй тип поедет следующим циклом."""
    s = copy_settings(_server(copy_script=dict(FULL_DIFF)))
    rows = [{"db": "base", "btype": "I", "finished": "2026-09-05 03:30:00"},
            {"db": "base", "btype": "D", "finished": "2026-09-05 03:00:00"}]
    state = {"run": {"pid": 1, "started": "2026-09-05 03:35:00"}}

    ready, reason = next_to_send(rows, state, s, NOW)
    assert ready is None and "идёт" in reason


def test_old_state_format_is_understood():
    """До разделения по типам отметка была одной строкой на сервер. После
    обновления она обязана значить «уже отправлено», иначе бот повёз бы
    заново то, что уже уехало."""
    assert sent_marker({"last_finished": "2026-09-05 03:30:00"}, "I") == \
        "2026-09-05 03:30:00"

    state = {"last_finished": "2026-09-05 03:30:00"}
    mark_sent(state, "D", "2026-09-05 04:00:00")
    assert state["last_finished"]["D"] == "2026-09-05 04:00:00"
    assert state["last_finished"]["I"] == "2026-09-05 03:30:00"


def test_newest_of_each_type_wins():
    rows = [{"db": "base", "btype": "I", "finished": "2026-09-05 03:30:00"},
            {"db": "base", "btype": "I", "finished": "2026-09-05 01:30:00"},
            {"db": "base", "btype": "D", "finished": "2026-09-04 03:00:00"}]
    picked = pick_ready_backups(rows, copy_settings(_server(copy_script=dict(FULL_DIFF))))
    assert [(p["type"], p["finished"].hour) for p in picked] == [("I", 3), ("D", 3)]


# ─── Пора ли запускать ───────────────────────────────────────

def _ready(minutes_ago=30):
    return {"db": "base", "type": "I", "finished": NOW - timedelta(minutes=minutes_ago),
            "size_gb": 70.4}


def test_starts_when_backup_is_ready():
    ok, reason = should_start(_ready(), {}, copy_settings(_server()), NOW)
    assert ok and reason is None


def test_waits_out_the_delay():
    """SQL закрывает файл раньше, чем система дописывает его на диск."""
    ok, reason = should_start(_ready(1), {}, copy_settings(_server()), NOW)
    assert not ok and "ждём" in reason


def test_same_backup_is_sent_once():
    state = {"last_finished": "2026-09-05 03:30:00"}
    ok, _ = should_start(_ready(), state, copy_settings(_server()), NOW)
    assert not ok


def test_does_not_start_while_previous_copy_runs():
    state = {"run": {"pid": 1, "started": "2026-09-05 03:35:00"}}
    ok, reason = should_start(_ready(), state, copy_settings(_server()), NOW)
    assert not ok and "идёт" in reason


def test_stale_backup_is_not_shipped():
    """Монитор перезапустили, состояние потеряли — вчерашнюю копию везти
    некуда, она давно уехала."""
    ok, reason = should_start(_ready(minutes_ago=600), {},
                              copy_settings(_server()), NOW)
    assert not ok and "старая" in reason


def test_auto_off_blocks_start():
    ok, _ = should_start(_ready(), {}, copy_settings(_server(copy_after_backup=False)), NOW)
    assert not ok


# ─── Сколько ждать окончания ─────────────────────────────────

def test_long_copy_is_not_a_failure():
    """70 ГБ едут часами — при своём таймауте это норма, а не авария."""
    run = {"started": "2026-09-05 01:00:00"}
    settings = copy_settings(_server(copy_timeout_minutes=360))
    assert run_verdict(run, settings, NOW) == "running"


def test_timeout_is_counted_from_start():
    run = {"started": "2026-09-05 01:00:00"}
    settings = copy_settings(_server(copy_timeout_minutes=120))
    assert run_verdict(run, settings, NOW) == "timeout"


# ─── Запуск скрипта ──────────────────────────────────────────

def test_ps1_runs_through_powershell():
    script = launch_script_ps("C:\\Scripts\\copy.ps1", "id")
    assert "powershell.exe" in script and "Bypass" in script


def test_launch_returns_pid_immediately():
    """Ждать окончания нельзя: сессия WinRM живёт минуты, копия — часы."""
    text = launch_script_ps("C:\\a.bat", "id")
    assert "Win32_Process" in text and "Pid" in text


def test_launch_writes_log_and_exit_code():
    """Одного PID мало: упавший на первой строке скрипт выглядел бы как
    идущая копия. Код возврата и журнал — единственный честный ответ."""
    text = launch_script_ps("C:\\a.bat", "20260905-102701-I")
    assert "ERRORLEVEL" in text
    assert "20260905-102701-I.log" in text
    assert "20260905-102701-I.done" in text


def test_exit_code_is_taken_after_the_script_ran():
    """Регрессия: %ERRORLEVEL% в составной команде подставляется при
    РАЗБОРЕ строки, то есть до запуска скрипта. Нужна отложенная
    подстановка (/v:on и !ERRORLEVEL!), иначе в метку попадает код,
    который был ДО копирования."""
    text = launch_script_ps("C:\\a.bat", "id")
    assert "/v:on" in text
    assert "!ERRORLEVEL!" in text
    assert "%ERRORLEVEL%" not in text


def test_marker_write_is_not_a_stream_redirect():
    """Регрессия: `echo !ERRORLEVEL!> файл` без пробела перед `>` — это
    перенаправление потока с таким номером (0> это stdin), а не запись в
    файл. Метка не появлялась, и удачный рейс выглядел как «процесс
    исчез, не дописав код возврата»."""
    text = launch_script_ps("C:\\a.bat", "id")
    assert "!ERRORLEVEL! > " in text
    assert "!ERRORLEVEL!>" not in text


def test_old_logs_are_cleaned_on_launch():
    """Рейсов несколько в сутки: без уборки каталог рос бы вечно, а
    отдельного похода на сервер ради этого заводить незачем."""
    text = launch_script_ps("C:\\a.bat", "id")
    assert "AddDays(-" in text and "Remove-Item" in text


def test_quotes_do_not_break_the_script():
    assert "''" in launch_script_ps("C:\\Scripts\\it's copy.bat", "id")


def test_quotes_in_path_are_refused():
    """Кавычка в пути разъехалась бы с перенаправлением вывода."""
    with pytest.raises(ValueError):
        launch_script_ps('C:\\a"b.cmd', "id")


def test_type_label_is_readable():
    assert type_label("I") == "разностная"


# ─── Журнал в двух кодировках ────────────────────────────────

def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode()


def test_log_with_two_encodings_stays_readable():
    """В одном файле cmd пишет в CP866, а WinSCP при перенаправлении —
    в UTF-8. Единая кодировка превращала половину журнала в «РС‰Сѓ
    СЃРµСЂРІРµСЂ»."""
    raw = ("[10:42:38] Проверка remote-файла...".encode("cp866") + b"\n"
           + "Ищу сервер…".encode("utf-8") + b"\n"
           + "[10:42:38] SKIP: файл уже загружен".encode("cp866"))

    text = decode_log_tail(_b64(raw))

    assert "Проверка remote-файла" in text
    assert "Ищу сервер" in text
    assert "SKIP: файл уже загружен" in text


def test_windows_1251_lines_are_read_too():
    """`chcp 1251` в скрипте — обычное дело: тогда cmd пишет не в CP866.
    Байты у этих кодировок пересекаются полностью, отличить можно только
    по виду результата — промах даёт псевдографику вместо букв."""
    raw = "[10:42] Поиск каталогов DIFF в D:\\backup".encode("cp1251")
    assert "Поиск каталогов DIFF" in decode_log_tail(_b64(raw))


def test_cp866_lines_are_read_too():
    raw = "[10:42] Найден файл".encode("cp866")
    assert "Найден файл" in decode_log_tail(_b64(raw))


def test_three_encodings_in_one_log():
    """Худший случай, он же настоящий: ASCII от cmd, UTF-8 от WinSCP
    и русские строки самого скрипта в кодировке консоли."""
    raw = (b"[10:42] START upload_common.cmd\n"
           + "Ищу сервер…".encode("utf-8") + b"\n"
           + "[10:42] Файл уже полностью загружен".encode("cp1251"))

    text = decode_log_tail(_b64(raw))

    assert "START upload_common.cmd" in text
    assert "Ищу сервер" in text
    assert "Файл уже полностью загружен" in text


def test_truncated_first_line_is_dropped():
    """Хвост читается с конца по байтам: первая строка обрезана
    посередине — и посередине символа тоже, поэтому её не показываем."""
    raw = b"x" * 4096 + b"\n" + "хвост".encode("utf-8")
    assert decode_log_tail(_b64(raw)).strip() == "хвост"


def test_short_log_keeps_its_first_line():
    """Если файл целиком влез, обрезанной строки нет — терять её нельзя."""
    raw = "первая строка\nвторая".encode("utf-8")
    assert decode_log_tail(_b64(raw)).startswith("первая строка")


def test_empty_log_is_not_an_error():
    assert decode_log_tail("") == ""
    assert decode_log_tail(None) == ""


def test_broken_base64_is_not_an_error():
    """Ответ сервера мог прийти обрезанным — это не повод ронять разбор
    рейса: код возврата важнее журнала."""
    assert decode_log_tail("не base64 вовсе") == ""


def test_tail_is_limited():
    raw = "\n".join(f"строка {n}" for n in range(50)).encode("utf-8")
    text = decode_log_tail(_b64(raw), lines=5)
    assert text.count("\n") == 4
    assert "строка 49" in text


# ─── Чем закончился рейс ─────────────────────────────────────

RUN = {"pid": 10848, "started": "2026-09-05 10:27:01",
       "log": "C:\\log", "done": "C:\\done", "type": "D"}


def test_running_while_process_lives_and_no_exit_code():
    out = run_outcome({"Alive": True, "Code": None, "Tail": ""}, RUN)
    assert out["state"] == "running"


def test_exit_code_zero_is_success():
    out = run_outcome({"Alive": False, "Code": "0", "Tail": "ok"}, RUN)
    assert out["state"] == "ok" and out["code"] == 0


def test_nonzero_exit_code_is_failure():
    """Главная поломка, ради которой это писалось: скрипт падал на первой
    строке, а бот показывал «идёт копирование»."""
    out = run_outcome({"Alive": False, "Code": "1",
                       "TailB64": _b64("Access denied".encode("cp866"))},
                      RUN)
    assert out["state"] == "failed" and out["code"] == 1
    assert "Access denied" in out["tail"]


def test_exit_code_wins_over_live_process():
    """PID переиспользуются: под тем же номером через сутки работает
    что-то чужое. Код возврата честнее."""
    out = run_outcome({"Alive": True, "Code": "0", "Tail": ""}, RUN)
    assert out["state"] == "ok"


def test_vanished_without_exit_code_is_lost():
    out = run_outcome({"Alive": False, "Code": None, "Tail": ""}, RUN)
    assert out["state"] == "lost"


def test_old_run_without_marker_still_ends_by_pid():
    """Рейсы, заведённые до появления файла-метки, знают только PID —
    после обновления они не должны зависнуть навсегда."""
    old_run = {"pid": 10848, "started": "2026-09-05 10:27:01"}
    assert run_outcome({"Alive": False}, old_run)["state"] == "ok"
    assert run_outcome({"Alive": True}, old_run)["state"] == "running"


def test_process_is_identified_by_run_number():
    """Регрессия: PID переиспользуются, и через пару часов под тем же
    номером работает чужая программа — закончившийся рейс висел «идёт»
    до самого таймаута. Процесс опознаём по номеру рейса в его
    командной строке."""
    text = check_run_ps({"pid": 14520, "ident": "20260905-110228-I",
                         "log": "C:\\l", "done": "C:\\d"})
    assert "ProcessId=14520" in text
    assert "20260905-110228-I" in text
    assert "CommandLine -like" in text


def test_old_run_without_number_falls_back_to_pid():
    """Рейсы, заведённые прошлой версией, номера не знают — для них
    остаётся прежняя проверка, иначе они зависли бы навсегда."""
    text = check_run_ps({"pid": 14520, "log": "C:\\l", "done": "C:\\d"})
    assert "$alive = $true" in text


# ─── Ручной запуск из бота ───────────────────────────────────

import backup_copy


def _wire_state(monkeypatch, tmp_path, state):
    path = tmp_path / "backup_transfer.json"
    monkeypatch.setattr(backup_copy, "TRANSFER_STATE_FILE", str(path))
    backup_copy.save_state(state)
    return path


def test_manual_start_writes_state(monkeypatch, tmp_path):
    _wire_state(monkeypatch, tmp_path, {})
    monkeypatch.setattr(backup_copy, "find_server", lambda n: _server(name=n))
    monkeypatch.setattr(backup_copy, "launch_copy",
                        lambda *a, **kw: {"pid": 42, "started": "2026-09-05 04:00:00",
                                          "by": kw.get("by")})

    run = backup_copy.start_copy_now("sql-region")

    assert run["pid"] == 42
    assert run["by"] == "бот"
    assert backup_copy.load_state()["sql-region"]["run"]["pid"] == 42


def test_manual_start_refuses_while_copy_runs(monkeypatch, tmp_path):
    """Второй запуск того же скрипта — это две копии одного файла в одну
    папку, самый быстрый способ получить огрызок."""
    _wire_state(monkeypatch, tmp_path,
                {"sql-region": {"run": {"pid": 7, "started": "2026-09-05 01:00:00"}}})
    monkeypatch.setattr(backup_copy, "find_server", lambda n: _server(name=n))

    with pytest.raises(RuntimeError, match="уже идёт"):
        backup_copy.start_copy_now("sql-region")


def test_manual_start_needs_script(monkeypatch, tmp_path):
    _wire_state(monkeypatch, tmp_path, {})
    monkeypatch.setattr(backup_copy, "find_server",
                        lambda n: {"name": n, "host": "h"})

    with pytest.raises(RuntimeError, match="copy_script"):
        backup_copy.start_copy_now("sql-region")


def test_manual_start_keeps_last_finished(monkeypatch, tmp_path):
    """Ручной рейс не отменяет обычного хода дел: следующую копию,
    которую закончит SQL, всё равно повезут."""
    _wire_state(monkeypatch, tmp_path,
                {"sql-region": {"last_finished": "2026-09-05 03:30:00"}})
    monkeypatch.setattr(backup_copy, "find_server", lambda n: _server(name=n))
    monkeypatch.setattr(backup_copy, "launch_copy", lambda *a, **kw: {"pid": 1})

    backup_copy.start_copy_now("sql-region")

    assert backup_copy.load_state()["sql-region"]["last_finished"] == "2026-09-05 03:30:00"


def test_reset_forgets_a_stuck_run(monkeypatch, tmp_path):
    """Процесс убили руками — иначе сервер навсегда «копирует», и
    следующая копия не поедет."""
    _wire_state(monkeypatch, tmp_path,
                {"sql-region": {"run": {"pid": 7, "started": "2026-09-05 10:27:01"}}})

    backup_copy.clear_run("sql-region")

    entry = backup_copy.load_state()["sql-region"]
    assert entry["run"] is None
    assert entry["last_run"]["state"] == "reset"


def test_reset_refuses_when_nothing_runs(monkeypatch, tmp_path):
    _wire_state(monkeypatch, tmp_path, {"sql-region": {}})
    with pytest.raises(RuntimeError):
        backup_copy.clear_run("sql-region")


# ─── Путь на приёмнике ───────────────────────────────────────

def test_target_settings_need_both_fields():
    """По одному полю процент не посчитать: нужен и сервер, и корень."""
    assert backup_copy.target_settings({"copy_target": "sftp-01"}) is None
    assert backup_copy.target_settings({"copy_target_root": "E:\\B"}) is None


def test_target_path_glues_sftp_path_to_the_root():
    settings = backup_copy.target_settings(
        {"copy_target": "sftp-01", "copy_target_root": "E:\\Backups\\AKT1C8\\"})
    path = backup_copy.target_path(settings["root"],
                                   "/new_pro_akt/FULL/file.bak")
    assert path == "E:\\Backups\\AKT1C8\\new_pro_akt\\FULL\\file.bak"


def test_size_check_looks_at_filepart_too():
    """WinSCP пишет в .filepart и переименовывает в конце — пока файл
    едет, под конечным именем его нет вовсе."""
    assert ".filepart" in backup_copy.file_size_ps("E:\\B\\file.bak")


# ─── Поиск приёмника по имени ────────────────────────────────

SERVERS = [
    {"name": "is-cc.rcku.net", "host": "192.0.2.38"},
    {"name": "akt1c8.rcku.net", "host": "192.0.2.10"},
]


def _servers(monkeypatch):
    monkeypatch.setattr(backup_copy, "load_servers", lambda *a, **kw: SERVERS)


def test_exact_name_wins(monkeypatch):
    _servers(monkeypatch)
    assert backup_copy.find_server_loose("is-cc.rcku.net")["host"] == "192.0.2.38"


def test_short_name_is_understood(monkeypatch):
    """«is-cc» вместо «is-cc.rcku.net» — обычная описка при вводе руками.
    Отказ «такого сервера нет» тут формально верен и бесполезен."""
    _servers(monkeypatch)
    assert backup_copy.find_server_loose("is-cc")["name"] == "is-cc.rcku.net"


def test_host_also_works(monkeypatch):
    _servers(monkeypatch)
    assert backup_copy.find_server_loose("192.0.2.38")["name"] == "is-cc.rcku.net"


def test_ambiguous_prefix_is_refused(monkeypatch):
    """Два сервера с общим началом имени — повод спросить человека,
    а не угадывать за него."""
    monkeypatch.setattr(backup_copy, "load_servers", lambda *a, **kw: [
        {"name": "is-cc.rcku.net", "host": "h1"},
        {"name": "is-cc.backup.rcku.net", "host": "h2"},
    ])
    assert backup_copy.find_server_loose("is-cc") is None


def test_unknown_name_gives_nothing(monkeypatch):
    _servers(monkeypatch)
    assert backup_copy.find_server_loose("нет-такого") is None
    assert backup_copy.find_server_loose("") is None


# ─── Предохранитель от второго рейса ─────────────────────────

def test_guard_looks_for_wrapper_and_winscp():
    """У WinSCP.com в командной строке скрипта нет — там временный файл
    задания и путь к журналу. Журнал лежит рядом со скриптом, поэтому
    вторым признаком идёт каталог: осиротевший WinSCP иначе прошёл бы
    незамеченным, а он и есть самый опасный случай."""
    text = backup_copy.running_copy_ps("C:\\roman\\2026\\upload_full.cmd")
    assert "cmd.exe" in text and "WinSCP.com" in text
    assert "C:\\roman\\2026\\upload_full.cmd" in text
    assert "'*C:\\roman\\2026*'" in text


def test_launch_refuses_while_a_copy_runs(monkeypatch):
    """Две программы, дописывающие один файл на приёмнике, — худшее, что
    может случиться с копией."""
    monkeypatch.setattr(backup_copy, "running_copies",
                        lambda server, script: [{"pid": 15344,
                                                 "name": "WinSCP.com",
                                                 "cmd": "..."}])
    settings = copy_settings(_server())

    with pytest.raises(RuntimeError, match="уже идёт"):
        backup_copy.launch_copy({"name": "s", "host": "h"}, settings)


def test_launch_refuses_when_the_check_fails(monkeypatch):
    """Не смогли спросить — не запускаем: цена ошибки здесь выше цены
    задержки, следующий цикл попробует снова."""
    def _boom(server, script):
        raise RuntimeError("WinRM не ответил")

    monkeypatch.setattr(backup_copy, "running_copies", _boom)
    settings = copy_settings(_server())

    with pytest.raises(RuntimeError, match="не проверить"):
        backup_copy.launch_copy({"name": "s", "host": "h"}, settings)


# ─── Закрытие закончившегося рейса ───────────────────────────

def _run(**over):
    run = {"pid": 8276, "started": "2026-09-05 18:55:53", "type": "D",
           "db": "new_pro_akt", "source_finished": "2026-09-05 01:30:00",
           "script": "C:\\roman\\2026\\upload_full.cmd",
           "ident": "20260905-185553-D", "log": "C:\\l", "done": "C:\\d"}
    run.update(over)
    return run


def test_finish_run_marks_the_copy_as_sent():
    entry = {"run": _run()}
    backup_copy.finish_run(entry, {"state": "ok", "code": 0},
                           datetime(2026, 9, 5, 18, 56, 53))

    assert entry["run"] is None
    assert entry["last_run"]["minutes"] == 1
    assert entry["last_run"]["state"] == "ok"
    assert sent_marker(entry, "D") == "2026-09-05 01:30:00"


def test_finish_run_keeps_a_failed_copy_in_the_queue():
    """Копия осталась дома — следующий цикл обязан попробовать снова."""
    entry = {"run": _run()}
    backup_copy.finish_run(entry, {"state": "failed", "code": 1},
                           datetime(2026, 9, 5, 19, 0, 0))

    assert entry["run"] is None
    assert sent_marker(entry, "D") is None


def test_refresh_closes_a_run_that_already_ended(monkeypatch, tmp_path):
    """Рейс, где все базы уже на приёмнике, кончается за полминуты, а
    следит за ним монитор — до его цикла карточка врала бы «идёт»."""
    _wire_state(monkeypatch, tmp_path, {"sql-region": {"run": _run()}})
    monkeypatch.setattr(backup_copy, "check_run",
                        lambda s, r: {"state": "ok", "code": 0, "tail": ""})

    assert backup_copy.refresh_run(_server()) == "ok"
    assert backup_copy.load_state()["sql-region"]["run"] is None


def test_refresh_leaves_a_failed_run_to_the_monitor(monkeypatch, tmp_path):
    """Тревогу по неудачному рейсу шлёт монитор: закрой его бот молча —
    она не ушла бы никому."""
    _wire_state(monkeypatch, tmp_path, {"sql-region": {"run": _run()}})
    monkeypatch.setattr(backup_copy, "check_run",
                        lambda s, r: {"state": "failed", "code": 1, "tail": ""})

    assert backup_copy.refresh_run(_server()) == "failed"
    assert backup_copy.load_state()["sql-region"]["run"]["pid"] == 8276


def test_refresh_says_nothing_when_no_run(monkeypatch, tmp_path):
    _wire_state(monkeypatch, tmp_path, {"sql-region": {}})
    assert backup_copy.refresh_run(_server()) == ""
