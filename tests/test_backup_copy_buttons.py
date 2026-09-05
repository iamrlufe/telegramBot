"""Кнопки запуска копирования в разделе 📤 Копирование."""
from backup_bot import copy_type_buttons


def test_button_per_type_when_scripts_differ():
    """Полную и разностную возят разными скриптами — и кнопки разные."""
    buttons = copy_type_buttons("akt1c8", {"scripts": {"D": "full.cmd",
                                                       "I": "diff.cmd"}})
    assert len(buttons) == 2


def test_single_script_needs_no_choice():
    """Один скрипт на все типы — выбирать нечего, тип ничего не меняет."""
    assert copy_type_buttons("akt1c8", {"scripts": {"D": "up.cmd",
                                                    "I": "up.cmd"}}) == []


def test_long_name_falls_back_to_the_picker():
    """callback_data Telegram — 64 байта: кнопка сверх лимита молча
    перестала бы работать, лучше показать общий выбор."""
    assert copy_type_buttons("x" * 70, {"scripts": {"D": "a.cmd",
                                                    "I": "b.cmd"}}) == []


def test_three_types_give_three_buttons():
    buttons = copy_type_buttons("akt1c8", {"scripts": {"D": "f.cmd",
                                                       "I": "d.cmd",
                                                       "L": "l.cmd"}})
    assert len(buttons) == 3


# ─── Карточка копирования и подробности по базе ──────────────

import asyncio

import backup_bot


def _capture(monkeypatch):
    """Подменяет отправку сообщения: возвращает список показанных текстов."""
    shown = []

    async def fake_edit(query, text, **kw):
        shown.append(text)

    monkeypatch.setattr(backup_bot, "safe_edit_message", fake_edit)
    return shown


def test_card_closes_a_run_that_already_ended(monkeypatch):
    """Рейс кончился, а состояние об этом ещё не знает — спрашиваем сервер,
    иначе карточка показывает «идёт» до следующего цикла монитора."""
    monkeypatch.setattr(backup_bot, "find_server",
                        lambda n: {"name": n, "host": "h"})
    monkeypatch.setattr(backup_bot, "refresh_run", lambda s: "ok")
    monkeypatch.setattr(backup_bot, "load_copy_state", lambda: {"akt1c8": {}})

    state, notes = asyncio.run(backup_bot._refresh_running(
        ["akt1c8"], {"akt1c8": {"run": {"pid": 8276}}}))

    assert state["akt1c8"].get("run") is None
    assert notes == []


def test_card_warns_about_a_failed_run(monkeypatch):
    """Закрывать неудачный рейс боту нельзя — тревогу по нему шлёт
    монитор. Но молчать о нём в карточке тоже нельзя."""
    monkeypatch.setattr(backup_bot, "find_server",
                        lambda n: {"name": n, "host": "h"})
    monkeypatch.setattr(backup_bot, "refresh_run", lambda s: "failed")

    state, notes = asyncio.run(backup_bot._refresh_running(
        ["akt1c8"], {"akt1c8": {"run": {"pid": 8276}}}))

    assert state["akt1c8"]["run"]["pid"] == 8276
    assert notes and "монитор" in notes[0]


def test_card_survives_an_unreachable_server(monkeypatch):
    def boom(server):
        raise RuntimeError("WinRM: таймаут")

    monkeypatch.setattr(backup_bot, "find_server",
                        lambda n: {"name": n, "host": "h"})
    monkeypatch.setattr(backup_bot, "refresh_run", boom)

    _, notes = asyncio.run(backup_bot._refresh_running(
        ["akt1c8"], {"akt1c8": {"run": {"pid": 8276}}}))

    assert notes and "таймаут" in notes[0]


def test_card_does_not_touch_the_server_without_a_run(monkeypatch):
    """Ходов на сервер столько, сколько рейсов числится идущими."""
    def boom(server):
        raise AssertionError("сервер спрашивать не за чем")

    monkeypatch.setattr(backup_bot, "refresh_run", boom)
    state, notes = asyncio.run(backup_bot._refresh_running(["akt1c8"], {}))
    assert (state, notes) == ({}, [])


def test_missing_database_log_explains_a_skipped_database(monkeypatch):
    """«Файла нет» без объяснения читается как поломка. А это обычный
    случай: базу пропустили, WinSCP не запускали, писать было нечего."""
    shown = _capture(monkeypatch)
    monkeypatch.setattr(backup_bot, "find_server",
                        lambda n: {"name": n, "host": "h",
                                   "copy_script": "C:\\roman\\upload_full.cmd"})
    monkeypatch.setattr(backup_bot, "read_remote_log_info",
                        lambda *a, **kw: {"text": "", "size": 0})

    asyncio.run(backup_bot.show_copy_log_db(object(), None, "akt1c8", "D",
                                            "new_pro_akt"))

    assert "Файла нет" in shown[0]
    assert "пропущена" in shown[0]


# ─── Сверка с приёмником: «пропущено» ещё не значит «доехало» ─

def _wire_target(monkeypatch, remote_size):
    monkeypatch.setattr(backup_bot, "target_settings",
                        lambda s: {"server": "sftp-01", "root": "E:\\B"})
    monkeypatch.setattr(backup_bot, "find_server_loose",
                        lambda n: {"name": n, "host": "h"})
    monkeypatch.setattr(backup_bot, "remote_file_size",
                        lambda srv, path: remote_size)


def _summary(status="skip"):
    return {"databases": [{"name": "new_pro_akt", "status": status,
                           "remote": "/new_pro_akt/FULL/f.bak",
                           "bytes": 45330792448, "size_gb": 42.22,
                           "errors": [], "attempts": 0}]}


def test_skipped_database_is_checked_on_the_target(monkeypatch):
    """Обрыв заливки по SFTP выглядит успешным: скрипт видит файл с
    правильным именем и пропускает базу навсегда. Дома об этом не
    узнать — только у приёмника."""
    _wire_target(monkeypatch, 2776498176)
    summary = _summary()

    asyncio.run(backup_bot._fill_progress({"name": "akt1c8"}, summary))

    assert summary["databases"][0]["truncated"] is True
    assert summary["databases"][0]["remote_gb"] == 2.59


def test_skipped_database_that_really_arrived_is_left_alone(monkeypatch):
    _wire_target(monkeypatch, 45330792448)
    summary = _summary()

    asyncio.run(backup_bot._fill_progress({"name": "akt1c8"}, summary))

    assert "truncated" not in summary["databases"][0]


def test_uploaded_database_is_checked_too(monkeypatch):
    """SUCCESS от скрипта — тоже лишь его мнение: он спрашивал WinSCP,
    а не приёмник."""
    _wire_target(monkeypatch, 1024)
    summary = _summary(status="done")

    asyncio.run(backup_bot._fill_progress({"name": "akt1c8"}, summary))

    assert summary["databases"][0]["truncated"] is True


def test_file_gone_from_the_target_is_truncated_too(monkeypatch):
    _wire_target(monkeypatch, None)
    summary = _summary()

    asyncio.run(backup_bot._fill_progress({"name": "akt1c8"}, summary))

    assert summary["databases"][0]["truncated"] is True
    assert "remote_gb" not in summary["databases"][0]


def test_running_database_still_gets_a_percent(monkeypatch):
    _wire_target(monkeypatch, 22665396224)
    summary = _summary(status="upload")

    asyncio.run(backup_bot._fill_progress({"name": "akt1c8"}, summary))

    entry = summary["databases"][0]
    assert entry["percent"] == 50
    assert "truncated" not in entry
