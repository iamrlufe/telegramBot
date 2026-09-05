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


# ─── Вложенное меню: список серверов → карточка одного ───────

def _capture_kb(monkeypatch):
    """Как _capture, но запоминает и клавиатуру: тексты кнопок и callback."""
    shown = []

    async def fake_edit(query, text, reply_markup=None, **kw):
        rows = []
        if reply_markup is not None:
            for row in reply_markup.inline_keyboard:
                rows.append([(b.text, b.callback_data) for b in row])
        shown.append((text, rows))

    monkeypatch.setattr(backup_bot, "safe_edit_message", fake_edit)
    return shown


class _Button:
    def __init__(self, text, callback_data=None, **kw):
        self.text, self.callback_data = text, callback_data


class _Markup:
    def __init__(self, keyboard):
        self.inline_keyboard = [list(row) for row in keyboard]


def _real_keyboard(monkeypatch):
    """Заглушка telegram отдаёт MagicMock — кнопки на нём не разобрать."""
    monkeypatch.setattr(backup_bot, "InlineKeyboardButton", _Button)
    monkeypatch.setattr(backup_bot, "InlineKeyboardMarkup", _Markup)


def _wire_two_servers(monkeypatch, state):
    _real_keyboard(monkeypatch)
    monkeypatch.setattr(backup_bot, "copy_servers", lambda: ["akt1c8", "shmsql"])
    monkeypatch.setattr(backup_bot, "find_server",
                        lambda n: {"name": n, "host": "h"})
    monkeypatch.setattr(backup_bot, "copy_settings",
                        lambda s: {"scripts": {"D": "full.cmd", "I": "diff.cmd"},
                                   "auto": True})
    monkeypatch.setattr(backup_bot, "load_copy_state", lambda: state)
    monkeypatch.setattr(backup_bot, "refresh_run", lambda s: "busy")


def test_list_gives_one_button_per_server(monkeypatch):
    """Список — это выбор сервера, а не свалка кнопок всех серверов:
    запустить копирование не тому серверу отсюда нельзя."""
    shown = _capture_kb(monkeypatch)
    _wire_two_servers(monkeypatch, {})

    asyncio.run(backup_bot.show_copy_status(object(), None))

    _, rows = shown[0]
    data = [b[1] for row in rows for b in row]
    assert data == ["backup_copy_srv:akt1c8", "backup_copy_srv:shmsql",
                    "backup_menu"]


def test_list_shows_which_server_is_busy(monkeypatch):
    """Идущий рейс видно до захода в карточку — за этим сюда и приходят."""
    shown = _capture_kb(monkeypatch)
    _wire_two_servers(monkeypatch, {
        "shmsql": {"run": {"pid": 2320, "started": "2026-09-05 10:00:00"}}})

    asyncio.run(backup_bot.show_copy_status(object(), None))

    text, rows = shown[0]
    assert "⏳ shmsql" in text and "PID 2320" in text
    assert rows[1][0][0].startswith("⏳")


def test_card_holds_every_action_for_its_server(monkeypatch):
    """Внутри карточки — только этот сервер: запуск по типам, журнал,
    сброс идущего рейса и возврат к списку."""
    shown = _capture_kb(monkeypatch)
    _wire_two_servers(monkeypatch, {
        "shmsql": {"run": {"pid": 2320, "started": "2026-09-05 10:00:00"}}})

    asyncio.run(backup_bot.show_copy_server(object(), None, "shmsql"))

    text, rows = shown[0]
    data = [b[1] for row in rows for b in row]
    assert "🖥 shmsql" in text
    assert data == ["backup_copy_go:shmsql:D", "backup_copy_go:shmsql:I",
                    "backup_copy_log:shmsql", "backup_copy_reset:shmsql",
                    "backup_copy"]


def test_card_hides_reset_without_a_running_trip(monkeypatch):
    """Сброс нужен только для рейса, который числится идущим."""
    shown = _capture_kb(monkeypatch)
    _wire_two_servers(monkeypatch, {})

    asyncio.run(backup_bot.show_copy_server(object(), None, "akt1c8"))

    data = [b[1] for row in shown[0][1] for b in row]
    assert "backup_copy_reset:akt1c8" not in data


def test_back_leads_into_the_card(monkeypatch):
    """Из журнала и подтверждений возвращаемся в карточку сервера, а не
    в общий список: работа идёт внутри одного сервера."""
    assert backup_bot.copy_back_data("shmsql") == "backup_copy_srv:shmsql"
    # Длинное имя в 64 байта callback_data не влезает — тогда общий список
    assert backup_bot.copy_back_data("x" * 70) == "backup_copy"
    assert backup_bot.copy_back_data() == "backup_copy"
