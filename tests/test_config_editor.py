"""Тесты bot/config_editor.py: parse_field_value и validate_config."""
import pytest

from config_editor import (
    build_wizard_order,
    HELP_SECTIONS,
    _merge_backup_paths,
    display_value,
    parse_field_value,
    validate_config,
)
from tg_utils import TELEGRAM_TEXT_LIMIT, split_message


# ─── parse_field_value ───────────────────────────────────────

def test_parse_skip_inputs():
    for skip in ("-", "—", "", "   "):
        ok, value, err = parse_field_value("username", skip)
        assert ok and value is None and err is None


def test_parse_name_rejects_colon():
    ok, value, err = parse_field_value("name", "srv:1")
    assert not ok and err


def test_parse_name_duplicate():
    ok, value, err = parse_field_value("name", "srv1", existing_names={"srv1"})
    assert not ok and err


def test_parse_name_ok():
    ok, value, err = parse_field_value("name", "srv1", existing_names={"other"})
    assert ok and value == "srv1"


def test_parse_type_variants():
    assert parse_field_value("type", "windows") == (True, None, None)
    assert parse_field_value("type", "linux")[:2] == (True, "linux")
    assert parse_field_value("type", "device")[:2] == (True, "device")
    ok, _, err = parse_field_value("type", "solaris")
    assert not ok and err


def test_parse_list_splits_and_trims():
    ok, value, err = parse_field_value("services", "MSSQLSERVER, W3SVC ;Spooler")
    assert ok and value == ["MSSQLSERVER", "W3SVC", "Spooler"]


def test_parse_bool():
    assert parse_field_value("dbsize", "да")[:2] == (True, True)
    assert parse_field_value("dbsize", "нет") == (True, None, None)
    ok, _, err = parse_field_value("dbsize", "может быть")
    assert not ok and err


def test_parse_int_retention():
    assert parse_field_value("retention_days", "14")[:2] == (True, 14)
    ok, _, err = parse_field_value("retention_days", "2")
    assert not ok and err        # ниже минимума
    ok, _, err = parse_field_value("retention_days", "xx")
    assert not ok and err


def test_parse_regpath():
    assert parse_field_value("reg_file", "C:\\Scripts\\x.reg")[:2] == (True, "C:\\Scripts\\x.reg")
    ok, _, err = parse_field_value("reg_file", "C:\\Scripts\\x.txt")
    assert not ok and err


# ─── validate_config ─────────────────────────────────────────

def _valid():
    return [
        {"name": "a", "host": "10.0.0.1"},
        {"name": "b", "host": "10.0.0.2", "type": "linux", "services": ["nginx"]},
    ]


def test_validate_ok():
    validate_config(_valid())   # не должно бросить


def test_validate_requires_name_and_host():
    with pytest.raises(ValueError):
        validate_config([{"host": "10.0.0.1"}])
    with pytest.raises(ValueError):
        validate_config([{"name": "a"}])


def test_validate_duplicate_name():
    with pytest.raises(ValueError):
        validate_config([
            {"name": "a", "host": "10.0.0.1"},
            {"name": "a", "host": "10.0.0.2"},
        ])


def test_validate_duplicate_host():
    with pytest.raises(ValueError):
        validate_config([
            {"name": "a", "host": "10.0.0.1"},
            {"name": "b", "host": "10.0.0.1"},
        ])


def test_validate_bad_types():
    with pytest.raises(ValueError):
        validate_config([{"name": "a", "host": "h", "services": "nginx"}])
    with pytest.raises(ValueError):
        validate_config([{"name": "a", "host": "h", "retention_days": 2}])
    with pytest.raises(ValueError):
        validate_config([{"name": "a", "host": "h", "type": "solaris"}])
    with pytest.raises(ValueError):
        validate_config([{"name": "a", "host": "h", "reg_file": "x.txt"}])


# ─── Недельное расписание в конфиге ──────────────────────────

def _with_backup_path(path_spec):
    return [{"name": "a", "host": "h", "backups": {"sql": [path_spec]}}]


def test_validate_accepts_weekly_schedule():
    validate_config(_with_backup_path({
        "path": "F:\\FULL", "schedule_weekday": "mon", "schedule_by_hour": 9
    }))


def test_validate_rejects_half_schedule():
    """Одно поле без второго молча не работало бы."""
    with pytest.raises(ValueError):
        validate_config(_with_backup_path({"path": "F:\\FULL", "schedule_weekday": "mon"}))
    with pytest.raises(ValueError):
        validate_config(_with_backup_path({"path": "F:\\FULL", "schedule_by_hour": 9}))


def test_validate_rejects_bad_schedule_values():
    with pytest.raises(ValueError):
        validate_config(_with_backup_path({
            "path": "F:\\FULL", "schedule_weekday": "monday", "schedule_by_hour": 9
        }))
    with pytest.raises(ValueError):
        validate_config(_with_backup_path({
            "path": "F:\\FULL", "schedule_weekday": "mon", "schedule_by_hour": 24
        }))


# ─── _merge_backup_paths: правка не теряет расписание ────────

def test_merge_preserves_schedule_on_edit():
    """Регрессия: правка alert_hours из бота стирала schedule_* молча."""
    existing = [{
        "path": "F:\\FULL", "schedule_weekday": "mon", "schedule_by_hour": 9
    }]
    merged = _merge_backup_paths(existing, [{"path": "F:\\FULL", "alert_hours": 30}])
    assert merged == [{
        "path": "F:\\FULL", "alert_hours": 30,
        "schedule_weekday": "mon", "schedule_by_hour": 9,
    }]


def test_merge_preserves_schedule_when_path_becomes_plain_string():
    existing = [{"path": "F:\\FULL", "schedule_weekday": "mon", "schedule_by_hour": 9}]
    merged = _merge_backup_paths(existing, ["F:\\FULL"])
    assert merged[0]["schedule_weekday"] == "mon"
    assert merged[0]["schedule_by_hour"] == 9


def test_merge_allows_explicit_override():
    existing = [{"path": "F:\\FULL", "schedule_weekday": "mon", "schedule_by_hour": 9}]
    merged = _merge_backup_paths(existing, [{
        "path": "F:\\FULL", "schedule_weekday": "sun", "schedule_by_hour": 3
    }])
    assert merged == [{
        "path": "F:\\FULL", "schedule_weekday": "sun", "schedule_by_hour": 3
    }]


def test_merge_keeps_other_paths_untouched():
    existing = ["F:\\DIFF", {"path": "F:\\FULL", "schedule_weekday": "mon",
                             "schedule_by_hour": 9}]
    merged = _merge_backup_paths(existing, [{"path": "F:\\FULL", "alert_hours": 30}])
    assert merged[0] == "F:\\DIFF"
    assert len(merged) == 2


# ─── Ввод расписания в мастере: путь@день:час ────────────────

def _parse_paths(text):
    ok, value, err = parse_field_value("backups_sql", text)
    assert ok, err
    return value


def test_parse_path_with_weekly_schedule():
    assert _parse_paths("E:\\Full@mon:9") == [{
        "path": "E:\\Full", "schedule_weekday": "mon", "schedule_by_hour": 9
    }]


def test_parse_schedule_accepts_russian_and_loose_format():
    for text in ("E:\\Full@пн:9", "E:\\Full@пн 9", "E:\\Full@mon9", "E:\\Full@MON:09"):
        assert _parse_paths(text)[0]["schedule_weekday"] == "mon"
        assert _parse_paths(text)[0]["schedule_by_hour"] == 9


def test_parse_schedule_keeps_windows_path_with_colon():
    """В пути есть «:» — резать надо по «@», а не по первому двоеточию."""
    assert _parse_paths("F:\\ftp\\branch\\base_one\\FULL@пн:9")[0]["path"] \
        == "F:\\ftp\\branch\\base_one\\FULL"


def test_parse_schedule_clear():
    assert _parse_paths("E:\\Full@-") == [{
        "path": "E:\\Full", "schedule_weekday": None, "schedule_by_hour": None
    }]


def test_parse_rejects_hours_together_with_schedule():
    """Порог по возрасту к недельной копии не применяется — просим выбрать одно."""
    ok, _, err = parse_field_value("backups_sql", "E:\\Full=40@пн:9")
    assert not ok and "одно" in err


@pytest.mark.parametrize("text", [
    "E:\\Full@somemonday:9",
    "E:\\Full@пн:26",
    "E:\\Full@пн",
    "@пн:9",
])
def test_parse_rejects_bad_schedule(text):
    ok, _, err = parse_field_value("backups_sql", text)
    assert not ok and err


def test_parse_plain_path_unchanged():
    assert _parse_paths("E:\\Backups") == ["E:\\Backups"]
    assert _parse_paths("E:\\Backups=40") == [{"path": "E:\\Backups", "alert_hours": 40}]


def test_wizard_input_round_trips_into_valid_config():
    """Введённое в мастере расписание проходит валидацию конфига."""
    items = _parse_paths("E:\\Full@пн:9")
    validate_config([{"name": "a", "host": "h", "backups": {"sql": items}}])


def test_merge_clears_schedule_on_at_dash():
    existing = [{"path": "E:\\Full", "schedule_weekday": "mon", "schedule_by_hour": 9}]
    merged = _merge_backup_paths(existing, _parse_paths("E:\\Full@-"))
    assert merged == ["E:\\Full"]


def test_merge_sets_schedule_from_wizard():
    merged = _merge_backup_paths(["E:\\Full"], _parse_paths("E:\\Full@пн:9"))
    assert merged == [{
        "path": "E:\\Full", "schedule_weekday": "mon", "schedule_by_hour": 9
    }]


def test_display_value_shows_schedule():
    server = {"backups": {"sql": [{
        "path": "F:\\FULL", "schedule_weekday": "mon", "schedule_by_hour": 9
    }]}}
    assert "недельно: понедельник 09:00" in display_value(server, "backups_sql")


# ─── Справка ─────────────────────────────────────────────────

def test_help_sections_are_filled():
    assert HELP_SECTIONS, "справка не должна быть пустой"
    for key, (title, text) in HELP_SECTIONS.items():
        assert title.strip(), f"{key}: пустой заголовок кнопки"
        assert len(text.strip()) > 200, f"{key}: раздел подозрительно короткий"


def test_help_sections_fit_telegram_limit():
    """Раздел должен уходить одним сообщением — иначе кнопки уезжают вниз."""
    for key, (_title, text) in HELP_SECTIONS.items():
        assert len(split_message(text)) == 1, (
            f"{key}: {len(text)} символов > лимита {TELEGRAM_TEXT_LIMIT}, "
            f"раздел стоит разделить"
        )


def test_help_section_keys_are_valid_callbacks():
    """callback_data Telegram ограничен 64 байтами и не должен содержать «:»
    внутри ключа — обработчик режет строку по первому двоеточию."""
    for key in HELP_SECTIONS:
        assert ":" not in key, f"{key}: двоеточие сломает разбор callback_data"
        callback = f"cfg_help:{key}"
        assert len(callback.encode("utf-8")) <= 64, f"{key}: callback_data длиннее 64 байт"


def test_help_documents_weekly_schedule_syntax():
    """Синтаксис расписания обязан быть описан — иначе им не воспользуются."""
    backups = HELP_SECTIONS["backups"][1]
    assert "@пн:9" in backups
    assert "@-" in backups
    assert "НЕДЕЛЬНАЯ КОПИЯ" in backups


def test_help_explains_how_to_add_server():
    start = HELP_SECTIONS["start"][1]
    assert "Добавить сервер" in start
    assert "Пропустить" in start


# ─── Мастер для Linux/NAS ────────────────────────────────────

def test_linux_wizard_asks_for_backup_paths():
    """NAS (Synology) заводится как linux, и его каталоги должны задаваться
    из бота — иначе сетевые папки некуда прописать."""
    order = build_wizard_order("linux")
    for key in ("backups_sql", "backups_1c", "backups_veeam"):
        assert key in order, f"{key}: без него бэкапы NAS не настроить"
    assert "backup_alert_hours" in order
    assert "backup_size_check" in order


def test_linux_wizard_skips_windows_only_fields():
    """MSSQL, журналы 1С, реестр и PowerShell-удаление на Linux не работают."""
    order = build_wizard_order("linux")
    for key in ("dbsize", "onec_logs", "verify_backup", "reg_file", "retention_days"):
        assert key not in order, f"{key}: на Linux этого нет"


def test_device_wizard_is_minimal():
    assert build_wizard_order("device") == ["name", "host", "type"]


def test_windows_wizard_keeps_everything():
    order = build_wizard_order("windows")
    for key in ("dbsize", "verify_backup", "retention_days", "backups_sql"):
        assert key in order


# ─── Права на файлы конфига ──────────────────────────────────

import json as _json
import os as _os

import config_editor as _cfg


def _use_tmp_config(tmp_path, monkeypatch, content):
    path = tmp_path / "servers.json"
    path.write_text(_json.dumps(content), encoding="utf-8")
    monkeypatch.setattr(_cfg, "SERVERS_FILE", str(path))
    return path


def test_config_written_with_owner_only_mode(tmp_path, monkeypatch):
    """В servers.json лежат пароли WinRM/SSH — режим не должен зависеть
    от umask, под которым запущен процесс."""
    path = _use_tmp_config(tmp_path, monkeypatch, [{"name": "a", "host": "h"}])
    monkeypatch.setattr(_os, "umask", lambda mask: 0)   # даже при щедром umask

    _cfg.save_config([{"name": "a", "host": "h", "password": "s3cret-pw"}])

    assert _os.stat(path).st_mode & 0o777 == 0o600


def test_backup_copy_is_not_world_readable(tmp_path, monkeypatch):
    """Регрессия: .bak писался обычным open() и получал 0644 —
    полная копия конфига с паролями была читаема любому на хосте."""
    path = _use_tmp_config(tmp_path, monkeypatch,
                           [{"name": "a", "host": "h", "password": "s3cret-pw"}])

    _cfg.save_config([{"name": "a", "host": "h2"}])

    backup = tmp_path / "servers.json.bak"
    assert backup.exists(), "резервная копия должна создаваться"
    assert "s3cret-pw" in backup.read_text(encoding="utf-8"), \
        "копия обязана содержать пароль — потому и режим должен быть строгим"
    assert _os.stat(backup).st_mode & 0o777 == 0o600


def test_existing_loose_backup_is_tightened(tmp_path, monkeypatch):
    """Файл, оставшийся с прежних версий в 0644, надо ужать при перезаписи."""
    path = _use_tmp_config(tmp_path, monkeypatch, [{"name": "a", "host": "h"}])
    backup = tmp_path / "servers.json.bak"
    backup.write_text("старое", encoding="utf-8")
    _os.chmod(backup, 0o644)

    _cfg.save_config([{"name": "a", "host": "h2"}])

    assert _os.stat(backup).st_mode & 0o777 == 0o600
