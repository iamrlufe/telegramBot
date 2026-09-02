"""
shared/settings.py — общий разбор .env и общие константы.

Раньше `_int_env` был скопирован в одиннадцать модулей, и копии успели
разойтись: одни падали на пустой строке в .env, другие молча брали
умолчание, третьи писали в лог. Тесты фиксируют объединённое поведение,
чтобы расхождение не вернулось при следующем копировании.
"""
import settings


def test_int_from_env(monkeypatch):
    monkeypatch.setenv("TEST_HOURS", "12")
    assert settings.int_env("TEST_HOURS", 48) == 12


def test_missing_gives_default(monkeypatch):
    monkeypatch.delenv("TEST_HOURS", raising=False)
    assert settings.int_env("TEST_HOURS", 48) == 48


def test_empty_value_gives_default(monkeypatch):
    """`TEST_HOURS=` в .env — это «не задано», а не ноль и не ошибка."""
    monkeypatch.setenv("TEST_HOURS", "")
    assert settings.int_env("TEST_HOURS", 48) == 48


def test_whitespace_is_trimmed(monkeypatch):
    monkeypatch.setenv("TEST_HOURS", "  24  ")
    assert settings.int_env("TEST_HOURS", 48) == 24


def test_garbage_gives_default(monkeypatch):
    monkeypatch.setenv("TEST_HOURS", "двенадцать")
    assert settings.int_env("TEST_HOURS", 48) == 48


def test_garbage_is_logged_with_tag(monkeypatch, capsys):
    """Без строки в логе опечатка в .env выглядит как «настройка не работает»."""
    monkeypatch.setenv("TEST_HOURS", "12ч")
    assert settings.int_env("TEST_HOURS", 48, tag="monitor") == 48
    assert "[monitor]" in capsys.readouterr().out


def test_garbage_is_silent_without_tag(monkeypatch, capsys):
    monkeypatch.setenv("TEST_HOURS", "12ч")
    settings.int_env("TEST_HOURS", 48)
    assert capsys.readouterr().out == ""


def test_float_env(monkeypatch):
    monkeypatch.setenv("TEST_RATIO", "0.5")
    assert settings.float_env("TEST_RATIO", 1.0) == 0.5
    monkeypatch.setenv("TEST_RATIO", "половина")
    assert settings.float_env("TEST_RATIO", 1.0) == 1.0


def test_int_env_does_not_accept_float(monkeypatch):
    """«2.5 часа» — опечатка, а не 2 часа: молча округлять нельзя."""
    monkeypatch.setenv("TEST_HOURS", "2.5")
    assert settings.int_env("TEST_HOURS", 48) == 48


def test_single_timezone_and_config_path():
    """Обе константы раньше дублировались десятком литералов. Разойдись они —
    бот правил бы один servers.json, а монитор читал другой."""
    assert str(settings.ALMATY) == "Asia/Almaty"
    assert settings.SERVERS_FILE == "/app/config/servers.json"


def test_no_local_copies_left():
    """Регрессия: собственный разбор .env и свой ZoneInfo в модулях —
    именно то, от чего избавлялись."""
    from pathlib import Path

    root = Path(settings.__file__).resolve().parent.parent
    for directory in ("bot", "monitor", "shared"):
        for path in (root / directory).glob("*.py"):
            if path.name == "settings.py":
                continue
            source = path.read_text(encoding="utf-8")
            assert 'ZoneInfo("Asia/Almaty")' not in source, \
                f"{path.name}: свой часовой пояс вместо settings.ALMATY"
            assert '"/app/config/servers.json"' not in source, \
                f"{path.name}: свой путь вместо settings.SERVERS_FILE"
            for idiom in ('os.getenv(name, str(default))',
                          'os.getenv(name, "").strip()'):
                assert idiom not in source, \
                    f"{path.name}: свой разбор .env вместо settings.int_env"
