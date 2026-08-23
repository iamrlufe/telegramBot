"""Тесты bot/dirdig.py: проваливание в каталоги в разборе «кто съел место».

Путь вида /opt/zimbra/backup/sessions/full-20260806 не помещается в
callback_data (лимит Telegram — 64 байта), поэтому в кнопку идёт короткий
токен, а сам путь живёт в памяти процесса. Тесты держат этот контракт
и ограничитель глубины.
"""
import dirdig
from dirdig import (
    DIG_MAX_DEPTH, DIG_TOKENS, DIG_TOKENS_MAX,
    basename, dig_kb, dig_token, parent_path,
)

TOP = [("/opt/zimbra/store", 900.0), ("/opt/zimbra/backup", 400.5)]


def _button_calls():
    """Клавиатура собирается из застабленного telegram — читаем вызовы кнопок."""
    return dirdig.InlineKeyboardButton.call_args_list


def _datas():
    return [call.kwargs.get("callback_data") for call in _button_calls()]


# ─── Токены вместо путей ─────────────────────────────────────

def test_token_keeps_full_path():
    """Смысл токена: длинный путь не теряется, в кнопку идёт короткий ключ."""
    path = "/opt/zimbra/backup/sessions/full-20260806-050000.123"
    token = dig_token("nas.example.local", "/", path, 3)
    assert DIG_TOKENS[token] == ("nas.example.local", "/", path, 3)
    assert len(f"dig:{token}".encode("utf-8")) <= 64


def test_token_cache_is_bounded():
    """Кэш не должен расти бесконечно — бот живёт месяцами."""
    for i in range(DIG_TOKENS_MAX + 50):
        dig_token("srv", "/", f"/data/{i}", 1)
    assert len(DIG_TOKENS) <= DIG_TOKENS_MAX


# ─── Разбор путей ────────────────────────────────────────────

def test_parent_of_posix_path():
    assert parent_path("/opt/zimbra/backup") == "/opt/zimbra"
    assert parent_path("/opt") == "/"
    assert parent_path("/") == "/"           # выше корня не поднимаемся


def test_parent_of_windows_path():
    """Windows-пути приходят с бэкслешами — posixpath их не разберёт."""
    assert parent_path(r"E:\Backups\Old") == r"E:\Backups"


def test_basename():
    assert basename("/opt/zimbra/backup") == "backup"
    assert basename(r"E:\Backups\Old") == "Old"
    assert basename("/") == "/"              # у корня имени нет — отдаём как есть


# ─── Клавиатура ──────────────────────────────────────────────

def test_dig_buttons_created_for_children():
    dirdig.InlineKeyboardButton.reset_mock()
    dig_kb("mail", "/", "/opt", 1, TOP)
    datas = _datas()
    assert sum(1 for d in datas if d and d.startswith("dig:")) == 3  # 2 ребёнка + «наверх»
    assert "server:mail" in datas


def test_no_dig_buttons_at_max_depth():
    """На предельной глубине кнопок вглубь нет — только наверх и к серверу."""
    dirdig.InlineKeyboardButton.reset_mock()
    dig_kb("mail", "/", "/a/b/c/d", DIG_MAX_DEPTH, TOP)
    assert sum(1 for d in _datas() if d and d.startswith("dig:")) == 1


def test_no_up_button_at_root():
    """С корня диска подниматься некуда."""
    dirdig.InlineKeyboardButton.reset_mock()
    dig_kb("mail", "/", "/", 0, TOP)
    texts = [call.args[0] for call in _button_calls()]
    assert not any("Наверх" in t for t in texts)


def test_child_token_carries_next_depth():
    """Каждый спуск увеличивает глубину — иначе ограничитель не сработает."""
    dirdig.InlineKeyboardButton.reset_mock()
    dig_kb("mail", "/", "/opt", 2, [("/opt/zimbra", 1400.0)])
    tokens = [d.split(":", 1)[1] for d in _datas() if d and d.startswith("dig:")]
    entries = {DIG_TOKENS[t][2]: DIG_TOKENS[t] for t in tokens}
    assert entries["/opt/zimbra"] == ("mail", "/", "/opt/zimbra", 3)
    assert entries["/"] == ("mail", "/", "/", 1)      # кнопка «наверх»


def test_button_count_capped():
    """Топ может быть длинным, но кнопок под сообщением — не больше DIG_BUTTONS."""
    dirdig.InlineKeyboardButton.reset_mock()
    many = [(f"/opt/dir{i}", float(i)) for i in range(30)]
    dig_kb("mail", "/", "/opt", 1, many)
    assert sum(1 for d in _datas() if d and d.startswith("dig:")) == dirdig.DIG_BUTTONS + 1
