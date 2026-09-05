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
