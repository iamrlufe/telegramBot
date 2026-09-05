"""Пример конфига сверяется с кодом и с readme.

Для `.env` такой сторож есть давно (test_env_example.py), а для
`config/example.servers.json` не было — и пример отставал молча: поля
копирования на приёмник (copy_target, copy_target_root, copy_types,
copy_delay_minutes, copy_after_backup) были описаны в readme и читались
кодом, но в примере не встречались вовсе. Новая инсталляция узнавала о них
только из таблицы полей.

Здесь три проверки: пример валиден для самого бота, в нём встречается
каждое поле из таблицы readme и в readme описано каждое поле из примера.
"""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config" / "example.servers.json"
README = ROOT / "readme.md"

# Служебные ключи: комментарии в примере и вложенные структуры, которые
# описаны в readme прозой, а не строкой таблицы.
NOT_FIELDS = {"_comment"}


def _servers() -> list:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _readme_fields() -> set:
    """Первая колонка таблицы «Поля servers.json».

    Строка вида `| `mail_log` / `audit_log` | нет | … |` описывает два поля
    сразу — берём из колонки все имена в обратных кавычках.
    """
    text = README.read_text(encoding="utf-8")
    start = text.index("## Поля servers.json")
    table = text[start:].split("\n\n")[1]
    fields = set()
    for line in table.splitlines():
        if not line.startswith("| `"):
            continue
        first_column = line.split("|")[1]
        fields.update(re.findall(r"`([a-z_0-9]+)`", first_column))
    return fields


def _example_keys() -> set:
    keys = set()
    for server in _servers():
        keys.update(k for k in server if k not in NOT_FIELDS)
    return keys


def test_example_is_valid_for_the_bot():
    """Тот же разбор, что не пускает битый конфиг на диск."""
    spec = importlib.util.spec_from_file_location(
        "config_editor_for_example", ROOT / "bot" / "config_editor.py")
    config_editor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_editor)
    config_editor.validate_config(_servers())


def test_every_documented_field_appears_in_example():
    missing = sorted(_readme_fields() - _example_keys())
    assert not missing, (
        "поля описаны в readme, но их нет в config/example.servers.json: "
        + ", ".join(missing))


def test_every_example_field_is_documented():
    unknown = sorted(_example_keys() - _readme_fields())
    assert not unknown, (
        "поля есть в примере, но не описаны в таблице readme: "
        + ", ".join(unknown))


def test_example_has_no_real_addresses():
    """Репозиторий публичный: в примере только 192.0.2.0/24 и example.local."""
    text = EXAMPLE.read_text(encoding="utf-8")
    for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        assert address.startswith("192.0.2."), f"не документационный адрес: {address}"
    for host in re.findall(r"\b[a-z0-9-]+\.[a-z]+\.[a-z]+\b", text):
        assert host.endswith(".example.local") or host.endswith(".vsphere.local"), \
            f"не документационное имя: {host}"
