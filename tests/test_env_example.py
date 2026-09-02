"""Сверка .env.example с кодом.

Пример .env расходится с кодом молча: переменную добавили, в пример не
внесли — и настройка существует только в голове того, кто её писал.
Тест ловит расхождение в обе стороны.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
CODE_DIRS = ("bot", "monitor", "shared")

# Переменные читаются и напрямую, и через типизированные обёртки. Обёртки
# живут в shared/settings.py (int_env, float_env), а модули с собственным
# префиксом в логе оборачивают их ещё раз — отсюда необязательное «_».
READERS = re.compile(
    r'(?:getenv|_?int_env|_?float_env|_?num_env|_require_env|_require_int_env)'
    r'\(\s*"([A-Z_0-9]+)"'
)

# Задаются в docker-compose из тех же значений, отдельной строки не требуют.
NOT_USER_FACING: set = set()


def _vars_in_code() -> set:
    found = set()
    for directory in CODE_DIRS:
        for path in (ROOT / directory).glob("*.py"):
            found |= set(READERS.findall(path.read_text(encoding="utf-8")))
    # Имя переменной хранится в константе, а не в вызове getenv.
    found.add("TELEGRAM_DELETE_USERS")
    return found - NOT_USER_FACING


def _vars_in_example() -> set:
    text = EXAMPLE.read_text(encoding="utf-8")
    return set(re.findall(r'^#?\s*([A-Z_0-9]+)=', text, re.M))


def test_example_env_exists():
    assert EXAMPLE.exists(), ".env.example должен лежать в корне репозитория"


def test_every_env_var_documented():
    missing = sorted(_vars_in_code() - _vars_in_example())
    assert not missing, f"нет в .env.example: {', '.join(missing)}"


def test_no_obsolete_vars_in_example():
    extra = sorted(_vars_in_example() - _vars_in_code())
    assert not extra, f"в .env.example есть, а в коде не используется: {', '.join(extra)}"


def test_required_vars_are_not_commented():
    """Обязательные переменные должны быть готовы к заполнению, а не
    закомментированы: иначе бот падает на старте с «переменная не задана»."""
    text = EXAMPLE.read_text(encoding="utf-8")
    for name in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
                 "POSTGRES_HOST", "TELEGRAM_TOKEN", "TELEGRAM_ALLOWED_USER_ID",
                 "WINRM_USERNAME", "WINRM_PASSWORD"):
        assert re.search(rf'^{name}=', text, re.M), \
            f"{name} обязательна — строка не должна быть закомментирована"


def test_no_real_secrets_in_example():
    """Репозиторий публичный: в примере только заглушки."""
    text = EXAMPLE.read_text(encoding="utf-8")
    assert not re.search(r'^\s*TELEGRAM_TOKEN=\d+:[A-Za-z0-9_-]{20,}', text, re.M), \
        "похоже на настоящий токен бота"
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        assert "agrotnk" not in line.lower(), "реальный домен в примере"


def test_example_matches_readme_block():
    """В readme тот же набор переменных: две инструкции расходились бы."""
    readme = (ROOT / "readme.md").read_text(encoding="utf-8")
    block = re.search(r'```env\n(.*?)```', readme, re.S)
    assert block, "в readme должен остаться блок с примером .env"
    in_readme = set(re.findall(r'^#?\s*([A-Z_0-9]+)=', block.group(1), re.M))
    assert not (_vars_in_example() - in_readme), \
        "переменные из .env.example отсутствуют в readme"
