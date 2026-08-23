"""
Общая настройка для pytest.

Тесты покрывают «чистые» функции (парсинг, валидация, окна времени),
поэтому тяжёлые внешние зависимости (winrm, telegram, psycopg2, matplotlib …)
подменяются заглушками — их код при импорте модулей не нужен.
"""
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
for sub in ("shared", "bot", "monitor"):
    path = str(ROOT / sub)
    if path not in sys.path:
        sys.path.insert(0, path)


class _StubModule(types.ModuleType):
    """Модуль-заглушка: любой атрибут возвращает MagicMock (в т.ч. вложенный)."""
    def __getattr__(self, name):
        stub = MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, stub)
        return stub


_STUB_MODULES = [
    "winrm", "requests", "paramiko",
    "psycopg2", "psycopg2.errors",
    "telegram", "telegram.ext", "telegram.error", "telegram.constants",
    "matplotlib", "matplotlib.pyplot", "matplotlib.dates", "matplotlib.ticker",
    "matplotlib.patches", "matplotlib.transforms",
    "numpy",
]

for _name in _STUB_MODULES:
    sys.modules.setdefault(_name, _StubModule(_name))


# telegram.error.BadRequest должен быть настоящим классом исключения:
# код ловит его в except, а MagicMock туда подставить нельзя.
class BadRequest(Exception):
    pass


sys.modules["telegram.error"].BadRequest = BadRequest
