"""Утренняя и вечерняя сводка: дашборд-файл плюс графики бэкапов.

Раньше по расписанию уходили только графики, а дашборд приходилось
запрашивать руками. Здесь же проверяется, что одна отвалившаяся половина
не уносит с собой вторую: рассылка идёт дважды в сутки, молчание в ней
заметят не сразу.

`import db` в тестах достаётся из monitor/ — модули бота грузятся по пути.
"""
import asyncio
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def bot_main():
    """bot.py читает окружение на импорте — до него подставляем минимум."""
    import os

    saved_env = {k: os.environ.get(k) for k in ("TELEGRAM_TOKEN", "TELEGRAM_ALLOWED_USER_ID")}
    os.environ.setdefault("TELEGRAM_TOKEN", "test-token")
    os.environ.setdefault("TELEGRAM_ALLOWED_USER_ID", "1")

    saved_db = sys.modules.get("db")
    # sys.path трогать нельзя: conftest уже добавил shared/bot/monitor, и
    # перестановка bot/ вперёд меняла бы значение `import db` для всех
    # последующих тестов — монитор переставал видеть свой db.py.
    spec = importlib.util.spec_from_file_location("bot_db", ROOT / "bot" / "db.py")
    bot_db = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bot_db)
    sys.modules["db"] = bot_db

    try:
        spec = importlib.util.spec_from_file_location("bot_main", ROOT / "bot" / "bot.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        if saved_db is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = saved_db
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class _Recorder:
    """Что именно ушло в рассылку."""

    def __init__(self):
        self.documents = []
        self.photos = []


def _wire(monkeypatch, bot_main, tmp_path, dashboard_error=None, charts_error=None):
    sent = _Recorder()
    report = tmp_path / "Дашборд_2026-09-01_08-00.html"
    report.write_text("<!doctype html>", encoding="utf-8")

    def build():
        if dashboard_error:
            raise dashboard_error
        return str(report)

    async def send_document(context, path, caption):
        sent.documents.append((path, caption))

    async def send_charts(send_photo):
        if charts_error:
            raise charts_error
        await send_photo("/tmp/backup.png", "🗂 Свежесть")

    async def send_photo_to_notify(context, path, caption):
        sent.photos.append((path, caption))

    monkeypatch.setattr(bot_main, "build_dashboard_html", build)
    monkeypatch.setattr(bot_main, "_send_document_to_notify", send_document)
    monkeypatch.setattr(bot_main, "_send_photo_to_notify", send_photo_to_notify)
    monkeypatch.setattr(bot_main, "send_backup_charts", send_charts)
    return sent, report


def test_digest_sends_dashboard_and_charts(monkeypatch, bot_main, tmp_path):
    sent, report = _wire(monkeypatch, bot_main, tmp_path)

    asyncio.run(bot_main.scheduled_digest(MagicMock()))

    assert len(sent.documents) == 1
    assert sent.documents[0][1] == bot_main.DASHBOARD_CAPTION
    assert len(sent.photos) == 1
    assert not report.exists(), "временный файл дашборда должен убираться"


def test_charts_still_go_when_dashboard_fails(monkeypatch, bot_main, tmp_path):
    """Сбой дашборда не должен отменять графики бэкапов."""
    sent, _ = _wire(monkeypatch, bot_main, tmp_path,
                    dashboard_error=ValueError("Нет данных мониторинга"))

    asyncio.run(bot_main.scheduled_digest(MagicMock()))

    assert sent.documents == []
    assert len(sent.photos) == 1


def test_dashboard_still_goes_when_charts_fail(monkeypatch, bot_main, tmp_path):
    sent, _ = _wire(monkeypatch, bot_main, tmp_path,
                    charts_error=RuntimeError("база недоступна"))

    asyncio.run(bot_main.scheduled_digest(MagicMock()))

    assert len(sent.documents) == 1
    assert sent.photos == []


def test_digest_scheduled_morning_and_evening():
    """08:00 и 18:00 по Алматы — расписание сводки."""
    source = (ROOT / "bot" / "bot.py").read_text(encoding="utf-8")
    times = source.count("scheduled_digest,")

    assert times == 2
    assert "time(hour=8, minute=0, tzinfo=ALMATY)" in source
    assert "time(hour=18, minute=0, tzinfo=ALMATY)" in source


def test_weekly_report_does_not_duplicate_dashboard(bot_main):
    """Воскресным утром дашборд уже пришёл в 08:00 — второй раз в 09:00 незачем."""
    import inspect

    source = inspect.getsource(bot_main.weekly_report)

    assert "build_dashboard_html" not in source
