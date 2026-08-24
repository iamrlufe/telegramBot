"""
Файлы состояния алертов (monitor/alerts.py: save_json / load_json).

В этих файлах живут заглушённые серверы и состояния алертов. load_json
намеренно молчалив — на любой ошибке возвращает пустой словарь, — поэтому
битый файл не превращается в заметную аварию, а тихо стирает все mute.
Отсюда требование: запись должна быть атомарной.
"""
import json
import os

import pytest

import alerts


def test_writes_and_reads_back(tmp_path):
    path = str(tmp_path / "state.json")
    alerts.save_json(path, {"srv-01": True})

    assert alerts.load_json(path) == {"srv-01": True}


def test_no_temp_files_left_behind(tmp_path):
    path = str(tmp_path / "state.json")
    alerts.save_json(path, {"srv-01": True})
    alerts.save_json(path, {"srv-01": True, "srv-02": "2026-08-24T12:00:00"})

    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_failed_write_keeps_previous_file(tmp_path, monkeypatch):
    path = str(tmp_path / "state.json")
    alerts.save_json(path, {"srv-01": True})

    def boom(*args, **kwargs):
        raise OSError("на диске кончилось место")

    monkeypatch.setattr(alerts.json, "dump", boom)
    with pytest.raises(OSError):
        alerts.save_json(path, {"srv-02": True})

    # Прежнее содержимое цело: раньше открытие на "w" обрезало файл до нуля
    # ещё до записи, и сбой в этот момент терял все заглушённые серверы.
    assert alerts.load_json(path) == {"srv-01": True}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_corrupted_file_reads_as_empty(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{обрыв на середине")

    assert alerts.load_json(str(path)) == {}


def test_replaces_content_completely(tmp_path):
    path = str(tmp_path / "state.json")
    alerts.save_json(path, {"a": 1, "b": 2, "c": 3})
    alerts.save_json(path, {"a": 1})

    # os.replace меняет файл целиком — хвост от длинной прошлой записи
    # не должен оставаться
    with open(path) as f:
        assert json.load(f) == {"a": 1}
    assert os.path.getsize(path) == len(json.dumps({"a": 1}))
