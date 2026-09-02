"""
RESTORE VERIFYONLY: проверка восстановимости последнего .bak.

Ключевая деталь — WITH CHECKSUM. Без него VERIFYONLY читает заголовок и
структуру, но не сверяет контрольные суммы страниц: битая страница внутри
файла проходит проверку молча и всплывает уже при реальном восстановлении,
то есть в тот момент, когда бэкап был единственной надеждой.
"""
import backup_verify


def _script(monkeypatch):
    captured = {}

    def fake_run_ps(host, script, username=None, password=None, **kwargs):
        captured["host"] = host
        captured["script"] = script
        captured["kwargs"] = kwargs
        return "результат"

    monkeypatch.setattr(backup_verify, "run_ps", fake_run_ps)
    monkeypatch.setattr(backup_verify, "ps_json", lambda r: {"Status": "ok"})
    backup_verify.verify_newest_bak("srv-01.example.local", "D:\\backup")
    return captured


def test_verify_uses_checksum(monkeypatch):
    assert "RESTORE VERIFYONLY" in _script(monkeypatch)["script"]
    assert "WITH CHECKSUM" in _script(monkeypatch)["script"]


def test_verify_keeps_long_timeouts(monkeypatch):
    """Проверка читает весь файл целиком: на больших базах это часы, и
    обычный таймаут WinRM обрывал её на середине."""
    kwargs = _script(monkeypatch)["kwargs"]
    assert kwargs["operation_timeout_sec"] >= 3600
    assert kwargs["read_timeout_sec"] > kwargs["operation_timeout_sec"]


def test_verify_reports_status(monkeypatch):
    monkeypatch.setattr(backup_verify, "run_ps", lambda *a, **k: "результат")
    monkeypatch.setattr(backup_verify, "ps_json", lambda r: {
        "Status": "failed", "File": "D:\\backup\\db.bak", "SizeGB": 12.5,
        "Modified": "2026-09-01 03:00:00", "DurationSec": 940,
        "Error": "ошибка контрольной суммы страницы",
    })

    res = backup_verify.verify_newest_bak("srv-01.example.local", "D:\\backup")

    assert res["status"] == "failed"
    assert res["size_gb"] == 12.5
    assert res["duration_sec"] == 940
    assert "контрольной суммы" in res["error"]
    assert res["modified"].year == 2026
