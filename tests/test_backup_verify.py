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


def test_verify_asks_the_file_whether_it_has_checksums(monkeypatch):
    """WITH CHECKSUM нельзя ставить безусловно: на копии, снятой без
    контрольных сумм, сервер не предупреждает, а прерывает проверку ошибкой
    3187 — и verify не выполняется вовсе. Режим выбирается по заголовку."""
    script = _script(monkeypatch)["script"]

    assert "RESTORE HEADERONLY" in script
    assert "HasBackupChecksums" in script
    assert "RESTORE VERIFYONLY" in script
    # WITH CHECKSUM дописывается условием, а не входит в запрос всегда
    assert 'VERIFYONLY FROM DISK = N\'$escaped\' WITH CHECKSUM' not in script
    assert '$query + " WITH CHECKSUM"' in script
    # NULL в колонке приезжает как [System.DBNull] — объект, истинный в
    # PowerShell. Проверка на «просто истинность» снова включила бы режим
    # там, где сумм нет, и вернула бы ошибку 3187.
    assert "HasBackupChecksums -eq $true" in script


def test_verify_reports_whether_pages_were_checked(monkeypatch):
    """Отчёт обязан различать «проверено со сверкой страниц» и «проверено
    поверхностно»: это разная степень уверенности в копии."""
    monkeypatch.setattr(backup_verify, "run_ps", lambda *a, **k: "результат")

    monkeypatch.setattr(backup_verify, "ps_json",
                        lambda r: {"Status": "ok", "Checksum": True})
    assert backup_verify.verify_newest_bak("srv-01.example.local",
                                           "D:\\backup")["checksum"] is True

    monkeypatch.setattr(backup_verify, "ps_json",
                        lambda r: {"Status": "ok", "Checksum": False})
    assert backup_verify.verify_newest_bak("srv-01.example.local",
                                           "D:\\backup")["checksum"] is False

    # Поля нет вовсе (старый ответ) — считаем, что сумм не было
    monkeypatch.setattr(backup_verify, "ps_json", lambda r: {"Status": "ok"})
    assert backup_verify.verify_newest_bak("srv-01.example.local",
                                           "D:\\backup")["checksum"] is False


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
