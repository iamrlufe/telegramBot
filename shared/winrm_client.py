import base64
import binascii
import json
import os

import winrm

# Кусок PowerShell: печатает объект как base64(UTF-8 JSON).
# Нужен там, где в выводе бывает кириллица (имена папок, тексты ошибок SQL):
# консоль сервера в OEM-кодировке превращает её в «?????» ещё до передачи.
# Base64 — чистый ASCII, транспорт его не искажает.
PS_OUT_B64_HELPER = r"""
function Out-B64($obj) {
    $json = ($obj | ConvertTo-Json -Depth 4 -Compress)
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
}
"""


def decode_ps_output(output: str) -> str:
    """base64(UTF-8) из PowerShell → строка. Если пришёл обычный текст/JSON
    (старый скрипт или ошибка) — возвращаем как есть. validate=True важен:
    он отличает base64 от JSON, иначе JSON молча раскодировался бы в мусор."""
    clean = (output or "").strip()
    try:
        return base64.b64decode(clean, validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return output


def ps_json(output: str):
    """Разбирает вывод PowerShell (base64 или обычный JSON) в объект."""
    decoded = decode_ps_output(output)
    return json.loads(decoded) if decoded else {}


# pywinrm передаёт скрипт через `powershell -EncodedCommand`, а командная
# строка WinRM ограничена 8192 символами. UTF-16 + base64 раздувают текст
# примерно в 2.7 раза, поэтому отступы и комментарии стоят реальных лимитов:
# сервер отвечает «The command line is too long» ещё до запуска скрипта.
MAX_PS_COMMAND_CHARS = 8000


def compact_ps(script: str) -> str:
    """Убирает отступы, пустые строки и строки-комментарии из PS-скрипта."""
    lines = [line.strip() for line in script.splitlines()]
    return "\n".join(
        line for line in lines if line and not line.startswith("#")
    )


def run_ps(host: str, script: str, username: str = None, password: str = None,
           operation_timeout_sec: int = 120, read_timeout_sec: int = 180) -> str:
    """
    Выполняет PowerShell скрипт на удалённом Windows сервере.
    Если username/password не переданы — берёт из WINRM_USERNAME / WINRM_PASSWORD.
    Для долгих операций (RESTORE VERIFYONLY) таймауты можно увеличить.

    WINRM_MESSAGE_ENCRYPTION: auto (по умолчанию) | always | never.
    "always" запрещает передачу без шифрования полезной нагрузки.
    """
    username = username or os.getenv("WINRM_USERNAME")
    password = password or os.getenv("WINRM_PASSWORD")

    script = compact_ps(script)
    encoded_len = len(base64.b64encode(script.encode("utf_16_le")))
    if encoded_len > MAX_PS_COMMAND_CHARS:
        raise Exception(
            f"PowerShell-скрипт слишком длинный для WinRM: {encoded_len} из "
            f"{MAX_PS_COMMAND_CHARS} символов после кодирования"
        )

    session = winrm.Session(
        f"http://{host}:5985/wsman",
        auth=(username, password),
        transport="ntlm",
        message_encryption=os.getenv("WINRM_MESSAGE_ENCRYPTION", "auto"),
        operation_timeout_sec=operation_timeout_sec,
        read_timeout_sec=read_timeout_sec
    )
    result = session.run_ps(script)

    if result.status_code != 0:
        raise Exception(result.std_err.decode("utf-8", errors="replace").strip())

    return result.std_out.decode("utf-8", errors="replace").strip()
