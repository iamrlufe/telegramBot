"""
monitor/firewall_maintenance.py

Снятие истёкших блокировок IP.

Единственная часть раздела 🛡 Блокировка IP, которая работает без человека,
и обратная по смыслу остальным: она не отрезает доступ, а возвращает.
Ошибиться тут можно только в сторону «сняли раньше» — поэтому шаг и
автоматический.

Без него блокировки копятся: адрес отдали другому владельцу, сканирование
давно кончилось, а правило продолжает резать трафик, и разобраться, за что,
через полгода уже не по чему.
"""
from alerts import send_telegram
from firewall import apply_blocks
from firewall_store import list_blocks, take_expired
from server_check import server_type


def run_firewall_expiry(servers: list) -> int:
    """Снимает истёкшие блокировки. Возвращает число снятых адресов.

    Строки удаляются из базы одним запросом на все серверы, а правило
    переписывается по серверу: если WinRM до одного из них не достучался,
    остальные всё равно разблокируются.
    """
    expired = take_expired()
    if not expired:
        return 0

    # Не `has_firewall`, а все Windows-серверы: флаг могли выключить уже
    # после блокировки, и тогда снимать её стало бы некому — правило на
    # сервере осталось бы навсегда.
    by_name = {s.get("name"): s for s in servers
               if server_type(s) == "windows"}
    total = 0
    for server_name, addresses in expired.items():
        server = by_name.get(server_name)
        if server is None:
            # Сервер удалили или флаг сняли: строки из базы уже ушли, лезть
            # на сервер незачем.
            continue
        try:
            apply_blocks(server, [b["address"] for b in list_blocks(server_name)])
        except Exception as e:
            print(f"[firewall] ❌ {server_name}: правило не переписано: "
                  f"{str(e).splitlines()[0][:200]}", flush=True)
            continue
        total += len(addresses)
        print(f"[firewall] {server_name}: снято блокировок {len(addresses)}",
              flush=True)
        try:
            send_telegram(
                f"✅ {server_name}: истёк срок блокировки\n\n"
                + "\n".join(f"• {a}" for a in addresses[:20])
                + ("\n…" if len(addresses) > 20 else "")
                + "\n\nАдреса снова пропускаются. Список — 🛡 Блокировка IP "
                  "в карточке сервера."
            )
        except Exception as e:
            print(f"[firewall] Уведомление не отправлено: {e}", flush=True)
    return total
