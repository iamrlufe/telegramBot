"""
Детали сервера на общем томе (shared/service_details.py).

Здесь живут две секции: services — про службы (контейнеры Docker, сайты
веб-серверов), platform — про саму платформу (хосты ESXi, парк ВМ).
Пишут монитор в своём цикле и бот по кнопке «Проверить сейчас», читает
карточка сервера.
"""
import pytest

import service_details as sd


@pytest.fixture(autouse=True)
def details_file(tmp_path, monkeypatch):
    monkeypatch.setattr(sd, "DETAILS_FILE", str(tmp_path / "service_details.json"))


def test_saves_both_sections():
    sd.save_service_details("srv", {"docker": ["a"]}, {"hosts": ["esxi8"]})

    assert sd.load_service_details("srv") == {"docker": ["a"]}
    assert sd.load_platform_details("srv") == {"hosts": ["esxi8"]}


def test_platform_only_entry_survives():
    """У VMware секции services нет вовсе — запись всё равно должна жить."""
    sd.save_service_details("vcenter", {}, {"hosts": ["esxi8"], "vms": ["dc-01"]})

    assert sd.load_platform_details("vcenter")["hosts"] == ["esxi8"]


def test_empty_both_removes_entry():
    sd.save_service_details("srv", {"docker": ["a"]}, {})
    sd.save_service_details("srv", {}, {})

    assert sd.load_service_details("srv") == {}
    assert sd.load_platform_details("srv") == {}


def test_refresh_keeps_platform_section():
    """Регрессия: кнопка «Проверить сейчас» стирала разбивку по хостам.

    Бот сохранял детали своим вызовом, где секции platform не было, а
    пустой результат удаляет запись целиком — ВМ и хосты пропадали из
    карточки до следующего цикла монитора.
    """
    info = {
        "service_details": {},
        "platform_details": {"hosts": ["🟢 esxi8"], "vms": ["🟢 dc-01"]},
    }
    sd.save_details_from_info("vcenter", info)

    assert sd.load_platform_details("vcenter")["vms"] == ["🟢 dc-01"]

    # Повторный вызов (нажали «Обновить» ещё раз) ничего не теряет
    sd.save_details_from_info("vcenter", info)
    assert sd.load_platform_details("vcenter")["hosts"] == ["🟢 esxi8"]


def test_helper_handles_missing_keys():
    sd.save_service_details("srv", {"docker": ["a"]}, {})
    sd.save_details_from_info("srv", {})

    # Ответ без обеих секций — запись удаляется, это ожидаемо
    assert sd.load_service_details("srv") == {}


def test_corrupted_file_reads_as_empty(tmp_path):
    with open(sd.DETAILS_FILE, "w") as f:
        f.write("{обрыв")

    assert sd.load_all() == {}
    assert sd.load_platform_details("srv") == {}
