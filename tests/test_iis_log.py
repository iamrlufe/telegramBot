"""Чтение логов IIS по смещению.

Суточный файл на живой публикации 1С — десятки мегабайт и полмиллиона
строк. Полный проход занимает десятки секунд, поэтому читается только
дописанное с прошлого раза. Ошибка здесь стоит либо потерянных суток,
либо перечитывания 20 ГБ истории.
"""
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


iis_log = _load("iis_log", ROOT / "shared" / "iis_log.py")
winrm_client = _load("winrm_client", ROOT / "shared" / "winrm_client.py")

SERVER = {"name": "web-01.example.local", "host": "192.0.2.11",
          "username": "svc", "password": "x"}


def _scripts(monkeypatch, payload):
    import base64
    import json

    seen = []

    def run_ps(host, script, username=None, password=None, **kwargs):
        seen.append(script)
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    monkeypatch.setattr(iis_log, "run_ps", run_ps)
    return seen


# ─── Лимит WinRM ─────────────────────────────────────────────

def test_script_fits_winrm_command_line():
    """Командная строка WinRM — 8192 символа, а UTF-16 и base64 раздувают
    текст втрое. Не влезший скрипт падает ещё до запуска."""
    state = {f"u_ex2609{i:02d}.log": 123456789 for i in range(4)}

    assert winrm_client.ps_fits(iis_log._script(state, 10000, 25))


def test_extra_script_fits_too():
    """HTTPERR и конфигурация вынесены во второй вызов именно потому, что
    один скрипт на всё в лимит не влезает."""
    assert winrm_client.ps_fits(iis_log._extra_script({"httperr1.log": 5}, 25))


# ─── Смещения ────────────────────────────────────────────────

def test_offset_passed_into_script(monkeypatch):
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {"u_ex260901.log": 4096})

    assert "u_ex260901.log" in scripts[0]
    assert "4096" in scripts[0]


def test_script_rereads_file_that_became_shorter(monkeypatch):
    """Файл короче запомненного смещения — его подменили; продолжать с
    середины чужого файла нельзя."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {"u_ex260901.log": 10})

    assert "if($off -gt $f.Length){$off=0}" in winrm_client.compact_ps(scripts[0])


def test_script_skips_history_on_first_run(monkeypatch):
    """Истории здесь на 20 ГБ: с нуля читается только самый свежий файл,
    остальные пропускаются установкой смещения в конец."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {})
    compact = winrm_client.compact_ps(scripts[0])

    assert "$off=$f.Length" in compact


def test_custom_field_logs_are_picked_up():
    """Как только в логировании заводят пользовательское поле, IIS начинает
    писать в файл с суффиксом _x: u_ex260901_x.log. Маска обязана его
    захватывать, иначе после включения X-Forwarded-For сбор молча встанет."""
    script = iis_log._script({}, 10000, 25)

    assert "u_ex*.log" in script
    import fnmatch
    assert fnmatch.fnmatch("u_ex260901_x.log", "u_ex*.log")


def test_yesterdays_tail_is_not_lost(monkeypatch):
    """После полуночи у вчерашнего файла остаётся хвост: окно в 36 часов
    покрывает и его."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {})

    assert "AddHours(-36)" in scripts[0]


def test_state_returned_as_numbers(monkeypatch):
    _scripts(monkeypatch, {"total": 5, "state": {"u_ex260901.log": "8192"}})
    data = iis_log.read_site_logs(SERVER, {})

    assert data["state"] == {"u_ex260901.log": 8192}


# ─── Разбор ──────────────────────────────────────────────────

def test_fields_parsed_by_name(monkeypatch):
    """Набор колонок в логе IIS настраивается: позиции дадут чужие значения."""
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {})

    assert "#Fields:" in scripts[0]
    assert "$h[$n[$i]]=$i" in winrm_client.compact_ps(scripts[0])


def test_field_set_change_mid_file_is_picked_up():
    """IIS дописывает новую строку #Fields прямо в середину файла, когда
    меняют набор колонок. Пропустить её значит разбирать остаток файла по
    старым позициям — и молча подставлять чужие значения."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "if($l.StartsWith('#')){if($l.StartsWith('#Fields:')){$map=M $l}" in compact


def test_real_client_address_taken_from_forwarded_header():
    """За Cloudflare в c-ip лежит адрес узла прокси. Если в логировании сайта
    заведено поле для X-Forwarded-For, брать надо его."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "x-forwarded-for" in compact
    assert "-split ','" in compact


def test_script_shrinks_state_until_it_fits():
    """Смещений может накопиться много (почасовая ротация). Не влезший скрипт
    не выполнится вовсе, а потерянное смещение стоит одного перечитывания."""
    many = {f"u_ex2609{i:02d}.log": 123456789 for i in range(40)}

    assert winrm_client.ps_fits(iis_log._script(many, 10000, 25))
    assert winrm_client.ps_fits(iis_log._extra_script(many, 25))


def test_header_read_before_seek():
    """Строка #Fields лежит в начале файла, а читать надо с середины —
    заголовок вычитывается до перемотки."""
    script = iis_log._script({"u_ex260901.log": 100}, 10000, 25)
    compact = winrm_client.compact_ps(script)

    assert compact.index("#Fields:") < compact.index("$fs.Position=$off")


def test_log_file_opened_with_shared_access():
    """Текущие сутки IIS держит открытыми — монопольное чтение падает."""
    script = iis_log._script({}, 10000, 25)

    assert "'Open','Read','ReadWrite'" in winrm_client.compact_ps(script)


def test_publications_taken_from_iis_config():
    """Список баз нельзя зашивать: добавили публикацию — она мгновенно
    оказалась бы «посторонним путём»."""
    assert "Get-WebApplication" in iis_log._script({}, 10000, 25)


def test_local_paths_are_not_findings():
    """Регрессия: заход сотрудника по /отчеты давал красную находку
    «сервер отдал». Виртуальный каталог и обычная папка в корне сайта
    приложениями IIS не являются, поэтому попадали в посторонние пути,
    хотя содержимое по ним сервер отдаёт совершенно законно."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "Get-WebVirtualDirectory" in compact
    assert "$s.physicalPath" in compact and "-Directory" in compact
    assert "$loc -contains $g" in compact


def test_local_paths_are_not_publications():
    """Папка сайта — не публикация: считать по ней трафик и искать в ней
    подбор пароля 1С незачем, а «публикация без трафика» — это тревога
    про открытую наружу точку входа, и от папок она бы зашумилась."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    pubs = compact.index("A $pb $g")
    local = compact.index("$loc -contains $g")

    assert pubs < local, "$pb заполняется только из $ap, до проверки $loc"


def _worst_case_state():
    """Худшее, что вообще может приехать в скрипт: STATE_FILES файлов с
    пользовательскими полями (имя `u_exГГММДД_x.log` длиннее обычного на
    `_x`) и смещение в 12 цифр. Двенадцать цифр — это лог на сотню
    гигабайт: втрое больше всей истории, которая в этом проекте
    встречалась, и вчетверо больше суточного файла живой публикации 1С.
    Влезает этот случай — влезает любой настоящий."""
    return {f"u_ex2609{i:02d}_x.log": 999999999999
            for i in range(iis_log.STATE_FILES)}


def test_offsets_for_three_files_still_fit():
    """Потерянное смещение НЕ перечитывается: файл, который уже не самый
    свежий, просто пропускается — после полуночи это молча теряет хвост
    вчерашнего лога. Столько файлов, сколько обещает STATE_FILES, обязано
    доезжать до сервера, и на обоих вариантах имени."""
    for tag in (".log", "_x.log"):
        state = {f"u_ex2609{i:02d}{tag}": 999999999999
                 for i in range(iis_log.STATE_FILES)}
        script = iis_log._script(state, 10000, 25)

        assert winrm_client.ps_fits(script), tag
        for name in state:
            assert name in script, f"смещение {name} не доехало"


def test_script_keeps_reserve():
    """Сторож запаса. Дописать строку в скрипт разбора легко и незаметно, а
    расплачивается за неё не тот, кто дописал: смещения режутся первыми и
    молча, и сводка теряет часть суток на бою.

    Поэтому запас проверяется здесь. Если тест упал — место под новую
    строку не выкраивать, а уносить работу во второй вызов, как сделано с
    HTTPERR (`_extra_script`)."""
    script = iis_log._site_script(
        iis_log._trim_state(_worst_case_state()), 10000, 25)
    free = winrm_client.MAX_PS_COMMAND_CHARS - winrm_client.ps_encoded_length(script)

    assert free >= iis_log.SCRIPT_RESERVE, (
        f"свободно {free} символов из обещанных {iis_log.SCRIPT_RESERVE}: "
        f"скрипт разбора вырос и начнёт молча резать смещения"
    )


def test_dropped_offsets_are_not_silent(capsys):
    """Если запас всё-таки проели, это обязано быть видно в логах: молча
    потерянный хвост лога не отличить от тихого дня на сервере."""
    state = _worst_case_state()

    # Скрипт-пустышка ровно такой длины, чтобы влезать самому, но не
    # оставлять места ни одному смещению: именно так выглядит проеденный
    # запас, только на бою скрипт будет настоящим.
    def build(pad):
        return lambda state_json: "$x='" + "y" * pad + "'\n" + state_json

    empty, one = iis_log._trim_state(state, 0), iis_log._trim_state(state, 1)
    pad = 1
    while not (winrm_client.ps_fits(build(pad)(empty))
               and not winrm_client.ps_fits(build(pad)(one))):
        pad += 1

    iis_log._fit(build(pad), state)

    out = capsys.readouterr().out
    assert "[iis]" in out
    for name in state:
        assert name in out, f"в логе не назван потерянный {name}"


def test_fitting_script_says_nothing(capsys):
    """Обратная сторона: пока всё влезает, шуметь не о чем."""
    iis_log._script(_worst_case_state(), 10000, 25)

    assert capsys.readouterr().out == ""


def test_only_served_content_counts_as_a_finding():
    """Редирект ничего не отдал: на корень и на любой путь по 80-му порту
    он приходит всегда, а на сайте за IIS — ещё и 302 на /index.php.
    Находкой считается только ответ 200."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "$s2 -eq '200'" in compact
    assert "-eq '301'" not in compact
    assert "-eq '302'" not in compact


def test_files_any_site_serves_are_not_findings():
    """За robots.txt и sitemap.xml приходят поисковые роботы, а не взломщики."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "robots" in compact and "sitemap" in compact and "favicon" in compact


def test_long_polling_paths_are_not_slow_requests():
    """Уведомления OWA и RPC-over-HTTP держатся минутами по замыслу
    протокола: на Exchange это давало десятки тысяч ложных «медленных»."""
    compact = winrm_client.compact_ps(iis_log._script({}, 10000, 25))

    assert "ev" in compact and "owa2" in compact
    assert "rpcproxy" in compact


def test_idle_connections_excluded_from_httperr_details():
    """Timer_ConnectionIdle — 10 тысяч штатных записей в сутки; без отсева
    они похоронят десяток настоящих."""
    compact = winrm_client.compact_ps(iis_log._extra_script({}, 25))

    assert "-ne 'Timer_ConnectionIdle'" in compact


def test_slow_threshold_is_configurable(monkeypatch):
    scripts = _scripts(monkeypatch, {"total": 0, "state": {}})
    iis_log.read_site_logs(SERVER, {}, slow_ms=3000)

    assert "-gt 3000" in winrm_client.compact_ps(scripts[0])


def test_single_row_normalized(monkeypatch):
    """PowerShell отдаёт одиночный элемент объектом, а не массивом."""
    _scripts(monkeypatch, {"total": 1, "state": {},
                           "alienuris": {"k": "/index.php", "n": 5}})
    data = iis_log.read_site_logs(SERVER, {})

    assert data["alienuris"] == [{"k": "/index.php", "n": 5}]


# ─── Разбор находок: старый формат ключа ─────────────────────

def test_hit_key_current_format():
    assert iis_log.parse_hit("/shell.php|203.0.113.5|curl") == (
        "/shell.php", "203.0.113.5", "curl")


def test_legacy_key_with_status_is_realigned():
    """Восемь дней в базе живут ключи со старым порядком полей. Без разбора
    код ответа встаёт на место пути и раздел показывает «200 302»."""
    assert iis_log.parse_hit("200|/shell.php|203.0.113.5|curl") == (
        "/shell.php", "203.0.113.5", "curl")


def test_legacy_redirect_is_not_a_finding():
    """Раньше писались 301 и 302 — ими сервер ничего не отдал."""
    assert iis_log.parse_hit("302|/index.php|203.0.113.5|curl") is None
    assert iis_log.parse_hit("301|/index.php|203.0.113.5|curl") is None


def test_innocent_paths_are_not_findings():
    """robots.txt и sitemap.xml попали в базу до появления фильтра — за
    ними ходят поисковые роботы, а не взломщики."""
    for uri in ("/robots.txt", "/sitemap.xml", "/favicon.ico",
                "/iisstart.htm", "/.well-known/x"):
        assert iis_log.parse_hit(f"200|{uri}|203.0.113.5|curl") is None, uri
        assert iis_log.parse_hit(f"{uri}|203.0.113.5|curl") is None, uri


def test_root_is_not_a_finding():
    assert iis_log.parse_hit("/|203.0.113.5|curl") is None


def test_broken_key_does_not_raise():
    assert iis_log.parse_hit("") is None
    assert iis_log.parse_hit(None) is None
