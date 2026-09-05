@echo off
rem ============================================================
rem  ПРИМЕР скрипта копирования копий MSSQL на приёмник по SFTP.
rem  Обезличен: репозиторий публичный. Правьте блок «Настройки»
rem  и кладите на сервер-ИСТОЧНИК, путь укажите в servers.json
rem  полем copy_script (см. scripts/readme.md).
rem
rem  Запускает его бот, а не планировщик Windows: сигналом служит
rem  запись в msdb.dbo.backupset, то есть момент, когда SQL реально
rem  закончил копию. Скрипт об этом знать не обязан — он просто
rem  возит то, что нашёл, и честно возвращает код.
rem
rem  Формат журнала здесь — не украшение: его разбирает бот
rem  (shared/copy_log.py). Строки со штампом времени, «Найден файл»,
rem  «Локальный размер», «Remote:», «SKIP», «Режим: UPLOAD»,
rem  «SUCCESS», «WinSCP exit code=», «FAILED» и «END» — это контракт.
rem  Незнакомые строки бот пропускает молча, так что дописывать своё
rem  можно; переименовывать перечисленное — нельзя.
rem ============================================================

rem Кодировка. Двух chcp подряд быть не должно — работает последний.
rem 65001 имеет смысл ТОЛЬКО если сам .cmd сохранён в UTF-8 без BOM
rem (этот файл — именно такой). Иначе строки echo останутся в CP866,
rem и в журнале выйдет смесь. Бот читает обе кодировки построчно,
rem так что можно и вовсе убрать эту строку.
chcp 65001 > nul

rem EnableDelayedExpansion обязателен: значения внутри for и if
rem меняются по ходу, а %VAR% подставляется при разборе блока целиком.
setlocal EnableExtensions EnableDelayedExpansion

rem ─── Настройки ──────────────────────────────────────────────
rem Тип копии приходит первым аргументом: FULL или DIFF. Отдельные
rem обёртки example.upload_full.cmd / example.upload_diff.cmd нужны
rem потому, что copy_script в конфиге — карта «тип копии → скрипт».
set "TYPE=%~1"
if "%TYPE%"=="" set "TYPE=FULL"

rem Корень, где SQL складывает копии: <SRC_ROOT>\<база>\<FULL|DIFF>\*.bak
set "SRC_ROOT=D:\backup\EXAMPLE"

rem Сохранённая сессия WinSCP. Заводится один раз под той же учёткой,
rem от которой скрипт запускается (у бота это учётка WinRM), иначе
rem сессии просто не будет видно: они лежат в профиле пользователя.
set "SESSION=backup_user@sftp.example.local"
set "WINSCP=C:\Program Files (x86)\WinSCP\WinSCP.com"

rem Корень на приёмнике, соответствующий copy_target_root в конфиге бота.
set "REMOTE_ROOT="

set "ATTEMPTS=3"
rem Пауза, после которой размер файла сверяется повторно: копия,
rem которую SQL ещё дописывает, увозиться не должна.
set "STABLE_WAIT=5"

rem ─── Куда писать журнал ─────────────────────────────────────
rem Раскладку задаёт скрипт, а бот её ВЫЧИСЛЯЕТ по пути к нему
rem (copy_log.log_dir): рядом со скриптом logs\<дата>\, в нём общий
rem журнал на тип копии и подкаталог на каждую базу. Менять раскладку
rem нельзя — бот не найдёт журнал.
rem
rem %DATE% на русской локали — 05.09.2026, %TIME% — 11:17:42,07.
rem Именно этот формат штампа разбирает бот.
set "DAY=%DATE:~6,4%-%DATE:~3,2%-%DATE:~0,2%"
set "LOG_DIR=%~dp0logs\%DAY%"
set "COMMON_LOG=%LOG_DIR%\common_%TYPE%.log"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

call :log "============================================"
call :log "START upload_common.cmd"
call :log "TYPE=%TYPE%"
call :log "Поиск каталогов %TYPE% в %SRC_ROOT%"

set "FAILED=0"
for /d %%B in ("%SRC_ROOT%\*") do call :database "%%~nxB"

call :log "END upload_common.cmd"

rem Код возврата — единственное, по чему бот отличает «рейс прошёл» от
rem «рейс упал»: он пишет его в файл-метку рядом со своим журналом.
endlocal & exit /b %FAILED%


rem ─── Одна база ──────────────────────────────────────────────
:database
set "DB=%~1"
set "DIR=%SRC_ROOT%\%DB%\%TYPE%"
if not exist "%DIR%" goto :eof

call :log "[%DB%] [%TYPE%] Каталог: %DIR%"

rem Самый свежий .bak в каталоге.
set "FILE="
for /f "delims=" %%F in ('dir /b /a-d /o-d "%DIR%\*.bak" 2^>nul') do (
    if not defined FILE set "FILE=%%F"
)
if not defined FILE (
    call :log "[%DB%] [%TYPE%] Копий не найдено"
    goto :eof
)

for %%A in ("%DIR%\%FILE%") do set "SIZE=%%~zA"
call :log "[%DB%] [%TYPE%] Найден файл: %FILE%"
call :log "[%DB%] [%TYPE%] Локальный размер: %SIZE% bytes"

rem Файл, который ещё дописывается, увозить нельзя: на приёмнике
rem окажется обрезанная копия, и выглядеть она будет как исправная.
timeout /t %STABLE_WAIT% /nobreak > nul
for %%A in ("%DIR%\%FILE%") do set "SIZE2=%%~zA"
if not "%SIZE%"=="%SIZE2%" (
    call :log "[%DB%] [%TYPE%] Размер меняется: %SIZE% -^> %SIZE2%, пропускаю"
    goto :eof
)
call :log "[%DB%] [%TYPE%] Размер стабилен: %SIZE% bytes"

set "REMOTE=%REMOTE_ROOT%/%DB%/%TYPE%/%FILE%"
call :log "[%DB%] [%TYPE%] Remote: %REMOTE%"

set "DB_LOG_DIR=%LOG_DIR%\%DB%"
if not exist "%DB_LOG_DIR%" mkdir "%DB_LOG_DIR%"
set "DB_LOG=%DB_LOG_DIR%\%TYPE%.log"

rem ─── Что лежит на приёмнике ─────────────────────────────────
rem
rem Проверять ТОЛЬКО существование файла нельзя. Оборванная заливка по
rem SFTP оставляет на приёмнике файл с правильным именем и неправильным
rem размером — и выглядит как удачная. Такой огрызок пропускался бы
rem каждый следующий рейс, то есть навсегда: копии как бы есть, а
rem восстановить из них нечего.
rem
rem «No such file or directory / Error code: 2» в этот момент — нормальный
rem ответ «нет, заливай»; бот такие строки до «Режим: UPLOAD» ошибками
rem не считает.
call :log "[%DB%] [%TYPE%] Проверка remote-файла..."
set "LS_TMP=%TEMP%\winscp_ls_%DB%_%TYPE%.txt"
"%WINSCP%" /command "open %SESSION%" "ls %REMOTE%" "exit" > "%LS_TMP%" 2>&1
type "%LS_TMP%" >> "%DB_LOG%"

rem Размер из строки ls. Столбцы СЛЕВА считать нельзя: владельца и группы
rem может не быть вовсе (у SFTPGo они пустые), и номер столбца уезжает.
rem Справа порядок постоянный, это формат unix ls:
rem     … РАЗМЕР Sep  4 15:53:43 2026 имя_файла.bak
rem то есть размер — шестой токен с конца. Его и берём кольцом из шести
rem переменных, не заглядывая в начало строки.
set "RSIZE="
for /f "usebackq delims=" %%L in (`findstr /c:"%FILE%" "%LS_TMP%" 2^>nul`) do (
    set "T1=" & set "T2=" & set "T3=" & set "T4=" & set "T5=" & set "T6="
    for %%T in (%%L) do (
        set "T6=!T5!" & set "T5=!T4!" & set "T4=!T3!"
        set "T3=!T2!" & set "T2=!T1!" & set "T1=%%T"
    )
    set "RSIZE=!T6!"
)
del "%LS_TMP%" 2>nul

rem СРАВНЕНИЕ СТРОКАМИ, не числами. Копия в 45 330 792 448 байт в
rem арифметику cmd не влезает: и set /a, и IF EQU/GEQ считают 32-битными
rem знаковыми, 45 ГБ превращаются в отрицательное число, и сравнение
rem даёт что угодно. Ровно на этом файл в 2.59 ГБ был объявлен равным
rem домашним 42.22 ГБ и «пропускался» каждый рейс.
rem
rem Десятичные записи двух равных чисел совпадают посимвольно, поэтому
rem строковое сравнение здесь и точнее, и безопаснее. Кавычки обязательны:
rem пустой RSIZE иначе развалит разбор строки.
rem
rem И главное правило: сомневаешься — ЗАЛИВАЙ. Не разобрали размер, не
rem нашли строку, ответил не тот сервер — все эти случаи ведут в UPLOAD.
rem Лишняя заливка стоит времени, пропущенная — всей копии.
if defined RSIZE (
    call :log "[%DB%] [%TYPE%] Remote размер: !RSIZE! bytes"
    if "!RSIZE!"=="!SIZE!" (
        call :log "[%DB%] [%TYPE%] Remote == Local"
        call :log "[%DB%] [%TYPE%] SKIP: %FILE%"
        goto :eof
    )
    call :log "[%DB%] [%TYPE%] Remote ^!= Local: !RSIZE! против !SIZE! — перезаливаю"
) else (
    call :log "[%DB%] [%TYPE%] На приёмнике файла нет"
)

call :log "[%DB%] [%TYPE%] Режим: UPLOAD"

set "ATTEMPT=0"
:retry
set /a ATTEMPT+=1
call :log "[%DB%] [%TYPE%] Попытка %ATTEMPT%/%ATTEMPTS%"

rem mkdir на существующий каталог WinSCP считает ошибкой и печатает
rem простыню с «Error code: 4» — бот такие строки знает и не пугается.
"%WINSCP%" /command ^
    "open %SESSION%" ^
    "option batch abort" ^
    "option confirm off" ^
    "mkdir %REMOTE_ROOT%/%DB%/%TYPE%" ^
    "put -nopreservetime -resume ""%DIR%\%FILE%"" %REMOTE%" ^
    "exit" >> "%DB_LOG%" 2>&1
set "CODE=%ERRORLEVEL%"

if "%CODE%"=="0" (
    call :log "[%DB%] [%TYPE%] SUCCESS"
    call :log "[%DB%] [%TYPE%] WinSCP exit code=%CODE%"
    call :log "[%DB%] [%TYPE%] Файл успешно загружен: %FILE%"
    goto :eof
)

call :log "[%DB%] [%TYPE%] WinSCP exit code=%CODE%"
if %ATTEMPT% LSS %ATTEMPTS% goto :retry

call :log "[%DB%] [%TYPE%] FAILED: %FILE%"
set "FAILED=1"
goto :eof


rem ─── Строка журнала ─────────────────────────────────────────
rem Пробел перед >> обязателен. «echo текст1>> файл» без пробела cmd
rem читает как перенаправление ПОТОКА номер 1, а не как запись в файл:
rem на этой ловушке уже терялся код возврата рейса.
:log
echo [%DATE% %TIME%] %~1 >> "%COMMON_LOG%"
echo [%DATE% %TIME%] %~1
goto :eof
