@echo off
rem Полная копия (тип D в msdb). В servers.json:
rem   "copy_script": { "D": "C:\\Scripts\\upload_full.cmd", ... }
rem
rem Обёртка нужна потому, что copy_script — карта «тип копии → скрипт»:
rem у полной и разностной разные каталоги на приёмнике и разное
rem расписание, и бот ведёт для каждой свою очередь.
call "%~dp0upload_common.cmd" FULL
exit /b %ERRORLEVEL%
