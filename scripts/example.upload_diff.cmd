@echo off
rem Разностная копия (тип I в msdb). В servers.json:
rem   "copy_script": { "I": "C:\\Scripts\\upload_diff.cmd", ... }
rem
rem Разностная без своей полной на приёмнике не восстанавливается,
rem поэтому полную настраивают всегда, а разностную — по желанию.
call "%~dp0upload_common.cmd" DIFF
exit /b %ERRORLEVEL%
