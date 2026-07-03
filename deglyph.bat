@echo off
rem deglyph quick launcher (Windows). Author: Alex Spataru | GPLv3
rem
rem Bootstraps an isolated venv (first run only), installs requirements, and
rem launches deglyph. Pass any deglyph arguments straight through:
rem
rem   deglyph.bat C:\path\to\library.dll
rem   deglyph.bat lib.so --arch arm64
rem   deglyph.bat lib.dll --analyze SetRfPower
setlocal

rem %~dp0 has a trailing backslash; strip it so "%HERE%" doesn't become
rem  "...\deglyph\" — CMD reads the closing \" as an escaped quote and pip
rem  then sees a stray '"' at the end of the path.
set "HERE=%~dp0"
set "HERE=%HERE:~0,-1%"
set "VENV=%HERE%\.venv"
if not defined PYTHON set "PYTHON=python"

if not exist "%VENV%\Scripts\python.exe" (
    echo deglyph: creating virtual environment...>&2
    "%PYTHON%" -m venv "%VENV%" || goto :bootstrap_failed
    "%VENV%\Scripts\python.exe" -m pip install --quiet --upgrade pip || goto :bootstrap_failed
    rem The Anthropic SDK ships as a runtime dependency, so the assistant is
    rem usable on first launch.
    "%VENV%\Scripts\pip.exe" install --quiet -e "%HERE%" || goto :bootstrap_failed
)

"%VENV%\Scripts\python.exe" -m deglyph.cli %*
exit /b %ERRORLEVEL%

:bootstrap_failed
rem Remove the half-built venv so the next launch retries from scratch
rem  instead of running deglyph against an environment missing its deps.
if exist "%VENV%" rmdir /s /q "%VENV%"
exit /b 1
