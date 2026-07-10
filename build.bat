@echo off
chcp 65001 >nul
title QIAN IP-Reality Windows Build

echo ============================================
echo   QIAN  IP-Reality v2.0  Windows Build
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Python not found. Install Python 3.10+
    echo        https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/4] Install dependencies ...
pip install cryptography aiodns colorama aiohttp pyinstaller -q

echo [2/4] Install package ...
pip install -e . -q

echo [3/4] Build exe ...
pyinstaller --onefile --console --name qian ^
    --add-data "src;src" ^
    -m src.cli

if %errorlevel% neq 0 (
    echo [FAIL] Build failed
    pause
    exit /b 1
)

echo [4/4] Done!
echo.
echo   Output: dist\qian.exe
echo   Usage:  dist\qian.exe --sni images.apple.com --cf-domain your.domain.com
echo   Menu:   dist\qian.exe
echo.
pause
