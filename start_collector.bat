@echo off
cd /d "%~dp0"
echo ============================================================
echo   Starting MiniSIEM X Windows Security Event Collector
echo   NOTE: Run this script as Administrator to read Security log
echo ============================================================
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" windows_collector.py %*
) else (
    python windows_collector.py %*
)
if %errorlevel% neq 0 (
    echo.
    echo [!] Collector exited with code %errorlevel%.
    pause
)
