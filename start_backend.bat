@echo off
cd /d "%~dp0"
echo ============================================================
echo   Starting MiniSIEM X Backend and SOC Portal
echo ============================================================
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" run.py
) else (
    python run.py
)
pause
