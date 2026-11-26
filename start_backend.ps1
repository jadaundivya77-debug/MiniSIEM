$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting MiniSIEM X Backend and SOC Portal" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython run.py
} else {
    python run.py
}
