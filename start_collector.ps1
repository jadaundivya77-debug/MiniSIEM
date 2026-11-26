$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting MiniSIEM X Windows Security Event Collector" -ForegroundColor Cyan
Write-Host "  NOTE: Run PowerShell as Administrator to read Security log" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython windows_collector.py @args
} else {
    python windows_collector.py @args
}
