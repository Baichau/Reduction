param(
    [string]$OutputDirectory = "dist/worker"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$python = if (Test-Path "backend/.venv/Scripts/python.exe") { (Resolve-Path "backend/.venv/Scripts/python.exe").Path } else { (Get-Command python -ErrorAction Stop).Source }
& $python -m pip install --requirement backend/requirements-build.txt
& $python -m PyInstaller --noconfirm --clean --onedir --name LocalRedactionWorker --distpath $OutputDirectory --hidden-import app.main --hidden-import app.parser_worker backend/worker.py
& $python -m PyInstaller --noconfirm --clean --onedir --name LocalRedactionParser --distpath $OutputDirectory --hidden-import app.extractors backend/app/parser_worker.py
Write-Host "Worker artifacts created at $OutputDirectory/LocalRedactionWorker and LocalRedactionParser"
