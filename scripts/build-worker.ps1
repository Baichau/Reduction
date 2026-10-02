param(
    [string]$OutputDirectory = "dist/worker"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$pythonCandidates = @(
    "backend/.venv/Scripts/python.exe",
    "backend/.venv2/Scripts/python.exe"
)
$python = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-Path $candidate) {
        $probe = [System.Diagnostics.ProcessStartInfo]::new((Resolve-Path $candidate).Path)
        $probe.Arguments = '-c "import sys"'
        $probe.UseShellExecute = $false
        $probe.RedirectStandardOutput = $true
        $probe.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::Start($probe)
        $null = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -eq 0) { $python = $probe.FileName; break }
    }
}
if (-not $python) { $python = (Get-Command python -ErrorAction Stop).Source }
$workDirectory = Join-Path (Get-Location) "dist/pyinstaller-work"
New-Item -ItemType Directory -Force -Path $workDirectory | Out-Null
& $python -m pip install --requirement backend/requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed" }
& $python -m PyInstaller --noconfirm --clean --onedir --name LocalRedactionWorker --distpath $OutputDirectory --workpath (Join-Path $workDirectory "worker") --hidden-import app.main --hidden-import app.parser_worker backend/worker.py
if ($LASTEXITCODE -ne 0) { throw "Worker packaging failed" }
& $python -m PyInstaller --noconfirm --clean --onedir --name LocalRedactionParser --distpath $OutputDirectory --workpath (Join-Path $workDirectory "parser") --hidden-import app.extractors backend/app/parser_worker.py
if ($LASTEXITCODE -ne 0) { throw "Parser packaging failed" }
Write-Host "Worker artifacts created at $OutputDirectory/LocalRedactionWorker and LocalRedactionParser"
