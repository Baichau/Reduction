param(
    [string]$Configuration = "Release",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "[1/4] Build frontend"
Push-Location frontend
npm ci
if ($LASTEXITCODE -ne 0) { throw "npm ci failed with exit code $LASTEXITCODE" }
npm run build
if ($LASTEXITCODE -ne 0) { throw "npm run build failed with exit code $LASTEXITCODE" }
Pop-Location

Write-Host "[2/4] Build worker"
& .\scripts\build-worker.ps1 -OutputDirectory "dist/worker"
if ($LASTEXITCODE -ne 0) { throw "Worker build failed with exit code $LASTEXITCODE" }

Write-Host "[3/4] Build desktop host"
$dotnet = Get-Command dotnet -ErrorAction Stop
& $dotnet.Source publish desktop/SecureRedactionHost/SecureRedactionHost.csproj --configuration $Configuration --runtime win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true --output dist/host
if ($LASTEXITCODE -ne 0) { throw "Desktop host publish failed with exit code $LASTEXITCODE" }

if ($SkipInstaller) {
    Write-Host "Pilot payload built under dist/; installer compilation skipped."
    exit 0
}

Write-Host "[4/4] Compile Inno Setup installer"
$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $iscc) {
    $knownPaths = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    $knownPath = $knownPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($knownPath) { $iscc = @{ Source = $knownPath } } else { throw "Inno Setup is not installed. Install it, ensure iscc.exe is on PATH, then rerun this script." }
}
& $iscc.Source installer/LocalRedactionPilot.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed with exit code $LASTEXITCODE" }
Write-Host "Installer created under dist/installer."
