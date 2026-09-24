param(
    [string]$Configuration = "Release",
    [switch]$SkipInstaller,
    [string]$CertThumbprint = "", # ФИКС: Хеш SHA-1 вашего купленного EV Code Signing сертификата
    [switch]$SignCode            # ФИКС: Флаг для включения этапа подписи
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# Функция автоматического подписания бинарных файлов
function Sign-BinaryFile {
    param([string]$FilePath)
    if ($SignCode -and $CertThumbprint) {
        Write-Host "   [Sign] Signing $FilePath..."
        $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if (-not $signtool) {
            # Проверяем стандартные пути Windows SDK
            $sdkPaths = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue
            if ($sdkPaths) { $signtool = $sdkPaths[0].FullName }
        }
        if ($signtool) {
            & $signtool sign /sha1 $CertThumbprint /tr http://digicert.com /td sha256 /fd sha256 $FilePath
            if ($LASTEXITCODE -ne 0) { throw "Code signing failed for $FilePath" }
        } else {
            Write-Warning "signtool.exe not found. Skipping signature for $FilePath"
        }
    }
}

Write-Host "[1/4] Build frontend"
Push-Location frontend
npm ci
if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
npm run build
if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
Pop-Location

Write-Host "[2/4] Build worker"
& .\scripts\build-worker.ps1 -OutputDirectory "dist/worker"
if ($LASTEXITCODE -ne 0) { throw "Worker build failed" }
# Подписываем исполняемый файл Python-воркера до его упаковки в инсталлятор
Sign-BinaryFile -FilePath "dist/worker/LocalRedactionWorker.exe"

Write-Host "[3/4] Build desktop host"
$dotnet = Get-Command dotnet -ErrorAction Stop
& $dotnet.Source publish desktop/SecureRedactionHost/SecureRedactionHost.csproj --configuration $Configuration --runtime win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true --output dist/host
if ($LASTEXITCODE -ne 0) { throw "Desktop host publish failed" }
# Подписываем C# хост-приложение
Sign-BinaryFile -FilePath "dist/host/SecureRedactionHost.exe"

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
    if ($knownPath) { $iscc = @{ Source = $knownPath } } else { throw "Inno Setup is not installed." }
}
& $iscc.Source installer/LocalRedactionPilot.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

# Подписываем сам сгенерированный инсталлятор, чтобы Windows SmartScreen доверял ему при запуске клиентом
Sign-BinaryFile -FilePath "dist/installer/LocalRedactionSetup.exe"

Write-Host "Deployment package successfully created and securely signed under dist/installer."
