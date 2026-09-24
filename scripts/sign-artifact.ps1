param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [switch]$AllowUnsigned
)

$ErrorActionPreference = "Stop"
$signTool = $env:SIGNTOOL_PATH
if ([string]::IsNullOrWhiteSpace($signTool)) {
    if ($AllowUnsigned) {
        Write-Warning "SIGNTOOL_PATH is not configured; artifact is intentionally unsigned for a non-release build."
        exit 0
    }
    throw "SIGNTOOL_PATH must point to the approved Windows signing tool for release builds."
}

if (-not (Test-Path $Path)) { throw "Artifact does not exist: $Path" }
& $signTool sign /fd SHA256 /td SHA256 /tr $env:SIGNING_TIMESTAMP_URL /a $Path
if ($LASTEXITCODE -ne 0) { throw "Signing failed with exit code $LASTEXITCODE" }
& $signTool verify /pa $Path
if ($LASTEXITCODE -ne 0) { throw "Signature verification failed with exit code $LASTEXITCODE" }
