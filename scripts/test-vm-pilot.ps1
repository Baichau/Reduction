param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,
    [string]$VirtualBoxVmName = "LocalRedactionPilotTest"
)

$ErrorActionPreference = "Stop"
$VBoxManage = Get-Command VBoxManage -ErrorAction Stop
if (-not (Test-Path $InstallerPath)) { throw "Installer not found: $InstallerPath" }

Write-Host "Create a clean Windows 11 VM named $VirtualBoxVmName in VirtualBox before running this script."
Write-Host "Inside the VM, install the shared installer and run the smoke test from docs/VM_PILOT_TEST.md."
Write-Host "Host-side hash:"
Get-FileHash $InstallerPath -Algorithm SHA256
Write-Host "VirtualBox detected at $($VBoxManage.Source)."
Write-Host "This script intentionally does not auto-install software inside a guest VM or bypass Windows prompts."
