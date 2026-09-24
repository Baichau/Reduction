# VirtualBox Customer Pilot Test

This is a manual clean-machine test for the unsigned/local pilot installer. It is not a penetration test or production security certification.

## Host preparation

1. Install Python 3.13, Node.js 22, .NET 8 SDK, and Inno Setup on the build machine.
2. Open PowerShell in the repository root.
3. Run:

```powershell
.\scripts\build-pilot-installer.ps1
```

The script builds the React UI, PyInstaller worker, self-contained C# host, and Inno Setup installer. For machines without Inno Setup, build only the payload:

```powershell
.\scripts\build-pilot-installer.ps1 -SkipInstaller
```

4. Hash the installer:

```powershell
Get-FileHash .\dist\installer\LocalRedactionSetup.exe -Algorithm SHA256
```

5. Create a clean Windows 11 x64 VM in VirtualBox. Use a snapshot named `clean-before-install`.
6. Transfer the installer into the guest using a read-only ISO, a temporary VirtualBox shared folder, or the approved customer transfer method. Do not enable host clipboard or drag-and-drop for regulated pilot data.
7. In the guest, verify the copied installer hash matches the hash recorded by the build operator before running it.

## Guest installation test

1. Confirm Windows Defender is enabled.
2. Run the installer as an administrator.
3. Accept the warning that this is a local pilot build.
4. Install to the default directory.
5. Confirm a desktop shortcut named `Local Redaction` exists.
6. Launch it. The host should start the bundled worker and open `http://127.0.0.1:8765`.
7. Confirm the browser displays the Local Redaction Console without Node.js, Python, or npm installed in the guest.

## Functional smoke test

1. Paste:

```text
Contact jane@example.com. SSN 123-45-6789.
```

2. Select `Stable placeholders`.
3. Run local redaction.
4. Confirm the result contains `[EMAIL_1]` and `[SSN_1]` and does not contain the original values in the safe output.
5. Approve the detections.
6. Download the safe copy.
7. Upload a small `.txt` file and repeat the review.
8. Open local job history, reopen the job, then delete it.
9. Open Rules Manager and create a test dictionary profile containing `Project Falcon`.
10. Use that profile on text containing `Project Falcon` and confirm the custom placeholder appears.

## Security smoke test

From a PowerShell window in the guest:

```powershell
Invoke-WebRequest http://127.0.0.1:8765/health
Invoke-WebRequest http://127.0.0.1:8765/v1/jobs -UseBasicParsing
```

Expected results:

- `/health` returns a local worker health response.
- `/v1/jobs` without the local token returns HTTP 401.
- The browser can use the pilot-only local token bootstrap.
- No external network is required for redaction after installation.

The pilot installer does not yet automate Windows Firewall rules, malware scanning, AppContainer/Job Object sandboxing, or production DPAPI token injection. Record those as blocked production controls rather than marking them passed.

## Evidence to record

- Installer SHA-256.
- Windows version and VM snapshot name.
- Installer version.
- Worker/host logs with raw data removed.
- Screenshots of install, redaction, review, and download.
- HTTP auth result.
- List of installed files and versions.
- Uninstall result and confirmation that application files are removed.

Destroy the VM or restore `clean-before-install` after the test. Do not place real customer PII in this VM until the customer approves the pilot controls.
