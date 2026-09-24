# Local Redaction

One Windows installer for local PII redaction. The application processes text and supported documents on the customer computer before the result is sent to an external AI service.

## Customer Installation
1. Download `LocalRedactionSetup.exe` from the approved release location.
2. Verify the SHA-256 hash supplied with the release.
3. Double-click the installer and accept the Windows prompt.
4. Finish the installation.
5. Open **Local Redaction** from the desktop or Start menu.

The installer includes the application host, Python worker, parser worker, and React interface. The customer does not need Python, Node.js, npm, pip, or source code.

## Use The App
1. Paste text into the source panel or upload a TXT, CSV, JSON, PDF, DOCX, EML, Markdown, or LOG file.
2. Select a redaction profile.
3. Click **Redact locally**.
4. Review every detected item.
5. Approve true detections and reject false positives.
6. Download the safe output only after review is complete.
7. Send the downloaded safe output to the approved external AI workflow.

The original document is processed locally. The worker listens on `127.0.0.1` and the application does not require product cloud access.

## Custom Rules
Open **Rules manager** to create a local profile. Built-in rules can be enabled or disabled. Custom rules can be:

- Regex matcher
- Keyword dictionary
- Context word rule

Profiles are stored locally and validated before use.

## Build The Installer
Build machines need Python 3.13, Node.js 22, .NET 8 SDK, and Inno Setup 6.

```powershell
.\scripts\build-pilot-installer.ps1
```

The result is:

```text
dist\installer\LocalRedactionSetup.exe
```

The build creates a self-contained Windows host, bundled worker, isolated parser, and production frontend. No runtime installation is required for the customer.

## Pilot Notice
This is a security-hardened local-first pilot, not HIPAA/GDPR/CCPA certification. The installer must be code-signed before production distribution. Firewall enforcement, malware scanning, OS parser sandboxing, DPAPI production provisioning, and independent penetration testing are still deployment requirements.

Do not place real regulated data into an unsigned pilot build.

## Documentation
- [Threat model](docs/THREAT_MODEL.md)
- [VirtualBox pilot test](docs/VM_PILOT_TEST.md)
- [Installer project](installer/LocalRedactionPilot.iss)
- [Build script](scripts/build-pilot-installer.ps1)
