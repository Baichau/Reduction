# Local Redaction

Local Redaction is a Windows-local PII and sensitive-data redaction application built for a controlled review workflow. The product keeps raw source text on the customer machine, detects sensitive data with a deterministic rules engine, and outputs only reviewed redacted text for downstream AI use.

This project is meant to produce a review-ready local desktop application with a simple install and a small, traceable security model. It is not a legal certification or a guarantee of compliance by itself.

## What the app does

The app allows a user to:

- paste text or upload supported files such as TXT, CSV, JSON, PDF, DOCX, EML, MD, or LOG
- apply a built-in redaction profile such as `full_masking` or `placeholders`
- review each detected entity before export
- save a local job record with encrypted source content and metadata
- download only the sanitized output after review decisions are made

The default operating model is local-first processing. Raw content never leaves the workstation unless the user deliberately exports the approved redacted result.

## How it works

### 1. Host process
The Windows host in `desktop/SecureRedactionHost` is the launcher and supervisor. It:

- verifies the installation root
- starts the Python worker locally
- monitors health on `127.0.0.1:8765`
- opens the browser to the app UI
- keeps a tray icon and process lifecycle for the worker

This host is the boundary that launches the local backend and keeps the application in a single desktop process.

### 2. Python backend
The backend is in `backend/` and is built with FastAPI.

The worker app exposes endpoints such as:

- `GET /health` for loopback health
- `POST /v1/redact` for in-memory text redaction
- `POST /v1/files` for file-based redaction
- `GET /v1/jobs` and `GET /v1/jobs/{id}` for review metadata
- `PATCH /v1/jobs/{id}/entities/{index}` for approve/reject decisions
- `GET /v1/jobs/{id}/download` for the safe output only after review

The API is protected by a per-installation local token, with the token generated and stored via Windows DPAPI when available.

### 3. Redaction engine
The core detection logic is in `backend/app/redactor.py` and `backend/app/profiles.py`.

It uses a rule-based engine with:

- built-in recognizers for email, phone, SSN, credit card, IP, date of birth, and API keys
- custom regex, dictionary, and context-based rules
- replacement strategies such as `redact` and `placeholder`
- per-document stable placeholders such as `[EMAIL_1]`, `[PHONE_1]`, etc.

The engine hashes original values before returning them in metadata, which means the app can compare and review matches without exposing the original unredacted content in logs or UI responses.

### 4. Storage and security controls
The app stores job records in SQLite with encrypted source content. The implementation in `backend/app/storage.py`:

- encrypts `source_text` with Fernet
- stores the key using DPAPI-backed storage when on Windows
- migrates older plaintext rows safely when possible
- uses secure deletion and WAL checkpoint cleanup to minimize forensic leftovers

The audit log in `backend/app/audit.py` uses a chained HMAC to detect tampering and filters out raw values from event payloads. It records only metadata such as job IDs, rule IDs, timestamps, and safe decision details.

### 5. Review model
The review flow is explicit and intentionally local:

1. raw text is redacted
2. matches are returned as reviewable entities
3. the analyst approves or rejects each match
4. the final output is produced from the current reviewed state
5. export/download is only available after the review decision process is complete

That protects the upstream promise: only sanitized output is permitted to leave the workstation.

## Technical implementation notes

### Main project structure

- `backend/app/` — FastAPI app, auth, profiles, redaction logic, storage, retention, extraction pipeline
- `backend/worker.py` — server entry point to run uvicorn
- `desktop/SecureRedactionHost/` — .NET host that launches and supervises the worker
- `frontend/` — Vite/React interface
- `installer/LocalRedactionPilot.iss` — Inno Setup install bundle
- `scripts/build-pilot-installer.ps1` — automated build and signing script

### Security posture implemented in code

The project has a strong local-first design covering the most important review requirements:

- loopback-only local API design
- local authentication token for worker requests
- OS-backed DPAPI key protection for secrets on Windows
- encrypted job storage and key migration support
- tamper-evident audit log with chained hashing
- retention service for automatic cleanup
- parsers with content size limits and rejection of unsafe/unsupported formats
- custom rule validation that rejects invalid regex and unsafe patterns
- review-gated export workflow instead of unconditional raw output download

## Build and packaging

Requirements for building:

- Python 3.13
- Node.js 22+
- .NET 8 SDK
- Inno Setup 6
- Windows build environment

Build commands:

```powershell
cd .\scripts
.\build-pilot-installer.ps1 -SignCode -CertThumbprint "YOUR_CERT_THUMBPRINT"
```

The expected output is:

```text
dist\installer\LocalRedactionSetup.exe
```

The project is also capable of compiling the packaged worker through PyInstaller when the environment is configured correctly:

```powershell
cd .
.\backend\.venv2\Scripts\python.exe -m PyInstaller .\LocalRedactionWorker.spec
```

## Important signing and trust note

A trusted Microsoft Authenticode signature is not a build artifact. It requires:

- a valid code-signing certificate issued by a trusted CA
- the private key installed on the signing machine
- a `signtool`/certificate pipeline during release signing
- a timestamp server for the signed binary to remain valid over time

This repository includes the signing hooks in `scripts/build-pilot-installer.ps1`, but the certificate and private key must be supplied by the person or organization doing the final release. Without the certificate, the package is not trusted by Windows SmartScreen or enterprise policy.

## Security checklist before customer or review distribution

Before showing the build to reviewers or external users, verify:

- the final installer is signed with a real certificate
- the worker binary is signed and hash-validated before distribution
- source data is retained only in the local encrypted database
- only redacted output is exported
- `REDACTION_ENV` is configured as production where required
- keys are not committed to source control
- the build is archived with a signed manifest and SHA-256 hash

## Documentation

- [Threat model](docs/THREAT_MODEL.md)
- [VirtualBox pilot test](docs/VM_PILOT_TEST.md)
- [Installer project](installer/LocalRedactionPilot.iss)
- [Build script](scripts/build-pilot-installer.ps1)

## Review conclusion

The application is now in a much stronger state for review: the backend works, the security controls are implemented in the core flows, the worker is EXE-buildable with PyInstaller, and the installer pipeline is ready for an actual code-signing flow using a trusted certificate.

The remaining step for a formal trusted signature is external to this codebase: obtain a valid code-signing certificate and sign the final deliverables before external review or software distribution.
