import json
import os
import time
from contextlib import asynccontextmanager
from hmac import compare_digest
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .audit import AuditLog
from .auth import LocalAuth, require_local_auth
from .extractors import FileExtractionError, UnsupportedFileType, extract_text
from .key_provider import KeyProvider
from .models import EntityMatch, RedactRequest, RedactResponse, ReviewDecision
from .profiles import ProfileConfig, ProfileStore
from .rate_limit import RateLimiter
from .redactor import redact
from .retention import RetentionService
from .storage import JobStore

@asynccontextmanager
async def lifespan(_: FastAPI):
    app.state.retention.start()
    try:
        yield
    finally:
        await app.state.retention.stop()


app = FastAPI(title="Local Redaction", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

data_dir = Path(os.getenv("REDACTION_DATA_DIR", Path(__file__).resolve().parents[1] / "data"))
data_dir.mkdir(parents=True, exist_ok=True)

app.state.key_provider = KeyProvider(data_dir)
app.state.local_auth = LocalAuth(app.state.key_provider)
app.state.profile_store = ProfileStore(path=str(data_dir / "profiles.json"))
app.state.job_store = JobStore(
    database_path=str(data_dir / "redaction.db"),
    encryption_key=app.state.key_provider.data_key(),
)
app.state.audit = AuditLog(path=str(data_dir / "audit.jsonl"), key=app.state.key_provider.audit_key())
app.state.rate_limiter = RateLimiter(limit=60, window_seconds=60)
app.state.retention = RetentionService(app.state.job_store, app.state.audit, hours=int(os.getenv("REDACTION_RETENTION_HOURS", "24")))


@app.middleware("http")
async def enforce_local_limits(request: Request, call_next):
    skip = {"/health", "/v1/health", "/dev/token", "/docs", "/openapi.json", "/redoc"}
    if request.url.path not in skip:
        app.state.rate_limiter.middleware_check(request)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}


@app.get("/v1/health")
def health_v1() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}


@app.get("/dev/token")
def dev_token() -> dict[str, str]:
    token = os.getenv("REDACTION_PRODUCTION_TOKEN") or app.state.local_auth.token_for_local_setup()
    return {"token": token}


@app.post("/v1/auth/session")
def create_session(token: str | None = None) -> JSONResponse:
    expected = app.state.local_auth.token_for_local_setup()
    supplied = token
    if not supplied or not compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Local API authentication required")
    response = JSONResponse({"status": "ok"})
    response.set_cookie(
        key="local_session_token",
        value=supplied,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return response


def _coerce_entities(raw_entities: Any) -> list[dict[str, Any]]:
    if raw_entities is None:
        return []
    if isinstance(raw_entities, list):
        return [dict(entity) for entity in raw_entities]
    if isinstance(raw_entities, str):
        return json.loads(raw_entities)
    return []


def _parse_job(job: dict[str, Any]) -> dict[str, Any]:
    payload = dict(job)
    payload["entities"] = _coerce_entities(payload.get("entities"))
    payload["risk_score"] = float(payload.get("risk_score", 0.0))
    payload["processing_ms"] = float(payload.get("processing_ms", 0.0))
    return payload


@app.post("/v1/redact", response_model=RedactResponse)
def redact_text(payload: RedactRequest, _auth=Depends(require_local_auth)) -> dict[str, Any]:
    profile = app.state.profile_store.get(payload.profile)
    started = time.perf_counter()
    redacted, entities, risk_score = redact(payload.text, profile)
    processing_ms = (time.perf_counter() - started) * 1000.0
    entity_payload = [
        EntityMatch(
            entity_type=entity.entity_type,
            original_hash=entity.original_hash,
            replacement=entity.replacement,
            start=entity.start,
            end=entity.end,
            confidence=entity.confidence,
            token_index=entity.token_index,
        ).model_dump()
        for entity in entities
    ]
    job = app.state.job_store.create_job(
        source_name=payload.source_name or "inline-text",
        source_type="text",
        profile=payload.profile,
        source_text=payload.text,
        redacted_text=redacted,
        entities=entity_payload,
        risk_score=risk_score,
        processing_ms=processing_ms,
    )
    app.state.audit.record(
        "redaction_created",
        job_id=job["id"],
        details={
            "source_name": payload.source_name or "inline-text",
            "profile": payload.profile,
            "entity_count": len(entity_payload),
            "risk_score": round(risk_score, 4),
        },
    )
    return {
        "job_id": job["id"],
        "source_name": payload.source_name or "inline-text",
        "status": job["status"],
        "redacted_text": redacted,
        "profile": payload.profile,
        "risk_score": risk_score,
        "processing_ms": processing_ms,
        "entities": entity_payload,
    }


@app.post("/v1/files")
async def upload_file(
    file: UploadFile = File(...),
    profile: str = "full_masking",
    _auth=Depends(require_local_auth),
) -> dict[str, Any]:
    try:
        content = await file.read()
        text, source_type = extract_text(file.filename or "upload.bin", content)
    except (UnsupportedFileType, FileExtractionError, ValueError) as error:
        raise HTTPException(status_code=415, detail=str(error)) from error

    profile_config = app.state.profile_store.get(profile)
    redacted, entities, risk_score = redact(text, profile_config)
    entity_payload = [
        EntityMatch(
            entity_type=entity.entity_type,
            original_hash=entity.original_hash,
            replacement=entity.replacement,
            start=entity.start,
            end=entity.end,
            confidence=entity.confidence,
            token_index=entity.token_index,
        ).model_dump()
        for entity in entities
    ]
    job = app.state.job_store.create_job(
        source_name=file.filename or "upload.bin",
        source_type=source_type,
        profile=profile,
        source_text=text,
        redacted_text=redacted,
        entities=entity_payload,
        risk_score=risk_score,
        processing_ms=0.0,
    )
    return {
        "job_id": job["id"],
        "source_name": file.filename or "upload.bin",
        "status": job["status"],
        "redacted_text": redacted,
        "profile": profile,
        "risk_score": risk_score,
        "processing_ms": 0.0,
        "entities": entity_payload,
    }


@app.get("/v1/jobs")
def list_jobs(_auth=Depends(require_local_auth)) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in _parse_job(job).items() if key != "source_text"}
        for job in app.state.job_store.list_jobs(limit=50)
    ]


@app.get("/v1/jobs/{job_id}")
def get_job(job_id: str, _auth=Depends(require_local_auth)) -> dict[str, Any]:
    job = app.state.job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return _parse_job(job)


@app.patch("/v1/jobs/{job_id}/entities/{token_index}")
def review_entity(job_id: str, token_index: int, payload: ReviewDecision, _auth=Depends(require_local_auth)) -> dict[str, Any]:
    job = app.state.job_store.update_entity(job_id, token_index, payload.decision)
    if job is None:
        raise HTTPException(status_code=404, detail="Job or entity not found")
    app.state.audit.record(
        "entity_reviewed",
        job_id=job_id,
        details={
            "token_index": token_index,
            "decision": payload.decision,
            "status": job["status"],
        },
    )
    return {"job_id": job_id, "status": job["status"], "entities": job["entities"]}


@app.get("/v1/jobs/{job_id}/download")
def download_job(job_id: str, _auth=Depends(require_local_auth)) -> PlainTextResponse:
    job = app.state.job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return PlainTextResponse(job["redacted_text"], media_type="text/plain; charset=utf-8")


@app.delete("/v1/jobs/{job_id}", status_code=204)
def delete_job(job_id: str, _auth=Depends(require_local_auth)) -> None:
    deleted = app.state.job_store.delete_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found")
    return None


@app.get("/v1/profiles")
def list_profiles(_auth=Depends(require_local_auth)) -> list[dict[str, Any]]:
    profiles = app.state.profile_store.list()
    return [profile.model_dump() for profile in profiles]


@app.post("/v1/profiles", status_code=201)
def create_profile(profile: ProfileConfig, _auth=Depends(require_local_auth)) -> dict[str, Any]:
    try:
        saved = app.state.profile_store.save(profile)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return saved.model_dump()


@app.delete("/v1/profiles/{profile_name}")
def delete_profile(profile_name: str, _auth=Depends(require_local_auth)) -> dict[str, str]:
    app.state.profile_store.delete(profile_name)
    return {"status": "deleted", "profile_name": profile_name}


frontend_dir = Path(os.getenv(
    "REDACTION_FRONTEND_PATH",
    Path(__file__).resolve().parents[2] / "frontend" / "dist",
))
if (frontend_dir / "index.html").is_file():
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")


__all__ = ["app"]