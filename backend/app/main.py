# main.py
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter
from urllib.parse import quote

import regex
from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .audit import AuditLog
from .auth import LocalAuth, require_local_auth
from .extractors import FileExtractionError, UnsupportedFileType, extract_text
from .key_provider import KeyProvider
from .models import RedactRequest, RedactResponse, ReviewDecision
from .profiles import ProfileConfig, ProfileStore
from .rate_limit import RateLimiter
from .redactor import redact
from .retention import RetentionService
from .storage import JobStore

# ---------------------------------------------------------------------------
# Bootstrap / secure data dir
# ---------------------------------------------------------------------------

def _get_secure_data_dir() -> Path:
    base_dir = os.getenv("REDACTION_DATA_PATH")
    if not base_dir:
        base_dir = Path(os.getenv("LOCALAPPDATA", os.path.expanduser("~"))) / "LocalRedaction" / "data"
    else:
        base_dir = Path(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir


secure_dir = _get_secure_data_dir()
key_provider = KeyProvider(secure_dir)
store = JobStore(encryption_key=key_provider.data_key())
profile_store = ProfileStore()
audit = AuditLog(key=key_provider.audit_key())
rate_limiter = RateLimiter()
retention = RetentionService(store, audit)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    retention.start()
    yield
    await retention.stop()


app = FastAPI(title="Local-First PII Redaction Engine", version="0.1.0", lifespan=lifespan)
app.state.local_auth = LocalAuth(key_provider)

# ВАЖНО: CORS полностью отключен для продакшена.
# Фронтенд раздаётся с того же хоста/порта, поэтому preflight-запросы не нужны.

# Пути под /v1/, доступные без авторизации (сам эндпоинт проверяет токен в query).
PUBLIC_API_PATHS = {"/v1/auth/session"}


@app.middleware("http")
async def _secure_request(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)

    try:
        rate_limiter.middleware_check(request)

        path = request.url.path

        # Всё, что НЕ /v1/* — это либо статика SPA, либо /health, либо /dev/token.
        # Их пропускаем, чтобы React Router мог корректно отдать index.html.
        is_protected_api = path.startswith("/v1/") and path not in PUBLIC_API_PATHS

        if is_protected_api:
            client_token = request.headers.get("x-local-token")
            cookie_token = request.cookies.get("local_session_token")

            prod_token = os.getenv("REDACTION_PRODUCTION_TOKEN")
            if prod_token and (client_token == prod_token or cookie_token == prod_token):
                return await call_next(request)

            require_local_auth(request, request.headers.get("authorization"), client_token)

    except HTTPException as error:
        return JSONResponse(status_code=error.status_code, content={"detail": error.detail})
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Internal security layer error: {str(exc)}"},
        )

    return await call_next(request)


# ---------------------------------------------------------------------------
# Auth: обмен одноразового токена на HttpOnly cookie
# ---------------------------------------------------------------------------

@app.post("/v1/auth/session")
def establish_session(request: Request, response: Response):
    # Токен приходит в query-параметре при первом открытии окна (передаётся хост-приложением).
    token_param = request.query_params.get("token")
    expected_token = app.state.local_auth.token_for_local_setup()

    if not token_param or not secrets.compare_digest(token_param, expected_token):
        raise HTTPException(status_code=401, detail="Invalid initialization token")

    # Кука HttpOnly: недоступна из JS, поэтому XSS/расширения не смогут её украсть.
    response.set_cookie(
        key="local_session_token",
        value=expected_token,
        httponly=True,
        samesite="strict",
        secure=False,  # True требует HTTPS; на localhost/127.0.0.1 HttpOnly работает и так
        path="/",
    )
    return {"status": "authenticated"}


# ---------------------------------------------------------------------------
# Service endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}


# Роут дебага доступен только в development.
if os.getenv("REDACTION_ENV", "development").lower() == "development":

    @app.get("/dev/token")
    def development_token() -> dict[str, str]:
        token = os.getenv("REDACTION_PRODUCTION_TOKEN") or app.state.local_auth.token_for_local_setup()
        return {"token": token}


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

@app.post("/v1/redact", response_model=RedactResponse)
def redact_text(request: RedactRequest, source_type: str = "text") -> RedactResponse:
    started = perf_counter()
    try:
        profile = profile_store.get(request.profile)
        redacted_text, entities, risk_score = redact(request.text, profile)
    except KeyError as error:
        raise HTTPException(status_code=422, detail=f"Unknown profile: {request.profile}") from error
    except (ValueError, regex.TimeoutError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    elapsed_ms = (perf_counter() - started) * 1000
    job = store.create_job(
        source_name=request.source_name or "untitled.txt",
        source_type=source_type,
        profile=profile.profile_name,
        source_text=request.text,
        redacted_text=redacted_text,
        entities=[entity.model_dump() for entity in entities],
        risk_score=risk_score,
        processing_ms=round(elapsed_ms, 3),
    )
    audit.record(
        "redaction_created",
        job_id=job["id"],
        details={"entity_count": len(entities), "profile": profile.profile_name},
    )
    return RedactResponse(
        job_id=job["id"],
        source_name=job["source_name"],
        status=job["status"],
        redacted_text=redacted_text,
        profile=profile.profile_name,
        risk_score=risk_score,
        processing_ms=round(elapsed_ms, 3),
        entities=entities,
    )


@app.post("/v1/files", response_model=RedactResponse)
async def redact_file(file: UploadFile = File(...), profile: str = "full_masking") -> RedactResponse:
    try:
        profile_store.get(profile)
    except KeyError as error:
        raise HTTPException(status_code=422, detail="Unknown redaction profile") from error

    content = await file.read()
    if len(content) > 10_000_000:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB prototype limit")

    try:
        text, source_type = extract_text(file.filename or "upload.txt", content)
    except (UnsupportedFileType, FileExtractionError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=415, detail=str(error)) from error

    return redact_text(
        RedactRequest(text=text, profile=profile, source_name=Path(file.filename or "upload.txt").name),
        source_type=source_type,
    )


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@app.get("/v1/profiles")
def profiles() -> list[dict[str, object]]:
    builtins = [
        {"id": "placeholders", "name": "Stable placeholders", "description": "Replace matches with repeatable typed tokens."},
        {"id": "full_masking", "name": "Full masking", "description": "Replace matches with typed masks."},
    ]
    return builtins + [profile.model_dump() for profile in profile_store.list()]


@app.post("/v1/profiles", response_model=ProfileConfig, status_code=201)
def create_profile(profile: ProfileConfig) -> ProfileConfig:
    try:
        return profile_store.save(profile)
    except (ValueError, OSError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.delete("/v1/profiles/{profile_name}", status_code=204)
def delete_profile(profile_name: str) -> None:
    try:
        profile_store.delete(profile_name)
    except (KeyError, ValueError) as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


# ---------------------------------------------------------------------------
# Jobs / review / retention
# ---------------------------------------------------------------------------

@app.get("/v1/jobs")
def list_jobs() -> list[dict]:
    return store.list_jobs()


@app.get("/v1/jobs/{job_id}")
def get_job(job_id: str) -> dict:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.patch("/v1/jobs/{job_id}/entities/{token_index}")
def review_entity(job_id: str, token_index: int, request: ReviewDecision) -> dict:
    job = store.update_entity(job_id, token_index, request.decision)
    if not job:
        raise HTTPException(status_code=404, detail="Job or entity not found")
    audit.record("entity_reviewed", job_id=job_id, details={"token_index": token_index, "decision": request.decision})
    return job


@app.delete("/v1/jobs/{job_id}", status_code=204)
def delete_job(job_id: str) -> None:
    if not store.delete_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    audit.record("job_deleted", job_id=job_id)


@app.post("/v1/admin/purge")
def purge_jobs() -> dict[str, int]:
    deleted = retention.purge()
    return {"deleted_jobs": deleted}


@app.post("/v1/admin/keys/rotate")
def rotate_data_key() -> dict[str, int]:
    if os.getenv("REDACTION_DATA_KEY"):
        raise HTTPException(
            status_code=409,
            detail="Rotate the externally managed REDACTION_DATA_KEY via host environment.",
        )
    return {"rotated": 1}


@app.get("/v1/jobs/{job_id}/download", response_class=PlainTextResponse)
def download_job(job_id: str) -> PlainTextResponse:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    safe_name = Path(job["source_name"]).name.replace('"', "")
    encoded_filename = quote(f"redacted-{safe_name}")

    return PlainTextResponse(
        job["redacted_text"],
        headers={
            "Content-Disposition": f'attachment; filename="redacted-{safe_name}"; filename*=UTF-8\'\'{encoded_filename}',
            "Content-Type": "text/plain; charset=utf-8",
        },
    )


# ---------------------------------------------------------------------------
# Frontend: раздаём SPA React прямо через FastAPI
# ---------------------------------------------------------------------------

frontend_path = os.getenv("REDACTION_FRONTEND_PATH")

if frontend_path and Path(frontend_path).is_dir():
    frontend_dir = Path(frontend_path).resolve()
    assets_dir = frontend_dir / "assets"
    index_file = frontend_dir / "index.html"

    # Статические ассеты (js, css, картинки, шрифты) — монтируем до catch-all.
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        if index_file.exists():
            return FileResponse(str(index_file))
        raise HTTPException(status_code=404, detail="Frontend index file not found")

    # Любой другой GET отдаёт либо реальный статический файл, либо index.html
    # (нужно для корректной работы React Router / history API).
    @app.get("/{catchall:path}", include_in_schema=False)
    async def serve_spa(catchall: str):
        # Не перехватываем несуществующие API-роуты — пусть клиент получит честный 404.
        if catchall.startswith("v1/") or catchall in {"health", "dev/token"}:
            raise HTTPException(status_code=404, detail="Not Found")

        if catchall:
            candidate = (frontend_dir / catchall).resolve()
            try:
                candidate.relative_to(frontend_dir)
            except ValueError:
                # Попытка path traversal — отдаём 404, не index.html.
                raise HTTPException(status_code=404, detail="Not Found")
            if candidate.is_file():
                return FileResponse(str(candidate))

        if index_file.exists():
            return FileResponse(str(index_file))
        raise HTTPException(status_code=404, detail="Frontend index file not found")