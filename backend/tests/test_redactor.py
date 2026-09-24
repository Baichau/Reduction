from fastapi.testclient import TestClient
from pathlib import Path
import sqlite3
import tempfile

from app.main import app
from app.storage import JobStore


client = TestClient(app, headers={"X-Local-Token": app.state.local_auth.token_for_local_setup()})


def test_redacts_deterministic_pii_without_returning_original_value() -> None:
    response = client.post("/v1/redact", json={
        "text": "Contact jane@example.com or 555-123-4567. SSN 123-45-6789.",
        "profile": "placeholders",
    })

    assert response.status_code == 200
    payload = response.json()
    assert payload["redacted_text"] == "Contact [EMAIL_1] or [PHONE_1]. SSN [SSN_1]."
    assert "jane@example.com" not in payload["redacted_text"]
    assert len(payload["entities"]) == 3
    assert payload["entities"][0]["confidence"] == 1.0


def test_health_is_loopback_worker_signal() -> None:
    response = client.get("/health")

    assert response.json() == {"status": "ok", "mode": "local-only"}


def test_api_requires_local_token() -> None:
    unauthenticated = TestClient(app, raise_server_exceptions=False)
    assert unauthenticated.get("/v1/jobs").status_code == 401
    assert unauthenticated.get("/dev/token").status_code == 200


def test_text_request_creates_reviewable_job_and_download() -> None:
    response = client.post("/v1/redact", json={
        "text": "Send jane@example.com the report.",
        "profile": "placeholders",
        "source_name": "report.txt",
    })

    assert response.status_code == 200
    job_id = response.json()["job_id"]
    job = client.get(f"/v1/jobs/{job_id}")
    assert job.json()["status"] == "needs_review"
    assert job.json()["source_text"] == "Send jane@example.com the report."

    decision = client.patch(f"/v1/jobs/{job_id}/entities/0", json={"decision": "approved"})
    assert decision.json()["status"] == "approved"
    download = client.get(f"/v1/jobs/{job_id}/download")
    assert download.text == "Send [EMAIL_1] the report."


def test_text_file_upload_uses_same_redaction_pipeline() -> None:
    response = client.post(
        "/v1/files?profile=full_masking",
        files={"file": ("notes.txt", b"Call 555-123-4567", "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "Call [PHONE]"
    assert response.json()["source_name"] == "notes.txt"


def test_invalid_json_is_a_client_error_and_jobs_can_be_deleted() -> None:
    response = client.post(
        "/v1/files?profile=full_masking",
        files={"file": ("broken.json", b"{not-json", "application/json")},
    )
    assert response.status_code == 415

    created = client.post("/v1/redact", json={"text": "no pii"}).json()
    deleted = client.delete(f"/v1/jobs/{created['job_id']}")
    assert deleted.status_code == 204
    assert client.get(f"/v1/jobs/{created['job_id']}").status_code == 404


def test_custom_profile_supports_dictionary_and_builtin_toggles() -> None:
    profile = {
        "profile_name": "engineering_policy",
        "builtin_entities": {
            "EMAIL": {"enabled": True, "strategy": "placeholder"},
            "PHONE": {"enabled": False, "strategy": "redact"},
        },
        "custom_entities": [{
            "name": "PROJECT_CODE",
            "type": "dictionary",
            "words": ["Project Falcon", "Vanguard"],
            "strategy": "placeholder",
            "confidence": 1.0,
        }],
    }
    created = client.post("/v1/profiles", json=profile)
    assert created.status_code == 201

    response = client.post("/v1/redact", json={
        "profile": "engineering_policy",
        "text": "Project Falcon, jane@example.com, 555-123-4567",
    })
    assert response.status_code == 200
    assert response.json()["redacted_text"] == "[PROJECT_CODE_1], [EMAIL_1], 555-123-4567"


def test_invalid_custom_regex_is_rejected() -> None:
    response = client.post("/v1/profiles", json={
        "profile_name": "invalid_policy",
        "custom_entities": [{"name": "BROKEN", "type": "regex", "pattern": "[", "strategy": "redact"}],
    })
    assert response.status_code == 422


def test_job_source_is_encrypted_on_disk() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database_path = Path(directory) / "legacy.db"
        connection = sqlite3.connect(database_path)
        connection.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, source_name TEXT NOT NULL, source_type TEXT NOT NULL, profile TEXT NOT NULL, source_text TEXT NOT NULL, redacted_text TEXT NOT NULL, entities TEXT NOT NULL, risk_score REAL NOT NULL, processing_ms REAL NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)")
        connection.execute("INSERT INTO jobs VALUES ('legacy', 'secret.txt', 'text', 'full_masking', 'legacy@example.com', '[EMAIL]', '[]', 0, 1, 'approved', 'now')")
        connection.commit()
        connection.close()

        store = JobStore(str(database_path))
        assert b"legacy@example.com" not in database_path.read_bytes()
        assert store.get_job("legacy")["source_text"] == "legacy@example.com"
        job = store.create_job(
            source_name="secret.txt", source_type="text", profile="full_masking",
            source_text="unique-secret-value", redacted_text="[SECRET]", entities=[],
            risk_score=0, processing_ms=1,
        )
        assert b"unique-secret-value" not in database_path.read_bytes()
        assert store.get_job(job["id"])["source_text"] == "unique-secret-value"
        store.delete_job(job["id"])
