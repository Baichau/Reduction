from datetime import datetime, timedelta, timezone
from contextlib import closing

import pytest
from cryptography.fernet import Fernet

from app.audit import AuditLog
from app.rate_limit import RateLimiter
from app.retention import RetentionService
from app.storage import JobStore


def test_rate_limiter_rejects_after_budget() -> None:
    limiter = RateLimiter(limit=2, window_seconds=60)
    limiter.check("test")
    limiter.check("test")
    with pytest.raises(Exception) as error:
        limiter.check("test")
    assert getattr(error.value, "status_code", None) == 429


def test_audit_log_detects_tampering(tmp_path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl", key=b"x" * 32)
    audit.record("redaction_created", job_id="job-1", details={"entity_count": 2, "text": "must not log"})
    assert audit.verify()
    audit.path.write_text(audit.path.read_text().replace("entity_count", "tampered"), encoding="utf-8")
    assert not audit.verify()


def test_retention_purge_deletes_old_jobs(tmp_path) -> None:
    store = JobStore(tmp_path / "jobs.db", encryption_key=Fernet.generate_key())
    old = store.create_job(source_name="old.txt", source_type="text", profile="full_masking", source_text="old", redacted_text="old", entities=[], risk_score=0, processing_ms=1)
    fresh = store.create_job(source_name="fresh.txt", source_type="text", profile="full_masking", source_text="fresh", redacted_text="fresh", entities=[], risk_score=0, processing_ms=1)
    with closing(store._connect()) as connection:
        with connection:
            connection.execute("UPDATE jobs SET created_at = ? WHERE id = ?", ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(), old["id"]))
    service = RetentionService(store, AuditLog(tmp_path / "audit.jsonl", key=b"b" * 32), hours=24)
    assert service.purge() == 1
    assert store.get_job(old["id"]) is None
    assert store.get_job(fresh["id"]) is not None


def test_parser_runs_outside_worker_process() -> None:
    from app.extractors import extract_text

    text, source_type = extract_text("notes.txt", b"email jane@example.com")
    assert text == "email jane@example.com"
    assert source_type == "text"


def test_key_rotation_reencrypts_and_new_key_reads_jobs(tmp_path) -> None:
    from cryptography.fernet import Fernet

    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()
    first = JobStore(tmp_path / "rotate.db", encryption_key=old_key)
    job = first.create_job(source_name="secret.txt", source_type="text", profile="full_masking", source_text="rotate-me", redacted_text="[SECRET]", entities=[], risk_score=0, processing_ms=1)
    assert first.reencrypt(new_key) == 1
    second = JobStore(tmp_path / "rotate.db", encryption_key=new_key)
    assert second.get_job(job["id"])["source_text"] == "rotate-me"
    with pytest.raises(Exception):
        JobStore(tmp_path / "rotate.db", encryption_key=old_key).get_job(job["id"])