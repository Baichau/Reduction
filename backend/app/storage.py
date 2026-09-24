import json
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class JobStore:
    def __init__(self, database_path: str = "data/redaction.db", encryption_key: bytes | None = None) -> None:
        configured_path = os.getenv("REDACTION_DB_PATH", database_path)
        path = Path(configured_path)
        self.database_path = path if path.is_absolute() else Path(__file__).resolve().parents[1] / path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.encryption_key = encryption_key
        self.legacy_cipher = self._load_legacy_cipher()
        self.cipher = self._load_cipher()
        self._initialize()

    def _load_legacy_cipher(self) -> Fernet | None:
        legacy_path = self.database_path.with_name("redaction.key")
        if self.encryption_key and legacy_path.exists():
            return Fernet(legacy_path.read_bytes().strip())
        return None

    def _load_cipher(self) -> Fernet:
        if self.encryption_key:
            return Fernet(self.encryption_key)
        configured_key = os.getenv("REDACTION_DATA_KEY")
        key_path = self.database_path.with_name("redaction.key")
        if os.getenv("REDACTION_ENV", "development").lower() == "production" and not configured_key:
            raise RuntimeError("REDACTION_DATA_KEY is required in production")
        if configured_key:
            return Fernet(configured_key.encode("ascii"))
        if key_path.exists():
            return Fernet(key_path.read_bytes().strip())
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return Fernet(key)

    def _encrypt(self, value: str) -> str:
        return "enc:v1:" + self.cipher.encrypt(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, value: str) -> str:
        if not value.startswith("enc:v1:"):
            return value
        try:
            return self.cipher.decrypt(value[7:].encode("ascii")).decode("utf-8")
        except InvalidToken as error:
            if self.legacy_cipher:
                try:
                    return self.legacy_cipher.decrypt(value[7:].encode("ascii")).decode("utf-8")
                except InvalidToken:
                    pass
            raise RuntimeError("Cannot decrypt job data; verify REDACTION_DATA_KEY") from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA secure_delete = ON")
        return connection

    def _initialize(self) -> None:
        needs_vacuum = False
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS jobs (
                        id TEXT PRIMARY KEY,
                        source_name TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        profile TEXT NOT NULL,
                        source_text TEXT NOT NULL,
                        redacted_text TEXT NOT NULL,
                        entities TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        processing_ms REAL NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )"""
                )
                plaintext_rows = connection.execute(
                    "SELECT id, source_text FROM jobs"
                ).fetchall()
                for row in plaintext_rows:
                    value = row["source_text"]
                    try:
                        plaintext = self._decrypt(value)
                    except RuntimeError:
                        raise RuntimeError("Cannot migrate encrypted job data; verify the configured key")
                    if not value.startswith("enc:v1:") or self.legacy_cipher:
                        connection.execute(
                            "UPDATE jobs SET source_text = ? WHERE id = ?",
                            (self._encrypt(plaintext), row["id"]),
                        )
                        needs_vacuum = True
        if needs_vacuum:
            with closing(sqlite3.connect(self.database_path, timeout=5)) as connection:
                connection.execute("PRAGMA secure_delete = ON")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("VACUUM")

    def create_job(self, *, source_name: str, source_type: str, profile: str,
                   source_text: str, redacted_text: str, entities: list[dict[str, Any]],
                   risk_score: float, processing_ms: float) -> dict[str, Any]:
        job = {
            "id": str(uuid.uuid4()),
            "source_name": source_name,
            "source_type": source_type,
            "profile": profile,
            "source_text": source_text,
            "redacted_text": redacted_text,
            "entities": entities,
            "risk_score": risk_score,
            "processing_ms": processing_ms,
            "status": "needs_review" if entities else "approved",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (job["id"], job["source_name"], job["source_type"], job["profile"],
                     self._encrypt(job["source_text"]), job["redacted_text"], json.dumps(job["entities"]),
                     job["risk_score"], job["processing_ms"], job["status"], job["created_at"]),
                )
        return self.public_job(job)

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            with connection:
                rows = connection.execute(
                    "SELECT id, source_name, source_type, profile, risk_score, processing_ms, status, created_at, entities FROM jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self._summary(dict(row)) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            with connection:
                row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self.public_job(dict(row)) if row else None

    def update_entity(self, job_id: str, token_index: int, decision: str) -> dict[str, Any] | None:
        job = self.get_job(job_id)
        if not job or decision not in {"approved", "rejected"}:
            return None
        entities = job["entities"]
        if token_index < 0 or token_index >= len(entities):
            return None
        entities[token_index]["review_status"] = decision
        statuses = {entity.get("review_status") for entity in entities}
        status = "approved" if statuses == {"approved"} else "needs_review"
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("UPDATE jobs SET entities = ?, status = ? WHERE id = ?",
                                   (json.dumps(entities), status, job_id))
        job["entities"] = entities
        job["status"] = status
        return job

    def delete_job(self, job_id: str) -> bool:
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        return cursor.rowcount == 1

    def purge_before(self, cutoff_iso: str) -> int:
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute("DELETE FROM jobs WHERE created_at < ?", (cutoff_iso,))
                deleted = cursor.rowcount
        with closing(sqlite3.connect(self.database_path, timeout=5)) as checkpoint:
            checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted

    def reencrypt(self, new_key: bytes) -> int:
        new_cipher = Fernet(new_key)
        with closing(self._connect()) as connection:
            with connection:
                rows = connection.execute("SELECT id, source_text FROM jobs").fetchall()
                for row in rows:
                    plaintext = self._decrypt(row["source_text"])
                    encrypted = "enc:v1:" + new_cipher.encrypt(plaintext.encode("utf-8")).decode("ascii")
                    connection.execute("UPDATE jobs SET source_text = ? WHERE id = ?", (encrypted, row["id"]))
        self.cipher = new_cipher
        return len(rows)

    @staticmethod
    def _summary(job: dict[str, Any]) -> dict[str, Any]:
        job["entity_count"] = len(json.loads(job.pop("entities", "[]")))
        return job

    def public_job(self, job: dict[str, Any]) -> dict[str, Any]:
        if "source_text" in job:
            job["source_text"] = self._decrypt(job["source_text"])
        job["entities"] = json.loads(job["entities"]) if isinstance(job["entities"], str) else job["entities"]
        return job
