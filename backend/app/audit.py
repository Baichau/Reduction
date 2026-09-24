import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


class AuditLog:
    """Append-only metadata log with a chained HMAC; raw source values are prohibited."""

    def __init__(self, path: str = "data/audit.jsonl", key: bytes | None = None) -> None:
        configured = Path(os.getenv("REDACTION_AUDIT_PATH", path))
        self.path = configured if configured.is_absolute() else Path(__file__).resolve().parents[1] / configured
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key = key or os.urandom(32)
        self._lock = Lock()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])["event_hash"] if lines else "0" * 64

    def record(self, event_type: str, *, job_id: str | None = None, actor: str = "local-user", details: dict[str, Any] | None = None) -> dict[str, Any]:
        safe_details = {key: value for key, value in (details or {}).items() if key not in {"text", "source_text", "redacted_text", "value", "original"}}
        with self._lock:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "job_id": job_id,
                "actor": actor,
                "details": safe_details,
                "previous_hash": self._last_hash(),
            }
            payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
            event["event_hash"] = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
            return event

    def verify(self) -> bool:
        previous = "0" * 64
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            event_hash = event.pop("event_hash")
            if event["previous_hash"] != previous:
                return False
            payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if not hmac.compare_digest(event_hash, hmac.new(self.key, payload, hashlib.sha256).hexdigest()):
                return False
            previous = event_hash
        return True
