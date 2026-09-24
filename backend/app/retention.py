import asyncio
import os
from datetime import datetime, timedelta, timezone

from .audit import AuditLog
from .storage import JobStore


class RetentionService:
    def __init__(self, store: JobStore, audit: AuditLog, hours: int | None = None) -> None:
        self.store = store
        self.audit = audit
        self.hours = hours or int(os.getenv("REDACTION_RETENTION_HOURS", "24"))
        self._task: asyncio.Task[None] | None = None

    def purge(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.hours)
        count = self.store.purge_before(cutoff.isoformat())
        if count:
            self.audit.record("retention_purge", details={"deleted_jobs": count, "retention_hours": self.hours})
        return count

    async def run(self) -> None:
        while True:
            await asyncio.sleep(3600)
            self.purge()

    def start(self) -> None:
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
