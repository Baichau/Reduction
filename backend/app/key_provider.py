import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet


class KeyProvider:
    """Windows DPAPI-backed secret storage with an explicit development fallback."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    @property
    def production(self) -> bool:
        return os.getenv("REDACTION_ENV", "development").lower() == "production"

    def _protect(self, value: bytes) -> bytes:
        if os.name != "nt":
            if self.production:
                raise RuntimeError("DPAPI is required for production on Windows")
            return value
        try:
            import win32crypt
        except ImportError as error:
            raise RuntimeError("pywin32 is required for DPAPI-backed secrets") from error
        protected = win32crypt.CryptProtectData(value, "Local Redaction secret", None, None, None, 0)
        return protected[1] if isinstance(protected, tuple) else protected

    def _unprotect(self, value: bytes) -> bytes:
        if os.name != "nt":
            if self.production:
                raise RuntimeError("DPAPI is required for production on Windows")
            return value
        try:
            import win32crypt
        except ImportError as error:
            raise RuntimeError("pywin32 is required for DPAPI-backed secrets") from error
        unprotected = win32crypt.CryptUnprotectData(value, None, None, None, 0)
        return unprotected[1] if isinstance(unprotected, tuple) else unprotected

    def get_or_create(self, name: str, factory=Fernet.generate_key) -> bytes:
        path = self.directory / f"{name}.dpapi"
        if path.exists():
            return self._unprotect(path.read_bytes())
        value = factory()
        path.write_bytes(self._protect(value))
        return value

    def rotate(self, name: str, factory=Fernet.generate_key) -> bytes:
        path = self.directory / f"{name}.dpapi"
        value = factory()
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(self._protect(value))
        temporary.replace(path)
        return value

    def token(self) -> str:
        return self.get_or_create("api-token", lambda: base64.urlsafe_b64encode(os.urandom(32))).decode("ascii")

    def data_key(self) -> bytes:
        configured = os.getenv("REDACTION_DATA_KEY")
        if configured:
            return configured.encode("ascii")
        if self.production:
            raise RuntimeError("REDACTION_DATA_KEY is required in production")
        return self.get_or_create("data-key")

    def audit_key(self) -> bytes:
        return self.get_or_create("audit-key", lambda: os.urandom(32))
