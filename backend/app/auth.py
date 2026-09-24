# auth.py
import secrets
import os
from dataclasses import dataclass
from fastapi import Header, HTTPException, Request

from .key_provider import KeyProvider

@dataclass
class LocalAuth:
    provider: KeyProvider

    def __post_init__(self) -> None:
        # ПРИОРИТЕТ: берем токен, сгенерированный C# хостом, иначе откатываемся на DPAPI
        self._token = os.getenv("REDACTION_PRODUCTION_TOKEN")
        if not self._token:
            self._token = self.provider.token()

    def rotate(self) -> str:
        if os.getenv("REDACTION_PRODUCTION_TOKEN"):
            raise HTTPException(status_code=409, detail="Token management is delegated to the OS process host.")
        self._token = self.provider.rotate("api-token", lambda: secrets.token_urlsafe(32).encode("ascii")).decode("ascii")
        return self._token

    def check(self, authorization: str | None, x_local_token: str | None, cookie_token: str | None) -> None:
        supplied = x_local_token
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        if not supplied and cookie_token:
            supplied = cookie_token
            
        if not supplied or not secrets.compare_digest(supplied, self._token):
            raise HTTPException(status_code=401, detail="Local API authentication required")

    def token_for_local_setup(self) -> str:
        return self._token

def require_local_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_local_token: str | None = Header(default=None),
) -> None:
    # Извлекаем куки вручную во избежание лишних зависимостей
    cookie_token = request.cookies.get("local_session_token")
    request.app.state.local_auth.check(authorization, x_local_token, cookie_token)
