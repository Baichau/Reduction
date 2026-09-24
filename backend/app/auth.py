import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

from .key_provider import KeyProvider


@dataclass
class LocalAuth:
    provider: KeyProvider

    def __post_init__(self) -> None:
        self._token = self.provider.token()

    def rotate(self) -> str:
        self._token = self.provider.rotate("api-token", lambda: secrets.token_urlsafe(32).encode("ascii")).decode("ascii")
        return self._token

    def check(self, authorization: str | None, x_local_token: str | None) -> None:
        supplied = x_local_token
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        if not supplied or not secrets.compare_digest(supplied, self._token):
            raise HTTPException(status_code=401, detail="Local API authentication required")

    def token_for_local_setup(self) -> str:
        return self._token


def require_local_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_local_token: str | None = Header(default=None),
) -> None:
    request.app.state.local_auth.check(authorization, x_local_token)
