import json
import os
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class BuiltinEntityConfig(BaseModel):
    enabled: bool = True
    strategy: str = "redact"

    @field_validator("strategy")
    @classmethod
    def valid_strategy(cls, value: str) -> str:
        if value not in {"redact", "placeholder"}:
            raise ValueError("strategy must be redact or placeholder")
        return value


class CustomEntityConfig(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
    type: str
    pattern: str | None = Field(default=None, max_length=500)
    words: list[str] = Field(default_factory=list, max_length=500)
    case_sensitive: bool = False
    anchor_words: list[str] = Field(default_factory=list, max_length=20)
    capture_length_chars: int = Field(default=32, ge=1, le=256)
    strategy: str = "redact"
    confidence: float = Field(default=1.0, ge=0, le=1)

    @field_validator("type")
    @classmethod
    def valid_type(cls, value: str) -> str:
        if value not in {"regex", "dictionary", "context_word"}:
            raise ValueError("type must be regex, dictionary, or context_word")
        return value

    @field_validator("strategy")
    @classmethod
    def valid_strategy(cls, value: str) -> str:
        if value not in {"redact", "placeholder"}:
            raise ValueError("strategy must be redact or placeholder")
        return value

    @field_validator("pattern")
    @classmethod
    def safe_pattern(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if any(fragment in value for fragment in ("(?R", "(?0", "\\1", "\\2")):
            raise ValueError("recursive patterns and backreferences are not allowed")
        return value

    def validate_shape(self) -> None:
        if self.type == "regex" and not self.pattern:
            raise ValueError("regex rules require pattern")
        if self.type == "dictionary" and not self.words:
            raise ValueError("dictionary rules require words")
        if self.type == "context_word" and not self.anchor_words:
            raise ValueError("context_word rules require anchor_words")


class ProfileConfig(BaseModel):
    profile_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    builtin_entities: dict[str, BuiltinEntityConfig] = Field(default_factory=dict)
    custom_entities: list[CustomEntityConfig] = Field(default_factory=list, max_length=50)

    def validate_rules(self) -> "ProfileConfig":
        for rule in self.custom_entities:
            rule.validate_shape()
            if rule.type == "regex":
                try:
                    re.compile(rule.pattern or "")
                except re.error as error:
                    raise ValueError(f"Invalid regex for {rule.name}: {error.msg}") from error
        return self


DEFAULT_BUILTINS = {
    "EMAIL": BuiltinEntityConfig(strategy="placeholder"),
    "PHONE": BuiltinEntityConfig(strategy="placeholder"),
    "SSN": BuiltinEntityConfig(strategy="placeholder"),
    "CREDIT_CARD": BuiltinEntityConfig(strategy="placeholder"),
    "IP_ADDRESS": BuiltinEntityConfig(strategy="placeholder"),
    "DATE_OF_BIRTH": BuiltinEntityConfig(strategy="placeholder"),
    "API_KEY": BuiltinEntityConfig(strategy="placeholder"),
}


def builtin_profile(name: str) -> ProfileConfig:
    strategy = "redact" if name == "full_masking" else "placeholder"
    return ProfileConfig(
        profile_name=name,
        builtin_entities={key: BuiltinEntityConfig(strategy=strategy) for key in DEFAULT_BUILTINS},
    )


class ProfileStore:
    def __init__(self, path: str = "data/profiles.json") -> None:
        configured = Path(os.getenv("REDACTION_PROFILES_PATH", path))
        self.path = configured if configured.is_absolute() else Path(__file__).resolve().parents[1] / configured
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({})

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("Profile store is unavailable") from error

    def _write(self, profiles: dict[str, Any]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(profiles, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def list(self) -> list[ProfileConfig]:
        return [ProfileConfig.model_validate(value).validate_rules() for value in self._read().values()]

    def get(self, name: str) -> ProfileConfig:
        if name in {"full_masking", "placeholders"}:
            return builtin_profile(name)
        value = self._read().get(name)
        if value is None:
            raise KeyError(name)
        return ProfileConfig.model_validate(value).validate_rules()

    def save(self, profile: ProfileConfig) -> ProfileConfig:
        profile.validate_rules()
        profiles = self._read()
        profiles[profile.profile_name] = profile.model_dump()
        self._write(profiles)
        return profile

    def delete(self, name: str) -> None:
        if name in {"full_masking", "placeholders"}:
            raise ValueError("Built-in profiles cannot be deleted")
        profiles = self._read()
        if name not in profiles:
            raise KeyError(name)
        del profiles[name]
        self._write(profiles)
