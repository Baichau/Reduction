from typing import Literal

from pydantic import BaseModel, Field


class RedactRequest(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)
    profile: str = Field(default="full_masking", min_length=1, max_length=64)
    source_name: str | None = Field(default=None, max_length=255)


class EntityMatch(BaseModel):
    entity_type: str
    original_hash: str
    replacement: str
    start: int
    end: int
    confidence: float = Field(ge=0, le=1)
    token_index: int


class RedactResponse(BaseModel):
    job_id: str | None = None
    source_name: str | None = None
    status: str = "needs_review"
    redacted_text: str
    profile: str
    risk_score: float = Field(ge=0, le=1)
    processing_ms: float = Field(ge=0)
    entities: list[EntityMatch]


class ReviewDecision(BaseModel):
    decision: Literal["approved", "rejected"]
