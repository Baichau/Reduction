import hashlib
from dataclasses import dataclass
from typing import Any

import regex

from .models import EntityMatch
from .profiles import ProfileConfig


@dataclass(frozen=True)
class Rule:
    entity_type: str
    pattern: regex.Pattern[str]
    confidence: float
    strategy: str


BUILTIN_PATTERNS = {
    "EMAIL": (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", regex.IGNORECASE, 1.0),
    "PHONE": (r"(?<!\d)(?!\d{3}-\d{2}-\d{4}(?!\d))(?:\+?\d[\d ()-]{8,}\d)(?!\d)", 0, 0.98),
    "SSN": (r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", 0, 1.0),
    "CREDIT_CARD": (r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", 0, 0.99),
    "IP_ADDRESS": (r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", 0, 0.96),
    "DATE_OF_BIRTH": (r"(?i)\b(?:dob|date of birth)\s*[:=-]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", 0, 0.94),
    "API_KEY": (r"\b(?:sk|pk|api|token)[_-][A-Za-z0-9_-]{16,}\b", regex.IGNORECASE, 0.97),
}


@dataclass(frozen=True)
class Match:
    entity_type: str
    start: int
    end: int
    original: str
    confidence: float
    strategy: str


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _compile_custom(rule: Any) -> Rule:
    if rule.type == "regex":
        pattern = regex.compile(rule.pattern)
    elif rule.type == "dictionary":
        words = "|".join(regex.escape(word) for word in sorted(rule.words, key=len, reverse=True))
        flags = 0 if rule.case_sensitive else regex.IGNORECASE
        pattern = regex.compile(rf"(?<!\w)(?:{words})(?!\w)", flags)
    else:
        anchors = "|".join(regex.escape(word) for word in sorted(rule.anchor_words, key=len, reverse=True))
        pattern = regex.compile(rf"(?:{anchors})[ \t]*(.{{1,{rule.capture_length_chars}}})", regex.IGNORECASE)
    return Rule(rule.name, pattern, rule.confidence, rule.strategy)


def _rules_for(profile: ProfileConfig) -> list[Rule]:
    rules: list[Rule] = []
    for entity_type, (pattern, flags, confidence) in BUILTIN_PATTERNS.items():
        settings = profile.builtin_entities.get(entity_type)
        if settings is None or settings.enabled:
            strategy = settings.strategy if settings else "redact"
            rules.append(Rule(entity_type, regex.compile(pattern, flags), confidence, strategy))
    rules.extend(_compile_custom(rule) for rule in profile.custom_entities)
    return rules


def _find_matches(text: str, profile: ProfileConfig) -> list[Match]:
    matches: list[Match] = []
    for rule in _rules_for(profile):
        try:
            for result in rule.pattern.finditer(text, timeout=0.05):
                candidate = Match(rule.entity_type, result.start(), result.end(), result.group(), rule.confidence, rule.strategy)
                if not any(candidate.start < existing.end and candidate.end > existing.start for existing in matches):
                    matches.append(candidate)
        except regex.TimeoutError as error:
            raise ValueError(f"Rule {rule.entity_type} exceeded the 50 ms regex limit") from error
    return sorted(matches, key=lambda item: item.start)


def redact(text: str, profile: ProfileConfig) -> tuple[str, list[EntityMatch], float]:
    matches = _find_matches(text, profile)
    replacements: dict[str, int] = {}
    entities: list[EntityMatch] = []
    output: list[str] = []
    cursor = 0

    for index, match in enumerate(matches):
        output.append(text[cursor:match.start])
        replacements[match.entity_type] = replacements.get(match.entity_type, 0) + 1
        replacement = f"[{match.entity_type}]"
        if match.strategy == "placeholder":
            replacement = f"[{match.entity_type}_{replacements[match.entity_type]}]"
        output.append(replacement)
        entities.append(EntityMatch(
            entity_type=match.entity_type,
            original_hash=_hash(match.original),
            replacement=replacement,
            start=match.start,
            end=match.end,
            confidence=match.confidence,
            token_index=index,
        ))
        cursor = match.end

    output.append(text[cursor:])
    risk_score = min(1.0, sum(entity.confidence for entity in entities) / 4)
    return "".join(output), entities, risk_score
