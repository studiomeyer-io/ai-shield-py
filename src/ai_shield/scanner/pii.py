"""PII scanner — 8 PII types with 5 validators.

1:1 port of `packages/core/src/scanner/pii.ts`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ai_shield.types import PIIAction, PIIEntity, PIIType, ScannerResult, Violation

# -- Pattern + validator catalogue ---------------------------------------


@dataclass(frozen=True)
class PIIPattern:
    type: PIIType
    regex: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


_FLAGS = re.IGNORECASE | re.UNICODE


# -- Validators ----------------------------------------------------------


def validate_luhn(value: str) -> bool:
    """ISO 7812 Luhn check for credit-card numbers."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 12 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def validate_iban(value: str) -> bool:
    """ISO 13616-1 IBAN mod-97 check."""
    cleaned = re.sub(r"\s+", "", value).upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", cleaned):
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric: list[str] = []
    for ch in rearranged:
        if ch.isdigit():
            numeric.append(ch)
        else:
            numeric.append(str(ord(ch) - ord("A") + 10))
    big = "".join(numeric)
    # Chunk to avoid huge int — but Python can handle big ints fine.
    return int(big) % 97 == 1


def validate_german_tax_id(value: str) -> bool:
    """German Steuer-ID: 11 digits, no leading zero."""
    cleaned = re.sub(r"\s+", "", value)
    return bool(re.fullmatch(r"[1-9]\d{10}", cleaned))


def validate_phone(value: str) -> bool:
    """Phone-number digit-count check (7-15 digits per ITU E.164)."""
    digits = [c for c in value if c.isdigit()]
    return 7 <= len(digits) <= 15


def validate_ip_not_private(value: str) -> bool:
    """Filter out 10.x, 172.16-31.x, 192.168.x, 127.x — only flag public IPs."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    a, b, *_ = nums
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    return a != 127


# -- Patterns ------------------------------------------------------------

PII_PATTERNS: tuple[PIIPattern, ...] = (
    # url_with_credentials MUST come before email so deduplicate-overlap
    # picks the more specific (longer) match. Without this order,
    # `pass@vault.example.com` inside `https://user:pass@vault.example.com/x`
    # is greedily matched as an email and the url_with_credentials pattern
    # never gets a chance.
    PIIPattern(
        "url_with_credentials",
        re.compile(r"\bhttps?://[^\s/:@]+:[^\s/:@]+@[^\s]+", _FLAGS),
    ),
    PIIPattern(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", _FLAGS),
    ),
    PIIPattern(
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b", _FLAGS),
        validator=validate_iban,
    ),
    PIIPattern(
        "credit_card",
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b", _FLAGS),
        validator=validate_luhn,
    ),
    PIIPattern(
        "german_tax_id",
        re.compile(r"\b[1-9]\d{10}\b", _FLAGS),
        validator=validate_german_tax_id,
    ),
    PIIPattern(
        "german_social_security",
        re.compile(r"\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b", _FLAGS),
    ),
    PIIPattern(
        "phone",
        re.compile(r"(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,5}\d{2,4}", _FLAGS),
        validator=validate_phone,
    ),
    PIIPattern(
        "ip_address",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _FLAGS),
        validator=validate_ip_not_private,
    ),
)


def mask_value(value: str, type_: PIIType) -> str:
    """Mask a PII value type-appropriately for logs/redaction output."""
    if type_ == "email":
        if "@" in value:
            local, _, domain = value.partition("@")
            shown = local[:2] if len(local) > 2 else local[:1]
            return f"{shown}***@{domain}"
        return "***"
    if type_ in {"iban", "credit_card", "german_tax_id", "german_social_security", "phone"}:
        digits = "".join(c for c in value if c.isalnum())
        if len(digits) <= 4:
            return "***"
        return f"***{digits[-4:]}"
    if type_ == "ip_address":
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.***"
        return "***"
    if type_ == "url_with_credentials":
        return re.sub(r"//[^@]+@", "//***:***@", value)
    return "***"


# -- Scanner -------------------------------------------------------------


@dataclass
class PIIConfig:
    action: PIIAction = "redact"
    """What to do on PII match — allow / warn / redact / block."""

    redact_placeholder: str = "[REDACTED:{type}]"


class PIIScanner:
    name = "pii"

    def __init__(self, config: PIIConfig | None = None) -> None:
        self.config = config or PIIConfig()

    async def scan(self, text: str, _ctx: dict[str, Any] | None = None) -> ScannerResult:
        entities = self._find_entities(text)

        if not entities:
            return ScannerResult(decision="allow", violations=[], score=0.0)

        violations: list[Violation] = [
            Violation(
                type="pii_exposure",
                severity="medium",
                detector=f"pii:{e.type}",
                message=f"Detected {e.type}",
                confidence=0.9,
                metadata={"masked": e.masked, "start": e.start, "end": e.end},
            )
            for e in entities
        ]

        score = min(1.0, 0.2 + 0.1 * len(entities))

        if self.config.action == "block":
            return ScannerResult(decision="block", violations=violations, score=score)
        if self.config.action == "warn":
            return ScannerResult(decision="warn", violations=violations, score=score)
        if self.config.action == "redact":
            return ScannerResult(
                decision="warn",
                violations=violations,
                sanitized_text=self._redact(text, entities),
                score=score,
            )
        # allow
        return ScannerResult(decision="allow", violations=violations, score=score)

    def _find_entities(self, text: str) -> list[PIIEntity]:
        seen_spans: list[tuple[int, int]] = []
        out: list[PIIEntity] = []
        for pattern in PII_PATTERNS:
            for match in pattern.regex.finditer(text):
                value = match.group(0)
                if pattern.validator is not None and not pattern.validator(value):
                    continue
                start, end = match.start(), match.end()
                # Skip if span overlaps a previously-detected one (first-pattern wins).
                if any(not (end <= s or start >= e) for s, e in seen_spans):
                    continue
                seen_spans.append((start, end))
                out.append(
                    PIIEntity(
                        type=pattern.type,
                        value=value,
                        masked=mask_value(value, pattern.type),
                        start=start,
                        end=end,
                    )
                )
        out.sort(key=lambda e: e.start)
        return out

    def _redact(self, text: str, entities: list[PIIEntity]) -> str:
        chunks: list[str] = []
        cursor = 0
        for ent in entities:
            chunks.append(text[cursor : ent.start])
            chunks.append(self.config.redact_placeholder.format(type=ent.type))
            cursor = ent.end
        chunks.append(text[cursor:])
        return "".join(chunks)
