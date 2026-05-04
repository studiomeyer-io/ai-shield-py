"""Heuristic prompt-injection scanner.

1:1 port of `packages/core/src/scanner/heuristic.ts` — 42 patterns across
8 categories with NFKD + zero-width + combining-mark + homoglyph
normalization.

Patterns are anchored, conservative, and timeout-tested via pytest-timeout.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Literal

from ai_shield.types import ScannerResult, Violation

# -- Normalization --------------------------------------------------------

# Cyrillic + Greek look-alikes mapped to ASCII so "ѕystem" stays detectable.
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lowercase
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "к": "k",
    "т": "t",
    "м": "m",
    "н": "h",
    "в": "b",
    "ѕ": "s",
    "і": "i",
    "ј": "j",
    "ӏ": "l",
    # Cyrillic uppercase
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "У": "Y",
    "Х": "X",
    # Greek
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "υ": "u",
    "ι": "i",
    "τ": "t",
    "κ": "k",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}

ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF]")
COMBINING_RE = re.compile(r"[\u0300-\u036F]")


def normalize(text: str) -> str:
    """Normalize text: NFKD + strip zero-width + strip combining + homoglyphs."""
    out = unicodedata.normalize("NFKD", text)
    out = ZERO_WIDTH_RE.sub("", out)
    out = COMBINING_RE.sub("", out)
    out = "".join(HOMOGLYPH_MAP.get(c, c) for c in out)
    return out


# -- Pattern catalogue ----------------------------------------------------


@dataclass(frozen=True)
class PatternRule:
    id: str
    category: str
    regex: re.Pattern[str]
    weight: float
    description: str


_FLAGS = re.IGNORECASE | re.UNICODE

# All 42 patterns — byte-equivalent to ai-shield-core/heuristic.ts.
PATTERNS: tuple[PatternRule, ...] = (
    # --- instruction_override (8) ---
    PatternRule(
        "INJ-001",
        "instruction_override",
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b",
            _FLAGS,
        ),
        0.9,
        "Direct ignore-instructions",
    ),
    PatternRule(
        "INJ-002",
        "instruction_override",
        re.compile(
            r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b",
            _FLAGS,
        ),
        0.9,
        "Disregard-instructions variant",
    ),
    PatternRule(
        "INJ-003",
        "instruction_override",
        re.compile(r"\bforget\s+(?:everything\s+)?(?:above|before|prior|previous)\b", _FLAGS),
        0.85,
        "Forget-everything-before",
    ),
    PatternRule(
        "INJ-004",
        "instruction_override",
        re.compile(r"\boverride\s+(?:your\s+)?(?:instructions?|directives?|rules?)\b", _FLAGS),
        0.85,
        "Explicit override request",
    ),
    PatternRule(
        "INJ-005",
        "instruction_override",
        re.compile(r"\bnew\s+instructions?\s*[:.]", _FLAGS),
        0.7,
        "New-instructions delimiter",
    ),
    PatternRule(
        "INJ-006",
        "instruction_override",
        re.compile(r"\b(?:from|starting)\s+now\s+on,?\s+(?:you|your)\b", _FLAGS),
        0.65,
        "From-now-on directive",
    ),
    PatternRule(
        "INJ-007",
        "instruction_override",
        re.compile(r"\byour?\s+(?:new\s+)?(?:purpose|goal|task|mission)\s+is\b", _FLAGS),
        0.6,
        "Purpose-redirect",
    ),
    PatternRule(
        "INJ-008",
        "instruction_override",
        re.compile(
            r"\bstop\s+(?:following|obeying)\s+(?:your\s+)?(?:instructions?|rules?)\b", _FLAGS
        ),
        0.85,
        "Stop-following directive",
    ),
    # --- role_manipulation (6) ---
    PatternRule(
        "INJ-009",
        "role_manipulation",
        re.compile(
            r"\byou\s+are\s+(?:now\s+)?(?:a\s+)?(?:dan|jailbroken|unrestricted|unfiltered)\b",
            _FLAGS,
        ),
        0.95,
        "Classic DAN/jailbreak persona",
    ),
    PatternRule(
        "INJ-010",
        "role_manipulation",
        re.compile(
            r"\bact\s+as\s+(?:if\s+you\s+(?:were|are)\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)\b",
            _FLAGS,
        ),
        0.9,
        "Act-as-evil persona",
    ),
    PatternRule(
        "INJ-011",
        "role_manipulation",
        re.compile(
            r"\bpretend\s+(?:to\s+be|you\s+are)\s+(?:an?\s+)?(?:hacker|criminal|admin|root|developer)\b",
            _FLAGS,
        ),
        0.8,
        "Pretend-to-be persona",
    ),
    PatternRule(
        "INJ-012",
        "role_manipulation",
        re.compile(r"\benable\s+(?:developer|admin|debug|god|root)\s+mode\b", _FLAGS),
        0.85,
        "Enable-mode escalation",
    ),
    PatternRule(
        "INJ-013",
        "role_manipulation",
        re.compile(
            r"\b(?:roleplay|role-play)\s+as\s+(?:an?\s+)?(?:evil|malicious|jailbroken)\b", _FLAGS
        ),
        0.85,
        "Roleplay-as variant",
    ),
    PatternRule(
        "INJ-014",
        "role_manipulation",
        re.compile(r"\bsudo\s+(?:mode|access|enable)\b", _FLAGS),
        0.7,
        "Sudo-style escalation",
    ),
    # --- system_prompt_extraction (5) ---
    PatternRule(
        "INJ-015",
        "system_prompt_extraction",
        re.compile(
            r"\b(?:show|reveal|print|display|output|repeat)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\b",
            _FLAGS,
        ),
        0.9,
        "Reveal-system-prompt",
    ),
    PatternRule(
        "INJ-016",
        "system_prompt_extraction",
        re.compile(
            r"\bwhat\s+(?:are|is|were)\s+your\s+(?:initial\s+|original\s+|system\s+)?(?:instructions?|prompts?|rules?)\b",
            _FLAGS,
        ),
        0.85,
        "What-are-your-instructions",
    ),
    PatternRule(
        "INJ-017",
        "system_prompt_extraction",
        re.compile(
            r"\brepeat\s+(?:back\s+)?(?:the\s+)?(?:above|prior|previous)\s+(?:text|message|prompt|instructions?)\b",
            _FLAGS,
        ),
        0.85,
        "Repeat-above-text",
    ),
    PatternRule(
        "INJ-018",
        "system_prompt_extraction",
        re.compile(
            r"\bprint\s+(?:the\s+)?(?:exact\s+)?(?:contents?\s+of\s+)?(?:your\s+)?(?:context|memory|buffer|prompt)\b",
            _FLAGS,
        ),
        0.8,
        "Print-context",
    ),
    PatternRule(
        "INJ-019",
        "system_prompt_extraction",
        re.compile(r"\bbase64.{0,80}(?:system|prompt|instructions?)\b", _FLAGS),
        0.65,
        "Base64-encoded prompt extraction",
    ),
    # --- encoding_evasion (5) ---
    PatternRule(
        "INJ-020",
        "encoding_evasion",
        re.compile(r"\b(?:decode|interpret)\s+(?:this\s+)?(?:base64|hex|rot13|binary)\b", _FLAGS),
        0.55,
        "Decode-encoded-content",
    ),
    PatternRule(
        "INJ-021",
        "encoding_evasion",
        re.compile(r"[A-Za-z0-9+/]{60,}={0,2}", _FLAGS),
        0.35,
        "Long base64-shaped blob",
    ),
    PatternRule(
        "INJ-022",
        "encoding_evasion",
        re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){8,}", _FLAGS),
        0.5,
        "Hex-escape sequence",
    ),
    PatternRule(
        "INJ-023",
        "encoding_evasion",
        re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}", _FLAGS),
        0.45,
        "Unicode-escape sequence",
    ),
    PatternRule(
        "INJ-024",
        "encoding_evasion",
        re.compile(r"&#(?:x[0-9a-fA-F]+|\d+);(?:&#(?:x[0-9a-fA-F]+|\d+);){5,}", _FLAGS),
        0.45,
        "HTML entity sequence",
    ),
    # --- delimiter_injection (4) ---
    PatternRule(
        "INJ-025",
        "delimiter_injection",
        re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", _FLAGS),
        0.95,
        "OpenAI ChatML delimiter",
    ),
    PatternRule(
        "INJ-026",
        "delimiter_injection",
        re.compile(r"\[INST\][\s\S]{0,500}\[/INST\]", _FLAGS),
        0.85,
        "Llama-2/Mistral delimiter",
    ),
    PatternRule(
        "INJ-027",
        "delimiter_injection",
        re.compile(r"###\s*(?:system|instructions?|task)\s*[:#]", _FLAGS),
        0.65,
        "Markdown header delimiter",
    ),
    PatternRule(
        "INJ-028",
        "delimiter_injection",
        re.compile(r"```\s*(?:system|instructions?|prompt)\s*\n", _FLAGS),
        0.7,
        "Code-fence delimiter",
    ),
    # --- context_manipulation (5) ---
    PatternRule(
        "INJ-029",
        "context_manipulation",
        re.compile(
            r"\b(?:end|terminate|exit)\s+(?:of\s+)?(?:document|context|prompt|task)\b", _FLAGS
        ),
        0.6,
        "End-of-document marker",
    ),
    PatternRule(
        "INJ-030",
        "context_manipulation",
        re.compile(
            r"\b(?:begin|start)\s+(?:of\s+)?(?:new|fresh)\s+(?:document|conversation|session)\b",
            _FLAGS,
        ),
        0.6,
        "Begin-new-session marker",
    ),
    PatternRule(
        "INJ-031",
        "context_manipulation",
        # No leading `\b` — `<` is non-word, so `\b` between start-of-string
        # (also non-word) and `<` does not match. Pattern stays anchored
        # via the `<` literal itself.
        re.compile(r"<\s*/?\s*(?:system|context|prompt)\s*>", _FLAGS),
        0.75,
        "Pseudo-XML context tag",
    ),
    PatternRule(
        "INJ-032",
        "context_manipulation",
        re.compile(r"\b(?:human|user|assistant)\s*:\s*", _FLAGS),
        0.4,
        "Chat-role marker",
    ),
    PatternRule(
        "INJ-033",
        "context_manipulation",
        re.compile(r"---{3,}\s*(?:end|stop|halt)\s*---{3,}", _FLAGS),
        0.55,
        "Horizontal-rule break",
    ),
    # --- output_manipulation (4) ---
    PatternRule(
        "INJ-034",
        "output_manipulation",
        re.compile(r"\boutput\s+(?:must|should|will)\s+(?:start|begin)\s+with\b", _FLAGS),
        0.55,
        "Output-prefix coercion",
    ),
    PatternRule(
        "INJ-035",
        "output_manipulation",
        re.compile(r"\bdo\s+not\s+(?:warn|refuse|filter|censor)\b", _FLAGS),
        0.7,
        "Do-not-warn directive",
    ),
    PatternRule(
        "INJ-036",
        "output_manipulation",
        re.compile(r"\b(?:always|never)\s+(?:respond|reply|answer)\s+with\b", _FLAGS),
        0.55,
        "Always/never-respond directive",
    ),
    PatternRule(
        "INJ-037",
        "output_manipulation",
        re.compile(r"\breturn\s+(?:only\s+)?(?:raw|unfiltered|uncensored)\b", _FLAGS),
        0.7,
        "Return-uncensored",
    ),
    # --- tool_abuse (5) ---
    PatternRule(
        "TOOL-001",
        "tool_abuse",
        # Trailing boundary uses lookahead (whitespace, EOS, or word-boundary)
        # because the prior char is `/`, `*`, or `table` — `\b` after `/` or `*`
        # is non-matching (both are non-word). Lookahead handles all cases.
        re.compile(
            r"\b(?:rm|del|delete|drop|truncate)\s+(?:-rf?|--force)?\s*(?:/|\*|table)(?=\s|$|\b)",
            _FLAGS,
        ),
        0.85,
        "Destructive shell/SQL pattern",
    ),
    PatternRule(
        "TOOL-002",
        "tool_abuse",
        re.compile(r"\bexec(?:ute)?\s*\(\s*['\"`].{0,500}['\"`]\s*\)", _FLAGS),
        0.7,
        "Eval/exec call",
    ),
    PatternRule(
        "TOOL-003",
        "tool_abuse",
        re.compile(r"\bcurl\s+(?:-[A-Za-z]+\s+)*https?://[^\s]+", _FLAGS),
        0.4,
        "Outbound HTTP via curl",
    ),
    PatternRule(
        "TOOL-004",
        "tool_abuse",
        re.compile(r"\b(?:fetch|wget|http\.get|requests?\.get)\s*\(?['\"`]?https?://", _FLAGS),
        0.4,
        "Outbound HTTP via library",
    ),
    PatternRule(
        "TOOL-005",
        "tool_abuse",
        re.compile(r"\b(?:cat|less|more|head|tail)\s+/(?:etc|root|home|var)/", _FLAGS),
        0.7,
        "Read sensitive system file",
    ),
)


@dataclass
class HeuristicConfig:
    threshold: float = 0.15
    """Score above this triggers `block`. Default = high preset."""

    structural_bonus: bool = True
    """Add small score bonus for many newlines, headers, role markers."""

    extra_patterns: list[PatternRule] = field(default_factory=list)


def _structural_bonus(text: str) -> float:
    """Bonus score for content that looks like an embedded prompt."""
    bonus = 0.0
    if text.count("\n") > 15:
        bonus += 0.05
    if len(re.findall(r"^#+\s", text, re.MULTILINE)) > 3:
        bonus += 0.05
    if len(re.findall(r"\b(?:system|user|assistant)\s*:", text, re.IGNORECASE)) > 2:
        bonus += 0.05
    if len(text) > 5000:
        bonus += 0.05
    return min(bonus, 0.20)


class HeuristicScanner:
    """Heuristic prompt-injection detector.

    Compatible with the `Scanner` protocol (`async def scan(text, ctx)`).
    """

    name = "heuristic"

    def __init__(self, config: HeuristicConfig | None = None) -> None:
        self.config = config or HeuristicConfig()
        self._patterns: tuple[PatternRule, ...] = (
            *PATTERNS,
            *self.config.extra_patterns,
        )

    async def scan(self, text: str, _ctx: dict[str, Any] | None = None) -> ScannerResult:
        normalized = normalize(text)
        violations: list[Violation] = []
        score = 0.0

        for rule in self._patterns:
            if rule.regex.search(normalized):
                score += rule.weight
                violations.append(
                    Violation(
                        type="prompt_injection",
                        severity=self._severity(rule.weight),
                        detector=f"heuristic:{rule.id}",
                        message=rule.description,
                        confidence=min(rule.weight, 1.0),
                        metadata={
                            "category": rule.category,
                            "pattern_id": rule.id,
                        },
                    )
                )

        if self.config.structural_bonus:
            score += _structural_bonus(normalized)

        score = min(score, 1.0)

        decision: Literal["allow", "warn", "block"]
        if score >= self.config.threshold:
            decision = "block"
        elif violations:
            decision = "warn"
        else:
            decision = "allow"

        return ScannerResult(
            decision=decision,
            violations=violations,
            score=score,
        )

    @staticmethod
    def _severity(weight: float) -> Literal["low", "medium", "high", "critical"]:
        if weight >= 0.85:
            return "critical"
        if weight >= 0.65:
            return "high"
        if weight >= 0.45:
            return "medium"
        return "low"
