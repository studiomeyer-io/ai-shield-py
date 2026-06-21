"""Heuristic prompt-injection scanner.

Port of `packages/core/src/scanner/heuristic.ts` — 50 regex patterns across
8 categories with NFKD + zero-width + combining-mark + homoglyph + Unicode
TAG-block normalization, plus three non-regex signals: invisible TAG-char
smuggling (TAG-001), forged chat-transcript turns (DELIM-PP-5), and a lossy
leetspeak re-test for high-value categories.

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

ZERO_WIDTH_RE = re.compile(r"[​‌‍⁠﻿]")
COMBINING_RE = re.compile(r"[̀-ͯ]")

# Unicode TAG block (U+E0000..U+E007F). Invisible code points with no
# legitimate use in prose. U+E0020..U+E007E are tag-equivalents of ASCII
# 0x20..0x7E, so an attacker can spell "ignore previous instructions" entirely
# in tag chars: it renders as nothing but a model still reads the ASCII intent.
TAG_RANGE_RE = re.compile("[\U000E0000-\U000E007F]")

# Well-formed flag / subdivision-tag sequence: a base WAVING BLACK FLAG
# (U+1F3F4) followed by a run of one or more tag chars (U+E0000..U+E007E)
# terminated by U+E007F (CANCEL TAG). This is exactly how Unicode encodes
# subdivision flags like the Wales/Scotland/Texas flags -- legitimate emoji,
# not smuggling. The run is length-bounded (1..16) so it stays ReDoS-safe.
FLAG_TAG_SEQUENCE_RE = re.compile("\U0001F3F4[\U000E0000-\U000E007E]{1,16}\U000E007F")


def de_tag(text: str) -> str:
    """Decode Unicode TAG-block smuggling back to the ASCII it carries.

    U+E0020..U+E007E carry ASCII characters 0x20..0x7E (subtract 0xE0000).
    U+E0001 (language tag) and U+E007F (cancel tag) are control points with no
    ASCII payload and are dropped. Returns the ASCII the invisible tag run was
    hiding, so the normal injection patterns can scan it.
    """
    # Fast path: most inputs have no tag chars at all.
    if not TAG_RANGE_RE.search(text):
        return text
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            ascii_cp = cp - 0xE0000
            # 0x20..0x7E map to printable ASCII; the rest (E0000/E0001/E007F) drop.
            if 0x20 <= ascii_cp <= 0x7E:
                out.append(chr(ascii_cp))
        else:
            out.append(ch)
    return "".join(out)


def has_tag_chars(text: str) -> bool:
    """True if the input contains any Unicode TAG-block char (invisible smuggling)."""
    return TAG_RANGE_RE.search(text) is not None


def strip_well_formed_tag_sequences(text: str) -> str:
    """Remove every well-formed flag/subdivision-tag sequence from the input.

    Whatever tag chars are LEFT over are standalone or smuggled -- a bare tag
    run spelling ASCII, a tag char without its U+1F3F4 base, or a sequence with
    no CANCEL-TAG terminator. Used so the tag-presence signal only fires on
    those, not on legitimate flag emoji.

    This only suppresses the *presence* signal. The actual smuggled ASCII is
    still surfaced independently by `de_tag` (which decodes the tag-encoded
    characters regardless of any U+1F3F4 wrapper), so an attacker cannot hide an
    instruction by disguising it as a flag sequence.
    """
    if not TAG_RANGE_RE.search(text):
        return text
    return FLAG_TAG_SEQUENCE_RE.sub("", text)


def has_standalone_tag_chars(text: str) -> bool:
    """True if the input has tag chars NOT part of a well-formed flag sequence.

    I.e. standalone or smuggled invisible tag chars (the real attack indicator).
    Legitimate flag emoji return False.
    """
    if not TAG_RANGE_RE.search(text):
        return False
    return TAG_RANGE_RE.search(strip_well_formed_tag_sequences(text)) is not None


# Lossy leetspeak fold: maps the common char-substitutions an attacker uses to
# dodge literal patterns ("1gn0r3 pr3v10us 1nstruct10ns" -> "ignore previous
# instructions"). Run as an ADDITIONAL view, never as a replacement, and only
# the high-value injection categories are re-tested against it -- folding digits
# to letters in ordinary prose ("buy 3 items for 5 dollars" -> "buy e items for
# s dollars") would otherwise generate noise.
#
# 1->i (dominant in injection payloads like "1nstruct10ns"); the other digits
# are unambiguous. @->a and $->s cover the classic symbol substitutions.
LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}
_LEET_RE = re.compile(r"[013457@$]")


def leet_decode(text: str) -> str:
    """Fold common leetspeak char-substitutions back to plain letters."""
    return _LEET_RE.sub(lambda m: LEET_MAP[m.group(0)], text)


def normalize(text: str) -> str:
    """Normalize text for pattern matching.

    Order matters:
      1. Decode Unicode TAG-block smuggling so invisible tag chars surface as
         the ASCII they carry ("ignore previous instructions" hidden in U+E00xx).
      2. NFKD folds compatibility forms (fullwidth, ligatures, math-bold) AND
         decomposes precomposed accented letters into base + combining mark.
      3. Strip zero-width chars so "ig<ZWSP>nore" collapses to "ignore".
      4. Strip combining marks (diacritics) left behind by NFKD.
      5. Map remaining Cyrillic/Greek look-alikes to Latin.

    Side effect of step 2+4: accented Latin letters lose their diacritic and
    fold to the base letter ("precedentes"; German umlauts decompose so
    "ueberschreibe" reads as written). The localized injection patterns below
    are written against this folded form.
    """
    out = de_tag(text)
    out = unicodedata.normalize("NFKD", out)
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

# 50 patterns: the 42-rule base catalogue plus DE/ES/FR localized overrides
# (INJ-DE/ES/FR) and policy-puppetry fake-config delimiters (DELIM-PP-1..4),
# ported from ai-shield-core/heuristic.ts.
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
    # --- Localized instruction override (DE / ES / FR) -------------------
    # The English INJ-* rules above miss German/Spanish/French "ignore previous
    # instructions" entirely, so a non-English payload scored `allow`. Patterns
    # run against the NFKD-folded text (accents/umlauts already stripped:
    # "praezedenzfall" -> "prazedenzfall", "precedentes" stays "precedentes"),
    # so they spell the base-letter forms. The bounded `[\s\S]{0,40}?` gap is
    # lazy + length-capped -> ReDoS-safe. An override verb is REQUIRED before the
    # object noun, so benign prose that merely mentions "Anweisungen" /
    # "instrucciones" / "instructions" does not trip them. Kept in the existing
    # `instruction_override` category so the 8-category invariant holds.
    PatternRule(
        "INJ-DE-1",
        "instruction_override",
        # Negative lookahead after the verb excludes a negator in the gap:
        # "Vergiss NICHT, die vorherigen Anweisungen zu lesen" is benign and
        # must not block, while "Vergiss alle vorherigen Anweisungen" (no
        # negator) still fires. Bounded + lazy -> ReDoS-safe.
        re.compile(
            r"\b(?:ignoriere?|missachte|vergiss|verwirf|uebergehe|ueberschreibe)\b"
            r"(?![\s\S]{0,40}?\b(?:nicht|keine?)\b)"
            r"[\s\S]{0,40}?"
            r"\b(?:alle[ns]?|deine|die|jegliche)?\s*"
            r"(?:vorherigen?|bisherigen?|obigen?|frueheren?|vorhergehenden?|urspruenglichen?)\s+"
            r"(?:anweisungen?|anordnungen?|befehle?|regeln?|vorgaben?|instruktionen?)",
            _FLAGS,
        ),
        0.85,
        "German instruction override",
    ),
    PatternRule(
        "INJ-DE-2",
        "instruction_override",
        re.compile(
            r"\bdu\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine|der|die|das|mein|meine)\b",
            _FLAGS,
        ),
        0.7,
        "German role takeover (du bist jetzt ...)",
    ),
    PatternRule(
        "INJ-ES-1",
        "instruction_override",
        re.compile(
            r"\b(?:ignora|olvida|descarta|desestima|omite|anula)\b"
            r"[\s\S]{0,40}?"
            r"\b(?:todas?\s+)?(?:las?\s+)?"
            r"(?:instrucciones?|ordenes?|reglas?|directrices?|indicaciones?)\s+"
            r"(?:anteriores?|previas?|precedentes?|de\s+arriba)",
            _FLAGS,
        ),
        0.85,
        "Spanish instruction override",
    ),
    PatternRule(
        "INJ-FR-1",
        "instruction_override",
        # "ignore" + "instructions" are identical in English and French, so the
        # shared verb path requires a French determiner (les/tes/mes) to avoid
        # double-firing on English "ignore previous instructions" (INJ-001
        # already covers that). French-only verbs match the object noun directly.
        re.compile(
            r"\b(?:ignore\s+(?:toutes?\s+)?(?:les|tes|mes)\s+"
            r"(?:instructions?|consignes?|directives?|regles?|ordres?)"
            r"|(?:oublie|neglige|fais\s+abstraction\s+de|ne\s+tiens?\s+pas\s+compte\s+des?)\s+"
            r"(?:toutes?\s+)?(?:les?\s+|tes\s+|mes\s+)?"
            r"(?:instructions?|consignes?|directives?|regles?|ordres?))",
            _FLAGS,
        ),
        0.85,
        "French instruction override",
    ),
    # --- Policy-puppetry / fake-config delimiters -----------------------
    # HiddenLayer 2025 "Policy Puppetry" universal bypass: the attacker pastes a
    # fake config block (interaction-config / allowed-modes / blocked-strings)
    # so the model treats user content as authoritative configuration. These
    # previously scored `allow` -- only INJ-031's bare <system> tag was covered.
    # Tags are specific enough (hyphenated config names, privileged <role>) that
    # ordinary HTML/JSX prose does not trip them. Kept in `delimiter_injection`.
    PatternRule(
        "DELIM-PP-1",
        "delimiter_injection",
        re.compile(
            r"<\s*/?\s*(?:interaction-config|interaction_config|system-config|model-config|ai-config)\b",
            _FLAGS,
        ),
        0.9,
        "Fake interaction-config block",
    ),
    PatternRule(
        "DELIM-PP-2",
        "delimiter_injection",
        re.compile(
            r"<\s*/?\s*(?:allowed-modes|allowed_modes|blocked-modes|allowed-responses)\b",
            _FLAGS,
        ),
        0.85,
        "Fake allowed-modes directive",
    ),
    PatternRule(
        "DELIM-PP-3",
        "delimiter_injection",
        re.compile(
            r"<\s*/?\s*(?:blocked-strings|blocked_strings|blocked-words|forbidden-strings|blocked-responses)\b",
            _FLAGS,
        ),
        0.85,
        "Fake blocked-strings directive",
    ),
    PatternRule(
        "DELIM-PP-4",
        "delimiter_injection",
        re.compile(
            r"<\s*role\s*>\s*(?:god|dan|admin|root|developer|jailbroken|unrestricted|sudo)\b",
            _FLAGS,
        ),
        0.85,
        "Fake privileged <role> assignment",
    ),
    # DELIM-PP-5 (forged chat transcript turn) is NOT a plain regex rule -- a
    # single benign <assistant>...</assistant> / <human>...</human> pair (a
    # quoted snippet, a doc example) is common and must not block on its own.
    # It is evaluated by `detect_forged_transcript()` in scan(), which fires
    # only with an ATTACK CO-SIGNAL (override keyword inside a turn, OR >=2
    # forged turns). A sibling policy-config tag is already covered by
    # DELIM-PP-1/2/3. See the dedicated signal block in scan().
)


# -- Forged chat-transcript detection (DELIM-PP-5) ------------------------

# A full open+close <assistant>/<user>/<human> tag PAIR. The bounded lazy gap
# `{0,200}?` keeps it ReDoS-safe; the backreference requires the close tag to
# match the open tag, so "<user>...</assistant>" alone isn't a pair.
_FORGED_TURN_PAIR_RE = re.compile(
    r"<(assistant|user|human)\b[^>]*>([\s\S]{0,200}?)</\1>",
    re.IGNORECASE,
)
_CLOSING_TURN_RE = re.compile(r"</(?:assistant|user|human)>", re.IGNORECASE)

# Override / privileged / compliance phrasing that turns a benign-looking
# transcript snippet into a policy-puppetry payload. Specific enough that an
# ordinary quoted reply ("<assistant>Hello, how can I help?</assistant>")
# doesn't match.
_OVERRIDE_IN_TURN_RE = re.compile(
    r"\b(?:ignore|disregard|bypass|override|jailbroken|jailbreak|unrestricted"
    r"|no\s+(?:restrictions?|filters?|limits?|rules?)"
    r"|without\s+(?:restrictions?|refus\w+|filter\w+)"
    r"|comply\s+fully|will\s+comply"
    r"|i\s+will\s+(?:now\s+)?(?:ignore|comply|obey|bypass)"
    r"|developer\s+mode|dev\s+mode\s+(?:active|enabled|on)"
    r"|debug\s+mode|god\s+mode|sudo\s+mode|admin\s+mode"
    r"|safety\s+(?:rules?|guidelines?|filters?)"
    r"|dan\b|do\s+anything\s+now|obey\s+(?:all|every)"
    r"|reveal\s+(?:your|the)\s+(?:system\s+)?prompt)",
    re.IGNORECASE,
)


def detect_forged_transcript(text: str) -> bool:
    """Detect a FORGED chat transcript (policy-puppetry, HiddenLayer 2025).

    Returns True only when a real attack co-signal is present, so a lone benign
    turn pair (a quoted transcript snippet, a doc example) does NOT trip it:
      (a) an override/privileged keyword inside any turn's content, OR
      (b) >=2 distinct forged turns (a fabricated multi-turn exchange).
    A sibling policy-config tag is intentionally NOT required here -- it already
    blocks via DELIM-PP-1/2/3. Iteration is capped (64) for defense-in-depth.
    """
    # Fast path: no closing turn tag -> no pair possible.
    if not _CLOSING_TURN_RE.search(text):
        return False
    turn_bodies: list[str] = []
    for guard, m in enumerate(_FORGED_TURN_PAIR_RE.finditer(text)):
        if guard >= 64:
            break
        turn_bodies.append(m.group(2) or "")
    if not turn_bodies:
        return False
    # (a) override keyword inside a turn -> single forged turn is enough.
    if any(_OVERRIDE_IN_TURN_RE.search(body) for body in turn_bodies):
        return True
    # (b) two or more forged turns -> fabricated exchange.
    return len(turn_bodies) >= 2


# Categories where a lossy leetspeak re-test is worth the FP risk. Excludes
# encoding_evasion (INJ-021 long-base64 -- folding its digits is noise) and the
# low-confidence context/output/delimiter categories. Python folds the localized
# DE/ES/FR rules into `instruction_override`, so they are covered here too.
_LEET_SENSITIVE: frozenset[str] = frozenset(
    {
        "instruction_override",
        "role_manipulation",
        "system_prompt_extraction",
        "tool_abuse",
    }
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
        # Second view that folds leetspeak ("1gn0r3 pr3v10us" -> "ignore
        # previous"). ADDITIONAL pass, only computed when it differs, and only
        # the high-value categories are re-tested -- digit->letter folding in
        # benign prose ("buy 3 items for 5 dollars") would otherwise add noise.
        leet_view = leet_decode(normalized)
        leet_differs = leet_view != normalized
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
            elif (
                leet_differs
                and rule.category in _LEET_SENSITIVE
                and rule.regex.search(leet_view)
            ):
                # Matched only after leetspeak folding -> char-substitution evasion.
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
                            "evasion": "leetspeak",
                        },
                    )
                )

        # Unicode TAG-block smuggling signal. `normalize` already de-tagged the
        # payload so any hidden ASCII instruction was scored by the rules above
        # -- but the mere PRESENCE of invisible tag chars in user text is itself
        # an attack indicator (no benign prose uses U+E00xx). Well-formed
        # flag/subdivision emoji (base U+1F3F4 ... U+E007F) are excluded; only
        # standalone/smuggled tag chars count. A smuggled instruction disguised
        # as a flag is still caught above, because de_tag decodes its ASCII
        # regardless of the wrapper. Run on the ORIGINAL input (normalize strips
        # the tag chars).
        if has_standalone_tag_chars(text):
            score += 0.9
            violations.append(
                Violation(
                    type="prompt_injection",
                    severity="critical",
                    detector="heuristic:TAG-001",
                    message="Invisible Unicode TAG characters detected (smuggling)",
                    metadata={
                        "category": "encoding_evasion",
                        "pattern_id": "TAG-001",
                    },
                    confidence=0.9,
                )
            )

        # Forged chat-transcript signal (DELIM-PP-5). Fires only with an attack
        # co-signal (override keyword inside a turn, or >=2 forged turns) so a
        # lone benign transcript pair stays allowed. Run on the normalized view
        # so homoglyph/zero-width evasion in the turn content can't dodge the
        # override-keyword check.
        if detect_forged_transcript(normalized):
            score += 0.85
            violations.append(
                Violation(
                    type="prompt_injection",
                    severity="critical",
                    detector="heuristic:DELIM-PP-5",
                    message="Forged chat transcript turn",
                    metadata={
                        "category": "delimiter_injection",
                        "pattern_id": "DELIM-PP-5",
                    },
                    confidence=0.85,
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
