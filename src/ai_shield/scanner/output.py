"""Output scanner -- OWASP LLM05 Improper Output Handling + LLM02.

Port of `packages/core/src/scanner/output.ts` from ai-shield-core.

The input scanners answer "is this prompt safe to send to the model?". This
answers the other half: "is this model OUTPUT safe to act on / show / forward?".
LLM output must never reach a SQL engine, a shell, an HTML sink, or a template
renderer unfiltered. Five checks: secret leak, output injection, system-prompt
leak (canary + heuristic), jailbreak indicator, output-side PII.
"""

from __future__ import annotations

import re

from ai_shield.scanner.heuristic import normalize
from ai_shield.scanner.pii import PIIConfig, PIIScanner
from ai_shield.types import OutputSink, ScannerResult, Violation

_MAX_OUTPUT_CHARS = 256 * 1024
_SECRET_REDACTION = "[REDACTED_SECRET]"

# High-confidence secret formats, anchored on a provider prefix so prose
# false-positives are near-zero. Linear (no nested quantifiers).
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("SEC-OPENAI", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "OpenAI API key"),
    ("SEC-ANTHROPIC", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "Anthropic API key"),
    ("SEC-AWS-AKID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("SEC-GITHUB", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    ("SEC-GOOGLE", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    ("SEC-GOOGLE-OAUTH", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"), "Google OAuth client secret"),
    ("SEC-GCP-SA", re.compile(r'"type"\s*:\s*"service_account"'), "GCP service-account JSON"),
    ("SEC-HUGGINGFACE", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "HuggingFace token"),
    ("SEC-NPM", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "npm publish token"),
    ("SEC-SLACK", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("SEC-STRIPE", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b"), "Stripe live key"),
    (
        "SEC-JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "JWT",
    ),
    (
        "SEC-PEM",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "PEM private key",
    ),
    (
        "SEC-DSN",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/"
            r"[^\s:/@]{1,64}:[^\s@]{3,80}@"
        ),
        "connection string with credentials",
    ),
)

# Output-injection payloads, grouped by downstream sink.
_INJECTION_PATTERNS: tuple[tuple[str, OutputSink, re.Pattern[str], str], ...] = (
    (
        "OUTI-SQL-1",
        "sql",
        re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
        "SQL UNION SELECT",
    ),
    (
        "OUTI-SQL-2",
        "sql",
        re.compile(
            r"""['"]\s*;\s*(?:drop|delete|update|insert|truncate|alter)\s+""", re.IGNORECASE
        ),
        "SQL statement break",
    ),
    (
        "OUTI-SQL-3",
        "sql",
        re.compile(r"\bor\s+1\s*=\s*1\b|\bor\s+'1'\s*=\s*'1'", re.IGNORECASE),
        "SQL tautology",
    ),
    (
        "OUTI-SH-1",
        "shell",
        re.compile(r"\$\([^)]{1,200}\)|`[^`]{1,200}`"),
        "shell command substitution",
    ),
    (
        "OUTI-SH-2",
        "shell",
        re.compile(r"[;&|]\s*(?:rm|curl|wget|nc|bash|sh|chmod|mkfifo|dd)\s+-?", re.IGNORECASE),
        "chained shell command",
    ),
    (
        "OUTI-SH-3",
        "shell",
        re.compile(r"\|\s*(?:sh|bash|zsh|python[0-9.]*)\b", re.IGNORECASE),
        "pipe to interpreter",
    ),
    ("OUTI-XSS-1", "html", re.compile(r"<script[\s>]", re.IGNORECASE), "<script> tag"),
    (
        "OUTI-XSS-2",
        "html",
        re.compile(
            r"""\bon(?:error|load|click|mouseover)\s*=\s*["']?[^"'>]{1,200}""", re.IGNORECASE
        ),
        "inline event handler",
    ),
    (
        "OUTI-XSS-3",
        "html",
        re.compile(r"\bjavascript:\s*[^\s\"']{1,200}", re.IGNORECASE),
        "javascript: URI",
    ),
    (
        "OUTI-XSS-4",
        "html",
        re.compile(
            r"""<iframe[\s>]|<img[^>]{0,200}\bsrc\s*=\s*["']?\s*(?:javascript|data):""",
            re.IGNORECASE,
        ),
        "iframe / data-URI image",
    ),
    (
        "OUTI-MDEXF",
        "html",
        re.compile(
            r"!\[[^\]]{0,200}\]\(\s*https?:\/\/[^)\s]{1,300}[?&][\w-]{1,40}=", re.IGNORECASE
        ),
        "markdown-image data exfiltration",
    ),
    (
        "OUTI-SSTI-1",
        "template",
        re.compile(
            r"\{\{[^}]{0,200}(?:constructor|process|require|global|__proto__|self\.|cycler)[^}]{0,200}\}\}",
            re.IGNORECASE,
        ),
        "template-injection payload",
    ),
    (
        "OUTI-SSTI-2",
        "template",
        re.compile(r"<%[^%]{0,200}(?:system|exec|require|eval)[^%]{0,200}%>", re.IGNORECASE),
        "ERB/EJS injection",
    ),
)

_SYSTEM_LEAK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|say|states?|read)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"i\s+(?:was|am|have\s+been)\s+(?:instructed|told|configured|programmed|designed)\s+to\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"here\s+(?:is|are)\s+my\s+(?:system\s+)?(?:prompt|instructions?|guidelines?|rules?)\b",
        re.IGNORECASE,
    ),
)

_JAILBREAK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bas\s+(?:DAN|an?\s+(?:unrestricted|unfiltered|jailbroken|uncensored))\b", re.IGNORECASE
    ),
    re.compile(
        r"i(?:'?ll|\s+will)\s+(?:now\s+)?(?:ignore|bypass|disregard|set\s+aside)\s+"
        r"(?:my|the|all)\s+(?:guidelines?|restrictions?|rules?|safety|programming|filters?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:jailbreak|developer\s+mode|dan\s+mode)\s+(?:enabled|activated|successful|engaged)",
        re.IGNORECASE,
    ),
)

_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿]")


def _strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text)


async def scan_output(
    text: str,
    *,
    sinks: list[OutputSink] | None = None,
    canary_tokens: list[str] | str | None = None,
    pii: bool = True,
    pii_action: str = "redact",
) -> ScannerResult:
    """Scan a model RESPONSE before acting on it. Secrets and canaries are
    scanned over the FULL (normalized) output; structural injection / leak
    heuristics over a length-capped copy. ``sanitized_text`` carries the output
    with secrets redacted and PII masked; gate on ``decision`` before forwarding
    a blocked output to any downstream sink.
    """
    safe_text = text if isinstance(text, str) else ""
    capped = safe_text[:_MAX_OUTPUT_CHARS]
    capped_detect = normalize(capped)
    full_detect = normalize(safe_text)

    violations: list[Violation] = []
    sanitized = safe_text
    rank = {"allow": 0, "warn": 1, "block": 2}
    worst = "allow"

    def bump(decision: str) -> None:
        nonlocal worst
        if rank[decision] > rank[worst]:
            worst = decision

    # 1. Secret leak -- full output, normalized; scrub-on-block guarantee.
    matched_secret_res: list[re.Pattern[str]] = []
    for rule_id, pattern, label in _SECRET_PATTERNS:
        if pattern.search(full_detect):
            violations.append(
                Violation(
                    type="secret_leak",
                    severity="critical",
                    detector="output",
                    message=f"Output leaks a secret: {label}",
                    confidence=1.0,
                    metadata={"rule": rule_id},
                )
            )
            bump("block")
            matched_secret_res.append(pattern)
            sanitized = pattern.sub(_SECRET_REDACTION, sanitized)
    # Detection ran on the normalized text; a key split by zero-width chars
    # would survive the raw .sub() above. If any matched pattern still hits the
    # normalized sanitized output, strip the invisible chars and redact again so
    # the live secret never survives in any evasion form. (any() over an empty
    # list is False, so this is a no-op when nothing matched.)
    if any(p.search(normalize(sanitized)) for p in matched_secret_res):
        sanitized = _strip_zero_width(sanitized)
        for p in matched_secret_res:
            sanitized = p.sub(_SECRET_REDACTION, sanitized)

    # 2. Output injection.
    for rule_id, sink, pattern, label in _INJECTION_PATTERNS:
        if sinks is not None and sink not in sinks:
            continue
        if pattern.search(capped_detect):
            violations.append(
                Violation(
                    type="output_injection",
                    severity="high",
                    detector="output",
                    message=f"Output carries a {sink} injection payload: {label}",
                    confidence=0.85,
                    metadata={"rule": rule_id, "sink": sink},
                )
            )
            bump("block")

    # 3. System-prompt leak -- canary first (exact, full), then heuristics.
    tokens = (
        [canary_tokens]
        if isinstance(canary_tokens, str)
        else [t for t in (canary_tokens or []) if isinstance(t, str) and t]
    )
    canary_hit = False
    for token in tokens:
        if len(token) >= 4 and token in safe_text:
            canary_hit = True
            violations.append(
                Violation(
                    type="system_prompt_leak",
                    severity="critical",
                    detector="output",
                    message="Output leaks a system-prompt canary token",
                    confidence=1.0,
                    metadata={"match": "canary"},
                )
            )
            bump("block")
    if not canary_hit and not tokens:
        for pattern in _SYSTEM_LEAK_PATTERNS:
            if pattern.search(capped_detect):
                violations.append(
                    Violation(
                        type="system_prompt_leak",
                        severity="medium",
                        detector="output",
                        message="Output may be echoing the system prompt",
                        confidence=0.4,
                        metadata={"match": "heuristic"},
                    )
                )
                bump("warn")
                break

    # 4. Jailbreak indicators -- heuristic, warn only.
    for pattern in _JAILBREAK_PATTERNS:
        if pattern.search(capped_detect):
            violations.append(
                Violation(
                    type="jailbreak_indicator",
                    severity="medium",
                    detector="output",
                    message="Output shows a possible jailbreak success indicator",
                    confidence=0.3,
                    metadata={"match": "heuristic"},
                )
            )
            bump("warn")
            break

    # 5. PII -- reuse the input-side scanner over the (already secret-redacted) text.
    if pii:
        pii_result = await PIIScanner(PIIConfig(action=pii_action)).scan(sanitized)  # type: ignore[arg-type]
        for v in pii_result.violations:
            violations.append(v.model_copy(update={"detector": "output"}))
        if pii_result.sanitized_text is not None:
            sanitized = pii_result.sanitized_text
        bump(pii_result.decision)

    return ScannerResult(
        decision=worst,  # type: ignore[arg-type]
        violations=violations,
        sanitized_text=sanitized,
        score=1.0 if worst == "block" else (0.5 if worst == "warn" else 0.0),
    )
