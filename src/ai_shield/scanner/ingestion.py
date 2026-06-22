"""Indirect prompt-injection (IPI) scanner.

Port of `packages/core/src/scanner/ingestion.ts` from ai-shield-core.

Scans non-user content -- RAG chunks, MCP tool descriptions and tool *results*,
stored memory, scraped web pages, agent-to-agent messages -- for
instruction-shaped payloads BEFORE they enter the model context. Per OWASP
LLM01:2025, indirect injection is the dominant attack class (>55% of incidents
arrive through trusted-looking data channels, not the user prompt).

The scanner runs the base heuristic patterns at a stricter threshold AND adds
source-specific patterns the user channel does not see.
"""

from __future__ import annotations

import re

from ai_shield.scanner.heuristic import HeuristicConfig, HeuristicScanner, normalize
from ai_shield.types import Decision, IngestionSource, ScannerResult, Violation

# Per-source (threshold, extra_patterns). Tighter than the user channel: data
# sources almost never legitimately contain instruction syntax, so the presence
# of one is itself a signal.
_SOURCE_PROFILE: dict[IngestionSource, tuple[float, tuple[re.Pattern[str], ...]]] = {
    "user": (0.3, ()),
    "rag": (
        0.15,
        (
            re.compile(
                r"(?:AI\s+(?:assistant|model)\s+(?:note|instruction|directive)"
                r"|attention\s+(?:AI|model|assistant))[:\s]+",
                re.IGNORECASE,
            ),
            re.compile(
                r"this\s+document\s+(?:is|contains|provides)\s+(?:your|the)\s+"
                r"(?:new\s+)?(?:instructions?|system\s+prompt|directives?)",
                re.IGNORECASE,
            ),
        ),
    ),
    "tool_desc": (
        0.12,
        (
            re.compile(
                r"(?:before|after|while)\s+(?:using|invoking|calling|executing)\s+"
                r"(?:this\s+)?(?:tool|function|action)[,\s]+(?:you\s+)?"
                r"(?:must|should|will|need\s+to|are\s+required\s+to)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:also|always|first|then|finally)\s+(?:call|invoke|use|execute|run)\s+"
                r"(?:the\s+)?[a-z][\w-]*(?:_[\w-]+|\s*\()",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:note|hidden\s+(?:instruction|directive|note))\s+to\s+"
                r"(?:LLM|model|assistant|AI|agent)[:\s]",
                re.IGNORECASE,
            ),
        ),
    ),
    "tool_output": (
        0.13,
        (
            re.compile(
                r"(?:tool|function|api|search|query)\s+(?:result|response|output)[:\s]+"
                r"(?:ignore|disregard|override|new\s+instructions?|system\s+prompt)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:result|response|data|output)\s+(?:indicates?|says?|requires?|means?)\s+"
                r"(?:that\s+)?you\s+(?:should|must|need\s+to|will)\s+(?:now\s+)?"
                r"(?:call|invoke|run|execute|use)\s+[a-z_][\w-]{2,}",
                re.IGNORECASE,
            ),
            re.compile(
                r'"(?:role|system|instruction|directive)"\s*:\s*"(?:system|ignore|override|admin)',
                re.IGNORECASE,
            ),
        ),
    ),
    "memory": (
        0.18,
        (
            re.compile(
                r"(?:remember|important|critical)\s+(?:note|instruction|directive)\s+"
                r"(?:for\s+(?:next|future|all)\s+(?:sessions?|conversations?|calls?))[:\s]",
                re.IGNORECASE,
            ),
            re.compile(
                r"override\s+(?:default|standard|normal)\s+(?:behavior|response|policy)",
                re.IGNORECASE,
            ),
        ),
    ),
    "web": (
        0.15,
        (
            re.compile(
                r"\[(?:ignore|disregard|override|system\s+(?:prompt|message))[^\]]{0,200}\]"
                r"\([^)]{0,500}\)",
                re.IGNORECASE,
            ),
        ),
    ),
    "agent_output": (
        0.18,
        (
            re.compile(
                r"(?:tell|instruct|forward\s+to)\s+(?:the\s+)?"
                r"(?:next|downstream|receiving|other)\s+(?:agent|model|assistant)\s+to",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:relay|pass|propagate)\s+(?:these|the\s+following)\s+"
                r"(?:instructions?|directives?|orders?)",
                re.IGNORECASE,
            ),
        ),
    ),
}


async def scan_ingested(
    content: str,
    source: IngestionSource,
    *,
    strictness: str = "high",
) -> ScannerResult:
    """Scan one piece of ingested content against its source-specific profile.

    Use at the ingestion boundary -- before storing a chunk in a vector DB, or
    before passing a tool description / tool result into the model context.
    ``result.decision == "allow"`` means safe. On ``block`` the
    ``sanitized_text`` is set to ``""`` so a naive
    ``if not safe: use(result.sanitized_text)`` path is a no-op rather than a
    vulnerability -- use the original ``content`` for quarantine/logging.
    """
    threshold, extra = _SOURCE_PROFILE.get(source, _SOURCE_PROFILE["user"])
    violations: list[Violation] = []

    # 1. Base heuristic at high strictness; re-tag its violations as ingested.
    heuristic = HeuristicScanner(HeuristicConfig(threshold=0.15 if strictness == "high" else 0.3))
    base = await heuristic.scan(content)
    for v in base.violations:
        violations.append(
            v.model_copy(
                update={
                    "type": "ingested_injection",
                    "detector": "ingestion",
                    "metadata": {**v.metadata, "source": source},
                }
            )
        )

    # 2. Source-specific patterns against the normalized form (same Unicode-
    #    evasion defense the user channel gets).
    normalized = normalize(content)
    source_score = 0.0
    for pattern in extra:
        if pattern.search(normalized):
            source_score += 0.4
            violations.append(
                Violation(
                    type="ingested_injection",
                    severity="high",
                    detector="ingestion",
                    message=f"Indirect injection pattern in {source} content",
                    confidence=0.8,
                    metadata={"source": source, "pattern": pattern.pattern[:80]},
                )
            )
    source_score = min(source_score, 1.0)

    base_blocks = base.decision == "block"
    base_warns = base.decision == "warn"
    source_blocks = source_score >= threshold
    source_warns = source_score >= threshold * 0.6

    decision: Decision
    if base_blocks or source_blocks:
        decision = "block"
    elif base_warns or source_warns:
        decision = "warn"
    else:
        decision = "allow"

    return ScannerResult(
        decision=decision,
        violations=violations,
        sanitized_text="" if decision == "block" else content,
        score=max(base.score, source_score),
    )


async def scan_tool_output(
    tool_name: str,
    content: str,
    *,
    strictness: str = "high",
) -> ScannerResult:
    """Scan the runtime *result* a tool returned before it re-enters the model
    context -- the dominant indirect-injection channel in agentic loops
    (PoisonedRAG: 5 planted docs reach a 90% attack-success rate). Thin wrapper
    over ``scan_ingested(content, "tool_output")`` that stamps the originating
    ``tool_name`` into every violation's metadata for audit.
    """
    safe_name = tool_name[:120] if isinstance(tool_name, str) and tool_name else "unknown"
    result = await scan_ingested(content, "tool_output", strictness=strictness)
    tagged = [
        v.model_copy(update={"metadata": {**v.metadata, "tool": safe_name}})
        for v in result.violations
    ]
    return result.model_copy(update={"violations": tagged})
