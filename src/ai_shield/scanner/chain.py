"""Async sequential scanner chain with early-exit-on-block.

1:1 port of `packages/core/src/scanner/chain.ts`.
"""

from __future__ import annotations

from typing import Any, Protocol

from ai_shield.types import Decision, ScannerResult, ScanResult, Violation

_DECISION_PRIORITY: dict[Decision, int] = {"allow": 0, "warn": 1, "block": 2}


class Scanner(Protocol):
    """Minimal scanner protocol — anything with `name` + async `scan`."""

    name: str

    async def scan(self, text: str, ctx: dict[str, Any] | None = None) -> ScannerResult: ...


class ScannerChain:
    """Run scanners sequentially. Early-exit when a scanner returns `block`."""

    def __init__(self, *, early_exit: bool = True) -> None:
        self._scanners: list[Scanner] = []
        self.early_exit = early_exit

    def add(self, scanner: Scanner) -> ScannerChain:
        self._scanners.append(scanner)
        return self

    async def run(self, text: str, ctx: dict[str, Any] | None = None) -> ScanResult:
        all_violations: list[Violation] = []
        worst_decision: Decision = "allow"
        max_score = 0.0
        sanitized_text: str | None = None

        current_text = text

        for scanner in self._scanners:
            result = await scanner.scan(current_text, ctx)
            all_violations.extend(result.violations)
            max_score = max(max_score, result.score)

            if _DECISION_PRIORITY[result.decision] > _DECISION_PRIORITY[worst_decision]:
                worst_decision = result.decision

            if result.sanitized_text is not None:
                sanitized_text = result.sanitized_text
                current_text = result.sanitized_text

            if self.early_exit and result.decision == "block":
                break

        return ScanResult(
            decision=worst_decision,
            violations=all_violations,
            sanitized_text=sanitized_text,
            score=min(max_score, 1.0),
        )

    def __len__(self) -> int:
        return len(self._scanners)
