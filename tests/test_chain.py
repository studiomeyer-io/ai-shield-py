"""Scanner chain tests — early-exit, ratchet, sanitization propagation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from ai_shield.scanner.chain import ScannerChain
from ai_shield.types import Decision, ScannerResult, Violation


@dataclass
class FakeScanner:
    """Configurable test scanner — returns a fixed result."""

    name: str
    decision: Decision = "allow"
    score: float = 0.0
    violations_count: int = 0
    sanitize_to: str | None = None
    call_count: int = 0

    async def scan(self, text: str, _ctx: dict[str, Any] | None = None) -> ScannerResult:
        self.call_count += 1
        violations = [
            Violation(
                type="prompt_injection",
                detector=f"{self.name}:V{i}",
                severity="medium",
                message="test",
                confidence=0.5,
            )
            for i in range(self.violations_count)
        ]
        return ScannerResult(
            decision=self.decision,
            violations=violations,
            score=self.score,
            sanitized_text=self.sanitize_to,
        )


class TestEmptyChain:
    @pytest.mark.asyncio
    async def test_no_scanners_allows(self) -> None:
        chain = ScannerChain()
        result = await chain.run("anything")
        assert result.decision == "allow"
        assert result.violations == []
        assert result.score == 0.0


class TestEarlyExit:
    @pytest.mark.asyncio
    async def test_block_short_circuits(self) -> None:
        a = FakeScanner("a", decision="block", score=1.0)
        b = FakeScanner("b", decision="allow")
        chain = ScannerChain(early_exit=True).add(a).add(b)
        await chain.run("x")
        assert a.call_count == 1
        assert b.call_count == 0

    @pytest.mark.asyncio
    async def test_disabled_runs_all(self) -> None:
        a = FakeScanner("a", decision="block", score=1.0)
        b = FakeScanner("b", decision="warn", score=0.5)
        chain = ScannerChain(early_exit=False).add(a).add(b)
        await chain.run("x")
        assert a.call_count == 1
        assert b.call_count == 1

    @pytest.mark.asyncio
    async def test_warn_does_not_short_circuit(self) -> None:
        a = FakeScanner("a", decision="warn", score=0.4)
        b = FakeScanner("b", decision="allow")
        chain = ScannerChain(early_exit=True).add(a).add(b)
        await chain.run("x")
        assert b.call_count == 1


class TestWorstDecisionRatchet:
    @pytest.mark.asyncio
    async def test_allow_then_warn_yields_warn(self) -> None:
        a = FakeScanner("a", decision="allow")
        b = FakeScanner("b", decision="warn")
        chain = ScannerChain().add(a).add(b)
        result = await chain.run("x")
        assert result.decision == "warn"

    @pytest.mark.asyncio
    async def test_allow_then_block_yields_block(self) -> None:
        a = FakeScanner("a", decision="allow")
        b = FakeScanner("b", decision="block", score=0.9)
        chain = ScannerChain().add(a).add(b)
        result = await chain.run("x")
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_warn_does_not_downgrade_block(self) -> None:
        a = FakeScanner("a", decision="block", score=0.9)
        b = FakeScanner("b", decision="warn", score=0.4)
        chain = ScannerChain(early_exit=False).add(a).add(b)
        result = await chain.run("x")
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_score_is_max_across_scanners(self) -> None:
        a = FakeScanner("a", decision="warn", score=0.4)
        b = FakeScanner("b", decision="warn", score=0.7)
        chain = ScannerChain().add(a).add(b)
        result = await chain.run("x")
        assert result.score == 0.7


class TestViolationsAccumulation:
    @pytest.mark.asyncio
    async def test_violations_collected_from_all_scanners(self) -> None:
        a = FakeScanner("a", decision="warn", violations_count=2)
        b = FakeScanner("b", decision="warn", violations_count=3)
        chain = ScannerChain().add(a).add(b)
        result = await chain.run("x")
        assert len(result.violations) == 5
        detectors = {v.detector for v in result.violations}
        assert "a:V0" in detectors
        assert "b:V2" in detectors

    @pytest.mark.asyncio
    async def test_block_short_circuit_keeps_partial_violations(self) -> None:
        a = FakeScanner("a", decision="block", score=1.0, violations_count=2)
        b = FakeScanner("b", decision="warn", violations_count=99)
        chain = ScannerChain(early_exit=True).add(a).add(b)
        result = await chain.run("x")
        # Only the first scanner's violations are present.
        assert len(result.violations) == 2


class TestSanitizationPropagation:
    @pytest.mark.asyncio
    async def test_downstream_sees_sanitized_text(self) -> None:
        a = FakeScanner("a", decision="warn", sanitize_to="REDACTED")

        # Capture what the second scanner sees.
        seen: list[str] = []

        @dataclass
        class CapturingScanner:
            name: str = "capture"

            async def scan(self, text: str, _ctx: dict[str, Any] | None = None) -> ScannerResult:
                seen.append(text)
                return ScannerResult(decision="allow", violations=[], score=0.0)

        chain = ScannerChain().add(a).add(CapturingScanner())
        await chain.run("ORIGINAL")
        assert seen == ["REDACTED"]

    @pytest.mark.asyncio
    async def test_last_sanitization_wins(self) -> None:
        a = FakeScanner("a", decision="warn", sanitize_to="A")
        b = FakeScanner("b", decision="warn", sanitize_to="B")
        chain = ScannerChain().add(a).add(b)
        result = await chain.run("ORIGINAL")
        assert result.sanitized_text == "B"


class TestChainBuilder:
    def test_add_returns_self_for_fluent_use(self) -> None:
        a = FakeScanner("a")
        chain = ScannerChain()
        returned = chain.add(a)
        assert returned is chain

    def test_len_reflects_scanner_count(self) -> None:
        chain = ScannerChain()
        assert len(chain) == 0
        chain.add(FakeScanner("a")).add(FakeScanner("b"))
        assert len(chain) == 2
