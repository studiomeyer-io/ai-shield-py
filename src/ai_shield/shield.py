"""AIShield main class — wires policy + scanners + cost + audit + cache.

1:1 port of `packages/core/src/shield.ts`.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

from ai_shield.audit.logger import AuditLogger
from ai_shield.cache.lru import ScanLRUCache
from ai_shield.cost.tracker import CostTracker
from ai_shield.policy.engine import PolicyEngine, PolicyPreset
from ai_shield.scanner.chain import Scanner, ScannerChain
from ai_shield.scanner.heuristic import HeuristicConfig, HeuristicScanner
from ai_shield.scanner.pii import PIIConfig, PIIScanner
from ai_shield.types import (
    BudgetCheckResult,
    BudgetConfig,
    CostRecord,
    ScanResult,
)

_DEFAULT_MAX_INPUT_BYTES = int(os.environ.get("AI_SHIELD_MAX_INPUT_BYTES", str(256 * 1024)))


@dataclass
class AIShieldConfig:
    """Optional configuration for AIShield."""

    policy_preset: PolicyPreset = "public_website"
    policy_overrides: dict[str, object] = field(default_factory=dict)
    extra_scanners: list[Scanner] = field(default_factory=list)
    cost_budget: BudgetConfig | None = None
    enable_cache: bool = True
    cache_max_size: int = 1000
    cache_ttl_ms: int = 300_000
    enable_audit: bool = True
    max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES


class AIShield:
    """Main entry point — call `await shield.scan(text, ...)`."""

    def __init__(
        self,
        *,
        policy_preset: PolicyPreset = "public_website",
        policy_overrides: dict[str, object] | None = None,
        extra_scanners: list[Scanner] | None = None,
        cost_budget: BudgetConfig | None = None,
        enable_cache: bool = True,
        cache_max_size: int = 1000,
        cache_ttl_ms: int = 300_000,
        enable_audit: bool = True,
        max_input_bytes: int = _DEFAULT_MAX_INPUT_BYTES,
        audit_logger: AuditLogger | None = None,
        cost_tracker: CostTracker | None = None,
    ) -> None:
        self.policy = PolicyEngine(
            preset=policy_preset,
            overrides=policy_overrides or {},
        )
        self.max_input_bytes = max_input_bytes

        # Scanner chain: heuristic + PII (with policy-derived configs).
        self.chain = ScannerChain()
        self.chain.add(
            HeuristicScanner(HeuristicConfig(threshold=self.policy.get_injection_threshold()))
        )
        self.chain.add(PIIScanner(PIIConfig(action=self.policy.get_pii_action())))
        for s in extra_scanners or []:
            self.chain.add(s)

        # Budget defaults from policy when not provided.
        budget = cost_budget or BudgetConfig(
            hard_limit_usd=self.policy.get_daily_budget(),
            period="daily",
        )
        self.cost = cost_tracker or CostTracker(budget=budget)

        self.cache: ScanLRUCache[ScanResult] | None = (
            ScanLRUCache(max_size=cache_max_size, ttl_ms=cache_ttl_ms) if enable_cache else None
        )

        self.audit: AuditLogger | None = (
            audit_logger if audit_logger is not None else AuditLogger() if enable_audit else None
        )

    async def scan(
        self,
        text: str,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Run the scanner chain on `text` and return a ScanResult."""
        if not isinstance(text, str):  # pragma: no cover — defensive
            raise TypeError("text must be a str")

        size = len(text.encode("utf-8"))
        if size > self.max_input_bytes:
            raise ValueError(f"Input exceeds max_input_bytes ({size} > {self.max_input_bytes})")

        cache_key: str | None = None
        if self.cache is not None:
            cache_key = self._cache_key(text)
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached.model_copy(update={"cache_hit": True})

        ctx: dict[str, Any] = {"user_id": user_id, "agent_id": agent_id}
        if metadata:
            ctx["metadata"] = metadata

        result = await self.chain.run(text, ctx)

        if self.cache is not None and cache_key is not None:
            self.cache.set(cache_key, result)

        if self.audit is not None:
            await self.audit.log(
                text=text,
                decision=result.decision,
                violations=result.violations,
                score=result.score,
                user_id=user_id,
                metadata=metadata or {},
            )

        return result

    def scan_sync(
        self,
        text: str,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Synchronous wrapper. Raises RuntimeError if a loop is already running.

        For Jupyter, install nest-asyncio and call `nest_asyncio.apply()`
        before invoking this method.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.scan(text, user_id=user_id, agent_id=agent_id, metadata=metadata),
            )
        raise RuntimeError(
            "scan_sync() cannot be called from a running event loop. "
            "Use `await shield.scan(...)` instead, or install nest-asyncio "
            "(`pip install ai-shield[notebook]`) and call "
            "`nest_asyncio.apply()` first.",
        )

    async def check_budget(self, entity_id: str) -> BudgetCheckResult:
        return await self.cost.check_budget(entity_id)

    async def record_cost(
        self,
        *,
        entity_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        actual_usd: float | None = None,
    ) -> CostRecord:
        return await self.cost.record(
            entity_id=entity_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            actual_usd=actual_usd,
        )

    async def get_current_spend(self, entity_id: str) -> float:
        return await self.cost.get_current_spend(entity_id)

    def get_policy(self) -> PolicyEngine:
        return self.policy

    def clear_cache(self) -> None:
        if self.cache is not None:
            self.cache.clear()

    async def close(self) -> None:
        if self.audit is not None:
            await self.audit.close()

    @staticmethod
    def _cache_key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
