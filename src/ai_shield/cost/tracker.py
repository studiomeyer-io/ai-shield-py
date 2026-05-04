"""Async cost tracker — soft/hard budgets, in-memory or Redis backend.

1:1 port of `packages/core/src/cost/tracker.ts`.
"""

from __future__ import annotations

import asyncio
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from ai_shield.cost.pricing import estimate_cost
from ai_shield.types import (
    BudgetCheckResult,
    BudgetConfig,
    BudgetPeriod,
    CostRecord,
)

_DEFAULT_MAX_RECORDS = int(os.environ.get("AI_SHIELD_MAX_RECORDS", "10000"))


class RedisLike(Protocol):
    """Minimal Redis interface — `incrbyfloat` + `expire` + `get`."""

    async def incrbyfloat(self, key: str, value: float) -> float: ...
    async def expire(self, key: str, seconds: int) -> bool: ...
    async def get(self, key: str) -> str | None: ...


@dataclass
class MemoryStore:
    """In-process fallback when Redis is not provided."""

    _data: dict[str, float] = field(default_factory=dict)
    _expires_at: dict[str, float] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def incrbyfloat(self, key: str, value: float) -> float:
        async with self._lock:
            self._sweep_expired()
            current = self._data.get(key, 0.0)
            new = current + value
            self._data[key] = new
            return new

    async def expire(self, key: str, seconds: int) -> bool:
        async with self._lock:
            if key not in self._data:
                return False
            loop_time = asyncio.get_event_loop().time()
            self._expires_at[key] = loop_time + seconds
            return True

    async def get(self, key: str) -> str | None:
        async with self._lock:
            self._sweep_expired()
            v = self._data.get(key)
            return None if v is None else str(v)

    def _sweep_expired(self) -> None:
        now = asyncio.get_event_loop().time()
        expired = [k for k, t in self._expires_at.items() if t <= now]
        for k in expired:
            self._data.pop(k, None)
            self._expires_at.pop(k, None)


def _period_seconds(period: BudgetPeriod) -> int:
    if period == "hourly":
        return 3600
    if period == "daily":
        return 86400
    if period == "monthly":
        return 86400 * 31
    raise ValueError(f"Unknown period: {period!r}")


def _period_key(period: BudgetPeriod, now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if period == "hourly":
        return moment.strftime("%Y%m%d%H")
    if period == "daily":
        return moment.strftime("%Y%m%d")
    if period == "monthly":
        return moment.strftime("%Y%m")
    raise ValueError(f"Unknown period: {period!r}")


@dataclass
class CostTracker:
    """Track LLM spend with optional Redis backend.

    All writes are atomic at the store level (`INCRBYFLOAT` on Redis,
    `asyncio.Lock` on the in-memory store).
    """

    budget: BudgetConfig = field(default_factory=BudgetConfig)
    store: RedisLike | None = None
    max_records: int = _DEFAULT_MAX_RECORDS

    _records: deque[CostRecord] = field(init=False)
    _store: RedisLike = field(init=False)

    def __post_init__(self) -> None:
        self._records = deque(maxlen=self.max_records)
        self._store = self.store if self.store is not None else MemoryStore()

    @staticmethod
    def _key(entity_id: str, period: BudgetPeriod) -> str:
        return f"ai-shield:cost:{entity_id}:{period}:{_period_key(period)}"

    async def record(
        self,
        *,
        entity_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        actual_usd: float | None = None,
    ) -> CostRecord:
        cost = (
            actual_usd
            if actual_usd is not None
            else estimate_cost(
                model,
                input_tokens,
                output_tokens,
            )
        )
        record = CostRecord(
            entity_id=entity_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            actual_usd=cost,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._records.append(record)

        key = self._key(entity_id, self.budget.period)
        await self._store.incrbyfloat(key, cost)
        await self._store.expire(key, _period_seconds(self.budget.period))
        return record

    async def check_budget(self, entity_id: str) -> BudgetCheckResult:
        key = self._key(entity_id, self.budget.period)
        raw = await self._store.get(key)
        spend = float(raw) if raw is not None else 0.0

        soft = self.budget.soft_limit_usd
        hard = self.budget.hard_limit_usd

        soft_exceeded = soft is not None and spend >= soft
        hard_exceeded = hard is not None and spend >= hard

        return BudgetCheckResult(
            allowed=not hard_exceeded,
            current_spend_usd=spend,
            limit_usd=hard if hard is not None else soft,
            period=self.budget.period,
            soft_exceeded=soft_exceeded,
            hard_exceeded=hard_exceeded,
        )

    async def get_current_spend(self, entity_id: str) -> float:
        key = self._key(entity_id, self.budget.period)
        raw = await self._store.get(key)
        return float(raw) if raw is not None else 0.0

    def recent_records(self, n: int = 100) -> list[CostRecord]:
        return list(self._records)[-n:]
