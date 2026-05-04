"""CostTracker tests — asyncio.Lock race, soft/hard budgets, period rollover."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from ai_shield.cost.tracker import CostTracker, MemoryStore, _period_key
from ai_shield.types import BudgetConfig


class TestPeriodKey:
    def test_hourly_format(self) -> None:
        moment = datetime(2026, 5, 4, 10, 30, tzinfo=timezone.utc)
        assert _period_key("hourly", moment) == "2026050410"

    def test_daily_format(self) -> None:
        moment = datetime(2026, 5, 4, 10, 30, tzinfo=timezone.utc)
        assert _period_key("daily", moment) == "20260504"

    def test_monthly_format(self) -> None:
        moment = datetime(2026, 5, 4, 10, 30, tzinfo=timezone.utc)
        assert _period_key("monthly", moment) == "202605"

    def test_unknown_period_raises(self) -> None:
        with pytest.raises(ValueError):
            _period_key("yearly", datetime.now(timezone.utc))  # type: ignore[arg-type]


class TestMemoryStore:
    @pytest.mark.asyncio
    async def test_incrbyfloat_creates_key(self) -> None:
        store = MemoryStore()
        v = await store.incrbyfloat("k", 1.5)
        assert v == 1.5

    @pytest.mark.asyncio
    async def test_incrbyfloat_accumulates(self) -> None:
        store = MemoryStore()
        await store.incrbyfloat("k", 1.0)
        v = await store.incrbyfloat("k", 2.5)
        assert v == 3.5

    @pytest.mark.asyncio
    async def test_get_returns_string_or_none(self) -> None:
        store = MemoryStore()
        assert await store.get("missing") is None
        await store.incrbyfloat("k", 2.0)
        assert await store.get("k") == "2.0"

    @pytest.mark.asyncio
    async def test_expire_on_missing_key_returns_false(self) -> None:
        store = MemoryStore()
        assert await store.expire("missing", 60) is False

    @pytest.mark.asyncio
    async def test_lock_serialises_concurrent_increments(self) -> None:
        store = MemoryStore()

        async def bump() -> None:
            await store.incrbyfloat("k", 1.0)

        # 100 concurrent increments — final value must be exactly 100.0.
        await asyncio.gather(*[bump() for _ in range(100)])
        assert await store.get("k") == "100.0"


class TestRecord:
    @pytest.mark.asyncio
    async def test_records_appended(self) -> None:
        tracker = CostTracker()
        rec = await tracker.record(
            entity_id="user-1",
            model="gpt-4o",
            input_tokens=1000,
            output_tokens=500,
        )
        assert rec.entity_id == "user-1"
        assert rec.actual_usd > 0.0
        assert len(tracker.recent_records()) == 1

    @pytest.mark.asyncio
    async def test_actual_usd_override_used(self) -> None:
        tracker = CostTracker()
        rec = await tracker.record(
            entity_id="x",
            model="gpt-4o",
            input_tokens=10,
            output_tokens=10,
            actual_usd=99.99,
        )
        assert rec.actual_usd == 99.99

    @pytest.mark.asyncio
    async def test_records_bounded_by_max_records(self) -> None:
        tracker = CostTracker(max_records=5)
        for _ in range(20):
            await tracker.record(
                entity_id="x",
                model="gpt-4o-mini",
                input_tokens=1,
                output_tokens=1,
            )
        assert len(tracker.recent_records(100)) == 5


class TestBudgetCheck:
    @pytest.mark.asyncio
    async def test_no_limits_always_allowed(self) -> None:
        tracker = CostTracker(budget=BudgetConfig(period="daily"))
        result = await tracker.check_budget("anyone")
        assert result.allowed is True
        assert result.soft_exceeded is False
        assert result.hard_exceeded is False

    @pytest.mark.asyncio
    async def test_soft_exceeded_still_allowed(self) -> None:
        tracker = CostTracker(
            budget=BudgetConfig(period="daily", soft_limit_usd=0.5, hard_limit_usd=10.0),
        )
        await tracker.record(
            entity_id="user",
            model="gpt-4o",
            input_tokens=200_000,
            output_tokens=0,
        )
        # 200_000 input * 2.50 / 1M = 0.50 USD — exactly at soft limit
        result = await tracker.check_budget("user")
        assert result.soft_exceeded is True
        assert result.hard_exceeded is False
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_hard_exceeded_blocks(self) -> None:
        tracker = CostTracker(
            budget=BudgetConfig(period="daily", hard_limit_usd=0.10),
        )
        await tracker.record(
            entity_id="user",
            model="gpt-4o",
            input_tokens=200_000,
            output_tokens=0,
        )
        result = await tracker.check_budget("user")
        assert result.hard_exceeded is True
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_per_entity_isolation(self) -> None:
        tracker = CostTracker(
            budget=BudgetConfig(period="daily", hard_limit_usd=0.10),
        )
        await tracker.record(
            entity_id="alice",
            model="gpt-4o",
            input_tokens=200_000,
            output_tokens=0,
        )
        # bob has spent nothing
        bob = await tracker.check_budget("bob")
        assert bob.allowed is True
        assert bob.current_spend_usd == 0.0


class TestGetCurrentSpend:
    @pytest.mark.asyncio
    async def test_zero_when_unknown(self) -> None:
        tracker = CostTracker()
        assert await tracker.get_current_spend("nobody") == 0.0

    @pytest.mark.asyncio
    async def test_accumulates(self) -> None:
        tracker = CostTracker()
        await tracker.record(
            entity_id="x",
            model="gpt-4o-mini",
            input_tokens=1_000_000,
            output_tokens=0,
        )
        # 1M input * 0.15 / 1M = 0.15
        spend = await tracker.get_current_spend("x")
        assert spend == pytest.approx(0.15, rel=1e-6)


class TestKeyDerivation:
    def test_key_includes_entity_period_and_keyform(self) -> None:
        k = CostTracker._key("user-1", "daily")
        assert k.startswith("ai-shield:cost:user-1:daily:")
