"""Model pricing table + estimate_cost tests."""

from __future__ import annotations

import math

import pytest

from ai_shield.cost.pricing import MODEL_PRICING, estimate_cost, get_model_pricing


class TestPricingTable:
    def test_table_contains_expected_providers(self) -> None:
        keys = set(MODEL_PRICING)
        assert "gpt-4o" in keys
        assert "claude-opus-4-7" in keys
        assert "gemini-2.5-pro" in keys
        assert "grok-4" in keys
        assert "mistral-large" in keys

    def test_all_prices_are_positive(self) -> None:
        for model, p in MODEL_PRICING.items():
            assert p.input_per_1m >= 0.0, model
            assert p.output_per_1m >= 0.0, model

    def test_output_price_at_least_input_price_for_frontier_models(self) -> None:
        # Frontier providers price output >= input across the board.
        for model in ["gpt-5.2", "claude-opus-4-7", "gemini-2.5-pro"]:
            p = MODEL_PRICING[model]
            assert p.output_per_1m >= p.input_per_1m


class TestGetModelPricing:
    def test_exact_match(self) -> None:
        p = get_model_pricing("gpt-4o-mini")
        assert math.isclose(p.input_per_1m, 0.15)

    def test_prefix_match(self) -> None:
        # "gpt-4o-mini-2024-07-18" starts with a known key.
        p = get_model_pricing("gpt-4o-mini-2024-07-18")
        assert math.isclose(p.input_per_1m, 0.15)

    def test_unknown_falls_back_to_gpt_4o_mini(self) -> None:
        p = get_model_pricing("zzz-unknown-model")
        assert math.isclose(p.input_per_1m, 0.15)
        assert math.isclose(p.output_per_1m, 0.60)


class TestEstimateCost:
    def test_zero_tokens_costs_zero(self) -> None:
        assert estimate_cost("gpt-4o", 0, 0) == 0.0

    def test_known_model_math(self) -> None:
        # gpt-4o = 2.50 in / 10.00 out per 1M
        cost = estimate_cost("gpt-4o", 1_000_000, 1_000_000)
        assert math.isclose(cost, 12.50)

    def test_partial_million(self) -> None:
        cost = estimate_cost("gpt-4o-mini", 100_000, 100_000)
        # 0.1*0.15 + 0.1*0.60 = 0.015 + 0.06 = 0.075
        assert math.isclose(cost, 0.075)

    def test_negative_tokens_raise(self) -> None:
        with pytest.raises(ValueError):
            estimate_cost("gpt-4o", -1, 0)
        with pytest.raises(ValueError):
            estimate_cost("gpt-4o", 0, -5)
