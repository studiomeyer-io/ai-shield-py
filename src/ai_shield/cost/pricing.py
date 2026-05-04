"""Model pricing table + estimate_cost helper.

1:1 port of `packages/core/src/cost/pricing.ts`.
USD per 1M tokens. Update as providers change rates.
"""

from __future__ import annotations

from ai_shield.types import ModelPricing

MODEL_PRICING: dict[str, ModelPricing] = {
    # OpenAI
    "gpt-5.2": ModelPricing(input_per_1m=4.50, output_per_1m=18.00),
    "gpt-5.0": ModelPricing(input_per_1m=3.00, output_per_1m=12.00),
    "gpt-4.1": ModelPricing(input_per_1m=2.50, output_per_1m=10.00),
    "gpt-4o": ModelPricing(input_per_1m=2.50, output_per_1m=10.00),
    "gpt-4o-mini": ModelPricing(input_per_1m=0.15, output_per_1m=0.60),
    "o3": ModelPricing(input_per_1m=15.00, output_per_1m=60.00),
    "o4-mini": ModelPricing(input_per_1m=1.10, output_per_1m=4.40),
    # Anthropic
    "claude-opus-4-7": ModelPricing(input_per_1m=15.00, output_per_1m=75.00),
    "claude-opus-4-6": ModelPricing(input_per_1m=15.00, output_per_1m=75.00),
    "claude-sonnet-4-7": ModelPricing(input_per_1m=3.00, output_per_1m=15.00),
    "claude-sonnet-4-5": ModelPricing(input_per_1m=3.00, output_per_1m=15.00),
    "claude-haiku-4-7": ModelPricing(input_per_1m=0.80, output_per_1m=4.00),
    # Google
    "gemini-2.5-pro": ModelPricing(input_per_1m=1.25, output_per_1m=5.00),
    "gemini-2.5-flash": ModelPricing(input_per_1m=0.075, output_per_1m=0.30),
    "gemini-2.5-flash-lite": ModelPricing(input_per_1m=0.0375, output_per_1m=0.15),
    # xAI
    "grok-4": ModelPricing(input_per_1m=5.00, output_per_1m=15.00),
    # Mistral
    "mistral-large": ModelPricing(input_per_1m=2.00, output_per_1m=6.00),
    "mistral-small": ModelPricing(input_per_1m=0.20, output_per_1m=0.60),
}


def get_model_pricing(model: str) -> ModelPricing:
    """Return pricing for `model`. Exact match → longest-prefix match → fallback.

    Longest-prefix-first ensures `gpt-4o-mini-2024-07-18` matches `gpt-4o-mini`
    ($0.15) NOT `gpt-4o` ($2.50) — critical for cost-accuracy with versioned
    snapshots. Insertion-order would otherwise return the first registered
    prefix (which is shorter for many providers).
    """
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    # Sort keys by length descending so most-specific prefix wins first.
    for key in sorted(MODEL_PRICING.keys(), key=len, reverse=True):
        if model.startswith(key):
            return MODEL_PRICING[key]
    return MODEL_PRICING["gpt-4o-mini"]


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Compute USD estimate for a single LLM call."""
    if input_tokens < 0 or output_tokens < 0:
        raise ValueError("Token counts must be non-negative")
    p = get_model_pricing(model)
    return (input_tokens / 1_000_000) * p.input_per_1m + (
        output_tokens / 1_000_000
    ) * p.output_per_1m
