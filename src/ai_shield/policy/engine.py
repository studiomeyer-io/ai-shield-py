"""Policy engine — 3 presets (public_website, internal_support, ops_agent).

1:1 port of `packages/core/src/policy/engine.ts`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ai_shield.types import PIIAction

PolicyPreset = Literal["public_website", "internal_support", "ops_agent"]


@dataclass(frozen=True)
class PolicyConfig:
    injection_threshold: float
    """Heuristic score threshold above which input is blocked."""

    pii_action: PIIAction
    dangerous_tool_patterns: tuple[str, ...]
    max_tool_chain_depth: int
    daily_budget_usd: float


PRESETS: dict[PolicyPreset, PolicyConfig] = {
    "public_website": PolicyConfig(
        injection_threshold=0.15,
        pii_action="redact",
        dangerous_tool_patterns=(
            "shell.*",
            "exec.*",
            "eval.*",
            "fs.write.*",
            "fs.delete.*",
            "db.drop.*",
            "db.truncate.*",
            "process.*",
            "*.execute",
        ),
        max_tool_chain_depth=3,
        daily_budget_usd=5.0,
    ),
    "internal_support": PolicyConfig(
        injection_threshold=0.30,
        pii_action="warn",
        dangerous_tool_patterns=(
            "shell.*",
            "exec.*",
            "fs.delete.*",
            "db.drop.*",
            "db.truncate.*",
        ),
        max_tool_chain_depth=5,
        daily_budget_usd=25.0,
    ),
    "ops_agent": PolicyConfig(
        injection_threshold=0.50,
        pii_action="allow",
        dangerous_tool_patterns=(
            "fs.delete.*",
            "db.drop.*",
            "db.truncate.*",
        ),
        max_tool_chain_depth=10,
        daily_budget_usd=100.0,
    ),
}


@dataclass
class PolicyEngine:
    """Read-only accessor for policy config — preset or custom."""

    preset: PolicyPreset = "public_website"
    overrides: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.preset not in PRESETS:
            raise ValueError(
                f"Unknown policy preset: {self.preset!r}. Choose one of {list(PRESETS)}.",
            )

    @property
    def config(self) -> PolicyConfig:
        return PRESETS[self.preset]

    def get_injection_threshold(self) -> float:
        v = self.overrides.get("injection_threshold")
        if isinstance(v, (int, float)):
            return float(v)
        return self.config.injection_threshold

    def get_pii_action(self) -> PIIAction:
        v = self.overrides.get("pii_action")
        if isinstance(v, str) and v in {"allow", "warn", "redact", "block"}:
            return v  # type: ignore[return-value]
        return self.config.pii_action

    def get_dangerous_tool_patterns(self) -> tuple[str, ...]:
        v = self.overrides.get("dangerous_tool_patterns")
        if isinstance(v, (list, tuple)):
            return tuple(str(p) for p in v)
        return self.config.dangerous_tool_patterns

    def get_max_tool_chain_depth(self) -> int:
        v = self.overrides.get("max_tool_chain_depth")
        if isinstance(v, int):
            return v
        return self.config.max_tool_chain_depth

    def get_daily_budget(self) -> float:
        v = self.overrides.get("daily_budget_usd")
        if isinstance(v, (int, float)):
            return float(v)
        return self.config.daily_budget_usd
