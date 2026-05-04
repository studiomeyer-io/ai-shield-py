"""Policy engine + tool-policy scanner tests."""

from __future__ import annotations

import pytest

from ai_shield.policy.engine import PRESETS, PolicyEngine
from ai_shield.policy.tools import (
    ToolPolicyScanner,
    add_agent_permissions,
)
from ai_shield.types import ToolCall, ToolPermissions, ToolPolicy


class TestPresetCatalogue:
    def test_three_presets_exist(self) -> None:
        assert set(PRESETS) == {"public_website", "internal_support", "ops_agent"}

    @pytest.mark.parametrize("preset", ["public_website", "internal_support", "ops_agent"])
    def test_threshold_in_zero_one(self, preset: str) -> None:
        assert 0.0 <= PRESETS[preset].injection_threshold <= 1.0

    def test_thresholds_increase_with_trust(self) -> None:
        # Public web is strictest; ops agent loosest.
        assert (
            PRESETS["public_website"].injection_threshold
            < PRESETS["internal_support"].injection_threshold
        )
        assert (
            PRESETS["internal_support"].injection_threshold
            < PRESETS["ops_agent"].injection_threshold
        )

    def test_budgets_increase_with_trust(self) -> None:
        assert (
            PRESETS["public_website"].daily_budget_usd
            < PRESETS["internal_support"].daily_budget_usd
        )
        assert PRESETS["internal_support"].daily_budget_usd < PRESETS["ops_agent"].daily_budget_usd


class TestPolicyEngineGetters:
    def test_default_preset_is_public_website(self) -> None:
        eng = PolicyEngine()
        assert eng.preset == "public_website"
        assert eng.get_pii_action() == "redact"

    def test_unknown_preset_rejected(self) -> None:
        with pytest.raises(ValueError):
            PolicyEngine(preset="unknown_preset")  # type: ignore[arg-type]

    def test_overrides_take_precedence(self) -> None:
        eng = PolicyEngine(
            preset="public_website",
            overrides={
                "injection_threshold": 0.7,
                "pii_action": "block",
                "daily_budget_usd": 99.0,
            },
        )
        assert eng.get_injection_threshold() == 0.7
        assert eng.get_pii_action() == "block"
        assert eng.get_daily_budget() == 99.0

    def test_invalid_pii_override_falls_back_to_preset(self) -> None:
        eng = PolicyEngine(
            preset="internal_support",
            overrides={"pii_action": "nonsense"},
        )
        assert eng.get_pii_action() == "warn"

    def test_dangerous_tool_patterns_override_accepts_list_or_tuple(self) -> None:
        eng = PolicyEngine(overrides={"dangerous_tool_patterns": ["foo.*"]})
        assert eng.get_dangerous_tool_patterns() == ("foo.*",)

    def test_max_chain_depth_default_per_preset(self) -> None:
        assert PolicyEngine(preset="public_website").get_max_tool_chain_depth() == 3
        assert PolicyEngine(preset="ops_agent").get_max_tool_chain_depth() == 10


class TestToolPolicyScannerWildcards:
    def test_globally_blocked_with_wildcard(self) -> None:
        scanner = ToolPolicyScanner(
            policy=ToolPolicy(globally_dangerous=["fs.delete.*"]),
        )
        assert scanner.is_globally_dangerous("fs.delete.user") is True
        assert scanner.is_globally_dangerous("fs.read.user") is False

    def test_suffix_wildcard(self) -> None:
        scanner = ToolPolicyScanner(
            policy=ToolPolicy(globally_dangerous=["*.execute"]),
        )
        assert scanner.is_globally_dangerous("db.execute") is True
        assert scanner.is_globally_dangerous("api.execute") is True
        assert scanner.is_globally_dangerous("execute.api") is False


class TestPermissions:
    def _policy_with_agent(self, perms: ToolPermissions) -> ToolPolicy:
        return ToolPolicy(agents={"agent-a": perms})

    def test_no_perms_blocks_all(self) -> None:
        scanner = ToolPolicyScanner(policy=ToolPolicy())
        ok, reason = scanner.check(ToolCall(name="anything", agent_id="ghost"))
        assert ok is False
        assert reason is not None

    def test_allowlist_match_passes(self) -> None:
        policy = self._policy_with_agent(ToolPermissions(allow=["search.*"]))
        scanner = ToolPolicyScanner(policy=policy)
        ok, reason = scanner.check(ToolCall(name="search.web", agent_id="agent-a"))
        assert ok is True
        assert reason is None

    def test_allowlist_miss_blocks(self) -> None:
        policy = self._policy_with_agent(ToolPermissions(allow=["search.*"]))
        scanner = ToolPolicyScanner(policy=policy)
        ok, _ = scanner.check(ToolCall(name="fs.delete", agent_id="agent-a"))
        assert ok is False

    def test_denylist_overrides_allowlist(self) -> None:
        policy = self._policy_with_agent(
            ToolPermissions(allow=["fs.*"], deny=["fs.delete"]),
        )
        scanner = ToolPolicyScanner(policy=policy)
        ok, _ = scanner.check(ToolCall(name="fs.delete", agent_id="agent-a"))
        assert ok is False

    def test_globally_blocked_overrides_allowlist(self) -> None:
        policy = ToolPolicy(
            agents={"agent-a": ToolPermissions(allow=["*"])},
            globally_dangerous=["shell.*"],
        )
        scanner = ToolPolicyScanner(policy=policy)
        ok, _ = scanner.check(ToolCall(name="shell.run", agent_id="agent-a"))
        assert ok is False

    def test_read_only_flag(self) -> None:
        policy = self._policy_with_agent(ToolPermissions(read_only=True))
        scanner = ToolPolicyScanner(policy=policy)
        assert scanner.is_read_only("agent-a") is True
        assert scanner.is_read_only("ghost") is False


class TestAddAgentPermissions:
    def test_adds_new_agent(self) -> None:
        policy = ToolPolicy()
        new_policy = add_agent_permissions(
            policy,
            "agent-a",
            ToolPermissions(allow=["search.*"]),
        )
        assert "agent-a" in new_policy.agents
        # Old policy is unchanged.
        assert "agent-a" not in policy.agents

    def test_replaces_existing(self) -> None:
        policy = ToolPolicy(
            agents={"agent-a": ToolPermissions(allow=["foo"])},
        )
        new_policy = add_agent_permissions(
            policy,
            "agent-a",
            ToolPermissions(allow=["bar"]),
        )
        assert new_policy.agents["agent-a"].allow == ["bar"]


class TestManifestPinning:
    def test_pin_then_verify_same(self) -> None:
        manifest = {"name": "weather-mcp", "version": "1.2.3", "tools": ["weather.get"]}
        pin = ToolPolicyScanner.pin_manifest("weather-mcp", manifest)
        assert ToolPolicyScanner.verify_manifest(pin, manifest) is True

    def test_pin_then_verify_modified_fails(self) -> None:
        manifest = {"name": "weather-mcp", "version": "1.2.3"}
        pin = ToolPolicyScanner.pin_manifest("weather-mcp", manifest)
        modified = {"name": "weather-mcp", "version": "1.2.4"}
        assert ToolPolicyScanner.verify_manifest(pin, modified) is False

    def test_canonicalisation_is_key_order_stable(self) -> None:
        a = {"x": 1, "y": 2}
        b = {"y": 2, "x": 1}
        pin_a = ToolPolicyScanner.pin_manifest("svc", a)
        pin_b = ToolPolicyScanner.pin_manifest("svc", b)
        assert pin_a.sha256 == pin_b.sha256
