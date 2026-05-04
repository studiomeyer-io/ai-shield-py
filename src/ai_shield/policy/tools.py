"""Tool-policy scanner — MCP allowlist + SHA-256 manifest pinning.

1:1 port of `packages/core/src/policy/tools.ts`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ai_shield.types import ToolCall, ToolManifestPin, ToolPermissions, ToolPolicy


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert `db.*` / `*.execute` style wildcards to a Python regex."""
    escaped = re.escape(pattern).replace(r"\*", ".*")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


@dataclass
class ToolPolicyScanner:
    """Deterministic gate for MCP tool calls."""

    policy: ToolPolicy = field(default_factory=ToolPolicy)

    def is_globally_dangerous(self, tool_name: str) -> bool:
        for pattern in self.policy.globally_dangerous:
            if _wildcard_to_regex(pattern).match(tool_name):
                return True
        return False

    def is_allowed(self, agent_id: str, tool_name: str) -> bool:
        perms = self.policy.agents.get(agent_id)
        if perms is None:
            return False
        if self._matches_any(perms.deny, tool_name):
            return False
        if not perms.allow:
            return False
        return self._matches_any(perms.allow, tool_name)

    def is_denied(self, agent_id: str, tool_name: str) -> bool:
        perms = self.policy.agents.get(agent_id)
        if perms is None:
            return True
        return self._matches_any(perms.deny, tool_name)

    def is_read_only(self, agent_id: str) -> bool:
        perms = self.policy.agents.get(agent_id)
        return bool(perms and perms.read_only)

    def check(self, call: ToolCall) -> tuple[bool, str | None]:
        """Return (allowed, reason). reason is None if allowed."""
        if self.is_globally_dangerous(call.name):
            return False, f"Tool {call.name!r} is globally blocked."
        agent = call.agent_id or "default"
        if self.is_denied(agent, call.name):
            return False, f"Tool {call.name!r} is on the deny list for agent {agent!r}."
        if not self.is_allowed(agent, call.name):
            return False, f"Tool {call.name!r} is not on the allow list for agent {agent!r}."
        return True, None

    @staticmethod
    def _matches_any(patterns: list[str], tool_name: str) -> bool:
        return any(_wildcard_to_regex(p).match(tool_name) for p in patterns)

    # -- Manifest pinning -------------------------------------------------

    @staticmethod
    def pin_manifest(server_name: str, manifest: dict[str, Any]) -> ToolManifestPin:
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        return ToolManifestPin(
            server_name=server_name,
            sha256=digest,
            pinned_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def verify_manifest(pin: ToolManifestPin, manifest: dict[str, Any]) -> bool:
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        return digest == pin.sha256


def add_agent_permissions(
    policy: ToolPolicy,
    agent_id: str,
    permissions: ToolPermissions,
) -> ToolPolicy:
    """Return a new policy with agent permissions added/replaced."""
    new_agents = dict(policy.agents)
    new_agents[agent_id] = permissions
    return ToolPolicy(
        agents=new_agents,
        globally_dangerous=list(policy.globally_dangerous),
        max_chain_depth=policy.max_chain_depth,
    )
