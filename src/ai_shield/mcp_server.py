"""MCP server exposing AIShield as 3 tools.

Tools:
  - scan_input        — run scanner chain on a text payload
  - record_llm_cost   — log an LLM call cost against an entity budget
  - check_budget      — report current spend / hard-limit status

Run via console script:
    ai-shield-mcp

Or:
    python -m ai_shield.mcp_server
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mcp.types import ToolAnnotations

from ai_shield.policy.engine import PRESETS, PolicyPreset
from ai_shield.shield import AIShield

# mcp 2.x renamed FastMCP to MCPServer (mcp.server.mcpserver); the parts used
# here (constructor name, .tool(annotations=...), .list_tools(), .run()) kept
# their shape. The type checker sees the 2.x class; at runtime a 1.x install
# falls back to the old name, so both majors keep working. Tool annotations
# are built from their wire names (camelCase) via model_validate: the Python
# field names differ between majors (readOnlyHint vs read_only_hint), the wire
# names do not.
if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer
else:
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as MCPServer

mcp: MCPServer = MCPServer("ai-shield")
_shield: AIShield = AIShield()


@mcp.tool(
    annotations=ToolAnnotations.model_validate(
        {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    ),
)
async def scan_input(
    text: str,
    user_id: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Scan an input string for prompt-injection + PII.

    Returns a JSON object with `decision`, `violations`, `score`,
    `sanitized_text`, `cache_hit`.
    """
    result = await _shield.scan(text, user_id=user_id, agent_id=agent_id)
    return result.model_dump()


@mcp.tool(
    annotations=ToolAnnotations.model_validate(
        {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        }
    ),
)
async def record_llm_cost(
    entity_id: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    actual_usd: float | None = None,
) -> dict[str, Any]:
    """Record an LLM call cost. Returns the persisted CostRecord."""
    record = await _shield.record_cost(
        entity_id=entity_id,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        actual_usd=actual_usd,
    )
    return record.model_dump()


@mcp.tool(
    annotations=ToolAnnotations.model_validate(
        {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    ),
)
async def check_budget(entity_id: str) -> dict[str, Any]:
    """Return current spend + budget status for `entity_id`."""
    res = await _shield.check_budget(entity_id)
    return res.model_dump()


def configure_preset(preset: PolicyPreset) -> None:
    """Reconfigure the in-process shield to use a different policy preset.

    Used by tests; safe to call from runtime config-reload hooks too.
    """
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset: {preset!r}")
    global _shield
    _shield = AIShield(policy_preset=preset)


def main() -> None:
    """Console entry point: runs the MCP server over stdio transport."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
