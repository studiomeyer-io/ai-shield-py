"""FastMCP server tests — tool listing, annotations, configure_preset."""

from __future__ import annotations

import pytest

from ai_shield import mcp_server
from ai_shield.mcp_server import configure_preset, mcp


class TestServerIdentity:
    def test_server_name(self) -> None:
        assert mcp.name == "ai-shield"


class TestToolRegistration:
    @pytest.mark.asyncio
    async def test_three_tools_registered(self) -> None:
        tools = await mcp.list_tools()
        names = {t.name for t in tools}
        assert names == {"scan_input", "record_llm_cost", "check_budget"}

    @pytest.mark.asyncio
    async def test_scan_input_annotations(self) -> None:
        tools = await mcp.list_tools()
        scan = next(t for t in tools if t.name == "scan_input")
        ann = scan.annotations
        assert ann is not None
        assert ann.readOnlyHint is True
        assert ann.destructiveHint is False
        assert ann.idempotentHint is True
        assert ann.openWorldHint is False

    @pytest.mark.asyncio
    async def test_record_llm_cost_annotations(self) -> None:
        tools = await mcp.list_tools()
        rec = next(t for t in tools if t.name == "record_llm_cost")
        ann = rec.annotations
        assert ann is not None
        assert ann.readOnlyHint is False
        # Recording cost is append-only; not destructive in MCP spec sense.
        assert ann.destructiveHint is False

    @pytest.mark.asyncio
    async def test_check_budget_annotations(self) -> None:
        tools = await mcp.list_tools()
        cb = next(t for t in tools if t.name == "check_budget")
        ann = cb.annotations
        assert ann is not None
        assert ann.readOnlyHint is True
        assert ann.idempotentHint is True


class TestConfigurePreset:
    def test_unknown_preset_raises(self) -> None:
        with pytest.raises(ValueError):
            configure_preset("nonsense")  # type: ignore[arg-type]

    def test_known_presets_succeed(self) -> None:
        for p in ("public_website", "internal_support", "ops_agent"):
            configure_preset(p)  # type: ignore[arg-type]
            assert mcp_server._shield.policy.preset == p
        # Reset to default.
        configure_preset("public_website")


class TestToolBehaviour:
    """Direct calls to the underlying tool functions (FastMCP wraps them)."""

    @pytest.mark.asyncio
    async def test_scan_input_returns_dict(self) -> None:
        # Reset preset to default.
        configure_preset("public_website")
        out = await mcp_server.scan_input("the weather is fine")
        assert "decision" in out
        assert out["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_record_llm_cost_returns_dict(self) -> None:
        out = await mcp_server.record_llm_cost(
            entity_id="t-user",
            model="gpt-4o-mini",
            input_tokens=10,
            output_tokens=10,
        )
        assert out["entity_id"] == "t-user"
        assert out["model"] == "gpt-4o-mini"
        assert out["actual_usd"] >= 0.0

    @pytest.mark.asyncio
    async def test_check_budget_returns_dict(self) -> None:
        out = await mcp_server.check_budget("t-user")
        assert "allowed" in out
        assert "current_spend_usd" in out
        assert "period" in out


class TestEntryPoint:
    def test_main_callable_exists(self) -> None:
        # Direct call would block on stdio — only assert it is a callable.
        assert callable(mcp_server.main)
