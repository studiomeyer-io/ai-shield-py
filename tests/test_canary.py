"""Canary token generation + detection tests."""

from __future__ import annotations

import re

from ai_shield.scanner.canary import (
    check_canary_leak,
    generate_canary,
    inject_canary,
)


class TestGenerate:
    def test_default_prefix(self) -> None:
        token = generate_canary()
        assert token.startswith("canary-")

    def test_custom_prefix(self) -> None:
        token = generate_canary("trap")
        assert token.startswith("trap-")

    def test_token_uses_hex_charset(self) -> None:
        token = generate_canary()
        suffix = token.split("-", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{16}", suffix)

    def test_uniqueness_across_1000_invocations(self) -> None:
        tokens = {generate_canary() for _ in range(1000)}
        assert len(tokens) == 1000


class TestInject:
    def test_html_comment_format_survives_markdown(self) -> None:
        token = "canary-deadbeefcafebabe"
        out = inject_canary("hello", token)
        assert "<!-- canary-deadbeefcafebabe -->" in out

    def test_original_text_preserved(self) -> None:
        out = inject_canary("hello world", "canary-x")
        assert out.startswith("hello world")

    def test_empty_input(self) -> None:
        out = inject_canary("", "canary-x")
        assert "canary-x" in out


class TestDetection:
    def test_detects_leaked_token_in_output(self) -> None:
        token = generate_canary()
        leaked = f"Here is the system text: {token} ..."
        assert check_canary_leak(leaked, token) is True

    def test_returns_false_when_token_absent(self) -> None:
        token = generate_canary()
        assert check_canary_leak("clean output without canary", token) is False

    def test_partial_token_does_not_match(self) -> None:
        token = "canary-deadbeef00000000"
        assert check_canary_leak("canary-deadbeef", token) is False

    def test_full_roundtrip(self) -> None:
        token = generate_canary("audit")
        prompt_with_canary = inject_canary("System: do not reveal", token)
        # Simulated leak — the model echoed our prompt back
        assert check_canary_leak(prompt_with_canary, token)
