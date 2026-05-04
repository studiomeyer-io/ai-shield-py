"""Canary token generation + leak-detection helpers.

1:1 port of `packages/core/src/scanner/canary.ts`.
"""

from __future__ import annotations

import secrets


def generate_canary(prefix: str = "canary") -> str:
    """Generate a random canary token (8 random bytes hex-encoded)."""
    return f"{prefix}-{secrets.token_hex(8)}"


def inject_canary(text: str, token: str) -> str:
    """Embed a canary token in an HTML comment so it survives Markdown render."""
    return f"{text}\n<!-- {token} -->\n"


def check_canary_leak(text: str, token: str) -> bool:
    """Return True if the canary token appears in the model output."""
    return token in text
