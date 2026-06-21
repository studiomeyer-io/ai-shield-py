"""Scanner subpackage — heuristic, PII, chain, canary."""

from __future__ import annotations

from ai_shield.scanner.canary import check_canary_leak, generate_canary, inject_canary
from ai_shield.scanner.chain import Scanner, ScannerChain
from ai_shield.scanner.heuristic import (
    HeuristicScanner,
    de_tag,
    detect_forged_transcript,
    has_standalone_tag_chars,
    has_tag_chars,
    leet_decode,
    normalize,
)
from ai_shield.scanner.pii import PIIScanner

__all__ = [
    "HeuristicScanner",
    "PIIScanner",
    "Scanner",
    "ScannerChain",
    "check_canary_leak",
    "de_tag",
    "detect_forged_transcript",
    "generate_canary",
    "has_standalone_tag_chars",
    "has_tag_chars",
    "inject_canary",
    "leet_decode",
    "normalize",
]
