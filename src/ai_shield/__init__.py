"""ai-shield — LLM input shield for prompt-injection, PII, tool-policy, cost.

Python 1:1 port of ai-shield-core (TypeScript, MIT, 4 audit rounds).
"""

from __future__ import annotations

from ai_shield.scanner.heuristic import damerau_levenshtein, unscramble
from ai_shield.scanner.ingestion import scan_ingested, scan_tool_output
from ai_shield.scanner.output import scan_output
from ai_shield.shield import AIShield
from ai_shield.types import (
    AuditRecord,
    BudgetCheckResult,
    BudgetConfig,
    BudgetPeriod,
    CostRecord,
    Decision,
    IngestionSource,
    OutputSink,
    PIIAction,
    PIIEntity,
    PIIType,
    ScannerResult,
    ScanResult,
    ToolCall,
    ToolManifestPin,
    Violation,
    ViolationType,
)

__version__ = "0.3.0"

__all__ = [
    "AIShield",
    "AuditRecord",
    "BudgetCheckResult",
    "BudgetConfig",
    "BudgetPeriod",
    "CostRecord",
    "Decision",
    "IngestionSource",
    "OutputSink",
    "PIIAction",
    "PIIEntity",
    "PIIType",
    "ScanResult",
    "ScannerResult",
    "ToolCall",
    "ToolManifestPin",
    "Violation",
    "ViolationType",
    "__version__",
    "damerau_levenshtein",
    "scan_ingested",
    "scan_output",
    "scan_tool_output",
    "unscramble",
]
