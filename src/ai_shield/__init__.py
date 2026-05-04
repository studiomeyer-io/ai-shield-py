"""ai-shield — LLM input shield for prompt-injection, PII, tool-policy, cost.

Python 1:1 port of ai-shield-core (TypeScript, MIT, 4 audit rounds).
"""

from __future__ import annotations

from ai_shield.shield import AIShield
from ai_shield.types import (
    AuditRecord,
    BudgetCheckResult,
    BudgetConfig,
    BudgetPeriod,
    CostRecord,
    Decision,
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

__version__ = "0.1.0"

__all__ = [
    "AIShield",
    "AuditRecord",
    "BudgetCheckResult",
    "BudgetConfig",
    "BudgetPeriod",
    "CostRecord",
    "Decision",
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
]
