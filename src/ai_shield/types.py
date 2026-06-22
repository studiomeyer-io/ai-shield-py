"""Pydantic v2 models — public types of the ai-shield package.

1:1 port of `packages/core/src/types.ts` from ai-shield-core.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# -- Decisions -------------------------------------------------------------

Decision = Literal["allow", "warn", "block"]
"""Final decision for a scan — allow, warn (proceed with note), block."""

ViolationType = Literal[
    "prompt_injection",
    "pii_exposure",
    "tool_policy_violation",
    "budget_exceeded",
    "rate_limit",
    "anomaly",
    # Indirect injection (ingestion scanner)
    "ingested_injection",
    # Output side (OWASP LLM05 / LLM02)
    "output_injection",
    "secret_leak",
    "system_prompt_leak",
    "jailbreak_indicator",
]

IngestionSource = Literal[
    "user",
    "rag",
    "tool_desc",
    "tool_output",
    "memory",
    "web",
    "agent_output",
]
"""Provenance of scanned content — drives the ingestion scanner's per-source
threshold and extra patterns. Distinct from `tool_desc` (static schema),
`tool_output` is the runtime result a tool returned (the dominant indirect-
injection channel in agentic loops)."""

OutputSink = Literal["sql", "shell", "html", "template"]
"""Downstream sink an LLM output may flow into — narrows the output-injection
check (OWASP LLM05)."""


class Violation(BaseModel):
    """Single violation detected by a scanner."""

    model_config = ConfigDict(extra="forbid")

    type: ViolationType
    severity: Literal["low", "medium", "high", "critical"]
    detector: str
    message: str
    confidence: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregated outcome from running the scanner chain on one input."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    violations: list[Violation] = Field(default_factory=list)
    sanitized_text: str | None = None
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    cache_hit: bool = False


class ScannerResult(BaseModel):
    """Per-scanner result — chain combines these into a ScanResult."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    violations: list[Violation] = Field(default_factory=list)
    sanitized_text: str | None = None
    score: float = Field(default=0.0, ge=0.0, le=1.0)


class ScanContext(BaseModel):
    """Context passed through the scanner chain."""

    model_config = ConfigDict(extra="forbid")

    text: str
    user_id: str | None = None
    agent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# -- PII -------------------------------------------------------------------

PIIType = Literal[
    "email",
    "phone",
    "iban",
    "credit_card",
    "german_tax_id",
    "german_social_security",
    "ip_address",
    "url_with_credentials",
]

PIIAction = Literal["allow", "warn", "redact", "block"]


class PIIEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: PIIType
    value: str
    masked: str
    start: int = Field(ge=0)
    end: int = Field(ge=0)


# -- Tool policy -----------------------------------------------------------


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None


class ToolPermissions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    read_only: bool = False


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agents: dict[str, ToolPermissions] = Field(default_factory=dict)
    globally_dangerous: list[str] = Field(default_factory=list)
    max_chain_depth: int = Field(default=10, ge=1)


class ToolManifestPin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_name: str
    sha256: str
    pinned_at: str  # ISO 8601


# -- Cost / budget ---------------------------------------------------------

BudgetPeriod = Literal["hourly", "daily", "monthly"]


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    soft_limit_usd: float | None = Field(default=None, ge=0.0)
    hard_limit_usd: float | None = Field(default=None, ge=0.0)
    period: BudgetPeriod = "daily"


class CostEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    estimated_usd: float = Field(ge=0.0)
    model: str


class CostRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_id: str
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    actual_usd: float = Field(ge=0.0)
    timestamp: str  # ISO 8601
    metadata: dict[str, Any] = Field(default_factory=dict)


class BudgetCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    current_spend_usd: float = Field(ge=0.0)
    limit_usd: float | None = None
    period: BudgetPeriod
    soft_exceeded: bool = False
    hard_exceeded: bool = False


# -- Audit -----------------------------------------------------------------


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str  # ISO 8601
    user_id_hash: str | None = None
    input_sha256: str
    decision: Decision
    violations: list[Violation] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


# -- Pricing ---------------------------------------------------------------


class ModelPricing(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_per_1m: float = Field(ge=0.0)
    output_per_1m: float = Field(ge=0.0)


# -- Anomaly ---------------------------------------------------------------


class AnomalyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_anomaly: bool
    z_score: float
    current_value: float
    mean: float
    std_dev: float


# -- Canary ----------------------------------------------------------------


class CanaryToken(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    injected_into: str  # e.g. "system_prompt", "context", "tool_output"
    created_at: str  # ISO 8601
