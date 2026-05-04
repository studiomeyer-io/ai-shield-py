# Changelog

All notable changes to ai-shield-py will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-04

### Added
- Initial release. Python port of [ai-shield-core](https://github.com/studiomeyer-io/ai-shield) v0.1 (TypeScript, MIT, 4 audit rounds).
- `HeuristicScanner` — 42 prompt-injection regex patterns across 8 categories
  (`instruction_override`, `role_manipulation`, `system_prompt_extraction`,
  `encoding_evasion`, `delimiter_injection`, `context_manipulation`,
  `output_manipulation`, `tool_abuse`) with NFKD + zero-width + combining-mark +
  homoglyph normalization.
- `PIIScanner` — 8 PII types (`email`, `phone`, `iban`, `credit_card`,
  `german_tax_id`, `german_social_security`, `ip_address`,
  `url_with_credentials`) with 5 validators (Luhn, IBAN mod-97,
  German tax ID checksum, phone digit-count, IP not-private filter).
- `ScannerChain` — async sequential orchestrator with early-exit-on-block.
- `AIShield` main class — `scan()`, `check_budget()`, `record_cost()`, LRU
  scan cache, optional audit logger.
- `PolicyEngine` — 3 presets (`public_website`, `internal_support`,
  `ops_agent`).
- `ToolPolicyScanner` — deterministic MCP allowlist gate + SHA-256 manifest
  pinning.
- `CostTracker` — soft/hard budgets (hourly/daily/monthly), in-memory or
  Redis backend, atomic `INCRBYFLOAT` semantics.
- `CanaryToken` — generation + leak-detection helpers.
- `AuditLogger` — async batched writer with console + memory store
  implementations.
- `ScanLRUCache` — TTL + LRU with insertion-order semantics.
- MCP server demo (`ai-shield-mcp` console-script) with 3 tools:
  `scan_input`, `record_llm_cost`, `check_budget` (FastMCP, stdio transport).
- Pydantic v2 models for all public types.
- 90%+ test coverage target on scanners + validators.

### Provenance
- All heuristic patterns ported 1:1 from
  [`ai-shield/packages/core/src/scanner/heuristic.ts`](https://github.com/studiomeyer-io/ai-shield/blob/main/packages/core/src/scanner/heuristic.ts)
  (4 audit rounds, MIT).
- IBAN mod-97 / Luhn algorithms are public ISO 13616-1 / ISO 7812 references.
