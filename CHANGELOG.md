# Changelog

All notable changes to ai-shield-py will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-22

Core-port pass — brings the Python port up to the TypeScript `ai-shield-core`
v0.2/v0.3 feature waves with the two missing scanner *directions* plus a new
evasion fold. Until now the port only answered "is this prompt safe to send?";
v0.3 adds "is this ingested data safe to read?" and "is this model output safe
to act on?", the two halves OWASP LLM01:2025 and LLM05:2025 are actually about.
Additive only — no API breakage, no behavioural regression on the existing
catalogue. Test count grows 376 → 411 (+35).

### Added

- **Indirect prompt-injection scanner (`ingestion.py`, OWASP LLM01).** New
  `scan_ingested(content, source)` and `scan_tool_output(tool_name, content)`
  coroutines scan non-user content — RAG chunks, MCP tool descriptions and tool
  *results*, stored memory, scraped web pages, agent-to-agent messages — before
  it enters the model context. Runs the base heuristic at a stricter per-source
  threshold AND adds source-specific patterns the user channel does not see
  (`rag` / `tool_desc` / `tool_output` / `memory` / `web` / `agent_output`).
  Base-heuristic hits are re-tagged `ingested_injection`. On `block`,
  `sanitized_text` is set to `""` so a naive `if not safe: use(sanitized)` path
  is a no-op rather than a vulnerability. `scan_tool_output` stamps the
  originating `tool_name` (capped 120 chars) into every violation's metadata.
- **Output scanner (`output.py`, OWASP LLM05 + LLM02).** New `scan_output(text,
  *, sinks, canary_tokens, pii, pii_action)` coroutine guards a model RESPONSE
  before it reaches a SQL engine, shell, HTML sink or template renderer. Five
  checks: secret leak (15 anchored provider-prefix formats — OpenAI/Anthropic/
  AWS/GitHub/Google/GCP-SA/HF/npm/Slack/Stripe/JWT/PEM/DSN — with a
  scrub-on-block guarantee that survives zero-width splitting), output injection
  grouped by downstream sink (`sql` / `shell` / `html` / `template`, incl.
  markdown-image data exfiltration), system-prompt leak (exact canary match
  first, then heuristic), jailbreak indicator, and output-side PII (redact by
  default). `sanitized_text` carries the redacted/masked output; gate on
  `decision` before forwarding.
- **Typoglycemia defense (`heuristic.py`).** Scrambled-middle evasion
  ("Ignroe all prevoius instrcutions") reads fine to an LLM but dodges literal
  patterns. A new lossy `unscramble()` view folds permuted keywords back to
  canonical form and re-tests the high-value injection categories; matches are
  tagged `metadata.evasion == "typoglycemia"`. Matching is **anagram-only**
  (same length + first/last letter + sorted-middle multiset) — deliberately NOT
  edit-distance: a single Damerau-Levenshtein edit between two real words
  ("forgot"→"forget", "rulers"→"rules") is a frequent false positive, and a
  security scanner that blocks benign prose just gets disabled. Anagram folding
  is false-positive-free on a 116-word benign corpus. `damerau_levenshtein(a, b,
  cap)` ships as a standalone capped-DP utility (exported, not used in the fold).
- **New public exports.** `scan_ingested`, `scan_tool_output`, `scan_output`,
  `unscramble`, `damerau_levenshtein`, and the `IngestionSource` / `OutputSink`
  literal types. New `ViolationType` members: `ingested_injection`,
  `output_injection`, `secret_leak`, `system_prompt_leak`, `jailbreak_indicator`.

Three new test modules — `tests/test_ingestion.py`, `tests/test_output.py`,
`tests/test_typoglycemia.py` — each pairing bypass-now-caught cases with benign
false-positive guards (incl. the anagram-vs-edit-distance regression). Coverage
holds at 94.9% (gate ≥90%); `output.py` is at 100%.

## [0.2.0] - 2026-06-21

Detection-parity pass — ports the four new injection detectors from the
TypeScript `ai-shield-core` (branch `oss-improve/injection-detection-gaps`)
to reach feature parity. Additive only: no API breakage, no behavioural
regression on the existing 42-rule catalogue. Test count grows 311 → 376
(+65). Minor bump under SemVer for the new functionality.

### Added

- **Unicode TAG-block smuggling (TAG-001).** `normalize()` now de-tags
  the invisible Unicode TAG block (U+E0000–U+E007F) before NFKD, so an
  instruction spelled entirely in tag chars surfaces as the ASCII it
  carries and is scored by the normal rules. A standalone-presence signal
  (`heuristic:TAG-001`, score 0.9) fires on bare/smuggled tag runs.
  Well-formed flag/subdivision emoji (base U+1F3F4 … U+E007F, e.g. the
  Wales/Scotland/Texas flags) are excluded via
  `strip_well_formed_tag_sequences()`; an instruction disguised inside a
  flag wrapper is still decoded and caught. New public helpers: `de_tag`,
  `has_tag_chars`, `has_standalone_tag_chars`,
  `strip_well_formed_tag_sequences`.
- **Multilingual instruction overrides (DE / ES / FR).** Four new rules
  (`INJ-DE-1`, `INJ-DE-2`, `INJ-ES-1`, `INJ-FR-1`) in the existing
  `instruction_override` category catch German/Spanish/French "ignore
  previous instructions" payloads that the English rules missed. `INJ-DE-1`
  is negator-aware — "Vergiss **nicht**, die vorherigen Anweisungen zu
  lesen" stays allowed via a bounded negative lookahead.
- **Policy-puppetry / forged-transcript (DELIM-PP-1..5).** Four fake-config
  delimiter rules (`interaction-config`, `allowed-modes`, `blocked-strings`,
  privileged `<role>`) in `delimiter_injection`, plus a forged chat-
  transcript signal (`heuristic:DELIM-PP-5`, score 0.85) via
  `detect_forged_transcript()`. The transcript signal requires an attack
  co-signal (override keyword inside a turn, OR ≥2 forged turns), so a lone
  benign `<assistant>…</assistant>` pair stays allowed.
- **Leetspeak char-substitution evasion.** A lossy `leet_decode()` view
  ("1gn0r3 pr3v10us 1nstruct10ns" → "ignore previous instructions") is
  re-tested as an ADDITIONAL pass, scoped to the high-value categories
  (`instruction_override`, `role_manipulation`,
  `system_prompt_extraction`, `tool_abuse`). Benign digit text
  ("buy 3 for 5 dollars") is unaffected — `encoding_evasion` is excluded
  from the leet re-test. Matches tagged `metadata.evasion == "leetspeak"`.

The catalogue grows 42 → 50 regex patterns (all in the existing 8
categories); the three non-regex signals (TAG-001, DELIM-PP-5, leetspeak
re-test) live in `HeuristicScanner.scan`. Each detector ships with both a
bypass-now-caught test and a benign false-positive guard test in
`tests/test_detection_parity.py`, plus ReDoS hard-caps for the new
patterns.

## [0.1.1] - 2026-05-04

Cold cross-review hardening pass — 3-agent sweep (Analyst + Critic +
Research) on the v0.1.0 release identified two CI-deploy-blockers,
three security-class bugs, four medium-severity items and one PEP
gap. All addressed below. No API changes, no behavioural regression.
Test count grows 297 → 311 (+14).

### Fixed

- **CI broken: `Twine check` step** in `.github/workflows/ci.yml`
  failed since v0.1.0 because `twine` was not in
  `[project.optional-dependencies] dev`. Added `twine>=5.0.0` to dev
  extras and switched the step from `python -m twine` to plain
  `twine` (now in PATH after `uv sync --dev`).
- **Trusted Publisher URL mismatch.** `publish.yml` declared
  `environment.url = https://pypi.org/p/ai-shield` but the package
  was renamed to `studiomeyer-aishield` in v0.1.0 (Bosch's
  `aishield@0.1.7` blocked the simpler name, see S990). Updated to
  `https://pypi.org/p/studiomeyer-aishield`. The Pending Publisher
  on PyPI must match this URL or OIDC will fail with
  `invalid-publisher`.
- **PII credit-card regex ReDoS.** `(?:\d[ -]?){12,18}\d` had
  catastrophic backtracking on adversarial `1 2 3 4 5 ...` input
  (multiple seconds on a 4 KB payload). Replaced with anchored
  `\b(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|\d{12,19})\b`, validated
  by Luhn checksum. Three real card formats (Visa spaced, Visa
  dashed, raw, Amex 15-digit) still match.
- **PII phone regex ReDoS.** Nested `(?:\(?\d{2,4}\)?[\s.-]?){2,5}`
  was equally exploitable. Replaced with linear character-class
  `(?:\+|\b)\d[\d\s.()\-]{6,18}\d`, validated by ITU E.164 7–15
  digit count. `+49 30 12345678`, `(212) 555-1234` and
  `0049-30-1234567` still match.
- **German Tax ID validator** previously accepted any 11-digit
  string starting 1–9 (massive false-positive rate). Replaced with
  the BMF mod-11/10 algorithm (Anlage zum BMF-Schreiben vom
  9. Juli 2009): exactly one repeated digit in the first 10 (no
  digit four-or-more times), check digit must match. Verified
  against `26954371827`. The v0.1.0 false-positive
  `12345678901` is now correctly rejected.
- **`AuditLogger._auto_flush` was one-shot.** A single `await sleep`
  followed by `flush` and exit. Records could remain stranded if no
  follow-up `log()` re-armed the task. Now runs as a real loop until
  `close()` cancels it.
- **`asyncio.get_event_loop()` deprecated** in `cost/tracker.py`
  `MemoryStore.expire` and `_sweep_expired`. Replaced with
  `get_running_loop()` (Python 3.12 deprecation, removed Python
  3.14). Both call sites are inside async methods so a running loop
  is always present.

### Added

- `SECURITY.md` — vulnerability disclosure policy (72 h ack, 30 d
  fix target, scope, ReDoS disclosure clause, coordinated
  disclosure).
- `CONTRIBUTING.md` — build/test workflow, MSRV pin, what we accept,
  coding standards (no `print`, no `get_event_loop`, ReDoS-safe
  regex policy, type-hints everywhere).
- `src/ai_shield/py.typed` — PEP 561 marker so downstream `mypy`
  consumers pick up our types. Wired into the wheel via
  `[tool.hatch.build.targets.wheel.force-include]`.
- README "Status" section listing v0.1 vs v0.2 backlog as a single
  table (output-scanning, Postgres audit store, numpy z-score,
  FastMCP 3.0, google-re2). No more spelunking through CHANGELOG to
  find the open items.

### Removed

- **Ghost extras `[postgres]` and `[ml]`** from `pyproject.toml`.
  Both were declared in v0.1.0 but never wired to a code path
  (`anomaly.py` uses stdlib `math`, no asyncpg-backed
  AuditStore implementation exists). Removing them stops users from
  running `pip install studiomeyer-aishield[postgres]` and finding
  nothing changed. Tracked for v0.2 in the README "Status" table.

### Hardened

- `actions/attest-build-provenance` bumped `@v1` → `@v2` in
  `publish.yml` (mcp-armor S988 also pinned to v2).
- `TestReDoSAdversarial` test class added to `tests/test_pii.py`
  with 5 cases pinned to a 2 s `pytest.mark.timeout(2)` budget on
  4 KB pathological inputs — these would have hung the v0.1.0
  patterns for many seconds.

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
