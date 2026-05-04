# Contributing to studiomeyer-aishield

Thanks for considering a contribution. studiomeyer-aishield is a
security middleware for LLM apps; we are deliberately conservative
about scope and deliberately strict about evidence. The bar for new
code is "reproduces a real bypass and ships with a regression test".

## Quick Start

```sh
git clone https://github.com/studiomeyer-io/ai-shield-py
cd ai-shield-py
uv sync --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src/ai_shield
uv run pytest --cov=ai_shield --cov-report=term-missing
```

MSRV is **Python 3.10** (uses `from __future__ import annotations`,
`tomllib` only behind `if sys.version_info >= (3, 11)`). CI tests
3.10 / 3.11 / 3.12 / 3.13 on Linux and macOS — your patch needs to
compile and pass tests on all four.

## What we accept

- **New PII classes** with a real validator (Luhn, mod-97, mod-11/10,
  E.164 — not just length checks). Add a `PIIPattern` entry, a
  validator with at-least-three-known-valid + at-least-three-known-invalid
  test cases, and a masking strategy that preserves the last 4 digits.
- **New prompt-injection patterns.** Each new pattern needs at least
  one positive test (real attack string from the wild) and at least
  one negative test (false-positive avoidance).
- **Scanner improvements.** New evasion classes, new normalization
  steps, performance wins — all welcome, but each one needs a
  regression test that fails on `main` and passes with your patch.
- **ReDoS hardening.** New adversarial test cases for
  `TestReDoSAdversarial` (`tests/test_pii.py`). Pin the 2 s timeout
  via `@pytest.mark.timeout(2)`.
- **Bug fixes.** A failing test in your PR description is the fastest
  path to merge.
- **Docs.** Typo fixes, clarifications, ecosystem links.

## What we are slow on

- New top-level features (PostgreSQL audit store, numpy-based anomaly
  detection, output-scanning, FastMCP 3.0 migration). These are on
  the v0.2 roadmap and tracked in CHANGELOG "Known limitations".
  Please open an issue to discuss before opening a large PR.
- Adding runtime dependencies. The library is deliberately small —
  two runtime deps (`pydantic`, `mcp`). Optional features (Redis,
  Postgres, ML) live behind `[project.optional-dependencies]` extras.
  Each new transitive crate is a supply-chain surface for a security
  tool. We weigh `pip-audit` history and maintainership before
  accepting.
- Pull-request rewrites of the TS port. The 1:1 port to
  `ai-shield-core` is intentional — it gives us a known reference
  implementation. Substantive divergences need an explicit decision.

## Pull Request Process

1. Open an issue or draft PR first for anything non-trivial. We do
   not want either of us to waste a weekend on a refactor we cannot
   ship.
2. One logical change per PR. Easier to review, easier to revert.
3. CI must be green: ruff lint, ruff format, mypy strict, pytest
   `--cov-fail-under=90`, twine check, sdist + wheel build.
4. CHANGELOG entry under `[Unreleased]` describing the user-visible
   change in plain English.
5. For security-impacting changes, see [SECURITY.md](SECURITY.md) —
   please email instead of opening a public PR.

## Coding Standards

- **Type hints everywhere.** `mypy --strict` is the baseline. Use
  `from __future__ import annotations` for forward refs, `Protocol`
  for structural typing of optional backends.
- **Pydantic v2** for any user-facing data class. Strict for input,
  lax for LLM output (per Research Pattern S991).
- **No `print()`** outside `mcp_server.py` startup banner — use
  `logging` and let downstream consumers filter.
- **No `asyncio.get_event_loop()`** — `get_running_loop()` only.
  Deprecation since Python 3.12.
- **`timezone.utc`** rather than `datetime.UTC`. We pin Python 3.10
  as MSRV and `datetime.UTC` is 3.11+.
- **Regex must be ReDoS-safe.** No nested optional quantifiers.
  Adversarial test under `TestReDoSAdversarial` for any new pattern.
- **Inputs are NEVER logged in plain text.** SHA-256 only — see
  `audit/logger.py::_hash_input`.
- **`pytest-timeout`** is installed and active. Default is 5 s per
  test (`pyproject.toml`). Slow tests must justify the override.

## Testing

- Unit tests live in `tests/test_<module>.py`. Use `pytest.mark.asyncio`
  for the async API.
- Coverage gate: 90 %+ on `ai_shield/`. We do not measure coverage
  on tests themselves.
- Adversarial regex tests live in `tests/test_pii.py::TestReDoSAdversarial`
  and `tests/test_heuristic.py::TestReDoSAdversarial`.
- Smoke-test the FastMCP server with `uv run ai-shield-mcp` plus
  `mcp inspector` if you change `mcp_server.py`.

## Releasing (maintainers)

- Version bump in `pyproject.toml` and the top of `CHANGELOG.md`.
- Tag `vX.Y.Z` on `main`.
- The publish workflow runs `uv build` and publishes to PyPI via
  Trusted Publishing OIDC — no API token in CI.
- After release, verify on PyPI and via
  `pip install studiomeyer-aishield==X.Y.Z`.

## License

By contributing, you agree your work is licensed under the [MIT
License](LICENSE).

## Code of Conduct

Be kind. Assume good faith. We are a small project — do not bring
drama. Disagreement is fine, contempt is not.
