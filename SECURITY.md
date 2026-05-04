# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

studiomeyer-aishield is in active early development. Only the latest
0.1.x patch release receives security fixes. v0.2 will widen this to
"latest minor".

## Reporting a Vulnerability

studiomeyer-aishield is an LLM security middleware — a vulnerability
here may bypass an entire application's prompt-injection or PII gate.
We take vulnerability reports seriously.

**Please do NOT open a public GitHub issue for security problems.**

Email **matthias@studiomeyer.io** with:

1. A clear description of the issue and its impact.
2. Steps to reproduce (a failing pytest case is ideal).
3. Affected version(s) — `pip show studiomeyer-aishield`.
4. Your platform and Python version (`python -V`).
5. Optional: a suggested fix or mitigation.

We will acknowledge your report within **72 hours**, share an initial
triage assessment within **7 days**, and aim to ship a fix or
mitigation within **30 days** for high/critical severity.

If you have not received a reply after 7 days, feel free to escalate
publicly via a generic GitHub issue ("awaiting response on private
report") — we will pick it up.

## Scope

In scope:

- **Bypasses of the scanner pipeline.** Heuristic regex evasions,
  PII validator false-negatives or ReDoS patterns, missing PII
  classes that map to common standards (Luhn, IBAN mod-97, BMF
  mod-11/10, ITU E.164).
- **Auth/integrity issues** in the FastMCP `ai-shield-mcp` server
  (stdio-injection, unvalidated tool input, schema bypass).
- **Cost-tracker race conditions** that allow over-budget calls
  through the gate (e.g. non-atomic Redis increments).
- **Audit-log integrity**: tamperable hashing, missing fields, plain
  text leakage, retention failures.
- **Supply-chain** issues we missed (`pip-audit`, `safety`, transitive
  CVEs).

Out of scope (still report them, but they are not security-tier):

- Performance regressions outside the documented latency budgets.
- README or documentation typos.
- v0.2-backlog gaps that are already documented (output-scanning,
  PostgreSQL audit store, numpy-based anomaly detection, FastMCP 3.0
  migration).

## ReDoS Disclosure

The core scanner uses Python's built-in `re` module which is not
ReDoS-safe by design. v0.1.1 reworked the credit_card and phone
patterns to remove nested optional quantifiers and added
adversarial regression tests under `pytest.mark.timeout(2)`. If you
find a 4-KB-or-shorter input that pushes any pattern past 2 seconds
on commodity hardware, report it under this policy — we will treat
it as HIGH severity.

The longer-term fix is the `google-re2` Python binding which
guarantees linear-time matching; tracked for v0.2.

## Coordinated Disclosure

We follow responsible coordinated disclosure. After a fix lands and
a patched release is published to PyPI, we will:

1. Issue a CHANGELOG entry referencing the CVE (if assigned) or a
   GitHub Security Advisory.
2. Credit the reporter (if they wish to be credited).
3. Optionally backfill a regression test against the now-patched
   payload.

If you would like a CVE assigned, we can request one via GitHub once
the fix is in `main`.

## PGP / Encrypted Email

We do not currently offer PGP. If you need encrypted transport,
request a one-time Signal handle via the email above and we will set
it up.

## Acknowledgements

studiomeyer-aishield is a 1:1 Python port of
[ai-shield-core](https://github.com/studiomeyer-io/ai-shield) (TypeScript,
4 audit rounds). Threat model, heuristic-pattern set and PII validator
catalogue derive from that codebase.
