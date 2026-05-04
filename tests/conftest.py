"""Pytest configuration — async mode + ReDoS hard-cap defaults."""

from __future__ import annotations

import pytest_asyncio  # noqa: F401  (registers fixtures)


# pytest-timeout's `timeout` is set globally in pyproject.toml
# ([tool.pytest.ini_options] timeout = 5). For ReDoS-sensitive tests,
# individual cases must additionally decorate with
# `@pytest.mark.timeout(0.1)` to assert the per-pattern hard-cap.
