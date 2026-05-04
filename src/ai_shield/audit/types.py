"""AuditStore protocol — pluggable backend for AuditLogger.

1:1 port of `packages/core/src/audit/types.ts`.
"""

from __future__ import annotations

from typing import Protocol

from ai_shield.types import AuditRecord


class AuditStore(Protocol):
    """Pluggable backend for AuditLogger writes."""

    async def write(self, record: AuditRecord) -> None: ...
    async def write_batch(self, records: list[AuditRecord]) -> None: ...
    async def flush(self) -> None: ...
    async def close(self) -> None: ...
