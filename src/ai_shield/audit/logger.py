"""Async batched audit logger.

1:1 port of `packages/core/src/audit/logger.ts`.

Inputs are NEVER stored in plain text — only `sha256(input)` and an
optional `sha256(user_id)[:32]` end up on disk / in the store.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TextIO

from ai_shield.audit.types import AuditStore
from ai_shield.types import AuditRecord, Decision, Violation


def _hash_input(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def _hash_user(user_id: str | None) -> str | None:
    if user_id is None:
        return None
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:32]


@dataclass
class ConsoleAuditStore:
    """Write JSON lines to a TextIO sink (default stderr)."""

    sink: TextIO = field(default_factory=lambda: sys.stderr)

    async def write(self, record: AuditRecord) -> None:
        self.sink.write(record.model_dump_json() + "\n")
        self.sink.flush()

    async def write_batch(self, records: list[AuditRecord]) -> None:
        for r in records:
            self.sink.write(r.model_dump_json() + "\n")
        self.sink.flush()

    async def flush(self) -> None:
        self.sink.flush()

    async def close(self) -> None:
        self.sink.flush()


@dataclass
class MemoryAuditStore:
    """In-process AuditStore — useful for tests and short-lived processes."""

    records: list[AuditRecord] = field(default_factory=list)

    async def write(self, record: AuditRecord) -> None:
        self.records.append(record)

    async def write_batch(self, records: list[AuditRecord]) -> None:
        self.records.extend(records)

    async def flush(self) -> None:
        return None

    async def close(self) -> None:
        return None


class AuditLogger:
    """Buffer audit records and flush periodically to an AuditStore."""

    def __init__(
        self,
        store: AuditStore | None = None,
        *,
        flush_interval_seconds: float = 5.0,
        max_buffer: int = 100,
    ) -> None:
        self.store: AuditStore = store if store is not None else ConsoleAuditStore()
        self._flush_interval = flush_interval_seconds
        self._max_buffer = max_buffer
        self._buffer: list[AuditRecord] = []
        self._lock = asyncio.Lock()
        self._closed = False
        self._task: asyncio.Task[None] | None = None

    async def log(
        self,
        *,
        text: str,
        decision: Decision,
        violations: list[Violation],
        score: float,
        user_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id_hash=_hash_user(user_id),
            input_sha256=_hash_input(text),
            decision=decision,
            violations=violations,
            score=score,
            metadata=metadata or {},
        )
        async with self._lock:
            self._buffer.append(record)
            buffer_full = len(self._buffer) >= self._max_buffer

        if buffer_full:
            await self.flush()
        else:
            self._ensure_task()

    def _ensure_task(self) -> None:
        if self._closed:
            return
        if self._task is not None and not self._task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._task = loop.create_task(self._auto_flush())

    async def _auto_flush(self) -> None:
        try:
            await asyncio.sleep(self._flush_interval)
            await self.flush()
        except asyncio.CancelledError:
            pass

    async def flush(self) -> None:
        async with self._lock:
            if not self._buffer:
                return
            batch = self._buffer
            self._buffer = []
        await self.store.write_batch(batch)

    async def close(self) -> None:
        self._closed = True
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
        await self.flush()
        await self.store.close()
