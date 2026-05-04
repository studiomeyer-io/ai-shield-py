"""Audit logger + store tests — hashing, buffer flush, batch."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import unicodedata

import pytest

from ai_shield.audit.logger import (
    AuditLogger,
    ConsoleAuditStore,
    MemoryAuditStore,
    _hash_input,
    _hash_user,
)


class TestHashInput:
    def test_nfkd_normalised_before_hash(self) -> None:
        a = "café"  # NFC pre-composed
        b = unicodedata.normalize("NFD", "café")  # NFD decomposed
        assert _hash_input(a) == _hash_input(b)

    def test_deterministic(self) -> None:
        assert _hash_input("hello") == _hash_input("hello")

    def test_different_inputs_differ(self) -> None:
        assert _hash_input("a") != _hash_input("b")

    def test_returns_64_hex_chars(self) -> None:
        h = _hash_input("anything")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestHashUser:
    def test_none_input_passes_through(self) -> None:
        assert _hash_user(None) is None

    def test_truncated_to_32_chars(self) -> None:
        h = _hash_user("user-1")
        assert h is not None
        assert len(h) == 32

    def test_deterministic(self) -> None:
        assert _hash_user("u") == _hash_user("u")

    def test_truncation_matches_sha256_prefix(self) -> None:
        full = hashlib.sha256(b"user-1").hexdigest()
        assert _hash_user("user-1") == full[:32]


class TestMemoryAuditStore:
    @pytest.mark.asyncio
    async def test_write_appends(self) -> None:
        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=1)
        await logger.log(text="hi", decision="allow", violations=[], score=0.0)
        await logger.flush()
        assert len(store.records) == 1
        assert store.records[0].decision == "allow"

    @pytest.mark.asyncio
    async def test_input_text_never_stored(self) -> None:
        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=1)
        secret = "PII: ssn=123-45-6789"
        await logger.log(text=secret, decision="block", violations=[], score=1.0)
        await logger.flush()
        # Plain text must not leak into the dumped record.
        dumped = store.records[0].model_dump_json()
        assert "123-45-6789" not in dumped
        assert "ssn=" not in dumped


class TestConsoleAuditStore:
    @pytest.mark.asyncio
    async def test_writes_jsonlines_to_sink(self) -> None:
        sink = io.StringIO()
        store = ConsoleAuditStore(sink=sink)
        logger = AuditLogger(store=store, max_buffer=1)
        await logger.log(text="x", decision="allow", violations=[], score=0.0)
        await logger.flush()
        out = sink.getvalue().strip()
        # Must be one valid JSON line.
        parsed = json.loads(out)
        assert parsed["decision"] == "allow"


class TestBufferFlush:
    @pytest.mark.asyncio
    async def test_max_buffer_triggers_immediate_flush(self) -> None:
        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=3, flush_interval_seconds=60.0)
        for _ in range(3):
            await logger.log(text="x", decision="allow", violations=[], score=0.0)
        # After 3 logs, buffer should auto-flush.
        await asyncio.sleep(0.05)
        assert len(store.records) == 3

    @pytest.mark.asyncio
    async def test_explicit_flush(self) -> None:
        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=100, flush_interval_seconds=60.0)
        await logger.log(text="x", decision="allow", violations=[], score=0.0)
        # Not yet flushed.
        assert len(store.records) == 0
        await logger.flush()
        assert len(store.records) == 1

    @pytest.mark.asyncio
    async def test_close_flushes_pending(self) -> None:
        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=100, flush_interval_seconds=60.0)
        await logger.log(text="x", decision="allow", violations=[], score=0.0)
        await logger.close()
        assert len(store.records) == 1


class TestRecordShape:
    @pytest.mark.asyncio
    async def test_record_carries_score_and_violations(self) -> None:
        from ai_shield.types import Violation

        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=1)
        v = Violation(
            type="pii_exposure",
            detector="pii:email",
            severity="medium",
            message="email",
            confidence=0.9,
        )
        await logger.log(text="x", decision="warn", violations=[v], score=0.4)
        await logger.flush()
        rec = store.records[0]
        assert rec.score == 0.4
        assert len(rec.violations) == 1
        assert rec.violations[0].detector == "pii:email"

    @pytest.mark.asyncio
    async def test_user_id_hash_truncated_to_32(self) -> None:
        store = MemoryAuditStore()
        logger = AuditLogger(store=store, max_buffer=1)
        await logger.log(
            text="x",
            decision="allow",
            violations=[],
            score=0.0,
            user_id="user-1",
        )
        await logger.flush()
        h = store.records[0].user_id_hash
        assert h is not None
        assert len(h) == 32
