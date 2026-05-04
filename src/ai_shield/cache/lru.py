"""TTL + insertion-order LRU cache for scan results.

1:1 port of `packages/core/src/cache/lru.ts` — relies on dict-insertion
order semantics (guaranteed in CPython 3.7+).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, TypeVar

V = TypeVar("V")


@dataclass
class _Entry(Generic[V]):
    value: V
    expires_at: float


class ScanLRUCache(Generic[V]):
    """Least-recently-used cache with per-entry TTL."""

    def __init__(self, *, max_size: int = 1000, ttl_ms: int = 300_000) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        if ttl_ms < 0:
            raise ValueError("ttl_ms must be >= 0")
        self._max_size = max_size
        self._ttl_ms = ttl_ms
        self._data: OrderedDict[str, _Entry[V]] = OrderedDict()

    def get(self, key: str) -> V | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        if self._expired(entry):
            del self._data[key]
            return None
        # promote to MRU
        self._data.move_to_end(key)
        return entry.value

    def set(self, key: str, value: V) -> None:
        if key in self._data:
            del self._data[key]
        elif len(self._data) >= self._max_size:
            # evict oldest
            self._data.popitem(last=False)
        self._data[key] = _Entry(value=value, expires_at=self._now_ms() + self._ttl_ms)

    def has(self, key: str) -> bool:
        entry = self._data.get(key)
        if entry is None:
            return False
        if self._expired(entry):
            del self._data[key]
            return False
        return True

    def delete(self, key: str) -> bool:
        if key in self._data:
            del self._data[key]
            return True
        return False

    def clear(self) -> None:
        self._data.clear()

    def prune(self) -> int:
        """Remove all expired entries. Returns count removed."""
        keys = [k for k, e in self._data.items() if self._expired(e)]
        for k in keys:
            del self._data[k]
        return len(keys)

    def __len__(self) -> int:
        return len(self._data)

    @staticmethod
    def _now_ms() -> float:
        return time.monotonic() * 1000.0

    def _expired(self, entry: _Entry[V]) -> bool:
        if self._ttl_ms == 0:
            return False
        return self._now_ms() >= entry.expires_at
