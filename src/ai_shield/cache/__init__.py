"""Cache subpackage — TTL + insertion-order LRU."""

from __future__ import annotations

from ai_shield.cache.lru import ScanLRUCache

__all__ = ["ScanLRUCache"]
