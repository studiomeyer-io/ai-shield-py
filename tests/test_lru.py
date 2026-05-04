"""TTL-aware insertion-order LRU cache tests."""

from __future__ import annotations

import time

import pytest

from ai_shield.cache.lru import ScanLRUCache


class TestConstruction:
    def test_max_size_zero_rejected(self) -> None:
        with pytest.raises(ValueError):
            ScanLRUCache(max_size=0)

    def test_negative_ttl_rejected(self) -> None:
        with pytest.raises(ValueError):
            ScanLRUCache(ttl_ms=-1)

    def test_default_construction_ok(self) -> None:
        cache: ScanLRUCache[str] = ScanLRUCache()
        assert len(cache) == 0


class TestBasicOps:
    def test_set_and_get(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(max_size=10, ttl_ms=10_000)
        cache.set("a", 1)
        assert cache.get("a") == 1
        assert len(cache) == 1

    def test_missing_key_returns_none(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache()
        assert cache.get("missing") is None

    def test_set_overwrites_existing(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache()
        cache.set("a", 1)
        cache.set("a", 2)
        assert cache.get("a") == 2
        assert len(cache) == 1

    def test_has_respects_ttl(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(ttl_ms=1)
        cache.set("a", 1)
        time.sleep(0.005)
        assert cache.has("a") is False

    def test_delete_removes_key(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache()
        cache.set("a", 1)
        assert cache.delete("a") is True
        assert cache.get("a") is None
        assert cache.delete("missing") is False

    def test_clear(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache()
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert len(cache) == 0


class TestEviction:
    def test_evicts_oldest_when_full(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(max_size=3, ttl_ms=60_000)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.set("d", 4)  # evicts 'a'
        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        assert cache.get("d") == 4

    def test_get_promotes_to_mru(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(max_size=3, ttl_ms=60_000)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        # Touch 'a' so it becomes MRU
        cache.get("a")
        cache.set("d", 4)  # evicts oldest = 'b'
        assert cache.get("a") == 1
        assert cache.get("b") is None
        assert cache.get("c") == 3
        assert cache.get("d") == 4


class TestExpiration:
    def test_expired_get_returns_none(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(ttl_ms=1)
        cache.set("a", 1)
        time.sleep(0.005)
        assert cache.get("a") is None

    def test_zero_ttl_means_no_expiration(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(ttl_ms=0)
        cache.set("a", 1)
        # No sleep — but at ttl=0 entries never expire by design
        assert cache.get("a") == 1

    def test_prune_removes_expired(self) -> None:
        cache: ScanLRUCache[int] = ScanLRUCache(ttl_ms=1)
        cache.set("a", 1)
        cache.set("b", 2)
        time.sleep(0.005)
        cache.set("c", 3)  # fresh, with same ttl=1ms but just inserted
        time.sleep(0.005)  # now c is also expired
        removed = cache.prune()
        assert removed == 3
        assert len(cache) == 0
