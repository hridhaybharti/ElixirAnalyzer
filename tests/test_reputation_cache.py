"""Tests for reputation cache."""

import pytest
import time
from backend.utils.reputation_cache import TTLCache, HybridReputationCache


def test_ttl_cache_set_get():
    """Test basic set/get operations."""
    cache = TTLCache(ttl_seconds=10)
    cache.set("key1", {"value": "data"})
    result = cache.get("key1")
    assert result == {"value": "data"}


def test_ttl_cache_expiration():
    """Test that TTL cache expires entries."""
    cache = TTLCache(ttl_seconds=1)  # 1 second TTL
    cache.set("key1", {"value": "data"})
    time.sleep(1.1)
    result = cache.get("key1")
    assert result is None


def test_ttl_cache_delete():
    """Test cache deletion."""
    cache = TTLCache(ttl_seconds=10)
    cache.set("key1", {"value": "data"})
    cache.delete("key1")
    result = cache.get("key1")
    assert result is None


def test_ttl_cache_stats():
    """Test cache statistics."""
    cache = TTLCache(ttl_seconds=10)
    cache.set("key1", "value1")
    cache.set("key2", "value2")
    stats = cache.stats()
    assert stats["total_keys"] == 2
    assert stats["active_keys"] == 2
    assert stats["expired_keys"] == 0


@pytest.mark.asyncio
async def test_hybrid_cache_memory_fallback():
    """Test hybrid cache memory fallback."""
    cache = HybridReputationCache(ttl_seconds=10)
    await cache.initialize()
    
    await cache.set("key1", {"value": "data"})
    result = await cache.get("key1")
    assert result == {"value": "data"}
    
    await cache.close()


@pytest.mark.asyncio
async def test_hybrid_cache_stats():
    """Test hybrid cache statistics."""
    cache = HybridReputationCache(ttl_seconds=10)
    await cache.initialize()
    
    await cache.set("key1", "value1")
    stats = await cache.stats()
    assert "memory" in stats
    assert "redis_enabled" in stats
    
    await cache.close()


@pytest.mark.asyncio
async def test_hybrid_cache_delete():
    """Test hybrid cache deletion."""
    cache = HybridReputationCache(ttl_seconds=10)
    await cache.initialize()
    
    await cache.set("key1", "value1")
    await cache.delete("key1")
    result = await cache.get("key1")
    assert result is None
    
    await cache.close()
