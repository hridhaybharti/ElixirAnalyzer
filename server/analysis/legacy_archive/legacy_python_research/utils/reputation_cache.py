"""Reputation Cache Layer.

Supports Redis if REDIS_URL env var is set.
Falls back to in-memory TTL cache if Redis unavailable.
TTL = 24 hours.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("reputation_cache")


class TTLCache:
    """Simple in-memory TTL cache."""

    def __init__(self, ttl_seconds: int = 86400):  # 24 hours
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        if key not in self._cache:
            return None
        expires_at, value = self._cache[key]
        if time.time() > expires_at:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Set value in cache with TTL."""
        expires_at = time.time() + self.ttl_seconds
        self._cache[key] = (expires_at, value)

    def delete(self, key: str) -> None:
        """Delete key from cache."""
        if key in self._cache:
            del self._cache[key]

    def clear(self) -> None:
        """Clear all cache."""
        self._cache.clear()

    def stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        now = time.time()
        expired = sum(1 for _, (exp, _) in self._cache.items() if now > exp)
        return {
            "total_keys": len(self._cache),
            "expired_keys": expired,
            "active_keys": len(self._cache) - expired,
            "ttl_seconds": self.ttl_seconds,
        }


class RedisCache:
    """Redis-backed cache."""

    def __init__(self, redis_url: str, ttl_seconds: int = 86400):
        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds
        self.redis: Optional[Any] = None

    async def connect(self) -> None:
        """Connect to Redis."""
        try:
            import aioredis
        except ImportError:
            logger.warning("aioredis not installed; Redis cache disabled")
            return

        try:
            # Attempt to connect to Redis
            # aioredis.from_url returns a Redis connection
            self.redis = await aioredis.from_url(self.redis_url)
            logger.info(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis = None

    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis."""
        if not self.redis:
            return None
        try:
            value = await self.redis.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None

    async def set(self, key: str, value: Any) -> None:
        """Set value in Redis with TTL."""
        if not self.redis:
            return
        try:
            await self.redis.setex(key, self.ttl_seconds, json.dumps(value))
        except Exception as e:
            logger.error(f"Redis set error: {e}")

    async def delete(self, key: str) -> None:
        """Delete key from Redis."""
        if not self.redis:
            return
        try:
            await self.redis.delete(key)
        except Exception as e:
            logger.error(f"Redis delete error: {e}")

    async def clear(self) -> None:
        """Clear all cache (dangerous in production!)."""
        if not self.redis:
            return
        try:
            await self.redis.flushdb()
        except Exception as e:
            logger.error(f"Redis clear error: {e}")

    async def stats(self) -> Dict[str, Any]:
        """Get cache statistics from Redis."""
        if not self.redis:
            return {"status": "disconnected"}
        try:
            info = await self.redis.info()
            return {
                "status": "connected",
                "used_memory": info.get("used_memory_human", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "ttl_seconds": self.ttl_seconds,
            }
        except Exception as e:
            logger.error(f"Redis stats error: {e}")
            return {"status": "error", "error": str(e)}

    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()


class HybridReputationCache:
    """Hybrid cache: tries Redis first, falls back to in-memory TTL cache."""

    def __init__(self, ttl_seconds: int = 86400):
        self.ttl_seconds = ttl_seconds
        self._memory_cache = TTLCache(ttl_seconds)
        self._redis_cache: Optional[RedisCache] = None
        self._redis_enabled = False

    async def initialize(self) -> None:
        """Initialize Redis if REDIS_URL is set."""
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                self._redis_cache = RedisCache(redis_url, self.ttl_seconds)
                await self._redis_cache.connect()
                if self._redis_cache.redis:
                    self._redis_enabled = True
                    logger.info("Redis cache enabled")
            except Exception as e:
                logger.warning(f"Redis initialization failed: {e}; using in-memory cache only")

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache (tries Redis first, then memory)."""
        # Try Redis first if enabled
        if self._redis_enabled and self._redis_cache:
            value = await self._redis_cache.get(key)
            if value is not None:
                logger.debug(f"Cache hit (Redis): {key}")
                return value

        # Fall back to in-memory cache
        value = self._memory_cache.get(key)
        if value is not None:
            logger.debug(f"Cache hit (Memory): {key}")
            return value

        logger.debug(f"Cache miss: {key}")
        return None

    async def set(self, key: str, value: Any) -> None:
        """Set value in both caches."""
        self._memory_cache.set(key, value)
        if self._redis_enabled and self._redis_cache:
            await self._redis_cache.set(key, value)

    async def delete(self, key: str) -> None:
        """Delete key from both caches."""
        self._memory_cache.delete(key)
        if self._redis_enabled and self._redis_cache:
            await self._redis_cache.delete(key)

    async def clear(self) -> None:
        """Clear both caches."""
        self._memory_cache.clear()
        if self._redis_enabled and self._redis_cache:
            await self._redis_cache.clear()

    async def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats: Dict[str, Any] = {
            "memory": self._memory_cache.stats(),
            "redis_enabled": self._redis_enabled,
        }
        if self._redis_enabled and self._redis_cache:
            stats["redis"] = await self._redis_cache.stats()
        return stats

    async def close(self) -> None:
        """Close connections."""
        if self._redis_enabled and self._redis_cache:
            await self._redis_cache.close()


# Global cache instance
_cache: Optional[HybridReputationCache] = None


async def get_cache() -> HybridReputationCache:
    """Get or create the global reputation cache."""
    global _cache
    if _cache is None:
        _cache = HybridReputationCache()
        await _cache.initialize()
    return _cache


# Caching helpers for specific domain/IP data

_CACHE_KEY_WHOIS = "whois:"
_CACHE_KEY_DNS = "dns:"
_CACHE_KEY_GEOIP = "geoip:"
_CACHE_KEY_ASN = "asn:"


def _make_cache_key(prefix: str, data: str) -> str:
    """Generate cache key with hash of data."""
    h = hashlib.md5(data.encode()).hexdigest()[:8]
    return f"{prefix}{h}:{data}"


async def cache_whois(domain: str, whois_data: Dict[str, Any]) -> None:
    """Cache WHOIS data for a domain."""
    cache = await get_cache()
    key = _make_cache_key(_CACHE_KEY_WHOIS, domain)
    await cache.set(key, whois_data)


async def get_cached_whois(domain: str) -> Optional[Dict[str, Any]]:
    """Get cached WHOIS data for a domain."""
    cache = await get_cache()
    key = _make_cache_key(_CACHE_KEY_WHOIS, domain)
    return await cache.get(key)


async def cache_dns(domain: str, dns_data: Dict[str, Any]) -> None:
    """Cache DNS resolution results for a domain."""
    cache = await get_cache()
    key = _make_cache_key(_CACHE_KEY_DNS, domain)
    await cache.set(key, dns_data)


async def get_cached_dns(domain: str) -> Optional[Dict[str, Any]]:
    """Get cached DNS data for a domain."""
    cache = await get_cache()
    key = _make_cache_key(_CACHE_KEY_DNS, domain)
    return await cache.get(key)


async def cache_geoip(ip: str, geoip_data: Dict[str, Any]) -> None:
    """Cache GeoIP data for an IP."""
    cache = await get_cache()
    key = _make_cache_key(_CACHE_KEY_GEOIP, ip)
    await cache.set(key, geoip_data)


async def get_cached_geoip(ip: str) -> Optional[Dict[str, Any]]:
    """Get cached GeoIP data for an IP."""
    cache = await get_cache()
    key = _make_cache_key(_CACHE_KEY_GEOIP, ip)
    return await cache.get(key)
