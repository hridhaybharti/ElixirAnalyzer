import time
from typing import Any, Dict


class TTLCache:
    def __init__(self, ttl_seconds: int = 60):
        self.ttl_seconds = ttl_seconds
        self._store: Dict[str, tuple[Any, float]] = {}

    def set(self, key: str, value: Any) -> None:
        expire_at = time.time() + self.ttl_seconds
        self._store[key] = (value, expire_at)

    def get(self, key: str) -> Any:
        if key not in self._store:
            return None
        value, expire_at = self._store[key]
        if expire_at < time.time():
            del self._store[key]
            return None
        return value

    def delete(self, key: str) -> None:
        if key in self._store:
            del self._store[key]

    def stats(self) -> Dict[str, int]:
        now = time.time()
        total_keys = len(self._store)
        active = sum(1 for _, exp in self._store.values() if exp > now)
        expired = total_keys - active
        return {"total_keys": total_keys, "active_keys": active, "expired_keys": expired}


class HybridReputationCache:
    def __init__(self, ttl_seconds: int = 60):
        self.ttl_seconds = ttl_seconds
        self._memory: Dict[str, tuple[Any, float]] = {}

    async def initialize(self) -> None:
        return None

    async def set(self, key: str, value: Any) -> None:
        self._memory[key] = (value, time.time())

    async def get(self, key: str) -> Any:
        if key not in self._memory:
            return None
        value, t0 = self._memory[key]
        if time.time() - t0 > self.ttl_seconds:
            del self._memory[key]
            return None
        return value

    async def delete(self, key: str) -> None:
        if key in self._memory:
            del self._memory[key]

    async def stats(self) -> Dict[str, object]:
        return {"memory": len(self._memory), "redis_enabled": False}

    async def close(self) -> None:
        self._memory.clear()
