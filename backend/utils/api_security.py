"""API Security: Rate Limiting, API Keys, Request ID Tracking.

Minimal reimplementation to support tests in this workspace.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger("api_security")


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.tokens_per_second = requests_per_minute / 60.0
        self.buckets: Dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_update_time)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if a request from client_ip is allowed."""
        now = time.time()

        if client_ip not in self.buckets:
            self.buckets[client_ip] = (self.requests_per_minute, now)
            return True

        tokens, last_update = self.buckets[client_ip]
        elapsed = now - last_update

        # Add tokens for elapsed time
        tokens = min(self.requests_per_minute, tokens + (elapsed * self.tokens_per_second))

        if tokens >= 1:
            tokens -= 1
            self.buckets[client_ip] = (tokens, now)
            return True
        else:
            self.buckets[client_ip] = (tokens, now)
            return False

    def get_reset_time(self, client_ip: str) -> float:
        """Get seconds until client can make another request."""
        if client_ip not in self.buckets:
            return 0.0

        tokens, last_update = self.buckets[client_ip]
        if tokens >= 1:
            return 0.0

        # Time to accumulate 1 token
        time_needed = (1 - tokens) / self.tokens_per_second
        return max(0.1, time_needed)


class APIKeyManager:
    """Manages API keys for authentication."""

    def __init__(self):
        self.valid_keys: Dict[str, Dict[str, Any]] = {}

    def generate_key(self, name: str, rate_limit: Optional[int] = None) -> str:
        """Generate a new API key."""
        key = f"sk-{secrets.token_urlsafe(32)}"
        self.valid_keys[key] = {
            "name": name,
            "created_at": time.time(),
            "last_used": None,
            "rate_limit": rate_limit or 60,  # Default 60 req/min
            "use_count": 0,
        }
        logger.info(f"Generated API key {key[:10]}... for {name}")
        return key

    def validate_key(self, key: str) -> bool:
        """Check if a key is valid."""
        if key not in self.valid_keys:
            return False
        return True

    def record_use(self, key: str) -> None:
        """Record that an API key was used."""
        if key in self.valid_keys:
            self.valid_keys[key]["last_used"] = time.time()
            self.valid_keys[key]["use_count"] += 1

    def get_key_info(self, key: str) -> Optional[Dict[str, Any]]:
        """Get info about an API key."""
        return self.valid_keys.get(key)

    def revoke_key(self, key: str) -> bool:
        """Revoke an API key."""
        if key in self.valid_keys:
            del self.valid_keys[key]
            logger.info(f"Revoked API key {key[:10]}...")
            return True
        return False

    def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """List all API keys (redacted)."""
        return {
            k: {k2: (v2 if k2 != "name" else f"{v2[:20]}***") for k2, v2 in v.items()}
            for k, v in self.valid_keys.items()
        }


class RequestIDManager:
    """Generates and tracks request IDs."""

    _storage: Dict[str, Dict[str, Any]] = {}  # request_id -> metadata

    @staticmethod
    def generate() -> str:
        """Generate a new request ID."""
        return f"req_{uuid.uuid4().hex[:12]}"

    @staticmethod
    def store_metadata(request_id: str, metadata: Dict[str, Any]) -> None:
        """Store metadata about a request."""
        RequestIDManager._storage[request_id] = {
            "timestamp": time.time(),
            **metadata,
        }

    @staticmethod
    def get_metadata(request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata about a request."""
        return RequestIDManager._storage.get(request_id)

    @staticmethod
    def cleanup(older_than_seconds: int = 3600) -> int:
        """Clean up old request metadata."""
        now = time.time()
        cutoff = now - older_than_seconds
        to_delete = [k for k, v in RequestIDManager._storage.items() if v.get("timestamp", 0) < cutoff]
        for k in to_delete:
            del RequestIDManager._storage[k]
        return len(to_delete)


# Global instances
_rate_limiter_global: Optional[RateLimiter] = None
_api_key_manager_global: Optional[APIKeyManager] = None


def get_rate_limiter(requests_per_minute: int = 60) -> RateLimiter:
    """Get or create global rate limiter."""
    global _rate_limiter_global
    if _rate_limiter_global is None:
        _rate_limiter_global = RateLimiter(requests_per_minute)
    return _rate_limiter_global


def get_api_key_manager() -> APIKeyManager:
    """Get or create global API key manager."""
    global _api_key_manager_global
    if _api_key_manager_global is None:
        _api_key_manager_global = APIKeyManager()
    return _api_key_manager_global


def generate_request_id() -> str:
    """Generate a new request ID."""
    return RequestIDManager.generate()


def store_request_metadata(request_id: str, metadata: Dict[str, Any]) -> None:
    """Store request metadata."""
    RequestIDManager.store_metadata(request_id, metadata)


def get_request_metadata(request_id: str) -> Optional[Dict[str, Any]]:
    """Get request metadata."""
    return RequestIDManager.get_metadata(request_id)
