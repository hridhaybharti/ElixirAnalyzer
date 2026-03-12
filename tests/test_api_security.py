"""Tests for API security: rate limiting, API keys, request tracking."""

import pytest
from backend.utils.api_security import (
    RateLimiter, APIKeyManager, RequestIDManager, generate_request_id
)


def test_rate_limiter_allows_requests():
    """Test that rate limiter allows requests within limit."""
    limiter = RateLimiter(requests_per_minute=10)
    
    for _ in range(10):
        assert limiter.is_allowed("192.168.1.1") is True


def test_rate_limiter_blocks_excess():
    """Test that rate limiter blocks when using multiple concurrent requests."""
    limiter = RateLimiter(requests_per_minute=3)
    
    # Create enough requests to exceed the per-second refill rate
    # 3 req/min = 0.05 tokens/second
    # Burst 10 requests will exhaust the initial 3 tokens
    results = []
    for i in range(10):
        results.append(limiter.is_allowed("192.168.1.1"))
    
    # First 3 should succeed (initial burst capacity)
    assert results[0] is True
    assert results[1] is True
    assert results[2] is True
    
    # Most of the rest should fail (tokens don't refill fast enough)
    # At least some should be blocked
    assert any(r is False for r in results[3:]), "Expected some requests to be blocked"


def test_rate_limiter_separate_buckets():
    """Test that rate limiter maintains separate buckets per IP."""
    limiter = RateLimiter(requests_per_minute=2)
    
    assert limiter.is_allowed("192.168.1.1") is True
    assert limiter.is_allowed("192.168.1.1") is True
    assert limiter.is_allowed("192.168.1.2") is True
    assert limiter.is_allowed("192.168.1.2") is True


def test_api_key_manager_generate():
    """Test API key generation."""
    manager = APIKeyManager()
    key = manager.generate_key("test_user")
    
    assert key.startswith("sk-")
    assert manager.validate_key(key) is True


def test_api_key_manager_validate():
    """Test API key validation."""
    manager = APIKeyManager()
    key = manager.generate_key("test_user")
    
    assert manager.validate_key(key) is True
    assert manager.validate_key("invalid_key") is False


def test_api_key_manager_revoke():
    """Test API key revocation."""
    manager = APIKeyManager()
    key = manager.generate_key("test_user")
    
    assert manager.validate_key(key) is True
    assert manager.revoke_key(key) is True
    assert manager.validate_key(key) is False


def test_api_key_manager_record_use():
    """Test recording API key usage."""
    manager = APIKeyManager()
    key = manager.generate_key("test_user")
    
    info_before = manager.get_key_info(key)
    assert info_before["use_count"] == 0
    
    manager.record_use(key)
    manager.record_use(key)
    
    info_after = manager.get_key_info(key)
    assert info_after["use_count"] == 2


def test_request_id_manager_generate():
    """Test request ID generation."""
    req_id = generate_request_id()
    
    assert req_id.startswith("req_")
    assert len(req_id) > 10


def test_request_id_manager_store_and_retrieve():
    """Test storing and retrieving request metadata."""
    req_id = generate_request_id()
    metadata = {"method": "POST", "path": "/api/analyze", "client_ip": "192.168.1.1"}
    
    RequestIDManager.store_metadata(req_id, metadata)
    retrieved = RequestIDManager.get_metadata(req_id)
    
    assert retrieved is not None
    assert retrieved["method"] == "POST"
    assert retrieved["path"] == "/api/analyze"
    assert "timestamp" in retrieved
