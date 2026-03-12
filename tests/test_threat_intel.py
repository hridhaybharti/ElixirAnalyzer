"""Tests for threat intelligence aggregator."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from backend.utils.threat_intel import ThreatIntelAggregator, ThreatIntelConfig


@pytest.mark.asyncio
async def test_threat_intel_config_defaults():
    """Test default configuration."""
    config = ThreatIntelConfig()
    assert config.timeout == 10.0
    assert config.max_retries == 2
    assert config.abuseipdb_key == ""


@pytest.mark.asyncio
async def test_aggregator_initialize():
    """Test aggregator initialization."""
    agg = ThreatIntelAggregator()
    await agg.initialize()
    # Should not raise
    await agg.cleanup()


@pytest.mark.asyncio
async def test_aggregator_context_manager():
    """Test aggregator as context manager."""
    async with ThreatIntelAggregator() as agg:
        assert agg is not None


@pytest.mark.asyncio
async def test_abuseipdb_lookup_no_key():
    """Test AbuseIPDB lookup without API key."""
    agg = ThreatIntelAggregator()
    result = await agg.lookup_abuseipdb("1.2.3.4")
    assert result["available"] is False


@pytest.mark.asyncio
async def test_threatfox_lookup_disabled():
    """Test ThreatFox lookup when disabled."""
    agg = ThreatIntelAggregator()
    result = await agg.lookup_threatfox("example.com")
    assert result["available"] is False


@pytest.mark.asyncio
async def test_aggregate_ip_basic():
    """Test basic IP aggregation without network calls."""
    agg = ThreatIntelAggregator()
    result = await agg.aggregate_ip("1.2.3.4", sources=[])
    assert result["ip"] == "1.2.3.4"
    assert "sources" in result


@pytest.mark.asyncio
async def test_aggregate_domain_basic():
    """Test basic domain aggregation."""
    agg = ThreatIntelAggregator()
    result = await agg.aggregate_domain("example.com", sources=[])
    assert result["domain"] == "example.com"
    assert "sources" in result
