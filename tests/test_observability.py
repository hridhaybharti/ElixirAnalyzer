"""Tests for observability and metrics."""

import pytest
from backend.utils.observability import (
    get_metrics_collector,
    record_scan,
    record_intel_lookup,
    record_cache_hit,
    record_cache_miss,
    record_signal_fired,
    record_error,
    get_metrics,
    reset_metrics,
)


def test_metrics_collector_defaults():
    """Test metrics collector initialization."""
    reset_metrics()
    metrics = get_metrics()
    assert metrics["analysis_count"] == 0
    assert metrics["analysis_errors"] == 0


def test_record_scan():
    """Test recording scan duration."""
    reset_metrics()
    record_scan(100.5)
    record_scan(150.2)
    
    metrics = get_metrics()
    assert metrics["scan_metrics"]["total_scans"] == 2
    assert abs(metrics["scan_metrics"]["avg_duration_ms"] - 125.35) < 0.05


def test_record_cache_metrics():
    """Test recording cache hits and misses."""
    reset_metrics()
    record_cache_hit()
    record_cache_hit()
    record_cache_miss()
    
    metrics = get_metrics()
    assert metrics["cache_metrics"]["hits"] == 2
    assert metrics["cache_metrics"]["misses"] == 1
    assert abs(metrics["cache_metrics"]["hit_rate"] - 0.667) < 0.01


def test_record_signal_fired():
    """Test recording signal frequency."""
    reset_metrics()
    record_signal_fired("Domain Age")
    record_signal_fired("Domain Age")
    record_signal_fired("Typosquatting")
    
    metrics = get_metrics()
    assert metrics["signal_frequency"]["Domain Age"] == 2
    assert metrics["signal_frequency"]["Typosquatting"] == 1


def test_record_error():
    """Test recording errors."""
    reset_metrics()
    record_error()
    record_error()
    
    metrics = get_metrics()
    assert metrics["analysis_errors"] == 2


def test_metrics_uptime():
    """Test metrics uptime tracking."""
    reset_metrics()
    metrics = get_metrics()
    assert "uptime_seconds" in metrics
    assert metrics["uptime_seconds"] >= 0
