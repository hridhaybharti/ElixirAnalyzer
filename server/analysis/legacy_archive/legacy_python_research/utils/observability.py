"""Observability and Metrics Tracking.

Tracks scan duration, intel lookup latency, cache hit rates, signal frequency.
Exposes a /metrics endpoint.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, List
from collections import defaultdict

logger = logging.getLogger("observability")


class MetricsCollector:
    """Collects operational metrics."""

    def __init__(self):
        self.scan_durations: List[float] = []  # milliseconds
        self.intel_lookup_latencies: List[float] = []  # milliseconds
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.signal_frequency: Dict[str, int] = defaultdict(int)
        self.analysis_count: int = 0
        self.analysis_errors: int = 0
        self.batch_analyses: int = 0

        self.start_time = time.time()

    def record_scan(self, duration_ms: float) -> None:
        """Record a scan duration."""
        self.scan_durations.append(duration_ms)
        self.analysis_count += 1

    def record_intel_lookup(self, duration_ms: float) -> None:
        """Record an intel lookup latency."""
        self.intel_lookup_latencies.append(duration_ms)

    def record_cache_hit(self) -> None:
        """Record a cache hit."""
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss."""
        self.cache_misses += 1

    def record_signal_fired(self, signal_name: str) -> None:
        """Record that a signal was fired."""
        self.signal_frequency[signal_name] += 1

    def record_error(self) -> None:
        """Record an analysis error."""
        self.analysis_errors += 1

    def record_batch_analysis(self) -> None:
        """Record a batch analysis."""
        self.batch_analyses += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot."""
        uptime_seconds = time.time() - self.start_time
        
        cache_hit_rate = (
            self.cache_hits / (self.cache_hits + self.cache_misses)
            if (self.cache_hits + self.cache_misses) > 0
            else 0.0
        )

        avg_scan_duration = (
            sum(self.scan_durations) / len(self.scan_durations)
            if self.scan_durations
            else 0.0
        )

        avg_intel_lookup = (
            sum(self.intel_lookup_latencies) / len(self.intel_lookup_latencies)
            if self.intel_lookup_latencies
            else 0.0
        )

        return {
            "uptime_seconds": int(uptime_seconds),
            "analysis_count": self.analysis_count,
            "analysis_errors": self.analysis_errors,
            "batch_analyses": self.batch_analyses,
            "scan_metrics": {
                "total_scans": len(self.scan_durations),
                "avg_duration_ms": round(avg_scan_duration, 2),
                "min_duration_ms": min(self.scan_durations) if self.scan_durations else None,
                "max_duration_ms": max(self.scan_durations) if self.scan_durations else None,
            },
            "cache_metrics": {
                "hits": self.cache_hits,
                "misses": self.cache_misses,
                "hit_rate": round(cache_hit_rate, 3),
            },
            "intel_metrics": {
                "total_lookups": len(self.intel_lookup_latencies),
                "avg_latency_ms": round(avg_intel_lookup, 2),
                "min_latency_ms": min(self.intel_lookup_latencies) if self.intel_lookup_latencies else None,
                "max_latency_ms": max(self.intel_lookup_latencies) if self.intel_lookup_latencies else None,
            },
            "signal_frequency": dict(sorted(
                self.signal_frequency.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),  # Top 10 signals
        }

    def reset(self) -> None:
        """Reset all metrics."""
        self.scan_durations.clear()
        self.intel_lookup_latencies.clear()
        self.cache_hits = 0
        self.cache_misses = 0
        self.signal_frequency.clear()
        self.analysis_count = 0
        self.analysis_errors = 0
        self.batch_analyses = 0
        self.start_time = time.time()


# Global metrics instance
_metrics: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics


def record_scan(duration_ms: float) -> None:
    """Record a scan duration."""
    get_metrics_collector().record_scan(duration_ms)


def record_intel_lookup(duration_ms: float) -> None:
    """Record an intel lookup latency."""
    get_metrics_collector().record_intel_lookup(duration_ms)


def record_cache_hit() -> None:
    """Record a cache hit."""
    get_metrics_collector().record_cache_hit()


def record_cache_miss() -> None:
    """Record a cache miss."""
    get_metrics_collector().record_cache_miss()


def record_signal_fired(signal_name: str) -> None:
    """Record that a signal was fired."""
    get_metrics_collector().record_signal_fired(signal_name)


def record_error() -> None:
    """Record an analysis error."""
    get_metrics_collector().record_error()


def record_batch_analysis() -> None:
    """Record a batch analysis."""
    get_metrics_collector().record_batch_analysis()


def get_metrics() -> Dict[str, Any]:
    """Get current metrics snapshot."""
    return get_metrics_collector().get_metrics()


def reset_metrics() -> None:
    """Reset all metrics."""
    get_metrics_collector().reset()
