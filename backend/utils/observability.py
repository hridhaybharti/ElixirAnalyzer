from __future__ import annotations

import time
from typing import Dict


# In-memory metrics store
_start_time = time.time()
_analysis_count = 0
_analysis_errors = 0
_scans: list[float] = []
_signal_frequency: Dict[str, int] = {}
_cache_hits = 0
_cache_misses = 0


def reset_metrics() -> None:
    global _start_time, _analysis_count, _analysis_errors, _scans, _signal_frequency, _cache_hits, _cache_misses
    _start_time = time.time()
    _analysis_count = 0
    _analysis_errors = 0
    _scans = []
    _signal_frequency = {}
    _cache_hits = 0
    _cache_misses = 0


def get_metrics_collector():
    # Simple accessor for compatibility; tests don't rely on this object directly.
    return {
        "reset": reset_metrics,
        "record": lambda *_: None,
    }


def record_scan(duration_ms: float) -> None:
    _scans.append(float(duration_ms))


def record_intel_lookup() -> None:
    global _analysis_count
    _analysis_count += 1


def record_cache_hit() -> None:
    global _cache_hits
    _cache_hits += 1


def record_cache_miss() -> None:
    global _cache_misses
    _cache_misses += 1


def record_signal_fired(signal_name: str) -> None:
    global _signal_frequency
    _signal_frequency[signal_name] = _signal_frequency.get(signal_name, 0) + 1


def record_error() -> None:
    global _analysis_errors
    _analysis_errors += 1


def get_metrics() -> Dict[str, object]:
    uptime = max(0.0, time.time() - _start_time)
    total_scans = len(_scans)
    avg_duration = (sum(_scans) / total_scans) if total_scans > 0 else 0.0
    hit_total = _cache_hits + _cache_misses
    hit_rate = (_cache_hits / hit_total) if hit_total > 0 else 0.0

    return {
        "analysis_count": _analysis_count,
        "analysis_errors": _analysis_errors,
        "scan_metrics": {
            "total_scans": total_scans,
            "avg_duration_ms": round(avg_duration, 2) if total_scans > 0 else 0.0,
        },
        "cache_metrics": {
            "hits": _cache_hits,
            "misses": _cache_misses,
            "hit_rate": round(hit_rate, 3) if hit_total > 0 else 0.0,
        },
        "signal_frequency": dict(_signal_frequency),
        "uptime_seconds": uptime,
    }
