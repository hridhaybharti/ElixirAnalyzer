from __future__ import annotations

from typing import Dict, List


def dns_overview(domain: str) -> Dict[str, object]:
    """Return a minimal DNS overview for a domain.

    This is a deterministic stub used by tests with monkeypatching.
    """
    return {
        "has_ns": True,
        "NS": ["ns1.example.com", "ns2.example.com"],
        "has_a_or_aaaa": True,
        "A": ["93.184.216.34"],
        "AAAA": [],
        "has_mx": True,
        "MX": ["mx.example.com"],
    }


async def dns_overview_async(domain: str) -> Dict[str, object]:
    return dns_overview(domain)
