from __future__ import annotations

from typing import Dict, Tuple, Optional
import time


def domain_age_days(domain: str) -> Tuple[Optional[int], Dict[str, object]]:
    """Return a deterministic domain age and meta for tests.

    The real implementation would query WHOIS; this is a simple stub.
    """
    # Simple deterministic heuristic based on domain name
    days = 10 if "example" in domain else 365
    meta = {"registrar": "Example Registrar", "creation_date": None}
    return days, meta


async def domain_age_days_async(domain: str) -> Tuple[Optional[int], Dict[str, object]]:
    return domain_age_days(domain)
