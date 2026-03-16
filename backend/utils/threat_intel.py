from __future__ import annotations

import asyncio


class ThreatIntelConfig:
    def __init__(self, timeout: float = 10.0, max_retries: int = 2, abuseipdb_key: str = ""):
        self.timeout = timeout
        self.max_retries = max_retries
        self.abuseipdb_key = abuseipdb_key


class ThreatIntelAggregator:
    def __init__(self):
        self.config = ThreatIntelConfig()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def initialize(self):
        return None

    async def cleanup(self):
        return None

    async def lookup_abuseipdb(self, ip: str):
        # No external calls in tests
        return {"available": False}

    async def lookup_threatfox(self, domain: str):
        return {"available": False}

    async def aggregate_ip(self, ip: str, sources=None):
        return {"ip": ip, "sources": sources or []}

    async def aggregate_domain(self, domain: str, sources=None):
        return {"domain": domain, "sources": sources or []}
