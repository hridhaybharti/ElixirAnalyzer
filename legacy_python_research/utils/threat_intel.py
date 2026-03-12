"""Threat Intelligence Aggregator.

Supports multiple sources: WHOIS, DNS, GeoIP, ASN, AbuseIPDB, ThreatFox.
Uses asyncio.gather() for concurrent lookups.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

logger = logging.getLogger("threat_intel")


class ThreatIntelConfig:
    """Configuration for threat intelligence lookups."""

    def __init__(self):
        self.abuseipdb_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
        self.threatfox_enabled: bool = bool(os.getenv("THREATFOX_ENABLED", ""))
        self.geoip_enabled: bool = True  # Usually no key needed (free services)
        self.timeout: float = 10.0
        self.max_retries: int = 2


class ThreatIntelAggregator:
    """Aggregates threat intelligence from multiple sources."""

    def __init__(self, config: Optional[ThreatIntelConfig] = None):
        self.config = config or ThreatIntelConfig()
        self.session: Optional[aiohttp.ClientSession] = None

    async def initialize(self) -> None:
        """Initialize aiohttp session."""
        if aiohttp:
            self.session = aiohttp.ClientSession()

    async def cleanup(self) -> None:
        """Close aiohttp session."""
        if self.session:
            await self.session.close()

    async def __aenter__(self) -> ThreatIntelAggregator:
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.cleanup()

    async def lookup_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Look up IP reputation on AbuseIPDB."""
        if not self.config.abuseipdb_key or not aiohttp:
            return {"source": "abuseipdb", "available": False, "reason": "No API key or aiohttp"}

        try:
            headers = {"Key": self.config.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            if not self.session:
                return {"source": "abuseipdb", "available": False, "reason": "Session not initialized"}

            async with self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    abuse_data = data.get("data", {})
                    return {
                        "source": "abuseipdb",
                        "available": True,
                        "ip": ip,
                        "abuseConfidenceScore": abuse_data.get("abuseConfidenceScore", 0),
                        "usageType": abuse_data.get("usageType", ""),
                        "isp": abuse_data.get("isp", ""),
                        "domain": abuse_data.get("domain", ""),
                    }
                else:
                    logger.warning(f"AbuseIPDB lookup failed with status {resp.status}")
                    return {"source": "abuseipdb", "available": False, "status": resp.status}
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error for {ip}: {e}")
            return {"source": "abuseipdb", "available": False, "error": str(e)}

    async def lookup_threatfox(self, domain: str) -> Dict[str, Any]:
        """Look up domain on ThreatFox."""
        if not self.config.threatfox_enabled or not aiohttp:
            return {"source": "threatfox", "available": False, "reason": "Not enabled or aiohttp unavailable"}

        try:
            payload = {"query": "domain", "search_term": domain}

            if not self.session:
                return {"source": "threatfox", "available": False, "reason": "Session not initialized"}

            async with self.session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("query_status") == "ok":
                        return {
                            "source": "threatfox",
                            "available": True,
                            "domain": domain,
                            "indicators": data.get("data", [])[:5],  # Top 5
                        }
                    else:
                        return {
                            "source": "threatfox",
                            "available": False,
                            "query_status": data.get("query_status"),
                        }
                else:
                    return {"source": "threatfox", "available": False, "status": resp.status}
        except Exception as e:
            logger.error(f"ThreatFox lookup error for {domain}: {e}")
            return {"source": "threatfox", "available": False, "error": str(e)}

    async def lookup_geoip(self, ip: str) -> Dict[str, Any]:
        """Look up GeoIP information."""
        if not aiohttp:
            return {"source": "geoip", "available": False, "reason": "aiohttp unavailable"}

        try:
            # Using a free GeoIP service (ip-api.com)
            if not self.session:
                return {"source": "geoip", "available": False, "reason": "Session not initialized"}

            async with self.session.get(
                f"http://ip-api.com/json/{ip}",
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        return {
                            "source": "geoip",
                            "available": True,
                            "ip": ip,
                            "country": data.get("country"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                        }
                    else:
                        return {"source": "geoip", "available": False, "status": data.get("status")}
                else:
                    return {"source": "geoip", "available": False, "status": resp.status}
        except Exception as e:
            logger.error(f"GeoIP lookup error for {ip}: {e}")
            return {"source": "geoip", "available": False, "error": str(e)}

    async def aggregate_ip(self, ip: str, sources: Optional[List[str]] = None) -> Dict[str, Any]:
        """Aggregate threat intel for an IP address."""
        if sources is None:
            sources = ["abuseipdb", "geoip"]

        tasks = []
        source_map = {}

        if "abuseipdb" in sources:
            tasks.append(self.lookup_abuseipdb(ip))
            source_map[len(tasks) - 1] = "abuseipdb"

        if "geoip" in sources:
            tasks.append(self.lookup_geoip(ip))
            source_map[len(tasks) - 1] = "geoip"

        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {
            "ip": ip,
            "sources": {},
        }

        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Intel lookup exception: {result}")
                continue
            aggregated["sources"][result.get("source", f"source_{idx}")] = result

        return aggregated

    async def aggregate_domain(self, domain: str, sources: Optional[List[str]] = None) -> Dict[str, Any]:
        """Aggregate threat intel for a domain."""
        if sources is None:
            sources = ["threatfox", "dns", "whois"]

        # For now, we only have ThreatFox for domain-specific async lookups
        # DNS and WHOIS are handled by the heuristics module

        tasks = []

        if "threatfox" in sources:
            tasks.append(self.lookup_threatfox(domain))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []

        aggregated = {
            "domain": domain,
            "sources": {},
        }

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Domain intel lookup exception: {result}")
                continue
            aggregated["sources"][result.get("source", "unknown")] = result

        return aggregated


# Global instance
_threat_intel_agg: Optional[ThreatIntelAggregator] = None


async def get_aggregator() -> ThreatIntelAggregator:
    """Get or create the global threat intel aggregator."""
    global _threat_intel_agg
    if _threat_intel_agg is None:
        _threat_intel_agg = ThreatIntelAggregator()
        await _threat_intel_agg.initialize()
    return _threat_intel_agg


async def aggregate_ip(ip: str, sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Convenience function to aggregate threat intel for an IP."""
    agg = await get_aggregator()
    return await agg.aggregate_ip(ip, sources)


async def aggregate_domain(domain: str, sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Convenience function to aggregate threat intel for a domain."""
    agg = await get_aggregator()
    return await agg.aggregate_domain(domain, sources)
