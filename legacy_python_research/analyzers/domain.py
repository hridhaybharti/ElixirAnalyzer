from __future__ import annotations

from typing import Any, Dict, Tuple

from ..core.scorer import score_signals_detailed
from ..core.verdict import verdict_for_score
from ..heuristics.domain_heuristics import domain_signals, domain_signals_async
from ..utils.validators import normalize_domain


def analyze_domain_explain(domain: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    d = normalize_domain(domain)
    signals = domain_signals(d)

    risk_score, confidence, breakdown, scoring_math = score_signals_detailed(signals)

    result: Dict[str, Any] = {
        "target": domain,
        "input": domain,
        "type": "domain",
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict_for_score(risk_score),
        "signals": signals,
        # Backward-compatible signal list kept under `signals`.
        # New field `signals_triggered` provides the same signals for clarity
        # and to support future UI expectations.
        "signals_triggered": signals,
        "breakdown": breakdown,
    }

    explain = {
        "target": domain,
        "input": domain,
        "type": "domain",
        "signals": signals,
        "signals_triggered": signals,
        # Heuristics currently use DNS and WHOIS lookups; list them for transparency.
        "intel_sources": ["dns", "whois"],
        "breakdown": breakdown,
        "scoring": scoring_math,
    }

    return result, explain


async def analyze_domain_explain_async(domain: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    d = normalize_domain(domain)
    signals = await domain_signals_async(d)

    risk_score, confidence, breakdown, scoring_math = score_signals_detailed(signals)

    result: Dict[str, Any] = {
        "target": domain,
        "type": "domain",
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict_for_score(risk_score),
        "signals": signals,
        "breakdown": breakdown,
    }

    explain = {
        "target": domain,
        "type": "domain",
        "signals": signals,
        "breakdown": breakdown,
        "scoring": scoring_math,
    }

    return result, explain


def analyze_domain(domain: str) -> Dict[str, Any]:
    return analyze_domain_explain(domain)[0]
