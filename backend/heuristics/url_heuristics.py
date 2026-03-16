from __future__ import annotations

from typing import List, Dict, Any
import urllib.parse
import math


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def url_signals(url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        p = None
    netloc = (p.netloc if p else "")
    if netloc and "bit.ly" in netloc:
        signals.append({"name": "URL Shortener Detected", "category": "url", "impact": 5, "description": "URL uses a known shortener (bit.ly).", "evidence": {"shortener": netloc}})
    if p and "xn--" in p.netloc:
        signals.append({"name": "Homograph/IDN Indicator", "category": "url", "impact": 6, "description": "URL uses IDN/Punycode for potential homoglyphs.", "evidence": {}})
    if p and p.query:
        entropy = _entropy(p.query)
        signals.append({"name": "Path/Query Entropy", "category": "url", "impact": 4, "description": "Entropy detected in path/query.", "evidence": {"query": p.query, "query_entropy": entropy}})
    return signals
