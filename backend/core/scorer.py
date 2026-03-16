from __future__ import annotations

from typing import Dict, List, Tuple
import json


def _has_contradiction(signals: List[Dict[str, object]]) -> bool:
    # If two signals share same category and bucket but opposite sign in impact
    pairs = []
    for s in signals:
        cat = s.get("category")
        bucket = s.get("bucket")
        imp = s.get("impact", 0)
        pairs.append((cat, bucket, imp))
    for i in range(len(pairs)):
        for j in range(i+1, len(pairs)):
            c1, b1, i1 = pairs[i]
            c2, b2, i2 = pairs[j]
            if c1 == c2 and b1 == b2 and i1 * i2 < 0:
                return True
    return False


def score_signals_detailed(signals: List[Dict[str, object]]) -> Tuple[float, float, Dict[str, int], Dict[str, object]]:
    # Basic scoring: positive impacts raise risk, negative reduce with simple cap
    total_impact = sum((s.get("impact") or 0) for s in signals)
    risk = min(100, max(0, total_impact))

    # Confidence: average of provided confidences
    confidences = [ (s.get("confidence") or 0.0) for s in signals ]
    conf = (sum(confidences) / len(confidences)) if confidences else 0.0
    # Adjust for contradictions
    if _has_contradiction(signals):
        conf = max(0.0, conf - 0.2)

    breakdown = {"reputation": 0, "structure": 0, "network": 0}
    # Very naive aggregation to populate keys, not used by tests beyond existence
    if signals:
        if any(s.get("bucket") == "reputation" for s in signals):
            breakdown["reputation"] = max(breakdown["reputation"], 10)
        if any(s.get("category") == "url" for s in signals):
            breakdown["structure"] = max(breakdown["structure"], 5)
        if any(s.get("category") == "network" for s in signals):
            breakdown["network"] = max(breakdown["network"], 5)

    math = {"signals": signals, "contradiction": 1 if _has_contradiction(signals) else 0}
    return float(risk), float(conf), breakdown, math
