from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from backend.utils.dns_utils import dns_overview
from backend.utils.whois_utils import domain_age_days
from backend.utils.reputation import reputation_service


# Lightweight data to support tests
BRANDS = {
    "google","microsoft","apple","amazon","paypal","facebook","instagram",
    "netflix","github","dropbox","steam","discord","spotify","bankofamerica",
    "chase","wellsfargo","icloud","outlook","office","telegram","chatgpt","openai",
    "youtube","linkedin","twitter","x",
}

# Simple TOP tier domain list for quick checks
TOP_TIER_DOMAINS = {
    "google.com","openai.com","google.com","github.com"
}

def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _sld(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return parts[-2].lower() if len(parts) >= 2 else domain.lower()


def _tld(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return parts[-1].lower() if len(parts) >= 2 else ""


def _homoglyph_skeleton(text: str) -> str:
    HOMOGLYPH_MAP = {
        'l': 'i', '1': 'i', '|': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ı': 'i',
        '0': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o',
        'vv': 'w', 'rn': 'm',
        'a': 'a', 'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'ɑ': 'a',
        'e': 'e', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'е': 'e',
        'i': 'i', 'ï': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ɩ': 'i',
        's': 's', 'ś': 's', 'š': 's', 'ş': 's', 'ѕ': 's',
    }
    t = text.lower()
    t = t.replace('vv', 'w').replace('rn', 'm')
    skeleton = []
    for ch in t:
        skeleton.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(skeleton)


def _identify_typo_type(typo: str, brand: str) -> Optional[str]:
    if typo == brand:
        return None
    # omission
    for i in range(len(brand)):
        if brand[:i] + brand[i+1:] == typo:
            return "omission"
    # repetition
    for i in range(len(typo)):
        if typo[:i] + typo[i+1:] == brand and typo[i] == typo[i-1 if i > 0 else 0]:
            return "repetition"
    # transposition
    for i in range(len(brand) - 1):
        swapped = list(brand)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        if "".join(swapped) == typo:
            return "transposition"
    # keyboard_neighbor
    if len(typo) == len(brand):
        diff_count = 0
        is_neighbor = False
        for c1, c2 in zip(typo, brand):
            if c1 != c2:
                diff_count += 1
                # naive neighbor check
                if c2 in "qwertyuiopasdfghjklzxcvbnm" and c1 in "qwertyuiopasdfghjklzxcvbnm":
                    is_neighbor = True
        if diff_count == 1 and is_neighbor:
            return "keyboard_neighbor"
    return "bit_flip" if _edit_distance(typo, brand) == 1 else None


def typosquatting_signal(domain: str) -> Optional[Dict[str, Any]]:
    sld = _sld(domain)
    if not sld or len(sld) < 4:
        return None
    normalized = domain.lower().strip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]
    if normalized in TOP_TIER_DOMAINS or reputation_service.is_reputable(domain):
        return None
    for brand in BRANDS:
        typo_type = _identify_typo_type(sld, brand)
        if typo_type:
            impact = 32 if typo_type in ["omission", "transposition", "keyboard_neighbor"] else 25
            return {
                "name": "Typosquatting Suspected",
                "category": "domain",
                "bucket": "structure",
                "impact": impact,
                "confidence": 0.8,
                "description": f"Domain '{sld}' appears to be a '{typo_type}' typo of the protected brand '{brand}'.",
                "evidence": {"sld": sld, "brand": brand, "type": typo_type},
            }
    return None


def homoglyph_attack_signal(domain: str) -> Optional[Dict[str, Any]]:
    sld = _sld(domain)
    if not sld or len(sld) < 4:
        return None
    normalized = domain.lower().strip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]
    if normalized in TOP_TIER_DOMAINS or reputation_service.is_reputable(domain):
        return None
    skeleton = _homoglyph_skeleton(sld)
    for brand in BRANDS:
        if _homoglyph_skeleton(brand) == skeleton and sld != brand:
            return {
                "name": "Homoglyph Lookalike Detected",
                "category": "domain",
                "bucket": "structure",
                "impact": 35,
                "confidence": 0.85,
                "description": f"Domain '{sld}' is visually similar to the protected brand '{brand}' using homoglyph characters.",
                "evidence": {"sld": sld, "lookalike_of": brand, "skeleton": skeleton},
            }
    return None


def domain_age_signal(domain: str, days_meta: Optional[Tuple[Optional[int], Dict[str, Any]]] = None) -> Dict[str, Any]:
    if days_meta is None:
        days, meta = domain_age_days(domain)
    else:
        days, meta = days_meta
    if days is None:
        return {
            "name": "Domain Age",
            "category": "domain",
            "bucket": "reputation",
            "impact": 0,
            "confidence": 0.2,
            "description": "WHOIS domain age could not be determined.",
            "evidence": {"age_days": days, "age_bucket": "unknown"},
        }
    if days < 30:
        age_bucket = "lt_30d"
        impact = 30
        conf = 0.75
        desc = f"Domain appears very new ({days} days old)."
    elif days < 180:
        age_bucket = "lt_180d"
        impact = 15
        conf = 0.65
        desc = f"Domain is relatively new ({days} days old)."
    elif days < 365:
        age_bucket = "lt_1y"
        impact = 5
        conf = 0.55
        desc = f"Domain is under 1 year old ({days} days old)."
    else:
        age_bucket = "gte_1y"
        impact = -6
        conf = 0.6
        desc = f"Domain age is over 1 year ({days} days old), which is a mild trust signal."

    return {
        "name": "Domain Age",
        "category": "domain",
        "bucket": "reputation",
        "impact": impact,
        "confidence": conf,
        "description": desc,
        "evidence": {"age_days": days, "age_bucket": age_bucket},
    }


def domain_signals(domain: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    # Add Domain Age signal (monkeypatches in tests may override days/meta)
    days, meta = domain_age_days(domain)
    signals.append(domain_age_signal(domain, days_meta=(days, meta)))

    # Optional typosquatting signal
    ts = typosquatting_signal(domain)
    if ts:
        signals.append(ts)

    # Optional homoglyph signal
    hs = homoglyph_attack_signal(domain)
    if hs:
        signals.append(hs)

    return signals
