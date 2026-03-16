import re


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if not (0 <= n <= 255):
            return False
    return True


def detect_target_type(value: str):
    v = value.strip()
    if _is_ip(v):
        return "ip", v
    # URL with scheme
    if v.startswith("http://") or v.startswith("https://"):
        return "url", v
    if "://" in v:
        return "url", v
    # Path-like domain (domain with path) should be treated as URL
    if "/" in v:
        return "url", f"http://{v}"
    # Domain with optional path (no path here)
    if "." in v:
        return "domain", v.lower()
    # Path without scheme treated as URL by prepending scheme
    return "url", f"http://{v}"
