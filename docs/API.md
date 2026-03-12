# ElixirAnalyzer API Documentation

## Base URL

```
http://localhost:8000
https://api.elixiranalyzer.com  # Production
```

## Authentication

### Optional API Keys (Rate Limit Tiers)

API keys are optional but required for higher rate limits and premium features.

**Format:** `sk_XXXXXXXXXXXXXXXX`

**Usage:** Add to request header:
```bash
Authorization: Bearer sk_XXXXXXXXXXXXXXXX
```

### Rate Limiting

**Default (Per IP):** 60 requests/minute
**With API Key:** Based on key tier (see `/api/security/keys`)
**Response Header:** `Retry-After: 45` seconds until reset

---

## Core Endpoints

### 1. Single Target Analysis

**POST** `/analyze`

Analyze a single target (URL, domain, or IP address).

#### Request

```json
{
  "target": "example.com"
}
```

#### Response

```json
{
  "input": "example.com",
  "risk_score": 72,
  "verdict": "malicious",
  "confidence": 0.86,
  "signals": [
    {
      "name": "Domain Age",
      "impact": 30,
      "confidence": 0.75,
      "bucket": "reputation",
      "description": "Domain registered < 30 days ago"
    },
    {
      "name": "Typosquatting Suspected",
      "impact": 32,
      "confidence": 0.8,
      "bucket": "structure",
      "description": "Likely typo of 'example-official.com'"
    }
  ],
  "signals_triggered": ["Domain Age", "Typosquatting Suspected", "..."],
  "intel_sources": ["whois", "dns", "geoip"],
  "breakdown": {
    "reputation": 50,
    "structure": 22,
    "network": 0
  }
}
```

#### Field Explanations

| Field | Type | Description |
|-------|------|-------------|
| `input` | string | Echoes back the analyzed target |
| `risk_score` | number (0-100) | Overall risk on 0-100 scale |
| `verdict` | string | `MALICIOUS`, `SUSPICIOUS`, `NEUTRAL`, `BENIGN` |
| `confidence` | number (0-1) | Confidence in the verdict |
| `signals` | array | Detailed signals fired (with impact, confidence) |
| `signals_triggered` | array | List of signal names that triggered |
| `intel_sources` | array | Which TI sources were queried |
| `breakdown` | object | Score by category (reputation, structure, network) |

#### Status Codes

- **200 OK** — Analysis successful
- **400 Bad Request** — Invalid target format
- **429 Too Many Requests** — Rate limit exceeded
- **500 Internal Server Error** — Analysis failed

#### Examples

**cURL:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

**Python:**
```python
import requests

response = requests.post("http://localhost:8000/analyze", json={
    "target": "example.com"
})
result = response.json()
print(f"Risk: {result['risk_score']}, Verdict: {result['verdict']}")
```

**JavaScript:**
```javascript
const response = await fetch("http://localhost:8000/analyze", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ target: "example.com" })
});
const result = await response.json();
console.log(`Risk: ${result.risk_score}, Verdict: ${result.verdict}`);
```

---

### 2. Batch Analysis

**POST** `/batch_analyze`

Analyze up to 100 targets in a single request with configurable concurrency.

#### Request

```json
{
  "inputs": [
    "example.com",
    "test.org",
    "sus-domain.tk",
    "192.168.1.1"
  ],
  "max_concurrent": 5
}
```

#### Response

```json
{
  "batch_id": "batch_6f4a21cb",
  "total_inputs": 4,
  "completed": 4,
  "malicious_count": 2,
  "clean_count": 2,
  "latency_ms": 3421,
  "results": [
    {
      "input": "example.com",
      "risk_score": 8,
      "verdict": "benign",
      "confidence": 0.92,
      "signals_triggered": ["Top-Tier Reputable Domain"],
      "error": null
    },
    {
      "input": "test.org",
      "risk_score": 15,
      "verdict": "neutral",
      "confidence": 0.65,
      "signals_triggered": ["New Domain", "Unusual Registrar"],
      "error": null
    },
    {
      "input": "sus-domain.tk",
      "risk_score": 85,
      "verdict": "malicious",
      "confidence": 0.91,
      "signals_triggered": ["Suspicious TLD", "Typosquatting"], 
      "error": null
    },
    {
      "input": "192.168.1.1",
      "risk_score": 0,
      "verdict": "benign",
      "confidence": 1.0,
      "signals_triggered": [],
      "error": null
    }
  ]
}
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `inputs` | array | required | 1-100 targets to analyze |
| `max_concurrent` | number | 5 | Concurrent analyzer workers (1-10) |

#### Status Codes

- **200 OK** — Batch analysis completed
- **400 Bad Request** — Invalid inputs (> 100, < 1, malformed)
- **429 Too Many Requests** — Rate limit exceeded
- **500 Internal Server Error** — Batch processing failed

#### Examples

**cURL:**
```bash
curl -X POST http://localhost:8000/batch_analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_XXXXXXX" \
  -d '{
    "inputs": ["example.com", "test.org"],
    "max_concurrent": 5
  }'
```

**Python:**
```python
import requests

response = requests.post("http://localhost:8000/batch_analyze", json={
    "inputs": ["example.com", "test.org", "192.168.1.1"],
    "max_concurrent": 5
})
batch = response.json()
print(f"Analyzed: {batch['completed']}/{batch['total_inputs']}")
print(f"Malicious: {batch['malicious_count']}")
```

---

### 3. Metrics Snapshot

**GET** `/metrics`

Retrieve operational metrics (cache hit rate, signal frequency, latency stats).

#### Response

```json
{
  "scan_count": 1247,
  "malicious_count": 312,
  "scan_duration": {
    "avg": 0.42,
    "min": 0.05,
    "max": 3.21
  },
  "intel_lookup_latency": {
    "avg": 0.12,
    "min": 0.01,
    "max": 1.5
  },
  "cache_hits": 892,
  "cache_misses": 355,
  "cache_hit_rate": 71.5,
  "signal_frequency": {
    "Domain Age": 248,
    "Typosquatting Suspected": 156,
    "Suspicious TLD": 142,
    "Top-Tier Reputable Domain": 89,
    "Homoglyph Lookalike Detected": 67
  },
  "error_count": 4,
  "uptime_seconds": 86400,
  "timestamp": "2024-03-15T10:30:00Z"
}
```

#### Field Explanations

| Field | Type | Description |
|-------|------|-------------|
| `scan_count` | number | Total analyses performed |
| `malicious_count` | number | Verdicts marked as MALICIOUS |
| `scan_duration` | object | Analysis execution time stats (seconds) |
| `intel_lookup_latency` | object | Threat intel API response time (seconds) |
| `cache_hits` | number | Number of cache hits |
| `cache_misses` | number | Number of cache misses |
| `cache_hit_rate` | number | Hit rate as percentage |
| `signal_frequency` | object | Top 10 signals by trigger count |
| `error_count` | number | Analysis errors |
| `uptime_seconds` | number | Server uptime |
| `timestamp` | string | Snapshot timestamp (ISO 8601) |

#### Status Codes

- **200 OK** — Metrics retrieved
- **403 Forbidden** — Requires admin API key or IP whitelist
- **500 Internal Server Error** — Metrics collection failed

#### Examples

**cURL:**
```bash
curl -X GET http://localhost:8000/metrics \
  -H "Authorization: Bearer sk_XXXXXXX"
```

**Python:**
```python
import requests

response = requests.get("http://localhost:8000/metrics")
metrics = response.json()
print(f"Cache hit rate: {metrics['cache_hit_rate']}%")
print(f"Avg scan time: {metrics['scan_duration']['avg']}s")
```

---

## Security Endpoints

### 1. List API Keys

**GET** `/api/security/keys`

List all active API keys (admin endpoint).

#### Response

```json
{
  "keys": [
    {
      "key_id": "key_1a2b3c4d",
      "name": "Production Frontend",
      "created_at": "2024-01-15T09:00:00Z",
      "rate_limit_per_minute": 120,
      "use_count": 15234,
      "last_used": "2024-03-15T10:29:00Z"
    },
    {
      "key_id": "key_5e6f7g8h",
      "name": "Partner Integration",
      "created_at": "2024-02-01T14:30:00Z",
      "rate_limit_per_minute": 240,
      "use_count": 8900,
      "last_used": "2024-03-15T10:15:00Z"
    }
  ]
}
```

#### Status Codes

- **200 OK** — Keys listed
- **403 Forbidden** — Unauthorized (not admin)
- **500 Internal Server Error** — Database error

---

### 2. Generate API Key

**POST** `/api/security/generate-key`

Create a new API key with optional rate limit tier.

#### Request

```json
{
  "name": "My App Integration",
  "rate_limit_per_minute": 120
}
```

#### Response

```json
{
  "key": "sk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "key_id": "key_newkey01",
  "name": "My App Integration",
  "rate_limit_per_minute": 120,
  "created_at": "2024-03-15T10:30:00Z"
}
```

**Note:** The full key is only shown once. Store it securely!

#### Status Codes

- **201 Created** — Key generated
- **400 Bad Request** — Invalid parameters
- **403 Forbidden** — Unauthorized
- **500 Internal Server Error** — Database error

---

## Response Headers

All responses include:

```
X-Request-ID: req_a1b2c3d4e5f6g7h8  (unique request identifier for debugging)
X-RateLimit-Limit: 60                (requests per minute)
X-RateLimit-Remaining: 45            (requests remaining)
X-RateLimit-Reset: 1710501600        (Unix timestamp when limit resets)
```

If rate limited:

```
Retry-After: 45  (seconds to wait before retrying)
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Invalid target format",
  "error_code": "INVALID_TARGET",
  "request_id": "req_a1b2c3d4e5f6g7h8",
  "details": {
    "target": "not a valid URL or domain"
  }
}
```

### Common Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_TARGET` | 400 | Target is not a valid URL, domain, or IP |
| `RATE_LIMITED` | 429 | Too many requests from this IP/key |
| `UNAUTHORIZED` | 403 | Missing or invalid API key for admin endpoint |
| `BATCH_TOO_LARGE` | 400 | More than 100 inputs in batch |
| `BATCH_EMPTY` | 400 | Batch has no inputs |
| `ANALYSIS_FAILED` | 500 | Internal analysis error |
| `DATABASE_ERROR` | 500 | Database query failed |
| `TIMEOUT` | 504 | Analysis exceeded timeout (30s) |

---

## Verdict Values

| Verdict | Score Range | Color | Description |
|---------|-------------|-------|-------------|
| `MALICIOUS` | 70-100 | 🔴 Red | High confidence threat (malware, phishing, C2) |
| `SUSPICIOUS` | 40-69 | 🟡 Yellow | Medium confidence threat (unusual patterns) |
| `NEUTRAL` | 1-39 | ⚪ Gray | Low risk but some concerns |
| `BENIGN` | 0 | 🟢 Green | Safe, reputable, or whitelisted |

---

## Signal Buckets

All signals are categorized into buckets reflecting their type:

### Reputation (`reputation`)
- Domain Age
- Registrar Privacy Status
- Known Bad Lists
- Top-Tier Reputable Domain
- Parked Domain Suspected
- **Typical Impact:** -65 to +40

### Structure (`structure`)
- Typosquatting Suspected
- Homoglyph Lookalike Detected
- Suspicious TLD
- IDN/Punycode
- **Typical Impact:** 0 to +35

### Network (`network`)
- DNS Nameservers
- DNS A/AAAA records
- Port Analysis
- ASN Reputation
- **Typical Impact:** 0 to +20

---

## Rate Limiting Details

ElixirAnalyzer uses **token-bucket** rate limiting:

- **Default:** 60 requests/minute per IP
- **With API Key:** Based on key tier (e.g., 120 req/min for standard, 240 for premium)
- **Per-Endpoint:** `/batch_analyze` has stricter limits (e.g., 30 req/min)
- **Burst Allowed:** Up to bucket capacity (typically 5 requests at once)

**Reset Behavior:**
- Limit resets every minute (based on 60-second windows)
- `X-RateLimit-Reset` header shows Unix timestamp of next window
- `Retry-After` header shows seconds to wait if limited

**Example:**
```
Initial state: 60 tokens available
After 45 requests: 15 tokens remaining
Next request: 429 Too Many Requests
Retry-After: 45 seconds
```

---

## Versioning

Current API version: **1.1.0**

**Backward Compatibility:**
- All response fields are cumulative (never removed, only added)
- New fields are marked with comment `← NEW`
- Clients should ignore unknown fields
- Version header: `API-Version: 1.1.0`

---

## Example Workflows

### Workflow 1: Simple Domain Check

```python
import requests

def check_domain(domain):
    response = requests.post("http://localhost:8000/analyze", 
        json={"target": domain})
    result = response.json()
    
    if result['verdict'] == 'MALICIOUS':
        print(f"🚨 {domain} is malicious!")
        for signal in result['signals']:
            print(f"  - {signal['name']}: +{signal['impact']} points")
    else:
        print(f"✓ {domain} is {result['verdict']} (risk: {result['risk_score']})")

check_domain("example.com")
```

### Workflow 2: Bulk URL Screening with Concurrency Control

```python
import requests

def screen_urls(url_list):
    response = requests.post("http://localhost:8000/batch_analyze", json={
        "inputs": url_list,
        "max_concurrent": 10
    })
    batch = response.json()
    
    malicious = [r for r in batch['results'] if r['verdict'] == 'MALICIOUS']
    print(f"Found {len(malicious)} malicious URLs:")
    for result in malicious:
        print(f"  - {result['input']}: {result['risk_score']}/100")

screen_urls(["example.com", "google.com", "phish-site.tk"])
```

### Workflow 3: Real-Time Monitoring

```python
import requests
import time

def monitor_health():
    while True:
        metrics = requests.get("http://localhost:8000/metrics").json()
        print(f"Cache hit rate: {metrics['cache_hit_rate']}%")
        print(f"Avg latency: {metrics['scan_duration']['avg']*1000:.1f}ms")
        print(f"Uptime: {metrics['uptime_seconds'] // 3600}h")
        time.sleep(5)

monitor_health()
```

---

## FAQ

**Q: How long are results cached?**
A: 24 hours by default. Redis TTL is configurable via `CACHE_TTL_SECONDS` env var.

**Q: What's the maximum batch size?**
A: 100 inputs per batch. Larger batches should be split into multiple requests.

**Q: Can I use IP addresses?**
A: Yes. The API auto-detects domain, URL, or IP and routes to appropriate analyzer.

**Q: Is HTTPS required?**
A: No for localhost testing. For production, HTTPS is strongly recommended.

**Q: How do I get an API key?**
A: Contact the admin or use `/api/security/generate-key` endpoint (admin-only).

**Q: What's included in the "intel_sources" field?**
A: List of TI databases that were queried (e.g., `["whois", "dns", "geoip"]`).
