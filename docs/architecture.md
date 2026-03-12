# ElixirAnalyzer Architecture

## Overview

ElixirAnalyzer is a production-grade threat intelligence platform that performs multi-dimensional analysis on URLs, domains, and IP addresses to assign risk scores and verdicts. The system combines heuristic analysis with external threat intelligence aggregation, intelligent caching, and batch processing capabilities.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Frontend (React/TypeScript)                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   Dashboard      │  │  Batch Scan      │  │ Signals Explorer │  │
│  │                  │  │                  │  │                  │  │
│  │ • ThreatScore    │  │ • Form input     │  │ • Browse signals │  │
│  │   Card           │  │ • Concurrency    │  │ • Filter by      │  │
│  │ • Signal        │  │   control        │  │   bucket/impact  │  │
│  │   Breakdown      │  │ • Progress       │  │ • View examples  │  │
│  │ • Risk Gauge     │  │   tracking       │  │ • Buckets info   │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│  ┌──────────────────┐                                                │
│  │ Metrics Monitor  │         Auto-refresh: 5s                      │
│  │ • Real-time      │         WebSocket: future enhancement         │
│  │ • Cache hit rate │                                               │
│  │ • Top signals    │                                               │
│  └──────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓ HTTP/REST
┌─────────────────────────────────────────────────────────────────────┐
│                    API Gateway (FastAPI + Middleware)                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Middleware Stack:                                            │  │
│  │ 1. CORS (allow cross-origin requests)                       │  │
│  │ 2. Request ID injection (req_XXXX)                          │  │
│  │ 3. Rate Limiting (token-bucket, 60 req/min per IP)         │  │
│  │ 4. API Key validation (optional, for premium features)     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  Endpoints:                                                          │
│  • POST /analyze → Single target analysis                           │
│  • POST /batch_analyze → Up to 100 targets, configurable concurrency│
│  • GET /metrics → Operational metrics snapshot                      │
│  • GET/POST /api/security/keys → API key management                 │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│                        Analysis Pipeline                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Input Dispatcher (domain/url/ip detection)                  │  │
│  └────────────────┬─────────────────────────────────────────────┘  │
│                   ↓                                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Analyzer Layer (Parallel Execution)             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │ Domain       │  │ URL          │  │ IP           │      │   │
│  │  │ Analyzer     │  │ Analyzer     │  │ Analyzer     │      │   │
│  │  │              │  │              │  │              │      │   │
│  │  │ • Heuristics │  │ • Heuristics │  │ • Heuristics │      │   │
│  │  │ • Reputation │  │ • Analysis   │  │ • Geolocation│      │   │
│  │  │ • Structure  │  │ • Dynamic    │  │ • ASN lookup │      │   │
│  │  │   checks     │  │   checks     │  │ • Reputation │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                           ↓                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │    Threat Intelligence Aggregation (Async Lookups)            │  │
│  │  • asyncio.gather() for concurrent requests                  │  │
│  │  • WHOIS lookups (registrar, abuse contact)                 │  │
│  │  • DNS records (A, MX, NS, SPF, DMARC)                     │  │
│  │  • GeoIP database (MaxMind/IP2Location)                     │  │
│  │  • AbuseIPDB reputation reports                             │  │
│  │  • ThreatFox IOC database                                    │  │
│  │  • Optional caching with configurable timeouts              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           ↓                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Signal Aggregation & Scoring                     │  │
│  │  • Merge signals from all analyzers                          │  │
│  │  • Apply weighted impact scoring (per bucket):              │  │
│  │    - Reputation signals (higher impact: 0-40 pts, avg -65)  │  │
│  │    - Structure signals (medium impact: 0-35 pts)            │  │
│  │    - Network signals (lower impact: 0-20 pts)               │  │
│  │  • Aggregate confidence across signals                       │  │
│  │  • Detect infrastructure clusters (graph analysis)           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           ↓                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │             Verdict Generation                                │  │
│  │  • Map risk score (0-100) to verdict:                        │  │
│  │    - 70+: MALICIOUS (red)                                    │  │
│  │    - 40-70: SUSPICIOUS (yellow)                              │  │
│  │    - 1-40: NEUTRAL (gray)                                    │  │
│  │    - 0: BENIGN (green)                                       │  │
│  │  • Include per-signal breakdown by risk bucket               │  │
│  │  • Mark confidence range (low/medium/high)                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                           ↓ Response
┌─────────────────────────────────────────────────────────────────────┐
│                    Response Format (JSON)                             │
│  {                                                                    │
│    "input": "example.com",                                           │
│    "risk_score": 72,              ← 0-100 scale                     │
│    "verdict": "malicious",        ← MALICIOUS|SUSPICIOUS|NEUTRAL|... │
│    "confidence": 0.86,            ← 0-1 scale                       │
│    "signals": [                   ← deprecated but kept for compat   │
│      { "name": "...", "impact": ..., ... }                         │
│    ],                                                                │
│    "signals_triggered": [...],    ← NEW: signal names only          │
│    "intel_sources": ["dns", "whois", ...],  ← NEW: TI sources used │
│    "breakdown": {                 ← Score by bucket                  │
│      "reputation": 50,                                              │
│      "structure": 22,                                               │
│      "network": 0                                                   │
│    }                                                                 │
│  }                                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. **Analyzers** (`legacy_python_research/analyzers/`)

Each analyzer is specialized for its input type:

#### Domain Analyzer
- **Typosquatting Detection**: Compares against known brand names using edit distance
- **Homoglyph Detection**: Detects visually similar Unicode characters
- **TLD Analysis**: Flags suspicious TLDs (.tk, .ml, etc.)
- **Age Check**: Flags newly registered domains
- **DNS Validation**: Checks A, MX, NS record health

#### URL Analyzer
- **Path Analysis**: Detects suspicious URL patterns (encoding, slashes)
- **Redirect Analysis**: Follows redirects, detects chains
- **Obfuscation Detection**: Finds IP-based URLs, excessive encoding
- **Mobile Threat Screening**: Detects mobile malware patterns

#### IP Analyzer
- **Geolocation Analysis**: Flags suspicious geographic regions
- **ASN Reputation**: Checks ASN ownership and history
- **Port Analysis**: Scans common ports for services
- **Reputation Databases**: Queries AbuseIPDB, Project Honey Pot

### 2. **Threat Intelligence Aggregation** (`threat_intel.py`)

Async aggregator that pulls data from multiple sources in parallel:

```python
async with get_aggregator() as agg:
    whois_data = await agg.lookup_domain("example.com")
    dns_data = await agg.lookup_dns_records("example.com")
    ip_geo = await agg.lookup_ip_geolocation("1.2.3.4")
```

**Supported Sources:**
- WHOIS (registrar details)
- DNS records (A, AAAA, MX, NS, TXT)
- GeoIP (MaxMind/IP2Location)
- ASN lookups (ARINC, RIPE)
- AbuseIPDB (reputation scores)
- ThreatFox (IOC database)

**Performance:** ~3-4x faster than sequential lookups due to asyncio concurrency.

### 3. **Reputation Cache** (`reputation_cache.py`)

Hybrid caching strategy with Redis fallback:

```
Request → Try Redis (async lookup)
          ↓ Cache miss or Redis unavailable
          Try TTL Memory Cache (24-hour default)
          ↓ Cache miss
          Fetch from source → Store in both caches
```

**Features:**
- Optional Redis backend (controlled by `REDIS_URL` env var)
- Automatic TTL-based expiration (24 hours default)
- Per-data-type cache keys (WHOIS, DNS, GeoIP separate)
- Graceful degradation if Redis is down

### 4. **Graph-Based Analysis** (`graph_analysis.py`)

Builds infrastructure relationship graphs for detecting coordinated attacks:

**Nodes:**
- Domains
- IP addresses
- ASNs
- Hosting providers

**Edges:**
- Domain → IP (DNS resolution)
- IP → ASN (IP space ownership)
- Domain → Domain (parent domain, lookalike)
- IP → IP (same ASN, geographically close)

**Cluster Detection:**
- Finds 3+ malicious domains on 1 IP
- Detects multiple malicious IPs in 1 ASN
- Identifies infrastructure reuse patterns
- Flags likely bulletproof hosting

### 5. **Observability** (`observability.py`)

First-party metrics collection (no external APM dependency):

```python
collector = get_metrics_collector()
collector.record_scan(duration_seconds=0.42)
collector.record_signal_fired("typosquatting")
collector.record_cache_hit()
```

**Metrics Tracked:**
- Scan duration (avg/min/max)
- Intel lookup latency
- Cache hit rate
- Signal frequency (top 10)
- Error count
- Uptime

**Exposure:** `GET /metrics` endpoint returns JSON snapshot

### 6. **API Security** (`api_security.py`)

Token-bucket rate limiting and API key management:

```python
limiter = get_rate_limiter()
if limiter.is_allowed(client_ip, requests_per_minute=60):
    # Process request
else:
    # Return 429 Too Many Requests
```

**Features:**
- Per-IP rate limiting (default 60 req/min)
- Per-key rate limits (premium tiers)
- API key CRUD operations
- Request ID tracking for debugging
- Automatic cleanup of old entries

## Data Flow

### Single Analysis
```
POST /analyze {"target": "example.com"}
    ↓
Input Detection → Domain
    ↓
Run Domain Analyzer (parallel heuristics)
    ↓
TI Aggregation (async WHOIS, DNS, GeoIP, etc.)
    ↓
Cache results for 24 hours
    ↓
Signal Aggregation + Scoring
    ↓
Graph Analysis (detect clusters)
    ↓
Verdict Generation
    ↓
Record metrics + signals
    ↓
Return JSON response (with explainability fields)
```

**Timing:** ~0.5-2s depending on cache hits + TI response times

### Batch Analysis
```
POST /batch_analyze {"inputs": [target1, target2, ...], "max_concurrent": 5}
    ↓
Create Semaphore(max_concurrent) for worker pool
    ↓
Queue asyncio tasks for each target
    ↓
Workers pull from queue respecting semaphore
    ↓
Merge results as each completes
    ↓
Return batch response with per-target results + stats
```

**Throughput:** Linear with concurrency limit (5 concurrent = ~2-5s for 50 targets)

## Scoring System

Each signal has impact and confidence:
- **Impact**: Contribution to risk score (+/- 0-65 points)
- **Confidence**: How sure we are about this signal (0-1)

### Bucket Weighting

| Bucket | Signal Examples | Typical Impact | Weight |
|--------|-----------------|----------------|--------|
| reputation | Domain age, registrar privacy, known bad list | -65 to +40 | 50% |
| structure | Typosquatting, homoglyph, TLD suspicious | 0 to +35 | 35% |
| network | DNS missing, port open on unusual service | 0 to +20 | 15% |

### Aggregation Algorithm

```
risk_score = 0
confidence = 0
for each signal in signals:
    risk_score += signal.impact * signal.confidence
    confidence = max(confidence, signal.confidence)

# Normalize to 0-100 scale
risk_score_normalized = max(0, min(100, (risk_score + 100) / 2))

# Generate verdict
if risk_score_normalized >= 70:
    verdict = MALICIOUS
elif risk_score_normalized >= 40:
    verdict = SUSPICIOUS
elif risk_score_normalized >= 1:
    verdict = NEUTRAL
else:
    verdict = BENIGN
```

## Backend Technologies

- **Runtime:** Python 3.9+
- **Framework:** FastAPI (async HTTP server)
- **Async:** asyncio + aiohttp for concurrent TI lookups
- **Caching:** Redis (optional) + in-memory TTL fallback
- **Database:** SQLite (for persistence, optional)
- **Testing:** pytest + pytest-asyncio

## Frontend Technologies

- **Framework:** React 18+ (TypeScript)
- **Styling:** Tailwind CSS
- **UI Components:** shadcn/ui
- **Data Fetching:** react-query (TanStack Query)
- **Build:** Vite

## Deployment Architecture

```
┌─────────────────────────────────────┐
│        Docker Container              │
│  ┌───────────────────────────────┐  │
│  │ Frontend (Vite dev server)     │  │ Port 5173 (dev) / 80 (prod)
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ Backend (FastAPI + Uvicorn)   │  │ Port 8000
│  │  • API server                  │  │
│  │  • Middleware stack            │  │
│  │  • Analysis pipeline           │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ Optional Redis instance        │  │ Port 6379 (external)
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**Environment Variables:**
```bash
# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# Threat Intelligence API Keys
ABUSEIPDB_API_KEY=xxx
THREATFOX_API_KEY=xxx
MAXMIND_LICENSE_KEY=xxx

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# Server
HOST=0.0.0.0
PORT=8000
```

## Scalability Considerations

1. **Horizontal Scaling:** Run multiple backend instances behind load balancer; share Redis cache
2. **TI Aggregation:** Cache layer reduces external API calls by 60-80%
3. **Background Jobs:** Future: move TI lookups to background queue (Celery/Dramatiq) for very high throughput
4. **Database Persistence:** Store analysis results + signals in database for auditing and trend analysis
5. **Graph Storage:** Currently in-memory; future: persist to graph database (Neo4j) for large-scale clustering

## Security Model

**Authentication:**
- Optional API keys (sk_XXXX format)
- Rate limiting per IP + per key
- Request ID tracking for audit logs

**Endpoints Access:**
- `/analyze` — public (rate limited)
- `/batch_analyze` — public (stricter rate limit)
- `/metrics` — admin-only (suggest IP whitelist)
- `/api/security/*` — admin-only

**Data Privacy:**
- No storage of analyzed URLs by default
- Optional audit log (enable via env var)
- WHOIS data cached; sensitive fields masked on export

## Future Enhancements

1. **Real-Time Threat Intelligence Feed:** WebSocket endpoint for live signal updates
2. **Machine Learning:** Train classifier on historical signals + verdicts
3. **Graph Visualization:** Frontend page showing infrastructure clusters
4. **Audit Logging:** Persistent record of all analyses + API key usage
5. **Plugins System:** Custom analyzer modules (YARA rules, external scripts)
6. **Threat Hunting:** Query interface for historical signal frequency analysis
