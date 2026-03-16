# Elixir Analyzer 🦞

**Premium Threat Intelligence & Structural Analysis Engine**

Elixir Analyzer is a professional-grade security ecosystem designed to dismantle and evaluate the risk of domains, URLs, and IP addresses. By combining real-time OSINT intelligence, visual behavioral heuristics, and deep structural analysis, it provides high-fidelity risk scores and explainable security verdicts.

## 📡 Intelligence Pillars

- **Parallel OSINT Pipeline:** Concurrent lookups via **VirusTotal (v3)**, **AbuseIPDB**, and **urlscan.io**.
- **Visual Intelligence:** Safe "Hazmat" browser capture (Playwright) and automated **Credential Harvester** detection.
- **Global Authority Reputation:** Automated weekly sync with the **Tranco Top 100K** reputable domain list.
- **Temporal Analysis:** Domain maturity and historical consistency tracking via the **Wayback Machine**.
- **Identity Protection:** Advanced **Homoglyph (lookalike)** shield and intelligent **Keyboard Typosquatting** classification.
- **Reliable Data Engine:** High-performance persistence layer using **PostgreSQL (Drizzle)** and **SQLite (WAL mode)**.

## 🚀 Deployment & Production

Elixir is production-hardened with security headers (Helmet), API rate limiting, and a multi-stage pipeline architecture.

### **1. Environment Provisioning**
Configure your intelligence keys:
```bash
cp .env.example .env
```
Recommended env keys (choose as needed): API_KEY, QUOTA_PER_15MIN, SANDBOX, SANDBOX_ALLOW_HOSTS, VISUAL_CAPTURE_ENABLED, DYN_JS_INSTRUMENT, DYN_CAPTURE_HAR, GSB_API_KEY, PHISHTANK_APP_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, REDIS_URL, YARA_ENABLED, YARA_RULES_DIR, CLAMAV_ENABLED, METRICS_ENABLED, OTEL_ENABLED, OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME.

### **2. Automated Setup & Build**
Install dependencies and build the production bundle:
```bash
npm run prod:setup
npm run prod:build
```

### **3. Launching the Hub**
Start the high-performance production server:
```bash
npm run prod:start
```

### **🐳 Containerization**
Deploy instantly in any environment using the optimized Docker image:
```bash
docker build -t elixir-analyzer .
docker run -p 5000:5000 --env-file .env elixir-analyzer
```
Optional Redis for queueing:
```bash
docker run -d --name elixir-redis -p 6379:6379 redis:7-alpine
```

## Local quick start (no Postgres)

If you don't have PostgreSQL running locally yet, you can run the API with an in-memory history store:

```bash
npm.cmd run build:server
npm.cmd run start:mem
```

This starts the API on `http://127.0.0.1:5000` and serves a small placeholder page at `/` if the client build is not present.

### Optional security hardening (recommended)

- Set `API_KEY` to require an `x-api-key` header for all `/api/*` endpoints.
- Set `VISUAL_CAPTURE_ENABLED=1` to enable Playwright screenshots (disabled by default). When enabled, the server blocks non-public IP/hostnames to reduce SSRF risk.
- Dynamic analysis (optional, behind flags):
	- `DYN_JS_INSTRUMENT=1` to enable runtime JS instrumentation (captures fetch/xhr/beacon/ws, eval/Function/atob, minimal DOM locks).
	- `DYN_TIMEOUT_MS=15000` to control navigation timeout for detonation (min 1000, max 60000).
	- `DYN_CAPTURE_HAR=1` to enable HAR capture during detonation (served from `/api/har/:file`).

External engines (optional):
- `GSB_API_KEY` for Google Safe Browsing v4.
- `PHISHTANK_APP_KEY` for PhishTank checkurl API.
- `SANDBOX` and `SANDBOX_ALLOW_HOSTS` to restrict egress (include: `safebrowsing.googleapis.com,urlscan.io,checkurl.phishtank.com`).
	- `DYN_CAPTURE_HAR=1` to record a HAR for the detonation session, downloadable from `/api/har/:id.har`.

When dynamic analysis is enabled, additional behavioral heuristics are generated, such as off-origin credential posts, off-origin exfil, WebSocket beacons, and script obfuscation bursts. Screenshots are served from `/api/screenshots/:file`.

### Multi-engine URL checks (VT-style)

- Enable (default on): `MULTI_ENGINE_ENABLED=1`
- Optional provider keys:
	- `GSB_API_KEY` or `GOOGLE_SAFE_BROWSING_KEY` — Google Safe Browsing v4
	- `PHISHTANK_APP_KEY` — PhishTank checkurl (legacy)
	- urlscan.io search works without a key (rate-limited)
- If you run with `SANDBOX=1`, allow the hosts via:
	```powershell
	$env:SANDBOX=1
	$env:SANDBOX_ALLOW_HOSTS='www.virustotal.com,api.abuseipdb.com,ipapi.co,ipwho.is,ip-api.com,safebrowsing.googleapis.com,urlscan.io,checkurl.phishtank.com'
	```

### Asynchronous scans (VT-style)

- Submit a scan job:
	```powershell
	$headers = @{ 'Content-Type' = 'application/json' }
	$body = @{ type = 'domain'; input = 'example.com' } | ConvertTo-Json
	Invoke-RestMethod -Uri http://127.0.0.1:5000/api/submit -Method Post -Headers $headers -Body $body
	```
- Poll for result:
	```powershell
	Invoke-RestMethod -Uri http://127.0.0.1:5000/api/result/<jobId>
	```

### Multi-engine URL checks

When engine keys are configured, responses include `details.threatIntelligence.engines`, an array of `{ engine, verdict, confidence, link? }`.

### File uploads + hashing (alpha)

- Upload a file via base64 JSON:
	```powershell
	$bytes = [IO.File]::ReadAllBytes('sample.bin')
	$b64 = [Convert]::ToBase64String($bytes)
	$body = @{ filename = 'sample.bin'; contentBase64 = $b64 } | ConvertTo-Json
	Invoke-RestMethod -Uri http://127.0.0.1:5000/api/samples/uploadBase64 -Method Post -Headers @{ 'Content-Type'='application/json' } -Body $body
	```
- Get metadata:
	```powershell
	Invoke-RestMethod -Uri http://127.0.0.1:5000/api/samples/<sha256>/meta
	```
- Download the stored sample:
	```powershell
	Invoke-RestMethod -Uri http://127.0.0.1:5000/api/samples/<sha256>/download -OutFile sample.bin
	```

Notes: Samples are de-duplicated by SHA-256 and stored under `server/data/samples`. A full file-analysis pipeline (YARA/AV/unpack) can be layered on top in future phases.

### Optional YARA integration

- Requirements: `YARA_ENABLED=1`, `YARA_RULES_DIR=./server/files/rules` (or your rules path), and YARA CLI available on PATH (`yara` or `yara64.exe`).
- Optional: `YARA_TIMEOUT_MS=8000`, `YARA_BIN=yara`.
- When enabled, file scans add `YARA:<rule>` detections to the sample report.

### Redis-backed queue (optional)
### Email Analysis (MVP)

**Unified email investigation dashboard:**

- Analyze raw EML via API:
  ```powershell
  $raw = Get-Content -Raw -Encoding UTF8 .\sample.eml
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($raw))
  $body = @{ source='upload'; contentBase64=$b64 } | ConvertTo-Json
  Invoke-RestMethod -Uri http://127.0.0.1:5000/api/email/analyze -Method Post -Headers @{ 'Content-Type'='application/json' } -Body $body
  ```

- **Features:**
  - RFC 5322 parsing (headers, Received path, attachments).
  - SPF evaluation (IPv4 CIDR, includes, catch-all).
  - DKIM signature verification (RSA-SHA256, relaxed/relaxed canonicalization).
  - DMARC policy alignment and enforcement.
  - Header heuristics: suspicious TLDs, new domains, alignment mismatches.
  - URL analysis leverage and drill-down.
  - Attachment scanning and verdict integration.
  - Risk scoring (composite from auth + heuristics + links + attachments).
  - Dashboard: Inbox, case detail with Headers/Body/Links/Attachments tabs, Received path timeline, alignment badges, tooltips.
  - PII controls: optional raw EML retention, HTML body storage, redacted fetch, TTL cleanup.

- Get case/list:
  ```powershell
  Invoke-RestMethod -Uri http://127.0.0.1:5000/api/email/<id>
  Invoke-RestMethod -Uri http://127.0.0.1:5000/api/email
  ```

- Optional flags:
  - `EMAIL_RETAIN_RAW=1` to save raw EML artifacts under `server/data/email/raw`.
  - `EMAIL_STORE_BODY_HTML=1` to optionally store parsed HTML body.
  - `EMAIL_RAW_TTL_DAYS=7` to auto-cleanup raw EML after N days (runs every 6 hours).
  - `EMAIL_RATE_MAX=30` to set endpoint-specific rate limit (default 30 per 15 min).
  - Install `mailparser` for robust MIME/HTML parsing: `npm install mailparser`.
  - Install `dompurify` for safe HTML preview on client: `npm install dompurify`.

- **See [EMAIL_ROLLOUT.md](./EMAIL_ROLLOUT.md) for full API reference, testing, and production rollout guidance.**
- Set `REDIS_URL=redis://localhost:6379` to switch async job processing from in-memory to Redis (BullMQ). Falls back to in-memory if BullMQ is not installed or env is missing.

### Multi-engine URL checks (opt-in)

Configure external providers (only engines with valid keys are queried):

- `GSB_API_KEY` (or `GOOGLE_SAFE_BROWSING_KEY`) — Google Safe Browsing v4
- `PHISHTANK_APP_KEY` — PhishTank checkurl API
- `URLSCAN_API_KEY` — urlscan.io API (passive search)
- `MULTI_ENGINE_ENABLED=1` — enable/disable the multi-engine block (default 1)

Results appear under `details.threatIntelligence.engines` as an array of `{ engine, verdict, ... }`.

### HAR capture (opt-in)

Enable HTTP Archive capture during detonation:

```powershell
$env:VISUAL_CAPTURE_ENABLED=1
$env:DYN_JS_INSTRUMENT=1
$env:DYN_CAPTURE_HAR=1
npm run start:mem
```

When enabled, a `.har` file is written per detonation and exposed at `/api/har/<id>.har` (also linked from `details.threatIntelligence.visualCapture.har`).

## Runbook (Ops quick notes)

- Health check: `/api/health`.
- Metrics (JSON): `/api/metrics` when `METRICS_ENABLED=1`.
- Prometheus exporter: `/metrics` when `PROMETHEUS_ENABLED=1`.
- If `/api/*` returns HTML, restart server to load new routes.
- Port conflicts: free port 5000 or set `PORT` env.
- Queue mode: if `REDIS_URL` is set and BullMQ is available, jobs use Redis; else in-memory.
- Visual capture timeouts: adjust `DYN_TIMEOUT_MS`.
- Sandbox egress: set `SANDBOX=1` and configure `SANDBOX_ALLOW_HOSTS`.

## 🛠️ Tech Stack

- **Backend:** Node.js, Express, TypeScript (Modular Pipeline Architecture)
- **Frontend:** React, Vite, TailwindCSS (Premium Cinematic UI)
- **Database:** PostgreSQL / SQLite (Drizzle ORM)
- **Investigation:** Playwright (Headless Browser), `tldextract`, `punycode`
- **Analytics:** Chart.js, Framer Motion

## 📂 Architecture overview

- `server/` Node/Express API and tactical analysis services.
- `client/` React UI (Dashboard, History, Results).
- `shared/` Unified Zod schemas and API contracts.
- `legacy_python_research/` Historical Python FastAPI engine and research shims.

---
