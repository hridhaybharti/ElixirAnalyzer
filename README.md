# Elixir Analyzer 🦞

Premium threat intelligence and heuristic risk scoring for domains, URLs, and IPs.

## 🚀 Real-World Production Setup

Elixir Analyzer is now production-hardened with security headers, rate limiting, and a parallel pipeline architecture.

### **1. Environment Provisioning**
Copy the example environment file and fill in your production keys:
```bash
cp .env.example .env
```

### **2. Automated Setup & Build**
Run the production initialization script to install dependencies (including headless browser binaries) and build the project:
```bash
npm run prod:setup
npm run prod:build
```

### **3. Launching the Engine**
Start the high-performance production server:
```bash
npm run prod:start
```

### **🐳 Docker Deployment (Recommended)**
For a seamless, isolated environment, use the provided Dockerfile:
```bash
docker build -t elixir-analyzer .
docker run -p 5000:5000 --env-file .env elixir-analyzer
```

---

## 🦾 Features & Heuristics
- **Parallel OSINT Pipeline:** Concurrent lookups via VirusTotal, AbuseIPDB, and urlscan.io.
- **Visual Intelligence:** Headless browser capture and Credential Harvester detection.
- **Authority Reputation:** Automated sync with Tranco Top 100K list.
- **Archive Insight:** Domain maturity analysis via the Wayback Machine.
- **Homoglyph Shield:** Visual similarity detection for protected brands.
- **Reliable Persistence:** SQLite WAL mode with atomic transactions.

## API Endpoints (Node)

- `POST /api/analyze`
  - Body: `{ "type": "domain|ip|url", "input": "..." }`
  - Note: `value` is also accepted for backward compatibility.
- `GET /api/history`
- `DELETE /api/history`
- `GET /api/analysis/:id`
- `GET /api/reputation/status`

## API Endpoints (Python Legacy)

- `GET /health`
- `POST /api/analyze`
- `GET /api/history`
- `DELETE /api/history`
- `GET /api/explain/{analysis_id}`
- `GET /api/reputation/status`

## Configuration

Node service (`.env`):
- `PORT`
- `DATABASE_URL`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`

Python service (optional):
- `SECURITY_ANALYZER_WEIGHTS=/path/to/weights.json`
- `SECURITY_ANALYZER_DB_PATH=/path/to/analyzer.sqlite3`

## Repository Layout

- `server/` Node/Express API, analysis pipeline, and database access.
- `client/` React UI (Vite).
- `shared/` Shared Zod schemas and API route contracts.
- `migrations/` Drizzle SQL migrations and snapshots.
- `script/` Build and smoke-test scripts.
- `backend/` Python FastAPI API and heuristics engine (legacy).
- `engine/` Python compatibility shims for legacy imports.
- `tests/` Python test suite for the legacy backend.
- `docs/` Architecture notes.
- `frontend/` Legacy frontend config (not used by current build).
- `.venv/` and `node_modules/` are local artifacts.

## Workflows

- Build production bundle:
  - `npm run build`
- Run production server:
  - `npm start`
- Smoke-test Node API:
  - `node script/test-analyze.js`
- Run Python analyzer sample:
  - `python run_analysis.py`
- Run Python tests:
  - `pytest`
