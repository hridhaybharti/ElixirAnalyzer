# Threat Analyzer

Threat intelligence and heuristic risk scoring for domains, URLs, and IPs. This repo contains two implementations:

- Primary stack: Node/Express API in `server/` with a React UI in `client/`.
- Legacy stack: Python FastAPI API in `backend/` with compatibility shims in `engine/`.

## Quick Start (Node + React)

1. Install dependencies:
   - `npm install`
2. Configure environment:
   - Copy `\.env.txt` to `\.env`
   - Set `DATABASE_URL`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `PORT`
3. Apply database schema:
   - `npm run db:push`
4. Run dev server:
   - `npm run dev`

The app will be available at `http://localhost:5000`.

## Quick Start (Python Legacy)

1. `python -m venv .venv`
2. `.\.venv\Scripts\Activate.ps1`
3. `pip install -r requirements.txt`
4. `uvicorn backend.main:app --reload`

The Python API will be available at `http://127.0.0.1:8000`.

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
