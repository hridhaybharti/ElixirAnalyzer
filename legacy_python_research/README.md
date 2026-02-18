# backend (Python FastAPI)

This folder hosts the legacy Python API and heuristic engine. It is used by the Python scripts and pytest suite, and provides a standalone FastAPI service.

## Entry points

- `backend/main.py`: FastAPI app factory, router registration, startup hooks.

## API routes (`backend/api`)

- `analyze.py`: `POST /api/analyze`, `GET /api/reputation/status`
- `history.py`: `GET /api/history`, `DELETE /api/history`
- `explain.py`: `GET /api/explain/{analysis_id}`

## Analysis pipeline

- `analyzers/`: domain, IP, and URL analyzers that orchestrate heuristics and scoring.
- `heuristics/`: domain, IP, URL, and SSL heuristics that produce signals.
- `core/`: weights loading, score aggregation, and verdict mapping.

## Data and persistence

- `persistence/sqlite_store.py`: writes analyses and explanations to SQLite.
- `data/analyzer.sqlite3`: default local database file.
- `config/weights.json`: heuristic weight configuration.

## Utilities

- `utils/validators.py`: input type detection and normalization.
- `utils/whois_utils.py` and `utils/dns_utils.py`: supporting signals.
- `utils/reputation.py`: loads and syncs Tranco Top 100K for reputation signals.

## Runtime configuration

- `SECURITY_ANALYZER_WEIGHTS`: override weight file path.
- `SECURITY_ANALYZER_DB_PATH`: override SQLite DB path.
