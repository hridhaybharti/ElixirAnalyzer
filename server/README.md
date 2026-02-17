# server (Node/Express API)

Primary API and analysis pipeline for the application.

## Entry points

- `server/index.ts`: Express app, logging, route registration, Vite dev middleware, and static serving.
- `server/routes.ts`: API routes and request validation.
- `server/db.ts`: Postgres connection and Drizzle initialization.
- `server/storage.ts`: CRUD access for the `analyses` table.

## Analysis pipeline

- `analysis/analyzeInput.ts`: orchestrates preprocessing, intelligence gathering, scoring, and verdict.
- `analysis/sanitization.ts`, `analysis/obfuscation.ts`: input cleanup and decoding.
- `analysis/idn.ts`, `analysis/homoglyph.ts`: IDN and homoglyph detection.
- `analysis/domain-reputation.ts`: domain trust signals and brand checks.
- `analysis/path-analysis.ts`, `analysis/port-analysis.ts`: URL structure checks.
- `analysis/redirect-analysis.ts`: redirect chain checks.
- `analysis/mobile-threats.ts`: mobile-specific risk patterns.
- `analysis/threat-intelligence.ts`: VirusTotal, AbuseIPDB, ipapi geolocation, WHOIS, and URL reputation lookups.
- `analysis/reputation.ts`: Tranco Top 100K sync to `server/data/top_100k.json`.

## Scoring and heuristics

- `analyzers/domain`, `analyzers/ip`, `analyzers/url`: core heuristic scoring per input type.
- `risk/aggregator.ts`, `risk/correlation.ts`: risk aggregation and correlation boosts.

## Supporting modules

- `intelligence/`: additional data sources for enrichment.
- `utils/secrets.ts`: secure API key handling and status reporting.
- `static.ts` and `vite.ts`: frontend serving in production and dev.

## Environment variables

- `PORT`
- `DATABASE_URL`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
