# VirusTotal-Parity Roadmap (Draft)

This document maps current capabilities to a VT-like analyzer and outlines the roadmap to reach feature parity in practical phases.

## Current Capabilities (Have)
- URL/Domain/IP analysis with hybrid risk engine (heuristics + OSINT + DNS/TLS/PDNS/CT logs)
- Visual sandbox (Playwright) with dynamic JS instrumentation and screenshots
- Threat intelligence aggregation (VirusTotal lookups, AbuseIPDB, WHOIS, URL reputation)
- Narrative summary + explainable signals; PDF export; storage (DB or in-memory)
- API endpoints for analyze/history; basic rate limiting; API key support

## Key Gaps vs VT (Targets)
- File uploads (samples), hash lookups (MD5/SHA1/SHA256), sample dedup/index
- Multi-engine verdicts (URLs & files) with engine-by-engine breakdown
- Asynchronous scan submissions + polling with job queue
- Rich behavior reports (HAR/PCAP/artifacts), unpack/JS deobf, indicators
- Relationship graph & pivoting (domains ↔ IPs ↔ certs ↔ samples)
- Community features (comments, votes), collections; advanced search
- Accounts, quotas/usage metering, org workspaces; audit logs

## Phased Plan

### Phase 1: VT-lite for URLs (2-3 weeks)
- Orchestrator & job queue (BullMQ / graphile-worker) for async scans
- Multi-engine URL checks (e.g., Google Safe Browsing, PhishTank, urlscan.io, OTX reputation), cached
- Expand dynamic detonation: mobile profile pass, HAR capture, artifact links
- UI: multi-engine tab, behavior report, screenshot, network map

### Phase 2: Samples (files) (3-5 weeks)
- File upload API + SHA256 hashing + dedup DB/index
- Basic AV integration (ClamAV container) and YARA scanning; unpack basics (zip/pdf/office metadata)
- Sample storage (S3-compatible or local FS with retention), evidence artifacts
- UI: Sample detail page (hashes, engines, behavior, relations)

### Phase 3: Graph & Intel (3-4 weeks)
- Relationship graph store (e.g., Postgres + graph tables or Neo4j optional)
- Automatic pivots: domain->IP->certs->samples, trackers, PDNS timelines
- Search: by IOC (hash/domain/ip/url/cert) with pivot navigation

### Phase 4: Productization (ongoing)
- Accounts, API keys, quotas, orgs; billing hooks
- Community: comments, votes, saved collections
- Observability (OpenTelemetry), budget guards, rate & concurrency controls

## Implementation Notes
- Use env flags to gate costly features; default to safe timeouts and allowlists.
- Prefer async scans for external engines; normalize results into a common schema.
- Keep artifacts immutable with content-addressed paths (by SHA256).
- Add background TTL policies for storage costs (screenshots/HAR/pcap retention).

## Next Actions
1) Define engine integration list + APIs and expected response schema
2) Introduce job queue + /submit and /result endpoints (async)
3) Extend UI to show per-engine verdicts + behavior tabs
