# Email Analysis Feature — MVP Rollout

## Overview

The Email Analysis dashboard lets you investigate suspicious emails via a unified UI. It parses RFC 5322 emails, performs SPF/DKIM/DMARC checks, extracts and analyzes URLs, scans attachments, detects header/domain anomalies, and computes a risk score.

## Quick Start

### 1. Install Dependencies (Optional but Recommended)

For robust MIME/HTML parsing and client-side sanitization:

```bash
npm install mailparser dompurify
```

### 2. Configure Environment

```powershell
# Enable raw EML artifact retention (7 days TTL, runs cleanup every 6 hours)
$env:EMAIL_RETAIN_RAW='1'
$env:EMAIL_RAW_TTL_DAYS='7'

# Enable HTML body storage (privacy-sensitive; defaults to false)
$env:EMAIL_STORE_BODY_HTML='1'

# Tighter rate limiter for email endpoints (default 30/15min)
$env:EMAIL_RATE_MAX='20'
```

### 3. Start the Server

```bash
npm run dev:mem
```

Navigate to http://127.0.0.1:5000/email

### 4. Upload & Analyze

Upload a `.eml` file via the Inbox page or use the API:

```powershell
$raw = Get-Content -Raw -Encoding UTF8 .\sample.eml
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($raw))
$body = @{ source='upload'; contentBase64=$b64 } | ConvertTo-Json
$res = Invoke-RestMethod -Uri http://127.0.0.1:5000/api/email/analyze `
  -Method Post `
  -Headers @{ 'Content-Type'='application/json' } `
  -Body $body
$caseId = $res.id
```

### 5. View Results

```powershell
# Full detail
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/email/$caseId

# Redacted (omit bodyHtml, artifacts.rawRef)
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/email/$caseId?redact=1
```

## Features & Design

### Email Parsing & Normalization

- **RFC 5322 Support**: Extracts From, Envelope-From, Return-Path, Subject, Date, Message-ID, Received headers, and body.
- **MIME/HTML**: parseEmailSmart prefers `mailparser` when installed; falls back to minimal regex-based parser.
- **URL Extraction**: Scans text body and HTML attributes (href, src, data-href) for links.
- **Attachment Extraction**: Base64 multipart extraction; supports up to 5 attachments per email.

### Authentication Checks (SPF/DKIM/DMARC)

**SPF Evaluation**
- Queries sender domain TXT for `v=spf1` mechanism chain.
- Evaluates IPv4 CIDR blocks (ip4:), includes, and catch-all (all).
- Returns pass/neutral/none/tempfail.
- Formula: aligns SPF verdict with From domain vs Envelope-From/Return-Path domains.

**DKIM Verification** (Relaxed/Relaxed)
- Parses DKIM-Signature header; extracts domain (d=), selector (s=), signature (b=), body hash (bh=).
- Reconstructs signed header string and computes body hash (relaxed canonicalization).
- Fetches public key from DNS s._domainkey.d TXT.
- Verifies RSA-SHA256 signature.
- Result: pass (verified) or neutral with reason (not-verified, key-not-found, signature-mismatch, etc.).

**DMARC Policy**
- Queries `_dmarc.domain` TXT for policy (none/quarantine/reject).
- Derives result from SPF+DKIM alignment (strict mode assumed); if no alignment, applies policy.

### Risk Scoring & Heuristics

**Anti-Spoofing**
- SPF not aligned → +15 points.
- DMARC not aligned → +15 points.

**Header Anomalies**
- Suspicious TLD (.zip, .mov, .click, etc.) → +5 points.
- Newly registered sender domain (<7 days) → +5 points.
- SPF/DKIM mismatch → +5 points.
- DMARC reject without alignment → +5 points.

**Body/Links**
- Suspicious keyword detection (password, gift card, crypto, urgent, reset).
- Malicious link detection (via existing URL analyzer).

**Attachments**
- Scanned for malware verdicts; feeds risk and topSignals.

**Formula**
```
Final Risk = base_score (from auth/heuristics) + URL risk (max found) + attachment risk
```

### Indicators & Top Signals

- **Indicators**: List of domains, URLs, IPs, hashes, and attachments found.
- **Top Signals**: High-confidence findings (e.g., "Malicious Link: http://...", "Suspicious Attachment", alignment mismatches).

### Dashboard UX

**Inbox Page** (`/email`)
- List recent email cases.
- Upload button to analyze .eml files.

**Case Detail Page** (`/email/:id`)
- **Sticky Summary**: Subject, From, Risk chip, and top signals.
- **Headers Tab**:
  - SPF/DKIM/DMARC badges with tooltips (reason, policy).
  - From, Envelope-From, Return-Path, Sender IP, Geo.
  - Header Signals chip panel (anomalies).
  - Received Path timeline (hop IPs + countries).
- **Body Tab**:
  - Suspicious phrase chips.
  - Conditional preview (Show/Hide button; sanitized with DOMPurify if installed).
- **Links Tab**:
  - URL list with risk scores.
  - "Analyze" button to drill into each URL.
- **Attachments Tab**:
  - Filename, MIME, size, verdict (Malicious/Suspicious/Clean).

### Observability & PII

**Metrics** (`GET /api/metrics`)
- Email-specific counters: total, spfPass, dkimKeyFound, dmarcRejectPolicy, withAttachments, linksTotal.

**Privacy Controls**
- Raw HTML body storage: opt-in via `EMAIL_STORE_BODY_HTML=1`.
- Raw EML artifact retention: opt-in via `EMAIL_RETAIN_RAW=1`; auto-cleanup after `EMAIL_RAW_TTL_DAYS`.
- Redacted fetch: `?redact=1` omits bodyHtml and artifacts.rawRef.

**Rate Limiting**
- General API: 100 req/15min (configurable via QUOTA_PER_15MIN).
- Email endpoints: 30 req/15min (configurable via EMAIL_RATE_MAX).

## Rollout Plan & Testing

### Phase 1: Internal Testing (Dev/Staging)

1. **Deploy all changes** and run builds:
   ```bash
   npm install
   npm run build:server
   ```

2. **Test fixtures** (included):
   ```bash
   node script/test-email-analyze.js tests/eml/benign.eml
   node script/test-email-analyze.js tests/eml/suspicious.eml
   node script/test-email-e2e.js
   ```

3. **Manual testing**:
   - Upload a known benign email; verify low risk.
   - Upload a suspicious email (with keywords, spoofed sender, malicious URL); verify high risk and topSignals.

### Phase 2: Production Hardening

1. **Add mailparser to dependencies** (if not already done):
   ```bash
   npm install mailparser dompurify
   ```

2. **Configure retention policies**:
   ```bash
   EMAIL_RAW_TTL_DAYS=7
   EMAIL_RATE_MAX=30
   ```

3. **Optional: Gmail Extension**
   - Scaffold exists: `extensions/gmail/`
   - Next: Implement OAuth2 + Gmail API RAW fetch, then POST to `/api/email/analyze`.

### Phase 3: Monitoring & Iteration

1. **Monitor metrics** (`/api/metrics`):
   - Watch `email.total`, `email.spfPass`, `email.dmarcRejectPolicy`.
   - Alert on anomalies.

2. **Collect user feedback**:
   - False positives in risk scoring?
   - Missing headers or attachment info?
   - UI usability (tabs, tooltips clear?).

3. **Iterate**:
   - Tune risk scoring weights.
   - Add custom heuristics (e.g., brand impersonation patterns).
   - Improve header presentation (strictness, DMARC policy badges).

## API Reference

### POST /api/email/analyze

Analyze a raw RFC 5322 email.

**Request:**
```json
{
  "source": "upload|gmail|...user-defined",
  "contentBase64": "..."
}
```

**Response:**
```json
{
  "id": "abc123xy",
  "riskScore": 45,
  "riskLevel": "Suspicious",
  "summary": "..."
}
```

### GET /api/email

List recent email cases (latest 20).

**Response:**
```json
[
  {
    "id": "...",
    "createdAt": 1710527400000,
    "from": "...",
    "subject": "...",
    "riskScore": 45,
    "riskLevel": "Suspicious"
  }
]
```

### GET /api/email/:id

Fetch full email case details.

**Query:**
- `?redact=1` to omit bodyHtml and artifacts.

**Response:**
```json
{
  "id": "...",
  "from": "...",
  "subject": "...",
  "riskScore": 45,
  "riskLevel": "Suspicious",
  "spf": { "domain": "...", "result": "pass" },
  "dkim": { "domain": "...", "result": "pass" },
  "dmarc": { "policy": "none", "result": "pass" },
  "linkResults": [ { "url": "...", "riskScore": 90 } ],
  "attachmentReports": [ ... ],
  "headerSignals": [ "Suspicious TLD: .zip" ],
  "topSignals": [ ... ],
  "receivedPath": [ { "ip": "...", "countryCode": "US" } ]
}
```

### GET /api/metrics

Snapshot of email pipeline metrics (if METRICS_ENABLED=1).

**Response:**
```json
{
  "email": {
    "total": 42,
    "spfPass": 30,
    "dkimKeyFound": 28,
    "dmarcRejectPolicy": 5,
    "withAttachments": 12,
    "linksTotal": 87
  }
}
```

## Known Limitations & Future Work

1. **DKIM Crypto**: Signature verification works; canonicalization is relaxed/relaxed only. Future: add strict mode.
2. **SPF Modifiers**: Handles basic ip4/include/all; does not handle ~, -, +, ? qualifiers yet.
3. **DMARC Alignment**: Simplified to From domain; future: full strict/relaxed alignment negotiation.
4. **Body Analysis**: Basic keyword detection; future: ML-based phishing/social-engineering scoring.
5. **Screenshots/Detonation**: URLs are analyzed locally; no live browser detonation yet.

## Support

For issues or questions:
- Check metrics (`/api/metrics`) for pipeline health.
- Compare against test fixtures (benign.eml vs suspicious.eml).
- Review server logs for DNS/parsing errors.

---

**Version:** MVP (v0.1)  
**Last Updated:** March 15, 2026  
**Status:** Ready for staging/testing
