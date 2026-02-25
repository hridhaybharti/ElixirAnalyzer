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

Designed and Developed by **Hridhay Bharti**. 🦾
