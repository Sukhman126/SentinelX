# SentinelX — AI-Powered Vulnerability Assessment & Security Intelligence Platform

A full-stack security platform that ingests scan results (Nmap, JSON, CSV), enriches
them against a CVE knowledge base, computes a weighted composite risk score, and
generates enterprise-style PDF assessment reports — with an AI assistant that
explains findings in plain language.

This build is a **working, runnable scope** of the full project spec: it implements
every module end-to-end (auth, projects, import, CVE mapping, risk scoring,
dashboards, AI assistant, PDF reports) using a zero-external-dependency stack
(SQLite + vanilla JS) so it runs immediately with no cloud services or API keys.
Swapping in PostgreSQL, a React frontend, Nessus/ZAP import, or a live OpenAI key
are documented drop-in upgrades (see "Extending" below) — the architecture is
already built to support them.

## Stack

- **Backend:** FastAPI + SQLAlchemy + JWT auth (bcrypt password hashing)
- **Database:** SQLite by default; set `DATABASE_URL` to switch to PostgreSQL — no code changes needed
- **Frontend:** Vanilla HTML/CSS/JS + Chart.js (no build step required)
- **Reports:** reportlab (PDF generation)
- **AI:** Pluggable — works fully offline with a templated expert-system engine;
  automatically upgrades to OpenAI (`gpt-4o-mini`) if `OPENAI_API_KEY` is set

## Quick start

### 1. Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
python3 -m uvicorn main:app --reload --port 8000
```

The API is now live at `http://localhost:8000` (interactive docs at `/docs`).
A SQLite file `sentinelx.db` is created automatically on first run.

### 2. Frontend

In a separate terminal:

```bash
cd frontend
python3 -m http.server 5500
```

Open `http://localhost:5500/index.html` in your browser.

> The frontend talks to the backend at `http://localhost:8000` by default. To point it
> elsewhere (e.g. a deployed API), set `window.SENTINELX_API_BASE = "https://your-api.com"`
> before `api.js` loads — e.g. add a `<script>window.SENTINELX_API_BASE = "...";</script>`
> tag above the `api.js` `<script>` include in each HTML file.

### 3. Try it out

1. Register an account (the **first** registered user automatically becomes admin).
2. Create a project.
3. Import `sample_data/sample_nmap.xml` (a fictional 3-host lab network) via
   **Import scan** — this demonstrates the full pipeline: Nmap XML parsing →
   product/version fingerprinting → CVE lookup → CVSS scoring → composite risk
   scoring, all in one request.
4. Explore the dashboard: severity breakdown, exposed services, top-risk findings.
5. Click **Ask AI** on any finding for a plain-language CVE explanation.
6. Click **Generate PDF report** for a full cover-page-to-conclusion assessment report.

## Project structure

```
SentinelX/
  backend/
    main.py              FastAPI app + all routes
    models.py             SQLAlchemy ORM models
    schemas.py             Pydantic request/response schemas
    database.py            DB engine/session config (SQLite/Postgres)
    security.py             JWT auth + password hashing
    parser.py                Report Import Module (Nmap XML / JSON / CSV)
    cve_data.py                CVE Intelligence Module (local knowledge base)
    risk.py                     Risk Prioritization Engine
    ai_engine.py                  AI Security Assistant (offline + OpenAI-pluggable)
    report_generator.py            Professional PDF Report Generator
    requirements.txt
  frontend/
    index.html            Login / registration
    dashboard.html          Project list
    project.html              Main dashboard: KPIs, charts, findings, AI, reports
    assets/css/style.css
    assets/js/api.js
  sample_data/
    sample_nmap.xml       Demo Nmap scan (fictional lab hosts)
  generated_reports/      PDF reports land here at runtime
  uploads/                 Reserved for raw upload persistence (not required by SQLite flow)
```

## How the risk score works

Each finding gets a composite **Risk Score (0–10)**, not just a raw CVSS number:

```
Risk Score = 0.60 × CVSS
           + 0.15 × (10 if exploit known to be actively used, else 0)
           + 0.10 × (10 if the finding is marked internet-exposed, else 0)
           + 0.10 × (service criticality, 1-5 scaled to 0-10)
           + 0.05 × (business impact, 1-5 scaled to 0-10)
```

This means two findings with identical CVSS scores can rank differently once
exposure and business context are factored in — mirroring how real vulnerability
management platforms prioritize remediation. Analysts can mark a finding as
internet-exposed or adjust its business impact from the dashboard, and the score
recalculates immediately.

## Extending this build

The spec describes a larger platform than any one sitting can fully build; every
module here is written as a clean extension point rather than a dead end:

- **PostgreSQL:** set `DATABASE_URL=postgresql://user:pass@host/db` — SQLAlchemy
  handles the rest.
- **Nessus / OWASP ZAP import:** `parser.py` has a documented `parse_nessus_xml()`
  stub showing the exact shape to fill in; `main.py`'s `/import` route just needs
  one more `elif ext == "nessus"` branch.
- **Live CVE data:** `cve_data.py` ships a curated offline dataset so the demo
  works with zero setup. Swap `lookup_cve()`'s body for a call to the NVD REST API
  (`services.nvd.nist.gov`) and cache results — the rest of the app is written
  against the same return shape.
- **Real LLM:** set `OPENAI_API_KEY` and `ai_engine.py` automatically switches
  from its offline template engine to live GPT-4o-mini calls for CVE explanations
  and executive summaries.
- **React frontend:** the API is fully decoupled (JWT bearer auth, JSON everywhere)
  so the vanilla-JS frontend can be replaced with a React/Vite app without backend
  changes.
- **Docker / deployment:** containerize `backend/` (single `Dockerfile`, exposes
  port 8000) and serve `frontend/` as a static site (Render, Netlify, S3, etc.).

## Security notes

- Change `SENTINELX_SECRET_KEY` (JWT signing secret) via environment variable
  before any real deployment — it defaults to a dev value.
- Passwords are hashed with bcrypt; never stored in plaintext.
- CORS is wide open (`*`) for local development — restrict `allow_origins` in
  `main.py` to your actual frontend domain in production.
- This platform **only analyzes scan output you provide** — it does not perform
  any scanning or exploitation itself. Only run Nmap/Nessus against systems you
  are authorized to test.
