# OWASP Top 10 Vulnerability Scanner

A web application vulnerability scanner that crawls a target site and checks
for common OWASP Top 10 issues, with a live dashboard and exportable PDF
reports.

> ⚠️ **Authorized use only.** Only scan applications you own or have explicit,
> written permission to test. Scanning systems without authorization is
> illegal in most jurisdictions and against most hosting providers' terms of
> service. This tool requires you to confirm authorization before every scan,
> and ships configured against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
> a deliberately vulnerable practice application, by default.

## What it checks for

| Check | OWASP category | What it does |
|---|---|---|
| SQL Injection | A03: Injection | Submits classic error-triggering payloads to form fields and looks for SQL error signatures or response anomalies |
| Reflected XSS | A03: Injection | Injects a unique marker script payload and checks if it's reflected unescaped |
| Security Headers | A05: Security Misconfiguration | Flags missing CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy |
| Exposed Sensitive Files | A05: Security Misconfiguration | Probes for `.git/`, `.env`, backup files, and other commonly-leaked paths |
| CSRF | A01: Broken Access Control | Flags state-changing forms with no CSRF token field |
| Insecure Cookies | A02: Cryptographic Failures | Flags cookies missing `Secure` / `HttpOnly` / `SameSite` |

## Architecture

```
scanner/        Core scan engine — crawler + individual checks, framework-agnostic
api/            FastAPI app — REST + WebSocket layer over the scanner
frontend/       Static dashboard — live findings feed, PDF report download
tests/          Pytest suite — runs checks against a local disposable Flask target
```

The scan engine (`scanner/`) has no dependency on the API layer, so it also
works as a standalone library or CLI if you don't want the web UI.

## Running locally

**Option A — Docker Compose (recommended, includes a safe test target):**

```bash
docker-compose up --build
```

This starts the scanner API on `http://localhost:8000` and OWASP Juice Shop
(the practice target) on `http://localhost:3000`. Open `http://localhost:8000`,
enter `http://juice-shop:3000` (or `http://localhost:3000` if scanning from
your host) as the target, check the authorization box, and start a scan.

**Option B — Run directly:**

```bash
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Then open `http://localhost:8000` in your browser.

## Running tests

```bash
pytest tests/ -v
```

Tests spin up a small deliberately-vulnerable Flask app in-process, so they
run offline and don't depend on Juice Shop being up.

## API

- `POST /api/scan` — start a scan. Body: `{"url": "...", "confirm_authorized": true, "max_depth": 2, "max_pages": 50}`
- `GET /api/scan/{scan_id}` — poll scan status + findings
- `GET /api/scan/{scan_id}/report.pdf` — download the PDF report (once completed)
- `WS /api/ws/{scan_id}` — live findings feed as the scan runs
- `GET /health` — health check

## Design notes / what this is not

- This is an **educational / portfolio project**, not a replacement for
  commercial tools like Burp Suite, Nessus, or OWASP ZAP. The checks are
  intentionally simple (signature and reflection-based) rather than exhaustive.
- The SQLi and XSS checks are **non-destructive**: no blind/time-based
  injection, no attempts to modify or exfiltrate data.
- Scan state is stored in memory (`api/store.py`) for simplicity. For a
  multi-instance deployment, swap this for Redis or a database.

## Roadmap / stretch ideas

- Add a rule-based layer (Suricata/Zeek-style signatures) alongside these
  checks and compare precision/recall against the payload-based approach
- Persist scan history to Postgres for a "past scans" view
- Add authenticated scanning (submit login credentials, scan behind auth)
