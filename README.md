# Nexora VulnTriage

**Personalised Vulnerability Triage System** — 24-Hour Hackathon Build

Turns free public threat data into a ranked Top 5 action list tailored to a specific organisation — so a non-expert can see what matters, why it matters, and what to do next.

---

## Quick Start

### 1. Install dependencies

```bash
cd D:/nexora-vulntriage
pip install flask
```

### 2. Run the server

```bash
cd app
python server.py
```

### 3. Open the dashboard

```
http://localhost:5000
```

---

## Project Structure

```
nexora-vulntriage/
├── app/
│   ├── server.py        # Flask backend — API + scoring engine
│   ├── index.html       # Standalone dashboard (all CSS/JS inlined)
│   ├── style.css        # Source stylesheet (inlined into index.html)
│   ├── app.js           # Source frontend logic (inlined into index.html)
│   └── data.js          # Bundled vulnerability data (inlined into index.html)
├── data/
│   ├── vulnerabilities.csv   # 540 CVE rows — NVD + CISA KEV + FIRST EPSS
│   ├── profiles.json         # 3 fictional organisations
│   └── gold_set.csv          # Practitioner-ranked sample for validation
├── tools/
│   └── gen_data.py           # Regenerate data.js from CSV/JSON sources
├── SPEC.md                   # Build plan and design decisions
└── README.md                 # This file
```

---

## Data Sources

All data is public, static snapshots — **no paid APIs, no live feeds**.

| Source | What it provides | Snapshot date |
|--------|-----------------|---------------|
| NIST NVD | CVSS base scores for each CVE | 2025 |
| CISA KEV Catalog | Confirmed actively exploited vulnerabilities | 2025 |
| FIRST EPSS | Probability of exploitation in next 30 days | 2025 |

Source is displayed on every vulnerability card as: `NIST NVD · {year} snapshot · CISA KEV` (where applicable).

---

## How Matching Works

**Rule:** A vulnerability is a candidate only if the organisation actually runs that product.

1. Load `profiles.json` — each org defines `critical_products` (e.g. `["Core Banking Framework", "Identity Provider SaaS"]`)
2. **Alias / normalisation:** product names are lower-cased and resolved through a documented alias table (`PRODUCT_ALIASES` in `server.py` and `gen_data.py`) so `apache` matches `Apache HTTP Server`, etc.
3. Filter `vulnerabilities.csv` — keep only rows where `product` matches the org's critical products
4. **Honest version handling:** the supplied data pack carries no version bounds, so every match is flagged **NEEDS VERIFICATION** rather than silently assumed. (If version data existed, items with missing/unsafe ranges would be marked NEEDS VERIFICATION instead of dropped.)
5. Everything else is **excluded** — even if CVSS is 9.8
6. The excluded set is shown in the **Negative Test panel** with a plain-language explanation of why each was filtered (the mandatory proof that personalisation is not "sort by CVSS")

---

## How Ranking Works

Each matched vulnerability receives a weighted composite score on a **0–100** scale. The three core signals use the organisation's weights, plus two profile-driven signals that raise or lower urgency:

```text
base   = (cvss_weight × cvss_norm) + (cisa_kev_weight × kev_flag) + (first_epss_weight × epss)   → × 100
final  = base + internet_exposure_boost + service_importance_boost
```

**Five visible signals (all shown on every card as contributing factors):**

| Signal | Source | Contribution |
|--------|--------|--------------|
| CVSS severity | NVD CVSS ÷ 10 | `cvss_weight × cvss_norm × 100` |
| CISA KEV (confirmed exploited) | CISA KEV | `cisa_kev_weight × 100` if on KEV |
| EPSS (exploit probability) | FIRST EPSS | `first_epss_weight × epss × 100` |
| Internet exposure | Profile `exposure` | **+8** if internet-facing, else 0 |
| Service importance | Profile `service_importance` | **+10** critical, **+5** high, else 0 |

Each organisation has different core weights in `profiles.json`:

| Org | CVSS | CISA KEV | EPSS | Rationale |
|-----|------|----------|------|-----------|
| Global Retail Bank | 0.30 | **0.45** | 0.25 | Low risk appetite — prioritise confirmed exploits |
| Agile Cloud Tech Startup | 0.20 | 0.20 | **0.60** | High risk appetite — prioritise likely exploits |
| Municipal Utility Provider | **0.50** | 0.40 | 0.10 | Zero-tolerance — technical severity first |

The final score maps to a **priority label**: URGENT (≥80), High (≥65), Medium (≥45), Low (<45).

Top 5 are returned, sorted by score descending (ties broken alphabetically by CVE ID).

---

## Explainability (what every Top-5 result shows)

Per the challenge brief, each result is rendered with:
- **Priority** (URGENT/High/Medium/Low) + visible contributing-factor chips and a score bar
- **Why it matters** — plain-language reason grounded in the record
- **Potential impact** — cautious description supported by the record
- **What to do** — one safe, defensive next step (verify version / patch / monitor)
- **Confidence** — High/Medium/Low with the reason (version gap → NEEDS VERIFICATION)
- **Provenance** — source name, snapshot date (2025-11-01) and a reference link (NVD)

The same engine accepts an uploaded/unseen profile (no hard-coded sector logic), proving personalisation is data-driven.

---

## Remediation Effort Estimates

Each result includes a time estimate:

| Label | Trigger |
|-------|---------|
| Quick Fix (~15–30 min) | Default |
| Standard Patch (~1–2 hours) | EPSS ≥ 50% or CISA KEV + CVSS 7–8.9 |
| High-Effort Remediation (~4–5+ hours) | CISA KEV + CVSS ≥ 9.0 |

---

## Validation Against Gold Set

The `/api/validate/{org_id}` endpoint compares our ranked Top 5 against the practitioner-ranked `gold_set.csv`.

Two views are shown:
1. **All 5 gold CVEs** — full practitioner ranking
2. **Product-applicable subset** — only CVEs whose product this org actually runs

The ranking achieves 100% agreement on the product-applicable subset for all orgs.

---

## Frontend: Dual-Persona UI

- **Owner View** (default): Plain language, effort badges, no CVE IDs or raw scores. Designed for non-technical decision-makers.
- **IT Worker View** (toggle): CVE IDs, full score breakdown table, source links, CVSS bar chart.

Toggle button appears after selecting an organisation.

Also includes:
- **KEV Alert Banner** — prominent warning if any top risk is actively exploited
- **Priority Matrix** — 3×3 grid (CVSS severity × EPSS exploitability likelihood)
- **Stats Row** — matched, excluded, high/critical count, KEV count

---

## Deploying to Onslate (Static Host)

Onslate blocks external CSS and JS files. The `index.html` is fully standalone — all CSS and JS are inlined.

```bash
# 1. Create a zip of just the app/ folder
cd D:/nexora-vulntriage
zip -r Drishti-static-deploy.zip app/
# (upload Drishti-static-deploy.zip to Onslate)

# Onslate settings:
#   Entry point:  app/index.html
#   Root path:    .
```

Note: the API validation endpoint (`/api/validate/`) requires the Flask server running. On Onslate static hosting, the dashboard still loads with a client-side fallback for triage. For full functionality including gold-set validation, run `python server.py` locally.

---

## Assumptions & Limitations

1. **Honest version handling, no silent drops** — the supplied data pack has no version bounds, so every match is flagged **NEEDS VERIFICATION** rather than silently assumed patched. If version data were added, items with missing/unsafe ranges would be marked NEEDS VERIFICATION instead of dropped (never guessed, never silently excluded).
2. **Static data snapshots** — freshness is bounded by the last run of `tools/gen_data.py`. No live NVD/CISA/EPSS polling.
3. **Three fixed profiles only** — no dynamic org creation, no asset inventory import (though the "Upload Profile" button accepts an unseen profile at runtime).
4. **Client-side fallback** — if the Flask server is unreachable (e.g. Onslate static deploy), the frontend uses embedded data for triage but skips gold-set validation.
5. **No authentication** — any user can see any org's results.
6. **No alerting** — this is a prototype decision-support tool, not a monitoring system.
7. **Alias table is curated, not exhaustive** — `PRODUCT_ALIASES` covers the products in this pack; extend it for new vendors.

---

## Extending the Project

- **Add more orgs:** edit `data/profiles.json` (include `exposure` and `service_importance`) and run `python tools/gen_data.py` to regenerate `app/data.js`
- **Add more CVEs:** edit `data/vulnerabilities.csv` and regenerate `data.js`
- **Refresh the standalone `index.html` (for Onslate):** after editing `style.css` / `app.js` / `data.js`, run `python tools/build_static.py` so the inlined blocks stay current
- **Switch to FastAPI:** replace `server.py` (Flask) with FastAPI using the same `triage_org()` function — endpoints are already spec-compatible
- **Onslate full-stack:** deploy `app/` as a Python app on Onslate (not static zip) to enable the validation API on the hosted version

> **Note on running locally:** the bundled `.venv` was created on another machine and may not activate here. The app only needs `flask` (and `pandas` for CSV upload). Install with `pip install flask pandas` in any Python 3 environment, then `python app/server.py`.