# Nexora — Project Build Plan
## Personalised Vulnerability Triage System

---

## 1. What We Are Building

A **smart vulnerability prioritisation engine** that:
- Reads real vulnerability data (CVEs with severity scores)
- Reads organisation profiles (what software they use + risk appetite)
- Filters only relevant threats (negative test: exclude irrelevant software)
- Ranks threats using weighted CVSS + CISA KEV + EPSS signals
- Outputs a clean, prioritised Top 5 action list
- Serves it through a **polished dual-persona web dashboard**

---

## 2. Folder Structure

```
D:/nexora-vulntriage/
│
├── data/                    ← source data files (original nexora files)
│   ├── vulnerabilities.csv
│   ├── profiles.json
│   └── gold_set.csv
│
├── app/                     ← Python backend
│   ├── triage_engine.py     ← core logic: load, filter, score, rank
│   ├── server.py            ← FastAPI web server + API endpoints
│   └── requirements.txt     ← python dependencies
│
├── static/                  ← frontend assets
│   ├── index.html           ← main dashboard (all-in-one HTML)
│   ├── styles.css           ← custom styles
│   └── app.js               ← frontend JS (fetch API, render UI)
│
├── SPEC.md                  ← this file
└── README.md                ← setup/run instructions
```

---

## 3. Data Layer

### 3.1 Files
- **vulnerabilities.csv** — 500+ rows: cve_id, product_name, cvss_base_score, cisa_kev, first_epss
- **profiles.json** — 3 orgs with: org_id, name, sector, risk_appetite, critical_products, weight_modifiers
- **gold_set.csv** — expected correct rankings per org (for validation)

### 3.2 Triage Engine (triage_engine.py → server.py `triage_org`)
Input: vulnerabilities.csv + profiles.json
Output: prioritised list per org, with full explainability

Logic:
1. Load all vulnerabilities
2. **Alias / normalisation:** resolve product names through `PRODUCT_ALIASES` so casings/spellings match
3. For each org, filter only vulns where `norm(product) in norm(org.critical_products)`
4. Compute composite score on a 0–100 scale:
   - `base = (cvss_weight × cvss_norm + cisa_kev_weight × cisa_val + epss_weight × epss) × 100`
   - `final = base + internet_exposure_boost + service_importance_boost`
   - cvss_norm = cvss_score / 10; cisa_val = 1 if CISA KEV else 0
   - internet_exposure_boost = +8 if `exposure` is internet-facing else 0
   - service_importance_boost = +10 (critical) / +5 (high) / 0 (normal)
5. Map final score → priority label: URGENT (≥80) / High (≥65) / Medium (≥45) / Low (<45)
6. Sort descending by score, then by CVE ID alphabetically for ties
7. Return Top 5, plus the excluded high-CVSS example for the negative test

Honest version handling: the data pack has no version bounds, so every match is flagged `needs_verification = true` (confidence Low) instead of being silently assumed. If version data existed, missing/unsafe ranges would be marked NEEDS VERIFICATION rather than dropped.

Extra fields per result (all rendered on the card):
- `priority` + `factors[]` (5 visible contributing signals with values & contributions)
- `why_it_matters`: plain-language reason grounded in the record
- `potential_impact`: cautious description supported by the record
- `next_step`: one safe, defensive action
- `confidence` + `confidence_reason`
- `needs_verification`: true (version gap)
- `source_name`, `source_snapshot_date`, `reference_url`: provenance
- `quick_summary`: one-line plain-English description

---

## 4. API Layer (server.py — FastAPI)

### Endpoints
| Method | Path | Description |
|---|---|---|
| GET | `/api/organizations` | List all orgs (id, name, sector, risk_appetite) |
| GET | `/api/triage/{org_id}` | Get Top 5 prioritised vulns for org |
| GET | `/api/goldset/{org_id}` | Get gold set ranking for org (for validation) |
| GET | `/api/products` | List all unique products in the dataset |
| GET | `/api/health` | Health check |

### Response format (triage endpoint)
```json
{
  "org": { "id": "ORG-001", "name": "Global Retail Bank", ... },
  "total_matched": 23,
  "vulnerabilities": [
    {
      "rank": 1,
      "cve_id": "CVE-2025-1111",
      "product_name": "Core Banking Framework",
      "cvss_score": 9.8,
      "cisa_kev": true,
      "epss": 0.95,
      "priority_score": 0.89,
      "remediation_effort": "High-Effort Remediation (~4–6 hours)",
      "quick_summary": "ACTIVELY EXPLOITED — patch immediately"
    },
    ...
  ]
}
```

---

## 5. Frontend — Dual-Persona Dashboard

### 5.1 Owner View (Default)
Simple, non-technical language:
- Org name + sector shown prominently
- "What this means for your business" section
- Each vulnerability shows:
  - Rank badge (#1, #2...)
  - "What is at risk?" (product name in plain terms)
  - "How bad is it?" (Low/Medium/High/Critical label)
  - "What should you do?" (effort label + quick summary)
  - "How urgent?" (CISA KEV badge if actively exploited)
- No CVE IDs, no raw scores

### 5.2 IT Worker View (Toggle)
Technical details:
- CVE ID + product name
- CVSS score (with colour bar)
- CISA KEV flag
- EPSS probability
- Exact priority score breakdown
- Version/product context
- Filter/sort controls

### 5.3 UI Components
- **Org Selector** — dropdown to switch between the 3 orgs
- **View Toggle** — Owner ↔ IT Worker switch
- **Priority Matrix** — 3×3 grid (CVSS severity × Exploitation likelihood)
- **Summary Stats** — total matched, highest risk, avg CVSS for selected org
- **Alert Banner** — if any CISA KEV vulnerabilities exist, show prominent warning

### 5.4 Visual Style
- Dark theme (matching Drishti project convention)
- Colour coding: Critical=Red, High=Orange, Medium=Yellow, Low=Green
- CISA KEV badges: pulsing red highlight
- Responsive design (mobile-friendly)

---

## 6. Validation (Gold Set)

gold_set.csv has expected rankings. After building the engine:
- Compare our computed Top 5 vs gold_set.csv
- Calculate accuracy metrics (Hit@5, MRR)
- Report results in the UI or in a validation endpoint

---

## 7. Deployment Plan

### Local Run
```bash
cd D:/nexora-vulntriage
pip install -r app/requirements.txt
python -m app.server
# Dashboard at http://localhost:8000
```

### Onslate Deployment
- Zip `app/` folder only (not full project)
- Entry point: `python app/server.py`
- Root Path: `.`
- Note: external JS/CSS blocked on Onslate → all CSS inline in HTML, no external deps

---

## 8. Task Checklist

### Phase 1 — Core Logic
- [ ] Copy data files to `data/`
- [ ] Build `triage_engine.py` (load, filter, score, rank)
- [ ] Test engine outputs with gold_set.csv
- [ ] Validate Top 5 accuracy

### Phase 2 — API
- [ ] Build `server.py` with FastAPI
- [ ] Wire up all 5 endpoints
- [ ] Test with curl/browser

### Phase 3 — Frontend
- [ ] Build `index.html` (skeleton + org selector)
- [ ] Build `styles.css` (dark theme, dual-persona styling)
- [ ] Build `app.js` (fetch API, render Owner View)
- [ ] Implement IT Worker View toggle
- [ ] Add Priority Matrix + summary stats
- [ ] Add CISA KEV alert banner

### Phase 4 — Polish
- [ ] Inline all CSS/JS into index.html for Onslate compatibility
- [ ] Add validation display (gold set accuracy)
- [ ] README with setup/run instructions
- [ ] Test end-to-end on local server

---

## 9. Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| Web framework | FastAPI | Fast, automatic docs, Pydantic validation |
| Frontend | Vanilla HTML/CSS/JS | No build step, simple, portable |
| Dashboard style | Dark theme | Matches Drishti project, looks modern |
| CSS inlining | Yes | Onslate blocks external CSS |
| Org data | Hardcoded in data/ | No database needed for prototype |
| Gold set validation | Hit@5 + MRR | Standard ranking metrics |

---

*Plan version 1.0 — confirm before starting build*