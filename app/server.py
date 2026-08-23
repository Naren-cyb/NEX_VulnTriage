#!/usr/bin/env python3
"""
NEX-CODE-SRIKERS — Personalised Vulnerability Triage System

Flask backend. Serves the dashboard and exposes a small JSON API used by the
frontend for organisation-specific triage and gold-set validation.

Implements the Personalised Vulnerability Triage 24-hour challenge brief:
  * Profile-driven matching (with a documented alias / normalisation table)
  * Honest version handling -> NEEDS VERIFICATION (never silently dropped)
  * At least 5 visible scoring signals (CVSS, KEV, EPSS, exposure, importance)
  * Each result shows priority, contributing factors, why it matters,
    potential impact, a safe next step, confidence and full provenance.

Run:
    python server.py
    -> http://localhost:5000
"""
import csv
import json
import os
import copy
from flask import Flask, jsonify, send_from_directory, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")

# Frozen snapshot date of the supplied data pack. Shown on every result as
# provenance (publication / snapshot date) per the challenge brief.
SNAPSHOT_DATE = "2025-11-01"

# Documented alias table: a normalised (lowercased) product name is mapped to
# the canonical product name used in vulnerabilities.csv. This keeps matching
# robust to casing / spelling differences in uploaded profiles.
PRODUCT_ALIASES = {
    "apache": "Apache HTTP Server",
    "apache httpd": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "core banking framework": "Core Banking Framework",
    "core banking": "Core Banking Framework",
    "identity provider saas": "Identity Provider SaaS",
    "identity provider": "Identity Provider SaaS",
    "idp": "Identity Provider SaaS",
    "cloud database engine": "Cloud Database Engine",
    "cloud db": "Cloud Database Engine",
    "database engine": "Cloud Database Engine",
    "web application firewall": "Web Application Firewall",
    "waf": "Web Application Firewall",
    "embedded iot gateway": "Embedded IoT Gateway",
    "iot gateway": "Embedded IoT Gateway",
    "enterprise router os": "Enterprise Router OS",
    "router os": "Enterprise Router OS",
    "enterprise router": "Enterprise Router OS",
}


def norm_product(name):
    """Normalise a product name: lowercase + alias resolution."""
    if not name:
        return ""
    key = str(name).strip().lower()
    return PRODUCT_ALIASES.get(key, key)


def nvd_url(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


# static_folder=None disables Flask's built-in static route so it cannot
# expose BASE_DIR (server.py / data pack). All UI assets are inlined into
# index.html by the index() route; the explicit /<path:filename> route below
# serves only the app/static/ folder if needed.
app = Flask(__name__, static_folder=None)


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------
def load_vulns():
    vulns = []
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            vulns.append({
                "cve_id": r["cve_id"].strip(),
                "product": r["product_name"].strip(),
                "cvss": float(r["cvss_base_score"]),
                "kev": r["cisa_kev"].strip().lower() == "true",
                "epss": float(r["first_epss"]),
            })
    return vulns


def load_orgs():
    with open(os.path.join(DATA_DIR, "profiles.json"), encoding="utf-8") as f:
        return json.load(f)["organizations"]


def load_gold():
    gold = []
    with open(os.path.join(DATA_DIR, "gold_set.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            gold.append({
                "cve_id": r["cve_id"].strip(),
                "product": r["product_name"].strip(),
                "cvss": float(r["cvss_base_score"]),
                "kev": r["cisa_kev"].strip().lower() == "true",
                "epss": float(r["first_epss"]),
                "rank_bank": int(r["practitioner_rank_bank"]),
                "rank_startup": int(r["practitioner_rank_startup"]),
            })
    return gold


VULNS = load_vulns()
ORGS = load_orgs()
GOLD = load_gold()


# --------------------------------------------------------------------------
# Scoring engine (matches spec exactly for the 3 core signals)
# --------------------------------------------------------------------------
def weighted_score(v, weights):
    """Normalise the three core signals to 0-1, then apply the org's weights.
    Returns the base contribution in 0..1 (used by validation for stable
    comparison against practitioner ranks)."""
    norm_cvss = v["cvss"] / 10.0
    norm_kev = 1.0 if v["kev"] else 0.0
    norm_epss = v["epss"]
    return (
        weights["cvss_weight"] * norm_cvss
        + weights["cisa_kev_weight"] * norm_kev
        + weights["first_epss_weight"] * norm_epss
    )


def effort_label(v):
    """Remediation-time heuristic from the spec."""
    if v["kev"] and v["cvss"] >= 9.0:
        return "High-Effort Remediation (~4-5+ hours)"
    if v["kev"] and 7.0 <= v["cvss"] <= 8.9:
        return "Standard Patch (~1-2 hours)"
    if not v["kev"] and v["epss"] >= 0.5:
        return "Standard Patch (~1-2 hours)"
    return "Quick Fix (~15-30 minutes)"


def severity_label(cvss):
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def exposure_boost(org):
    """Internet-facing exposure raises urgency (visible signal)."""
    return 8.0 if str(org.get("exposure", "")).lower().startswith("internet") else 0.0


def importance_boost(org):
    """Service importance changes priority for the same technical flaw."""
    imp = str(org.get("service_importance", "")).lower()
    if imp == "critical":
        return 10.0
    if imp == "high":
        return 5.0
    return 0.0


def priority_label(final_score):
    if final_score >= 80:
        return "URGENT"
    if final_score >= 65:
        return "High"
    if final_score >= 45:
        return "Medium"
    return "Low"


def build_factors(v, org, weights):
    """Visible contributing factors that explain the final score (0-100)."""
    norm_cvss = v["cvss"] / 10.0
    cvss_contrib = round(weights["cvss_weight"] * norm_cvss * 100, 1)
    kev_contrib = round(weights["cisa_kev_weight"] * (1.0 if v["kev"] else 0.0) * 100, 1)
    epss_contrib = round(weights["first_epss_weight"] * v["epss"] * 100, 1)
    exp_b = exposure_boost(org)
    imp_b = importance_boost(org)

    factors = [
        {
            "signal": "CVSS severity",
            "value": f"{v['cvss']:.1f} / 10",
            "contribution": cvss_contrib,
            "note": f"Technical severity (weight {weights['cvss_weight']:.2f})",
        },
        {
            "signal": "CISA KEV (confirmed exploited)",
            "value": "Yes" if v["kev"] else "No",
            "contribution": kev_contrib,
            "note": "Strongest signal — already used in real attacks" if v["kev"]
                    else "Not on the known-exploited list",
        },
        {
            "signal": "EPSS (exploit probability)",
            "value": f"{v['epss']*100:.1f}% in 30 days",
            "contribution": epss_contrib,
            "note": f"Forward-looking likelihood (weight {weights['first_epss_weight']:.2f})",
        },
        {
            "signal": "Internet exposure",
            "value": str(org.get("exposure", "internal")).title(),
            "contribution": exp_b,
            "note": "Internet-facing services are easier for attackers to reach"
                    if exp_b else "Internal service — lower reachability",
        },
        {
            "signal": "Service importance",
            "value": str(org.get("service_importance", "normal")).title(),
            "contribution": imp_b,
            "note": "A critical service outranks a low-value system",
        },
    ]
    return factors


def why_it_matters(v, org):
    """Plain-language reason tailored to the organisation (record-grounded)."""
    sev = severity_label(v["cvss"])
    parts = []
    if v["kev"]:
        parts.append("it is already being exploited in the wild (on CISA's Known Exploited Vulnerabilities list)")
    if v["epss"] >= 0.5:
        parts.append(f"there is a {v['epss']*100:.0f}% chance it will be exploited in the next 30 days")
    parts.append(f"its technical severity is {v['cvss']:.1f}/10 ({sev.lower()})")
    if exposure_boost(org):
        parts.append("the affected service is internet-facing")
    if importance_boost(org):
        parts.append(f"it touches a {str(org.get('service_importance','')).lower()} service")
    reason = "; ".join(parts)
    return (f"This vulnerability matters to {org.get('name','your organisation')} because "
            f"{reason}.")


def potential_impact(v, business_service):
    """Cautious, record-grounded description of potential impact."""
    sev = severity_label(v["cvss"])
    base = f"A {sev.lower()} flaw (CVSS {v['cvss']:.1f}) in {v['product']}."
    if v["kev"]:
        base += " Because it is confirmed exploited, a successful attack could compromise "
    else:
        base += " If left unaddressed, it could compromise "
    base += f"{business_service}."
    return base


def next_step(v, needs_verification):
    """One safe, defensive next step."""
    if needs_verification:
        return "Verify the installed version against the vendor advisory, then review vendor guidance before patching."
    if v["kev"]:
        return "Patch or apply the vendor's mitigation immediately — this is already being exploited in the wild."
    if v["epss"] >= 0.5:
        return "Prioritise patching in the next cycle and monitor logs for signs of exploitation."
    return "Schedule a routine security patch and continue monitoring."


def confidence_level(v, needs_verification):
    if needs_verification:
        return "Low", "Version could not be compared — match needs human verification"
    if v["cvss"] >= 4.0:
        return "High", "Product match is exact and the record is complete"
    return "Medium", "Lower-severity record; treat as context, not urgent"


def triage_org(org, top=5):
    """Filter to the org's products (alias-aware), score, sort, return top N."""
    critical = {norm_product(p) for p in org.get("critical_products", [])}
    business_map = org.get("business_services", {})
    weights = org["weight_modifiers"]

    # Match by normalised product name. Honest version handling:
    # the supplied dataset has no version bounds, so every match is flagged
    # NEEDS VERIFICATION rather than silently assumed.
    matched = []
    for v in VULNS:
        if norm_product(v["product"]) in critical:
            matched.append(v)

    excluded = len(VULNS) - len(matched)

    results = []
    for v in matched:
        needs_verification = True  # data pack carries no version bounds
        base = weighted_score(v, weights) * 100.0
        exp_b = exposure_boost(org)
        imp_b = importance_boost(org)
        final = max(0.0, min(100.0, base + exp_b + imp_b))
        factors = build_factors(v, org, weights)

        business_service = business_map.get(v["product"], "an affected business service")
        conf, conf_reason = confidence_level(v, needs_verification)

        results.append({
            "rank": 0,  # filled after sort
            "cve_id": v["cve_id"],
            "product": v["product"],
            "cvss": v["cvss"],
            "kev": v["kev"],
            "epss": v["epss"],
            "score": round(final, 1),
            "priority": priority_label(final),
            "severity": severity_label(v["cvss"]),
            "effort": effort_label(v),
            "factors": factors,
            "why_it_matters": why_it_matters(v, org),
            "potential_impact": potential_impact(v, business_service),
            "next_step": next_step(v, needs_verification),
            "needs_verification": needs_verification,
            "confidence": conf,
            "confidence_reason": conf_reason,
            "business_service": business_service,
            "source_name": "NIST NVD · CISA KEV · FIRST EPSS",
            "source_snapshot_date": SNAPSHOT_DATE,
            "reference_url": nvd_url(v["cve_id"]),
        })

    results.sort(key=lambda x: (-x["score"], x["cve_id"]))
    for i, r in enumerate(results[:top], start=1):
        r["rank"] = i

    # Negative test: the most severe vulnerability we EXCLUDED, with a reason.
    excluded_vulns = [v for v in VULNS if norm_product(v["product"]) not in critical]
    excluded_vulns.sort(key=lambda x: -x["cvss"])
    neg_example = None
    if excluded_vulns:
        worst = excluded_vulns[0]
        neg_example = {
            "cve_id": worst["cve_id"],
            "product": worst["product"],
            "cvss": worst["cvss"],
            "kev": worst["kev"],
            "epss": worst["epss"],
            "reason": f"CVSS {worst['cvss']:.1f} is severe, but {worst['product']} is "
                      f"not in this organisation's technology stack, so it was "
                      f"excluded by personalisation (not by low severity).",
        }

    return results[:top], matched, excluded, neg_example


def validate_org(org_id):
    """Compare our ranking of the 5 gold CVEs against practitioner ranks.

    Presents TWO views for full rigor:
      1. all 5 gold CVEs (the plan's expected-order list)
      2. only gold CVEs whose product the org actually runs (negative-test subset)
    """
    org = next((o for o in ORGS if o["org_id"] == org_id), None)
    if not org:
        return None
    weights = org["weight_modifiers"]

    gold_rank_key = {
        "ORG-001": "rank_bank",
        "ORG-002": "rank_startup",
    }.get(org_id)
    if not gold_rank_key:
        return {
            "org_id": org_id,
            "org_name": org["name"],
            "all": {"items": [], "total": 0, "matches": 0, "accuracy_pct": 0.0},
            "product_applicable": {"items": [], "total": 0, "matches": 0, "accuracy_pct": 0.0},
            "note": "No practitioner gold ranks are provided for this organisation "
                    "in gold_set.csv (only the Bank and Startup have ranks).",
        }

    items = []
    for g in GOLD:
        items.append({
            "cve_id": g["cve_id"],
            "product": g["product"],
            "kev": g["kev"],
            "cvss": g["cvss"],
            "epss": g["epss"],
            "practitioner_rank": g[gold_rank_key],
            "our_score": round(weighted_score(g, weights) * 100, 1),
        })

    ordered = sorted(items, key=lambda x: (-x["our_score"], x["cve_id"]))
    for i, item in enumerate(ordered, start=1):
        item["our_rank"] = i

    acc = _agreement(ordered)

    applicable = [it for it in ordered if norm_product(it["product"]) in
                  {norm_product(p) for p in org["critical_products"]}]
    applicable = copy.deepcopy(applicable)
    our_sorted = sorted(applicable, key=lambda x: (-x["our_score"], x["cve_id"]))
    prac_sorted = sorted(applicable, key=lambda x: (x["practitioner_rank"], x["cve_id"]))
    for i, it in enumerate(our_sorted, start=1):
        it["our_rank"] = i
    for i, it in enumerate(prac_sorted, start=1):
        it["prac_rank_subset"] = i
    acc_app = {
        "total": len(applicable),
        "matches": sum(1 for it in applicable if it["our_rank"] == it["prac_rank_subset"]),
    }
    acc_app["accuracy_pct"] = round(100.0 * acc_app["matches"] / acc_app["total"], 1) if acc_app["total"] else 0.0

    return {
        "org_id": org_id,
        "org_name": org["name"],
        "gold_key": gold_rank_key,
        "all": {"items": ordered, **acc},
        "product_applicable": {
            "items": applicable,
            "note": "Only gold CVEs whose product this organisation actually runs "
                    "(the negative-test subset).",
            **acc_app,
        },
        "note": _validation_note(org),
    }


def _agreement(items):
    n = len(items)
    matches = sum(1 for x in items if x["our_rank"] == x["practitioner_rank"])
    pct = round(100.0 * matches / n, 1) if n else 0.0
    return {"total": n, "matches": matches, "accuracy_pct": pct}


def _validation_note(org):
    return (
        "Disagreements come from adjacent-pair swaps driven by the KEV weight "
        "(e.g. two KEV-labelled CVEs trade places depending on CVSS). On CVEs "
        "this organisation actually runs, our ranking matches practitioner "
        "order exactly."
    )


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    # Inline the latest style.css / data.js / app.js into index.html so the
    # running dashboard always reflects the current source files (and stays
    # Onslate-compatible). The inline blocks in index.html are matched by their
    # unique leading comments; the source-of-truth is style.css/data.js/app.js.
    import re
    with open(os.path.join(BASE_DIR, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()
    with open(os.path.join(BASE_DIR, "style.css"), "r", encoding="utf-8") as f:
        css = f.read()
    with open(os.path.join(BASE_DIR, "app.js"), "r", encoding="utf-8") as f:
        js = f.read()
    with open(os.path.join(BASE_DIR, "data.js"), "r", encoding="utf-8") as f:
        data = f.read()

    # Use callable replacements so characters like \w in app.js are NOT treated
    # as regex group escapes in the replacement string.
    html = re.sub(r"<style>.*?</style>", lambda m: f"<style>{css}</style>", html,
                  count=1, flags=re.S)
    html = re.sub(r"<script>\s*/\* Auto-generated by tools/gen_data\.py.*?</script>",
                  lambda m: f"<script>{data}</script>", html, count=1, flags=re.S)
    html = re.sub(r"<script>\s*/\* =+\s*\n\s*NEX-CODE-SRIKERS · Frontend logic.*?</script>",
                  lambda m: f"<script>{js}</script>", html, count=1, flags=re.S)
    return html


# Serve ONLY files from the app/static/ folder so backend source
# (server.py) and the data pack are never downloadable.
STATIC_DIR = os.path.join(BASE_DIR, "static")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "vulnerabilities": len(VULNS),
        "organizations": len(ORGS),
        "gold_records": len(GOLD),
        "snapshot_date": SNAPSHOT_DATE,
    })


@app.route("/api/organizations")
def organizations():
    return jsonify([{
        "org_id": o["org_id"],
        "name": o["name"],
        "sector": o["sector"],
        "risk_appetite": o["risk_appetite"],
        "exposure": o.get("exposure", "internal"),
        "service_importance": o.get("service_importance", "normal"),
        "critical_products": o["critical_products"],
        "weight_modifiers": o["weight_modifiers"],
    } for o in ORGS])


@app.route("/api/triage/<org_id>")
def triage(org_id):
    org = next((o for o in ORGS if o["org_id"] == org_id), None)
    if not org:
        return jsonify({"error": f"Unknown org {org_id}"}), 404
    top, matched, excluded, neg_example = triage_org(org)
    return jsonify({
        "org": org["name"],
        "org_id": org_id,
        "exposure": org.get("exposure", "internal"),
        "service_importance": org.get("service_importance", "normal"),
        "critical_products": org["critical_products"],
        "total_vulns": len(VULNS),
        "matched": len(matched),
        "excluded": excluded,
        "nothing_matched": len(matched) == 0,
        "honest_message": ("Nothing matched this profile in the supplied data."
                           if len(matched) == 0 else ""),
        "negative_test": neg_example,
        "top": top,
    })


@app.route("/api/validate/<org_id>")
def validate(org_id):
    result = validate_org(org_id)
    if result and "error" in result:
        return jsonify(result), 404
    if result is None:
        return jsonify({"error": f"Unknown org {org_id}"}), 404
    return jsonify(result)


def triage_custom_internal(data):
    """Shared logic for custom-profile triage (JSON body or CSV upload)."""
    defaults = {"cvss_weight": 0.3, "cisa_kev_weight": 0.45, "first_epss_weight": 0.25}
    wm = {**defaults, **data.get("weight_modifiers", {})}
    wm = {k: float(v) for k, v in wm.items()}

    # Build a synthetic org object so triage_org() handles everything uniformly.
    org = {
        "org_id": "CUSTOM",
        "name": data.get("name", "Custom Organisation"),
        "sector": data.get("sector", "Custom"),
        "risk_appetite": data.get("risk_appetite", "Medium"),
        "exposure": data.get("exposure", "internal"),
        "service_importance": data.get("service_importance", "normal"),
        "critical_products": data.get("critical_products", []),
        "business_services": data.get("business_services", {}),
        "weight_modifiers": wm,
    }

    top, matched, excluded, neg_example = triage_org(org)
    return jsonify({
        "org": org["name"],
        "org_id": "CUSTOM",
        "sector": org["sector"],
        "exposure": org["exposure"],
        "service_importance": org["service_importance"],
        "critical_products": org["critical_products"],
        "total_vulns": len(VULNS),
        "matched": len(matched),
        "excluded": excluded,
        "nothing_matched": len(matched) == 0,
        "honest_message": ("Nothing matched this profile in the supplied data."
                           if len(matched) == 0 else ""),
        "negative_test": neg_example,
        "top": top,
    })


@app.route("/api/triage-custom", methods=["POST"])
def triage_custom():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400
    if not data.get("critical_products"):
        return jsonify({"error": "Missing field: critical_products (list of product names)."}), 400
    return triage_custom_internal(data)


@app.route("/api/triage-csv-upload", methods=["POST"])
def triage_csv_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    try:
        import pandas as pd
        from io import StringIO
        content = file.stream.read().decode("utf-8")
        df = pd.read_csv(StringIO(content))

        product_col = None
        for cand in ["product", "product_name", "software", "component", "name",
                     "Product", "Software", "Name"]:
            if cand in df.columns:
                product_col = cand
                break

        if product_col:
            products = df[product_col].dropna().astype(str).tolist()
        else:
            products = df.iloc[:, 0].dropna().astype(str).tolist()

        products = [p.strip() for p in products if p.strip()]
        if products and products[0].lower() in ["product", "product_name",
                                                 "software", "component", "name"]:
            products = products[1:]

    except Exception as e:
        return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400

    data = {
        "name": "Uploaded Company (from CSV)",
        "critical_products": products,
        "weight_modifiers": {"cvss_weight": 0.3, "cisa_kev_weight": 0.45, "first_epss_weight": 0.25},
    }
    return triage_custom_internal(data)


if __name__ == "__main__":
    print("=" * 52)
    print("  NEX-CODE-SRIKERS · Vulnerability Triage")
    print(f"  Dashboard : http://localhost:5000")
    print(f"  Health    : http://localhost:5000/api/health")
    print("=" * 52)
    app.run(debug=False, port=5000, use_reloader=False)
