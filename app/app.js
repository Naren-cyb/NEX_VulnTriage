/* =============================================================
   NEX-CODE-SRIKERS · Frontend logic
   Mirrors server.py scoring + renders PS-required explainability
   ============================================================= */

const ORG_ICONS = {
  "Global Retail Bank": "🏦",
  "Agile Cloud Tech Startup": "🚀",
  "Municipal Utility Provider": "🌐",
};
const ORG_EMOJI_TAG = { "Global Retail Bank": "🛡️", "Agile Cloud Tech Startup": "⚡", "Municipal Utility Provider": "🏭" };

// ---------- Element refs ----------
const $ = (id) => document.getElementById(id);
const elements = {
  orgContainer: $("orgContainer"),
  kevBanner: $("kevBanner"),
  kevBannerTitle: $("kevBannerTitle"),
  kevBannerText: $("kevBannerText"),
  statsRow: $("statsRow"),
  stMatched: $("stMatched"), stExcluded: $("stExcluded"), stSevere: $("stSevere"), stKev: $("stKev"),
  toggleRow: $("toggleRow"), toggleBtn: $("toggleBtn"),
  toggleLab: $("toggleLab"), toggleDesc: $("toggleDesc"),
  vulnList: $("vulnList"), vulnLoading: $("vulnLoading"),
  negBox: $("negBox"), negSummary: $("negSummary"), negList: $("negList"),
  validationArea: $("validationArea"),
  statusText: $("statusText"),
  toast: $("toast"),
  uploadModal: $("uploadModal"),
  uploadBtn: $("uploadBtn"),
  modalClose: $("modalClose"),
  modalCancel: $("modalCancel"),
  runTriage: $("runTriage"),
  dropZone: $("dropZone"),
  fileInput: $("fileInput"),
  profileJson: $("profileJson"),
  uploadError: $("uploadError"),
};

// Escape user-supplied strings before inserting into innerHTML (XSS-safe)
function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

let currentOrg = null;
let itView = false;          // false = Owner View (default)
let currentResult = null;    // last loaded triage payload
let currentNegatives = [];   // excluded vulns for "negative test" display

// ---------- Scoring (mirror of server.py) ----------
function exposureBoost(org) {
  const e = (org && (org.exposure || "")).toString().toLowerCase();
  return e.startsWith("internet") ? 8.0 : 0.0;
}
function importanceBoost(org) {
  const i = (org && (org.service_importance || "")).toString().toLowerCase();
  if (i === "critical") return 10.0;
  if (i === "high") return 5.0;
  return 0.0;
}
function weightedScore(v, w) {
  const normCvss = v.cvss / 10.0;
  const normKev = v.kev ? 1.0 : 0.0;
  const normEpss = v.epss;
  return w.cvss_weight * normCvss + w.cisa_kev_weight * normKev + w.first_epss_weight * normEpss;
}
function finalScore(v, org, w) {
  const base = weightedScore(v, w) * 100.0;
  return Math.max(0, Math.min(100, base + exposureBoost(org) + importanceBoost(org)));
}
function priorityLabel(s) {
  if (s >= 80) return "URGENT";
  if (s >= 65) return "High";
  if (s >= 45) return "Medium";
  return "Low";
}
function effortLabel(v) {
  if (v.kev && v.cvss >= 9.0) return "High-Effort Remediation (~4-5+ hours)";
  if (v.kev && v.cvss >= 7.0 && v.cvss <= 8.9) return "Standard Patch (~1-2 hours)";
  if (!v.kev && v.epss >= 0.5) return "Standard Patch (~1-2 hours)";
  return "Quick Fix (~15-30 minutes)";
}
function severityLabel(cvss) {
  if (cvss >= 9.0) return "Critical";
  if (cvss >= 7.0) return "High";
  if (cvss >= 4.0) return "Medium";
  return "Low";
}
function effortClass(label) {
  if (label.startsWith("High")) return "effort-high";
  if (label.startsWith("Standard")) return "effort-std";
  return "effort-quick";
}
function severityColor(cvss) {
  if (cvss >= 9.0) return "var(--crit)";
  if (cvss >= 7.0) return "var(--high)";
  if (cvss >= 4.0) return "var(--med)";
  return "var(--low)";
}
function toTitle(s) {
  return String(s).replace(/\w\S*/g, (w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
}

// Build visible contributing factors (mirror server)
function buildFactors(v, org, w) {
  const nc = v.cvss / 10.0;
  return [
    { signal: "CVSS severity", value: v.cvss.toFixed(1) + " / 10", contribution: +(w.cvss_weight * nc * 100).toFixed(1) },
    { signal: "CISA KEV (confirmed exploited)", value: v.kev ? "Yes" : "No", contribution: +(w.cisa_kev_weight * (v.kev ? 1 : 0) * 100).toFixed(1) },
    { signal: "EPSS (exploit probability)", value: (v.epss * 100).toFixed(1) + "% in 30 days", contribution: +(w.first_epss_weight * v.epss * 100).toFixed(1) },
    { signal: "Internet exposure", value: toTitle(org.exposure || "internal"), contribution: exposureBoost(org) },
    { signal: "Service importance", value: toTitle(org.service_importance || "normal"), contribution: importanceBoost(org) },
  ];
}
function whyItMatters(v, org) {
  const sev = severityLabel(v.cvss);
  const parts = [];
  if (v.kev) parts.push("it is already being exploited in the wild (on CISA's Known Exploited Vulnerabilities list)");
  if (v.epss >= 0.5) parts.push("there is a " + (v.epss * 100).toFixed(0) + "% chance it will be exploited in the next 30 days");
  parts.push("its technical severity is " + v.cvss.toFixed(1) + "/10 (" + sev.toLowerCase() + ")");
  if (exposureBoost(org)) parts.push("the affected service is internet-facing");
  if (importanceBoost(org)) parts.push("it touches a " + (org.service_importance || "").toString().toLowerCase() + " service");
  return "This vulnerability matters to " + (org.name || "your organisation") + " because " + parts.join("; ") + ".";
}
function potentialImpact(v, businessService) {
  const sev = severityLabel(v.cvss);
  let base = "A " + sev.toLowerCase() + " flaw (CVSS " + v.cvss.toFixed(1) + ") in " + v.product + ". ";
  base += v.kev
    ? "Because it is confirmed exploited, a successful attack could compromise "
    : "If left unaddressed, it could compromise ";
  return base + (businessService || "an affected business service") + ".";
}
function nextStep(v, needsVer) {
  if (needsVer) return "Verify the installed version against the vendor advisory, then review vendor guidance before patching.";
  if (v.kev) return "Patch or apply the vendor's mitigation immediately — this is already being exploited in the wild.";
  if (v.epss >= 0.5) return "Prioritise patching in the next cycle and monitor logs for signs of exploitation.";
  return "Schedule a routine security patch and continue monitoring.";
}
function confidenceLevel(v, needsVer) {
  if (needsVer) return ["Low", "Version could not be compared — match needs human verification"];
  if (v.cvss >= 4.0) return ["High", "Product match is exact and the record is complete"];
  return ["Medium", "Lower-severity record; treat as context, not urgent"];
}

// Enrich a raw vuln into a full result object (used for offline fallback)
function enrich(v, org, w, businessService) {
  const needsVer = true; // data pack carries no version bounds
  const score = finalScore(v, org, w);
  const [conf, confReason] = confidenceLevel(v, needsVer);
  return {
    cve_id: v.cve_id,
    product: v.product,
    cvss: v.cvss,
    kev: v.kev,
    epss: v.epss,
    score: +score.toFixed(1),
    priority: priorityLabel(score),
    severity: severityLabel(v.cvss),
    effort: effortLabel(v),
    factors: buildFactors(v, org, w),
    why_it_matters: whyItMatters(v, org),
    potential_impact: potentialImpact(v, businessService || "an affected business service"),
    next_step: nextStep(v, needsVer),
    needs_verification: needsVer,
    confidence: conf,
    confidence_reason: confReason,
    business_service: businessService || "an affected business service",
    source_name: "NIST NVD · CISA KEV · FIRST EPSS",
    source_snapshot_date: "2025-11-01",
    reference_url: "https://nvd.nist.gov/vuln/detail/" + v.cve_id,
  };
}

// ---------- Owner-view plain-language helpers ----------
function productBusiness(product) {
  const map = {
    "Core Banking Framework": "your core banking system",
    "Identity Provider SaaS": "your identity & login service",
    "Cloud Database Engine": "your cloud database",
    "Web Application Firewall": "your web application firewall",
    "Embedded IoT Gateway": "your IoT gateway devices",
    "Enterprise Router OS": "your network routers / enterprise OS",
  };
  return map[product] || ("a business service built on " + product);
}
function sourceLabel(v) {
  const yr = v.cve_id ? v.cve_id.split("-")[1] : "2025";
  const kevSrc = v.kev ? " · CISA KEV" : "";
  return `NIST NVD · ${yr} snapshot${kevSrc}`;
}
function sourceColor(v) { return v.kev ? "#ef4444" : "var(--muted)"; }

// ---------- Rendering ----------
function renderThreatFeed() {
  const el = document.getElementById("threatFeed");
  if (!el || !window.VULNERABILITIES) return;
  const items = window.VULNERABILITIES
    .filter((v) => v.kev || v.epss >= 0.5)
    .sort((a, b) => (b.kev - a.kev) || (b.epss - a.epss))
    .slice(0, 12);
  if (!items.length) { el.innerHTML = '<div class="empty">No active threats in snapshot.</div>'; return; }
  el.innerHTML = items.map((v, i) => {
    const tag = v.kev
      ? '<span class="tf-tag tf-kev">KEV</span>'
      : `<span class="tf-tag tf-epss">EPSS ${(v.epss*100).toFixed(0)}%</span>`;
    return `<div class="tf-item" style="animation-delay:${i*0.03}s"><span class="tf-cve">${v.cve_id}</span><span class="tf-prod">${v.product}</span>${tag}</div>`;
  }).join("");
}

function renderOrgSelector() {
  if (!window.ORGANIZATIONS) { elements.orgContainer.innerHTML = '<div class="empty">Organisation data not found.</div>'; return; }
  elements.orgContainer.innerHTML = "";
  window.ORGANIZATIONS.forEach((org) => {
    const card = document.createElement("div");
    card.className = "org-card" + (currentOrg === org.org_id ? " active" : "");
    card.dataset.orgId = org.org_id;

    const riskClass = org.risk_appetite === "Low" ? "tag-risk-low"
      : org.risk_appetite === "High" ? "tag-risk-high" : "tag-risk-zero";
    const exp = (org.exposure || "").toLowerCase().startsWith("internet");
    const imp = (org.service_importance || "").toLowerCase();
    const impPct = imp === "critical" ? 100 : imp === "high" ? 60 : 30;
    const expLabel = exp ? "Internet-facing" : "Internal";
    const expPct = exp ? 100 : 35;

    // SVG risk dial (risk appetite → angle)
    const appetiteScore = org.risk_appetite === "Low" ? 0.85 : org.risk_appetite === "High" ? 0.4 : 0.6;
    const ang = (appetiteScore * 270 - 135) * Math.PI / 180;
    const cx = 30, cy = 30, r = 22;
    const nx = (cx + r * Math.cos(ang)).toFixed(1), ny = (cy + r * Math.sin(ang)).toFixed(1);

    const chips = org.critical_products.map(p => `<span class="o-chip">${p}</span>`).join("");

    card.innerHTML = `
      <div class="o-top">
        <div class="o-emoji">${ORG_ICONS[org.name] || "🏢"}</div>
        <svg class="o-dial" viewBox="0 0 60 60" width="56" height="56">
          <circle cx="30" cy="30" r="22" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="6"
            stroke-dasharray="103.6 34.5" transform="rotate(135 30 30)"></circle>
          <circle cx="30" cy="30" r="22" fill="none" stroke="url(#dg-${org.org_id})" stroke-width="6"
            stroke-linecap="round" stroke-dasharray="${(appetiteScore*103.6).toFixed(1)} 138"
            transform="rotate(135 30 30)"></circle>
          <line x1="30" y1="30" x2="${nx}" y2="${ny}" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>
          <circle cx="30" cy="30" r="3" fill="#fff"/>
          <defs><linearGradient id="dg-${org.org_id}" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#a855f7"/><stop offset="1" stop-color="#06b6d4"/>
          </linearGradient></defs>
        </svg>
      </div>
      <h3>${org.name}</h3>
      <div class="o-sector">${org.sector}</div>
      <div class="o-meters">
        <div class="o-meter"><span>Exposure</span><div class="m-bar"><i style="width:${expPct}%;background:${exp ? 'var(--crit)' : 'var(--low)'}"></i></div><b>${expLabel}</b></div>
        <div class="o-meter"><span>Service importance</span><div class="m-bar"><i style="width:${impPct}%;background:var(--accent)"></i></div><b>${toTitle(imp)}</b></div>
      </div>
      <div class="o-chips">${chips}</div>
      <span class="o-tag ${riskClass}">Risk appetite: ${org.risk_appetite}</span>
    `;
    card.addEventListener("click", () => selectOrg(org));
    elements.orgContainer.appendChild(card);
  });
}

function selectOrg(org) {
  currentOrg = org.org_id;
  document.querySelectorAll(".org-card").forEach((c) => {
    c.classList.toggle("active", c.dataset.orgId === org.org_id);
    if (c.dataset.orgId === org.org_id) {
      c.classList.remove("clicked"); void c.offsetWidth; c.classList.add("clicked");
    }
  });
  // switch to triage view
  showView("triage");
  const tt = document.getElementById("triageTitle");
  if (tt) tt.textContent = org.name + " — Prioritised Triage";
  if (location.hash !== "#org=" + org.org_id) {
    try { history.pushState(null, "", "#org=" + org.org_id); } catch (e) { location.hash = "org=" + org.org_id; }
  }
  loadTriage(org);
}

function showView(name) {
  const home = document.getElementById("view-home");
  const triage = document.getElementById("view-triage");
  if (home) home.style.display = name === "home" ? "" : "none";
  if (triage) triage.style.display = name === "triage" ? "" : "none";
  window.scrollTo(0, 0);
}

// ---------- Data loading ----------
async function api(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function loadTriage(org) {
  elements.vulnLoading.style.display = "block";
  elements.vulnLoading.textContent = "Analysing vulnerabilities for " + org.name + "…";
  elements.vulnList.innerHTML = "";

  let payload;
  try {
    payload = await api("/api/triage/" + org.org_id);
  } catch (e) {
    // Offline fallback: compute locally from embedded data
    payload = localTriage(org);
  }
  currentResult = payload;
  renderStats(payload);
  renderKEVBanner(payload);
  renderNegatives(payload, org);
  renderPriorityMatrix(payload);
  renderList(payload.top);
  renderValidation(org);
  showToggleRow();
}

function normProduct(name) {
  if (!name) return "";
  const k = name.toString().trim().toLowerCase();
  return (window.PRODUCT_ALIASES && window.PRODUCT_ALIASES[k]) || k;
}

function localTriage(org) {
  // Used only if the Flask server is unreachable (e.g. static Onslate deploy).
  const w = org.weight_modifiers;
  const critical = new Set(org.critical_products.map(normProduct));
  const matched = window.VULNERABILITIES.filter((v) => critical.has(normProduct(v.product)));
  const excluded = window.VULNERABILITIES.length - matched.length;
  const busMap = org.business_services || {};
  let top = matched.map((v) => enrich(v, org, w, busMap[v.product]));
  top.sort((a, b) => (b.score - a.score) || (a.cve_id < b.cve_id ? -1 : 1));
  top = top.slice(0, 5);
  top.forEach((t, i) => (t.rank = i + 1));
  const excl = window.VULNERABILITIES.filter((v) => !critical.has(v.product.toLowerCase()));
  excl.sort((a, b) => b.cvss - a.cvss);
  const neg = excl[0]
    ? { cve_id: excl[0].cve_id, product: excl[0].product, cvss: excl[0].cvss, kev: excl[0].kev, epss: excl[0].epss,
        reason: `CVSS ${excl[0].cvss.toFixed(1)} is severe, but ${excl[0].product} is not in this organisation's technology stack, so it was excluded by personalisation.` }
    : null;
  return {
    org: org.name, org_id: org.org_id, critical_products: org.critical_products,
    total_vulns: window.VULNERABILITIES.length, matched: matched.length, excluded,
    nothing_matched: matched.length === 0,
    honest_message: matched.length === 0 ? "Nothing matched this profile in the supplied data." : "",
    negative_test: neg, top,
  };
}

function renderStats(p) {
  const top = p.top;
  const sev = top.filter((v) => v.cvss >= 7.0).length;
  const kev = top.filter((v) => v.kev).length;
  elements.stMatched.textContent = p.matched;
  elements.stExcluded.textContent = p.excluded;
  elements.stSevere.textContent = sev + " / " + top.length;
  elements.stKev.textContent = kev;
  elements.statsRow.style.display = "grid";
}

function renderKEVBanner(p) {
  const kevItems = p.top.filter((v) => v.kev);
  if (kevItems.length > 0) {
    elements.kevBannerTitle.textContent = kevItems.length + " of your top risks are actively exploited";
    elements.kevBannerText.textContent = kevItems.map((v) => v.product).join(", ") + " — on CISA's Known Exploited Vulnerabilities list. Prioritise these immediately.";
    elements.kevBanner.classList.add("show");
  } else {
    elements.kevBanner.classList.remove("show");
  }
}

function renderNegatives(p, org) {
  const neg = p.negative_test;
  if (!neg) {
    elements.negSummary.innerHTML = `<strong>Negative test — required proof of personalisation</strong><br><span style="font-size:12px;color:var(--muted)">No excluded high-severity example available.</span>`;
    elements.negList.innerHTML = "";
    elements.negBox.style.display = "block";
    return;
  }
  elements.negSummary.innerHTML =
    `<strong>Negative test — proof that personalisation is not just "sort by CVSS"</strong><br>` +
    `<span style="font-size:12px;color:var(--muted)">` +
    `${p.excluded.toLocaleString()} vulnerabilities filtered out. The most severe excluded item is shown below — ` +
    `it scored high but was excluded because this organisation does not run that product.</span>`;

  elements.negList.innerHTML = `
    <div class="neg-row">
      <div>
        <span class="neg-prod">${neg.cve_id} · ${neg.product}</span>
        <br><span style="font-size:11px;color:var(--low)">${neg.reason}</span>
      </div>
      <div style="text-align:right">
        <span class="neg-cvss">CVSS ${neg.cvss.toFixed(1)}</span>
        <br><span style="font-size:10px;color:var(--muted)">${neg.kev ? "⚠ KEV" : "EPSS " + (neg.epss * 100).toFixed(1) + "%"} · EXCLUDED</span>
      </div>
    </div>`;
  elements.negBox.style.display = "block";
}

// ---------- Priority Matrix (3x3: CVSS severity x EPSS exploitability) ----------
function matrixCol(epss) { if (epss >= 0.5) return "high"; if (epss >= 0.1) return "med"; return "low"; }
function matrixRow(cvss) { if (cvss >= 7.0) return "high"; if (cvss >= 4.0) return "med"; return "low"; }
function matrixDotColor(kev, cvss, epss) {
  if (kev) return "#ef4444";
  if (cvss >= 9.0) return "#f97316";
  if (cvss >= 7.0) return "#eab308";
  if (epss >= 0.5) return "#22d3ee";
  return "#22c55e";
}
function renderPriorityMatrix(p) {
  const el = document.getElementById("priorityMatrix");
  if (!el || !p || !p.top) { if (el) el.style.display = "none"; return; }
  const cells = { low: { low: [], med: [], high: [] }, med: { low: [], med: [], high: [] }, high: { low: [], med: [], high: [] } };
  p.top.forEach(v => { cells[matrixRow(v.cvss)][matrixCol(v.epss)].push(v); });
  const colOrder = ["low", "med", "high"], rowOrder = ["high", "med", "low"];
  const colLabel = { low: "Low likelihood", med: "Medium likelihood", high: "High likelihood" };
  const rowLabel = { high: "High / Critical", med: "Medium", low: "Low" };
  let html = `<div class="matrix-grid">
    <div class="matrix-corner"><span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px">EPSS&nbsp;→<br>CVSS&nbsp;↓</span></div>`;
  colOrder.forEach(c => {
    html += `<div class="matrix-col-hdr"><span>${colLabel[c]}<br><small style="color:var(--accent-2);opacity:.7">${c === 'low' ? '<0.1' : c === 'med' ? '0.1–0.5' : '≥0.5'}</small></span></div>`;
  });
  rowOrder.forEach(r => {
    html += `<div class="matrix-row-hdr"><span>${rowLabel[r]}<br><small style="color:var(--accent);opacity:.7">${r === 'high' ? '≥7.0' : r === 'med' ? '4–6.9' : '<4'}</small></span></div>`;
    colOrder.forEach(c => {
      const items = cells[r][c];
      html += `<div class="matrix-cell">`;
      if (items.length === 0) { html += `<span class="mex" style="color:var(--border)">—</span>`; }
      else { items.forEach(v => {
        const color = matrixDotColor(v.kev, v.cvss, v.epss);
        const label = itView ? v.cve_id : `#${p.top.indexOf(v) + 1}`;
        html += `<div class="matrix-dot" style="background:${color}22;color:${color};border:1px solid ${color}55" title="${v.product} · CVSS ${v.cvss} · EPSS ${(v.epss * 100).toFixed(1)}%${v.kev ? ' · KEV' : ''}">` +
          `<span class="matrix-dot-inner" style="background:${color}"></span>${label}</div>`;
      }); }
      html += `</div>`;
    });
  });
  html += `</div><div class="matrix-legend">
      <span><span class="matrix-dot-inner" style="background:#ef4444;display:inline-block;width:8px;height:8px;border-radius:50%"></span> Actively exploited (KEV)</span>
      <span><span class="matrix-dot-inner" style="background:#f97316;display:inline-block;width:8px;height:8px;border-radius:50%"></span> Critical (CVSS ≥9)</span>
      <span><span class="matrix-dot-inner" style="background:#eab308;display:inline-block;width:8px;height:8px;border-radius:50%"></span> High (CVSS 7–8.9)</span>
      <span><span class="matrix-dot-inner" style="background:#22d3ee;display:inline-block;width:8px;height:8px;border-radius:50%"></span> High EPSS (≥50%)</span>
      <span><span class="matrix-dot-inner" style="background:#22c55e;display:inline-block;width:8px;height:8px;border-radius:50%"></span> Standard</span>
    </div>`;
  el.innerHTML = html;
  el.style.display = "block";
}

// ---------- Vulnerability list ----------
// Two genuinely different personas:
//   * Owner View  -> plain language, no CVE IDs / raw scores, business framing
//   * IT View     -> full technical detail: CVE, score breakdown, CVSS bar, sources
function renderList(top) {
  elements.vulnList.innerHTML = "";
  elements.vulnLoading.style.display = "none";

  if (!top || top.length === 0) {
    const honest = currentResult && currentResult.honest_message
      ? currentResult.honest_message
      : "No matching vulnerabilities found for this organisation.";
    elements.vulnList.innerHTML = '<div class="empty">' + honest + '</div>';
    return;
  }

  top.forEach((v, idx) => {
    const item = document.createElement("div");
    item.className = "vuln-item";
    item.style.animationDelay = (idx * 0.06) + "s";

    if (itView) {
      item.innerHTML = renderItCard(v, idx);
    } else {
      item.innerHTML = renderOwnerCard(v, idx);
    }
    // Compact report: click to expand / collapse (ignore clicks on links)
    item.addEventListener("click", (e) => {
      if (e.target.closest("a")) return;
      item.classList.toggle("open");
    });
    elements.vulnList.appendChild(item);
  });
}

// ---- OWNER VIEW: plain language for non-technical decision-makers ----
function renderOwnerCard(v, idx) {
  const rankClass = "rank-" + (idx + 1);
  const priClass = "pri-" + (v.priority || priorityLabel(v.score)).toLowerCase();
  const effClass = effortClass(v.effort);
  const color = severityColor(v.cvss);
  const sev = severityLabel(v.cvss);
  const kevBadge = v.kev ? `<span class="badge-kev">⚠ Actively exploited</span>` : "";
  const verBadge = v.needs_verification ? `<span class="badge-verify">🔎 Verify version</span>` : "";
  const businessTerm = productBusiness(v.product);
  // Consequence-first plain sentence (no jargon)
  const consequence = v.kev
    ? `A weakness in ${businessTerm} is already being attacked in the real world.`
    : `A weakness in ${businessTerm} could let attackers disrupt it.`;
  const urgencyWord = v.priority === "URGENT" ? "Act this week"
    : v.priority === "High" ? "Act soon"
    : v.priority === "Medium" ? "Plan a fix" : "Schedule when convenient";

  return `
    <div class="rank-badge ${rankClass}">${idx + 1}</div>
    <div class="vuln-main">
      <div class="vuln-head">
        <span class="prod">${businessTerm}</span>
        <span class="pri ${priClass}">${v.priority || priorityLabel(v.score)}</span>
        ${kevBadge}${verBadge}
      </div>

      <div class="owner-plain">
        <p class="owner-consequence">${consequence}</p>
        <p class="owner-why">${v.why_it_matters}</p>
        <p class="owner-impact"><b>If ignored:</b> ${v.potential_impact}</p>
      </div>

      <div class="owner-foot">
        <span class="effort-badge ${effClass}">⏱ ${v.effort}</span>
        <span class="owner-urgency">${urgencyWord}</span>
        <span class="owner-confidence">Confidence: ${v.confidence}</span>
      </div>

      <div class="owner-next">
        <span class="rl-label">Recommended action</span>
        <span>${v.next_step}</span>
      </div>

      <div class="detail">${buildDetail(v)}</div>
      <div class="expand-hint">Click to view full detail</div>
    </div>`;
}

// ---- IT WORKER VIEW: full technical detail ----
function renderItCard(v, idx) {
  const rankClass = "rank-" + (idx + 1);
  const sevClass = "sev-" + severityLabel(v.cvss).toLowerCase();
  const priClass = "pri-" + (v.priority || priorityLabel(v.score)).toLowerCase();
  const effClass = effortClass(v.effort);
  const color = severityColor(v.cvss);
  const kevBadge = v.kev ? `<span class="badge-kev">⚠ KEV · ACTIVE</span>` : "";
  const verBadge = v.needs_verification ? `<span class="badge-verify">🔎 NEEDS VERIFICATION</span>` : "";

  const factorRows = (v.factors || []).map(f =>
    `<tr><td>${f.signal}</td><td>${f.value}</td><td class="fac-val">+${f.contribution}</td></tr>`
  ).join("");

  const sourceLine =
    `<div class="src-line">` +
    `<span class="src-name">${v.source_name || sourceLabel(v)}</span>` +
    `<span class="src-date"> · snapshot ${v.source_snapshot_date || "2025-11-01"}</span>` +
    `<a class="src-link" href="${v.reference_url || '#'}" target="_blank" rel="noopener">source ↗</a>` +
    `</div>`;

  return `
    <div class="rank-badge ${rankClass}">${idx + 1}</div>
    <div class="vuln-main">
      <div class="vuln-head">
        <span class="cve">${v.cve_id}</span>
        <span class="prod">${v.product}</span>
        <span class="sev ${sevClass}">${severityLabel(v.cvss)}</span>
        <span class="pri ${priClass}">${v.priority || priorityLabel(v.score)}</span>
        ${kevBadge}${verBadge}
      </div>

      <div class="it-metrics">
        <div class="it-metric"><span class="im-l">CVSS</span><span class="im-v" style="color:${color}">${v.cvss.toFixed(1)}</span></div>
        <div class="it-metric"><span class="im-l">EPSS</span><span class="im-v">${(v.epss * 100).toFixed(1)}%</span></div>
        <div class="it-metric"><span class="im-l">KEV</span><span class="im-v">${v.kev ? "Yes" : "No"}</span></div>
        <div class="it-metric"><span class="im-l">Priority</span><span class="im-v">${v.score}/100</span></div>
      </div>

      <div class="vuln-tech show">
        <table class="breakdown">
          <tr><th>Signal</th><th>Value</th><th>Contribution</th></tr>
          ${factorRows}
          <tr class="fac-total"><td colspan="2">Total priority score</td><td class="fac-val">${v.score}/100</td></tr>
        </table>
        ${sourceLine}
        <div class="it-next"><b>Remediation:</b> ${v.next_step} <span class="effort-badge ${effClass}">${v.effort}</span></div>
        <div class="it-confidence">Confidence: <b>${v.confidence}</b> — ${v.confidence_reason}</div>
      </div>

      <div class="detail">${buildDetail(v)}</div>
      <div class="expand-hint">Click to view full detail</div>
    </div>`;
}

// Builds the expandable "full report" detail block (shared by both views)
function buildDetail(v) {
  const sev = severityLabel(v.cvss);
  const pri = v.priority || priorityLabel(v.score);
  const kevLine = v.kev ? `<div class="tf-tag tf-kev" style="display:inline-block;margin-top:6px">KEV · actively exploited</div>` : "";
  return `
    <div class="detail-title">Full triage report</div>
    <div class="owner-plain">
      <p class="owner-why">${v.why_it_matters}</p>
      <p class="owner-impact"><b>If ignored:</b> ${v.potential_impact}</p>
      <p><b>Severity:</b> ${sev} (CVSS ${v.cvss.toFixed(1)}) &nbsp;·&nbsp; <b>Priority:</b> ${pri} &nbsp;·&nbsp; <b>EPSS:</b> ${(v.epss * 100).toFixed(1)}%</p>
      ${kevLine}
      <p style="margin-top:8px"><b>Confidence:</b> ${v.confidence} — ${v.confidence_reason || ""}</p>
    </div>`;
}

// ---------- Validation ----------
async function renderValidation(org) {
  elements.validationArea.innerHTML = '<div class="loading"><div class="spinner"></div>Validating against practitioner ranking…</div>';
  try {
    const v = await api("/api/validate/" + org.org_id);
    const block = document.createElement("div");
    block.className = "vuln-item";
    block.style.flexDirection = "column";

    if (!v.all || v.all.total === 0) {
      block.innerHTML = `
        <div class="vuln-head">
          <span class="sev sev-low">ℹ️</span>
          <span class="prod" style="font-size:13.5px">Validation (gold-set) — ${v.note || "No practitioner gold ranks available for this organisation."}</span>
        </div>`;
      elements.validationArea.innerHTML = "";
      elements.validationArea.appendChild(block);
      return;
    }

    let html = `<div class="vuln-head">
        <span style="font-size:15px">🏅</span>
        <span class="prod">Ranking validated against practitioner expertise — <b style="color:${v.all.accuracy_pct >= 50 ? "var(--low)" : "var(--high)"}">${v.all.matches}/${v.all.total} matched (${v.all.accuracy_pct}%)</b></span>
      </div>
      <table class="breakdown">
        <tr><th>Gold CVE</th><th>Product</th><th>Our rank</th><th>Practitioner rank</th><th>Match</th><th>Our score</th></tr>`;

    v.all.items.forEach((it) => {
      const match = it.our_rank === it.practitioner_rank;
      html += `
        <tr>
          <td>${it.cve_id}</td><td>${it.product}</td>
          <td>${it.our_rank}</td><td>${it.practitioner_rank}</td>
          <td class="${match ? "match-y" : "match-n"}">${match ? "✓" : "✗"}</td>
          <td>${it.our_score}</td>
        </tr>`;
    });
    html += `</table>`;

    const pa = v.product_applicable;
    html += `
      <div style="margin-top:6px">
        <div class="vuln-head"><span class="sev sev-low">On your actual stack</span>
          <span class="prod">${pa.matches}/${pa.total} matched (${pa.accuracy_pct}%)</span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-top:6px">${pa.note}</div>
      </div>`;

    html += `<div style="font-size:12px;color:var(--muted);margin-top:12px;border-top:1px dashed var(--border);padding-top:10px">${v.note}</div>`;

    block.innerHTML = html;
    elements.validationArea.innerHTML = "";
    elements.validationArea.appendChild(block);
  } catch (e) {
    elements.validationArea.innerHTML = '<div class="empty">Validation unavailable: ' + e.message + "</div>";
  }
}

// ---------- Toggle ----------
function showToggleRow() { elements.toggleRow.style.display = "flex"; }
function setView(isIt) {
  itView = isIt;
  elements.toggleBtn.classList.toggle("on", !isIt);
  if (!isIt) {
    elements.toggleLab.textContent = "Owner View";
    elements.toggleDesc.textContent = "Plain language, for decision-makers";
  } else {
    elements.toggleLab.textContent = "IT Worker View";
    elements.toggleDesc.textContent = "CVE IDs, exact scores & breakdowns";
  }
  if (currentResult) renderList(currentResult.top);
}
elements.toggleBtn.addEventListener("click", () => setView(!itView));

// ---------- Toast ----------
let toastTimer;
function toast(msg) {
  elements.toast.textContent = msg;
  elements.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("show"), 2600);
}

// ---------- Upload Modal ----------
function openUploadModal() {
  elements.uploadModal.style.display = "flex";
  elements.uploadError.style.display = "none";
  elements.uploadError.textContent = "";
  elements.profileJson.value = "";
  elements.fileInput.value = "";
}
function closeUploadModal() { elements.uploadModal.style.display = "none"; elements.uploadError.style.display = "none"; }
function showUploadError(msg) { elements.uploadError.textContent = msg; elements.uploadError.style.display = "block"; }

function handleFileContent(content) { elements.profileJson.value = content; }

function validateProfileJson(text) {
  if (!text.trim()) { showUploadError("Please paste a JSON profile or upload a file."); return null; }
  try {
    const data = JSON.parse(text);
    if (!Array.isArray(data.critical_products) || data.critical_products.length === 0) {
      showUploadError("Missing or empty field: critical_products must be a non-empty list.");
      return null;
    }
    return data;
  } catch (e) { showUploadError("Invalid JSON: " + e.message); return null; }
}

async function runCustomTriage() {
  const jsonText = elements.profileJson.value;
  const profile = validateProfileJson(jsonText);
  if (!profile) return;
  elements.runTriage.disabled = true;
  elements.runTriage.textContent = "Running…";
  try {
    const res = await fetch("/api/triage-custom", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(profile),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const payload = await res.json();
    closeUploadModal();
    renderCustomResult(payload, profile);
  } catch (e) {
    // Offline fallback: compute locally from embedded data.js (works in file:// mode)
    if (window.VULNERABILITIES && window.VULNERABILITIES.length) {
      const payload = localTriageForProfile(profile);
      closeUploadModal();
      renderCustomResult(payload, profile);
      toast("Ran locally (offline mode) — for full validation run the server.");
    } else {
      showUploadError("Could not reach the server and no offline data is available. Run 'python server.py' first.");
    }
  } finally { elements.runTriage.disabled = false; elements.runTriage.textContent = "▶ Run Triage"; }
}

// Local triage for an arbitrary (unseen) profile, using embedded data.js
function localTriageForProfile(profile) {
  const defaults = { cvss_weight: 0.3, cisa_kev_weight: 0.45, first_epss_weight: 0.25 };
  const w = Object.assign({}, defaults, profile.weight_modifiers || {});
  for (const k in w) w[k] = parseFloat(w[k]);
  const org = {
    org_id: "CUSTOM", name: profile.name || "Custom Organisation",
    exposure: profile.exposure || "internal", service_importance: profile.service_importance || "normal",
    critical_products: profile.critical_products || [], weight_modifiers: w,
    business_services: profile.business_services || {},
  };
  const critical = new Set(org.critical_products.map(normProduct));
  const matched = window.VULNERABILITIES.filter((v) => critical.has(normProduct(v.product)));
  let top = matched.map((v) => enrich(v, org, w, (org.business_services || {})[v.product]));
  top.sort((a, b) => (b.score - a.score) || (a.cve_id < b.cve_id ? -1 : 1));
  top = top.slice(0, 5);
  top.forEach((t, i) => (t.rank = i + 1));
  const excl = window.VULNERABILITIES.filter((v) => !critical.has(normProduct(v.product)));
  excl.sort((a, b) => b.cvss - a.cvss);
  const neg = excl[0]
    ? { cve_id: excl[0].cve_id, product: excl[0].product, cvss: excl[0].cvss, kev: excl[0].kev, epss: excl[0].epss,
        reason: `CVSS ${excl[0].cvss.toFixed(1)} is severe, but ${excl[0].product} is not in this organisation's technology stack, so it was excluded by personalisation.` }
    : null;
  return {
    org: org.name, org_id: "CUSTOM", critical_products: org.critical_products,
    total_vulns: window.VULNERABILITIES.length, matched: matched.length, excluded: window.VULNERABILITIES.length - matched.length,
    nothing_matched: matched.length === 0,
    honest_message: matched.length === 0 ? "Nothing matched this profile in the supplied data." : "",
    negative_test: neg, top,
  };
}

function renderCustomResult(payload, profile) {
  currentOrg = "CUSTOM";
  currentResult = payload;
  const fakeOrg = { critical_products: payload.critical_products, name: payload.org, exposure: payload.exposure, service_importance: payload.service_importance };
  document.querySelectorAll(".org-card").forEach((c) => c.classList.remove("active"));
  // switch to triage view so the result is actually visible
  showView("triage");
  const tt = document.getElementById("triageTitle");
  if (tt) tt.textContent = "Custom Profile — " + payload.org;
  // ensure a custom-profile summary card sits at the top of the results
  const summary = document.getElementById("customSummary");
  if (summary) {
    summary.style.display = "block";
    summary.innerHTML = `
      <div class="vuln-item" style="flex-direction:column">
        <div class="vuln-head">
          <span style="font-size:15px">📁</span>
          <span class="prod">Custom profile: <b>${escapeHtml(payload.org)}</b></span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-top:6px">
          Exposure: ${escapeHtml(payload.exposure)} &nbsp;·&nbsp; Service importance: ${escapeHtml(payload.service_importance)} &nbsp;·&nbsp; Products: ${escapeHtml(payload.critical_products.join(", "))}
        </div>
      </div>`;
  }
  renderStats(payload);
  renderKEVBanner(payload);
  renderNegatives(payload, fakeOrg);
  renderPriorityMatrix(payload);
  renderList(payload.top);
  showToggleRow();
  window.scrollTo({ top: 0, behavior: "smooth" });
  toast("Triage complete for " + payload.org);
}

// Event listeners
elements.uploadBtn.addEventListener("click", openUploadModal);
elements.modalClose.addEventListener("click", closeUploadModal);
elements.modalCancel.addEventListener("click", closeUploadModal);
elements.runTriage.addEventListener("click", runCustomTriage);
elements.uploadModal.addEventListener("click", (e) => { if (e.target === elements.uploadModal) closeUploadModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && elements.uploadModal.style.display !== "none") closeUploadModal(); });
elements.dropZone.addEventListener("dragover", (e) => { e.preventDefault(); elements.dropZone.classList.add("drag-over"); });
elements.dropZone.addEventListener("dragleave", () => elements.dropZone.classList.remove("drag-over"));
elements.dropZone.addEventListener("drop", (e) => { e.preventDefault(); elements.dropZone.classList.remove("drag-over"); const f = e.dataTransfer.files[0]; if (f) readFile(f); });
elements.fileInput.addEventListener("change", (e) => { const f = e.target.files[0]; if (f) readFile(f); });

function readFile(file) {
  if (file.name.endsWith(".csv") || file.type === "text/csv") { uploadCsv(file); return; }
  if (!file.name.endsWith(".json") && file.type !== "application/json") { showUploadError("Only .json and .csv files are accepted."); return; }
  const reader = new FileReader();
  reader.onload = (e) => handleFileContent(e.target.result);
  reader.onerror = () => showUploadError("Failed to read file.");
  reader.readAsText(file);
}

async function uploadCsv(file) {
  elements.runTriage.disabled = true;
  elements.runTriage.textContent = "Uploading CSV…";
  const formData = new FormData();
  formData.append("file", file);
  try {
    const res = await fetch("/api/triage-csv-upload", { method: "POST", body: formData });
    if (!res.ok) { const err = await res.json().catch(() => ({ error: "HTTP " + res.status })); showUploadError(err.error || "CSV upload failed."); return; }
    const payload = await res.json();
    closeUploadModal();
    renderCustomResult(payload, { name: payload.org });
  } catch (e) { showUploadError("Network error: " + e.message); }
  finally { elements.runTriage.disabled = false; elements.runTriage.textContent = "▶ Run Triage"; }
}

// ---------- 3D HERO (Three.js network sphere) ----------
function initHero3D() {
  const canvas = document.getElementById("hero3d");
  if (!canvas || typeof THREE === "undefined") return; // graceful skip if offline
  try {
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, 2, 0.1, 1000);
    camera.position.z = 230;

    const group = new THREE.Group();
    scene.add(group);

    // Build nodes on a sphere (Fibonacci distribution)
    const N = 90;
    const R = 120;
    const positions = [];
    const pts = [];
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const theta = golden * i;
      const x = Math.cos(theta) * r;
      const z = Math.sin(theta) * r;
      positions.push(x * R, y * R, z * R);
      pts.push(new THREE.Vector3(x * R, y * R, z * R));
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    const pMat = new THREE.PointsMaterial({ color: 0xa855f7, size: 3.4, transparent: true, opacity: 0.95 });
    group.add(new THREE.Points(geo, pMat));

    // Connect nearby nodes with glowing cyan lines
    const linePos = [];
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        if (pts[i].distanceTo(pts[j]) < R * 0.42) {
          linePos.push(pts[i].x, pts[i].y, pts[i].z, pts[j].x, pts[j].y, pts[j].z);
        }
      }
    }
    const lgeo = new THREE.BufferGeometry();
    lgeo.setAttribute("position", new THREE.Float32BufferAttribute(linePos, 3));
    const lmat = new THREE.LineBasicMaterial({ color: 0x06b6d4, transparent: true, opacity: 0.18 });
    group.add(new THREE.LineSegments(lgeo, lmat));

    // A few brighter "threat" nodes (pink)
    const threatGeo = new THREE.BufferGeometry();
    const tp = [];
    for (let i = 0; i < 12; i++) {
      const p = pts[Math.floor(Math.random() * pts.length)];
      tp.push(p.x * 1.02, p.y * 1.02, p.z * 1.02);
    }
    threatGeo.setAttribute("position", new THREE.Float32BufferAttribute(tp, 3));
    group.add(new THREE.Points(threatGeo, new THREE.PointsMaterial({ color: 0xec4899, size: 5.5 })));

    function resize() {
      const w = canvas.clientWidth || canvas.parentElement.clientWidth;
      const h = canvas.clientHeight || canvas.parentElement.clientHeight;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    window.addEventListener("resize", resize);
    resize();

    (function animate() {
      requestAnimationFrame(animate);
      group.rotation.y += 0.0024;
      group.rotation.x += 0.0009;
      renderer.render(scene, camera);
    })();
  } catch (e) { /* no-op: keep CSS hero if WebGL unavailable */ }
}

async function init() {
  initHero3D();
  renderThreatFeed();

  // Nav links
  document.querySelectorAll(".nav-link[data-view]").forEach((a) => {
    a.addEventListener("click", (e) => { e.preventDefault(); showView("home"); });
  });
  const navUpload = document.getElementById("navUpload");
  if (navUpload) navUpload.addEventListener("click", (e) => { e.preventDefault(); openUploadModal(); });

  // Back button
  const back = document.getElementById("backBtn");
  if (back) back.addEventListener("click", () => {
    try { history.pushState(null, "", location.pathname); } catch (e) {}
    showView("home");
  });

  // Global intel drawer (slide-in panel)
  const drawer = document.getElementById("intelDrawer");
  const drawerOverlay = document.getElementById("drawerOverlay");
  const drawerBtn = document.getElementById("drawerBtn");
  const drawerClose = document.getElementById("drawerClose");
  function openDrawer() { drawer.classList.add("show"); drawerOverlay.classList.add("show"); }
  function closeDrawer() { drawer.classList.remove("show"); drawerOverlay.classList.remove("show"); }
  if (drawerBtn) drawerBtn.addEventListener("click", openDrawer);
  if (drawerClose) drawerClose.addEventListener("click", closeDrawer);
  if (drawerOverlay) drawerOverlay.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // Deep-link: ?org=ORG-XXX
  const m = location.hash.match(/org=([^&]+)/);
  let initialOrg = null;
  if (m) {
    try { window.ORGANIZATIONS = await api("/api/organizations"); } catch (e) {}
    initialOrg = (window.ORGANIZATIONS || []).find((o) => o.org_id === m[1]);
  } else {
    try { window.ORGANIZATIONS = await api("/api/organizations"); } catch (e) {}
  }

  renderOrgSelector();
  checkHealth();

  if (initialOrg) { selectOrg(initialOrg); }
}

init();
