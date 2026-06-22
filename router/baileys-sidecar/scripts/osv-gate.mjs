#!/usr/bin/env node
// osv-gate.mjs — enforce the FUL-20 / FUL-24 OSV-Scanner threshold policy.
//
// Usage: node scripts/osv-gate.mjs <osv-results.json> [osv-waivers.toml]
//
// Policy (FUL-20 plan + Security Lead sign-off on FUL-24):
//   CVSS gate
//     * FAIL on any vulnerability with CVSS base score >= 7.0 that HAS A FIX
//       available (take the fix — not waivable).
//     * A vuln with NO fix available passes ONLY if covered by a valid,
//       non-expired, Security-signed waiver. Otherwise it FAILS too.
//     * Vulns below 7.0 are reported but do not gate (unless KEV/EPSS, below).
//   Exploitation gate (FUL-24 condition B) — applies REGARDLESS of CVSS:
//     * FAIL on any vuln listed in the CISA KEV catalog.
//     * FAIL on any vuln with EPSS >= 0.5.
//     * These are NOT waiver-eligible here — escalate to Security for sign-off.
//   Waiver rules (FUL-24 condition C):
//     * Only NO-FIX vulns can be waived; a fix existing always wins.
//     * Required fields: id, signed_by (approver), reason (justification), expires.
//     * Max remaining TTL: 14 days for Critical (CVSS >= 9.0), 30 days for High.
//     * runtime_capable = true (network/fs-capable runtime dep) requires an
//       explicit escalation_ack from Security.
//     * Expired / unsigned / over-TTL / missing-field => invalid => gate fails.
//
// Exit codes: 0 = pass, 1 = policy violation, 2 = usage/parse error.
//
// Dependency-free on purpose: this runs inside the locked install and must not
// pull anything new into the supply chain it is guarding. Enrichment data (KEV /
// EPSS) is fetched over HTTPS with Node's built-in fetch, or injected from local
// files for offline/deterministic runs (OSV_GATE_KEV_FILE / OSV_GATE_EPSS_FILE).

import { readFileSync } from 'node:fs';

const THRESHOLD = 7.0; // High
const CRITICAL = 9.0; // Critical
const EPSS_THRESHOLD = 0.5; // FUL-24 condition B
const MAX_TTL_DAYS_HIGH = 30; // FUL-24 condition C
const MAX_TTL_DAYS_CRITICAL = 14;

const KEV_URL =
  process.env.OSV_GATE_KEV_URL ||
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = process.env.OSV_GATE_EPSS_URL || 'https://api.first.org/data/v1/epss';

const [, , resultsPath, waiversPath] = process.argv;

if (!resultsPath) {
  console.error('usage: osv-gate.mjs <osv-results.json> [osv-waivers.toml]');
  process.exit(2);
}

/* ----------------------------- minimal TOML ------------------------------ */
// Parses the narrow waiver shape only: top-level scalars plus an array of
// [[waiver]] tables with simple key = "value" lines.
function parseWaivers(text) {
  const meta = {};
  const waivers = [];
  let cur = null;
  for (let raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    if (line === '[[waiver]]') {
      cur = {};
      waivers.push(cur);
      continue;
    }
    const m = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.+)$/);
    if (!m) continue;
    let [, key, val] = m;
    val = val.trim().replace(/^["']|["']$/g, '');
    (cur ?? meta)[key] = val;
  }
  return { meta, waivers };
}

/* ----------------------- CVSS v3.x base score calc ----------------------- */
const CVSS_W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0.0 },
};
const roundUp = (x) => Math.ceil(x * 10) / 10;

function cvssBaseFromVector(vector) {
  const parts = Object.fromEntries(
    vector
      .replace(/^CVSS:3\.[01]\//i, '')
      .split('/')
      .map((p) => p.split(':'))
  );
  if (!parts.AV || !parts.C) return null;
  const scopeChanged = parts.S === 'C';
  const av = CVSS_W.AV[parts.AV];
  const ac = CVSS_W.AC[parts.AC];
  const pr = (scopeChanged ? CVSS_W.PR_C : CVSS_W.PR)[parts.PR];
  const ui = CVSS_W.UI[parts.UI];
  const c = CVSS_W.CIA[parts.C];
  const i = CVSS_W.CIA[parts.I];
  const a = CVSS_W.CIA[parts.A];
  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const base = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp(base);
}

function severityScore(vuln, groupMax) {
  for (const sev of vuln.severity ?? []) {
    if ((sev.type || '').startsWith('CVSS_V3') && typeof sev.score === 'string') {
      const s = cvssBaseFromVector(sev.score);
      if (s != null) return s;
    }
  }
  const g = parseFloat(groupMax);
  return Number.isFinite(g) ? g : null;
}

function hasFix(vuln) {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) return true;
      }
    }
  }
  return false;
}

// Every CVE id associated with a vuln (its own id if a CVE, plus CVE aliases).
function cvesOf(vuln) {
  const ids = new Set();
  const add = (x) => {
    if (typeof x === 'string' && /^CVE-\d{4}-\d+$/i.test(x)) ids.add(x.toUpperCase());
  };
  add(vuln.id);
  for (const a of vuln.aliases ?? []) add(a);
  return [...ids];
}

/* --------------------------- KEV / EPSS enrichment ----------------------- */
async function fetchJson(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'osv-gate/2.0' } });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

// Returns a Set of CVE ids in the CISA KEV catalog.
async function loadKev() {
  const file = process.env.OSV_GATE_KEV_FILE;
  const doc = file ? JSON.parse(readFileSync(file, 'utf8')) : await fetchJson(KEV_URL);
  const set = new Set();
  for (const v of doc.vulnerabilities ?? []) if (v.cveID) set.add(v.cveID.toUpperCase());
  return set;
}

// Returns Map<CVE, epssScore(number)> for the requested CVEs.
async function loadEpss(cves) {
  const map = new Map();
  if (!cves.length) return map;
  const file = process.env.OSV_GATE_EPSS_FILE;
  if (file) {
    const doc = JSON.parse(readFileSync(file, 'utf8'));
    // Accept either {CVE: score} or FIRST API shape {data:[{cve,epss}]}.
    if (Array.isArray(doc.data)) {
      for (const r of doc.data) map.set(r.cve.toUpperCase(), parseFloat(r.epss));
    } else {
      for (const [k, v] of Object.entries(doc)) map.set(k.toUpperCase(), parseFloat(v));
    }
    return map;
  }
  // Live FIRST.org EPSS API, batched (URL length safety).
  for (let i = 0; i < cves.length; i += 100) {
    const batch = cves.slice(i, i + 100);
    const doc = await fetchJson(`${EPSS_URL}?cve=${batch.join(',')}`);
    for (const r of doc.data ?? []) map.set(r.cve.toUpperCase(), parseFloat(r.epss));
  }
  return map;
}

/* -------------------------------- load ----------------------------------- */
let results;
try {
  const txt = readFileSync(resultsPath, 'utf8').trim();
  results = txt ? JSON.parse(txt) : { results: [] };
} catch (e) {
  console.error(`osv-gate: cannot read/parse ${resultsPath}: ${e.message}`);
  process.exit(2);
}

let waiverDoc = { meta: {}, waivers: [] };
if (waiversPath) {
  try {
    waiverDoc = parseWaivers(readFileSync(waiversPath, 'utf8'));
  } catch {
    console.error(`osv-gate: waiver file ${waiversPath} not found — proceeding with zero waivers`);
  }
}

const today = process.env.OSV_GATE_TODAY || new Date().toISOString().slice(0, 10);
const daysBetween = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 86400000);

// Raw waiver lookup; validity (TTL/fields) is decided per-vuln since the TTL cap
// depends on the vuln's severity.
const waiverById = new Map();
for (const w of waiverDoc.waivers) if (w.id) waiverById.set(w.id.toUpperCase(), w);

function validateWaiver(w, score) {
  if (!w) return { ok: false, reason: 'no fix available, no valid Security waiver' };
  if (!w.signed_by) return { ok: false, reason: 'waiver missing signed_by (approver)' };
  if (!w.reason) return { ok: false, reason: 'waiver missing reason (justification)' };
  if (!w.expires) return { ok: false, reason: 'waiver missing expires (TTL)' };
  if (w.expires < today) return { ok: false, reason: `waiver expired ${w.expires}` };
  const remaining = daysBetween(today, w.expires);
  const cap = score >= CRITICAL ? MAX_TTL_DAYS_CRITICAL : MAX_TTL_DAYS_HIGH;
  if (remaining > cap)
    return { ok: false, reason: `waiver TTL ${remaining}d exceeds ${cap}d cap (expires ${w.expires})` };
  if (String(w.runtime_capable).toLowerCase() === 'true' && !w.escalation_ack)
    return { ok: false, reason: 'runtime_capable waiver requires escalation_ack from Security' };
  return { ok: true };
}

/* ------------------------------ enrichment ------------------------------- */
// Collect every vuln + its CVEs up front so we fetch KEV/EPSS once.
const rows = [];
for (const res of results.results ?? []) {
  const groupMaxById = {};
  for (const pkg of res.packages ?? [])
    for (const grp of pkg.groups ?? [])
      for (const id of grp.ids ?? []) groupMaxById[id] = grp.max_severity;
  for (const pkg of res.packages ?? []) {
    const name = pkg.package?.name ?? 'unknown';
    const version = pkg.package?.version ?? '?';
    for (const vuln of pkg.vulnerabilities ?? []) {
      rows.push({
        id: vuln.id,
        name,
        version,
        score: severityScore(vuln, groupMaxById[vuln.id]),
        fixed: hasFix(vuln),
        cves: cvesOf(vuln),
      });
    }
  }
}

let kev = new Set();
let epss = new Map();
const skipEnrichment = process.env.OSV_GATE_SKIP_ENRICHMENT === '1';
if (rows.length && !skipEnrichment) {
  try {
    const allCves = [...new Set(rows.flatMap((r) => r.cves))];
    [kev, epss] = await Promise.all([loadKev(), loadEpss(allCves)]);
  } catch (e) {
    // Fail-closed: this process holds the master key; we do not ship blind to
    // KEV/EPSS. Offline dev can set OSV_GATE_SKIP_ENRICHMENT=1 (loud + unsafe).
    console.error(`osv-gate: FAIL — KEV/EPSS enrichment unavailable (${e.message}).`);
    console.error('osv-gate: refusing to pass without exploitation data. Set');
    console.error('osv-gate: OSV_GATE_SKIP_ENRICHMENT=1 only for offline dev runs.');
    process.exit(1);
  }
} else if (skipEnrichment && rows.length) {
  console.error('osv-gate: WARNING — KEV/EPSS enrichment SKIPPED (OSV_GATE_SKIP_ENRICHMENT=1).');
  console.error('osv-gate: condition B (KEV / EPSS>=0.5) is NOT enforced this run.');
}

/* ------------------------------ evaluate --------------------------------- */
const failures = [];
const waived = [];
const below = [];

for (const r of rows) {
  const epssMax = Math.max(0, ...r.cves.map((c) => epss.get(c) ?? 0));
  const kevHit = r.cves.some((c) => kev.has(c));

  // Condition B — exploitation gate, regardless of CVSS, not waiver-eligible.
  if (kevHit || epssMax >= EPSS_THRESHOLD) {
    const why = kevHit
      ? 'in CISA KEV (actively exploited)'
      : `EPSS ${epssMax.toFixed(2)} >= ${EPSS_THRESHOLD}`;
    failures.push({ ...r, epssMax, reason: `${why} — not waiver-eligible, escalate to Security` });
    continue;
  }

  if (r.score == null || r.score < THRESHOLD) {
    below.push({ ...r, epssMax });
    continue;
  }
  if (r.fixed) {
    failures.push({ ...r, reason: 'CVSS>=7.0 with fix available — upgrade required' });
    continue;
  }
  // No fix: only a valid signed, in-TTL waiver lets it pass.
  const w = waiverById.get((r.id || '').toUpperCase());
  const v = validateWaiver(w, r.score);
  if (v.ok) waived.push({ ...r, waiver: w });
  else failures.push({ ...r, reason: `CVSS>=7.0, no fix — ${v.reason}` });
}

/* ------------------------------- report ---------------------------------- */
const fmt = (r) =>
  `  - ${r.id}  ${r.name}@${r.version}  CVSS=${r.score}  fix=${r.fixed}  EPSS=${(r.epssMax ?? 0).toFixed(2)}`;
if (below.length) {
  console.log(`osv-gate: ${below.length} sub-threshold finding(s) (reported, not gating):`);
  below.forEach((r) => console.log(fmt(r)));
}
if (waived.length) {
  console.log(`osv-gate: ${waived.length} waived no-fix high(s):`);
  waived.forEach((r) =>
    console.log(`${fmt(r)}  [waiver expires ${r.waiver.expires}, signed_by ${r.waiver.signed_by}]`)
  );
}
if (failures.length) {
  console.error(`\nosv-gate: FAIL — ${failures.length} policy violation(s):`);
  failures.forEach((r) => console.error(`${fmt(r)}\n      -> ${r.reason}`));
  process.exit(1);
}
console.log(
  `\nosv-gate: PASS — no fixable CVSS>=${THRESHOLD}, no KEV, no EPSS>=${EPSS_THRESHOLD}, all no-fix highs validly waived.`
);
process.exit(0);
