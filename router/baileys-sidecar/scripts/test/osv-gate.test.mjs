#!/usr/bin/env node
// osv-gate.test.mjs — exit-code matrix for the FUL-24 hardened gate.
// Run: node scripts/test/osv-gate.test.mjs   (exit 0 = all green)
//
// Deterministic + offline: KEV/EPSS are injected via fixture files and "today"
// is pinned, so no network is touched and TTL math is stable.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const GATE = join(HERE, '..', 'osv-gate.mjs');
const DIR = mkdtempSync(join(tmpdir(), 'osv-gate-'));
const TODAY = '2026-06-22';

// CVSS:3.1 vectors → base scores.
const C98 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; // 9.8 (Critical)
const C75 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'; // 7.5 (High)
const C54 = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N'; // ~5.4 (sub-threshold)

// Shared enrichment fixtures.
const kevFile = join(DIR, 'kev.json');
writeFileSync(kevFile, JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2099-0001' }] }));
const epssFile = join(DIR, 'epss.json');
writeFileSync(epssFile, JSON.stringify({ 'CVE-2099-0002': '0.91', 'CVE-2099-0003': '0.10' }));

let n = 0;
function vuln(id, { vector, fixed, aliases } = {}) {
  const v = { id };
  if (aliases) v.aliases = aliases;
  if (vector) v.severity = [{ type: 'CVSS_V3', score: vector }];
  v.affected = [
    { ranges: [{ type: 'SEMVER', events: fixed ? [{ introduced: '0' }, { fixed: '1.0.0' }] : [{ introduced: '0' }] }] },
  ];
  return v;
}
const results = (...vulns) => ({
  results: [{ packages: [{ package: { name: 'dep', version: '0.1.0' }, vulnerabilities: vulns }] }],
});

function run(name, { res, waiver, expect, stdoutIncludes }) {
  const rf = join(DIR, `res-${n}.json`);
  writeFileSync(rf, JSON.stringify(res));
  const args = [GATE, rf];
  if (waiver !== undefined) {
    const wf = join(DIR, `wv-${n}.toml`);
    writeFileSync(wf, waiver);
    args.push(wf);
  }
  n++;
  const out = spawnSync('node', args, {
    env: { ...process.env, OSV_GATE_TODAY: TODAY, OSV_GATE_KEV_FILE: kevFile, OSV_GATE_EPSS_FILE: epssFile },
    encoding: 'utf8',
  });
  const stdoutOk = !stdoutIncludes || (out.stdout || '').includes(stdoutIncludes);
  const ok = out.status === expect && stdoutOk;
  console.log(`${ok ? 'PASS' : 'FAIL'}  [${out.status} want ${expect}]  ${name}`);
  if (!ok) {
    if (!stdoutOk) console.log(`  --- expected stdout to include: ${stdoutIncludes}`);
    console.log('  --- stdout ---\n' + out.stdout);
    console.log('  --- stderr ---\n' + out.stderr);
  }
  return ok;
}

const W = (extra) =>
  `policy_version="2.0"\n[[waiver]]\nid="GHSA-nofix"\nreason="no upstream fix"\nsigned_by="Security Lead"\ntracking_issue="FUL-99"\n${extra}\n`;

const cases = [
  // CVSS gate
  ['empty results -> pass', { res: { results: [] }, expect: 0 }],
  ['CVSS 9.8 with fix -> fail (take the fix)', { res: results(vuln('GHSA-fix', { vector: C98, fixed: true })), expect: 1 }],
  ['CVSS 7.5 no-fix, no waiver -> fail', { res: results(vuln('GHSA-nofix', { vector: C75 })), expect: 1 }],
  ['CVSS 5.4 sub-threshold -> pass (reported)', { res: results(vuln('GHSA-low', { vector: C54 })), expect: 0 }],
  // Waiver TTL (condition C)
  ['7.5 no-fix, valid 18d waiver -> pass', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: W('expires="2026-07-10"'), expect: 0 }],
  ['7.5 no-fix, 45d waiver -> fail (>30d cap)', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: W('expires="2026-08-06"'), expect: 1 }],
  ['9.8 no-fix, 18d waiver -> fail (Critical cap 14d)', { res: results(vuln('GHSA-nofix', { vector: C98 })), waiver: W('expires="2026-07-10"'), expect: 1 }],
  ['9.8 no-fix, 10d waiver -> pass', { res: results(vuln('GHSA-nofix', { vector: C98 })), waiver: W('expires="2026-07-02"'), expect: 0 }],
  ['7.5 no-fix, expired waiver -> fail', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: W('expires="2026-06-01"'), expect: 1 }],
  ['7.5 no-fix, waiver missing reason -> fail', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: `[[waiver]]\nid="GHSA-nofix"\nsigned_by="Security Lead"\nexpires="2026-07-10"\n`, expect: 1 }],
  // runtime_capable escalation (condition C)
  ['7.5 no-fix, runtime_capable w/o escalation_ack -> fail', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: W('expires="2026-07-10"\nruntime_capable="true"'), expect: 1 }],
  ['7.5 no-fix, runtime_capable + escalation_ack -> pass', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: W('expires="2026-07-10"\nruntime_capable="true"\nescalation_ack="Security Lead 2026-06-22"'), expect: 0 }],
  // Exploitation gate (condition B) — regardless of CVSS, not waiver-eligible
  ['KEV-listed low CVSS -> fail (KEV)', { res: results(vuln('GHSA-kev', { vector: C54, aliases: ['CVE-2099-0001'] })), expect: 1 }],
  ['KEV-listed even WITH a waiver -> fail (not waivable)', { res: results(vuln('GHSA-kev', { vector: C54, aliases: ['CVE-2099-0001'] })), waiver: `[[waiver]]\nid="GHSA-kev"\nreason="x"\nsigned_by="Security Lead"\ntracking_issue="FUL-99"\nexpires="2026-07-02"\n`, expect: 1 }],
  ['EPSS 0.91 low CVSS -> fail (EPSS>=0.5)', { res: results(vuln('GHSA-epss', { vector: C54, aliases: ['CVE-2099-0002'] })), expect: 1 }],
  ['EPSS 0.10 sub-threshold CVSS -> pass', { res: results(vuln('GHSA-ok', { vector: C54, aliases: ['CVE-2099-0003'] })), expect: 0 }],
  // FUL-42 waiver-file hygiene (compensating control for count=0) — enforced on
  // EVERY entry independent of whether its vuln is in the scan. Use empty results
  // to prove the file itself gates, not a matched finding.
  ['7.5 no-fix, waiver missing tracking_issue -> fail', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: `[[waiver]]\nid="GHSA-nofix"\nreason="x"\nsigned_by="Security Lead"\nexpires="2026-07-10"\n`, expect: 1 }],
  ['waiver bad tracking_issue format -> fail', { res: results(vuln('GHSA-nofix', { vector: C75 })), waiver: W('expires="2026-07-10"\ntracking_issue="not-an-id"'), expect: 1 }],
  ['empty scan + malformed waiver (no expiry) -> fail (file gates)', { res: { results: [] }, waiver: `[[waiver]]\nid="GHSA-orphan"\nreason="x"\nsigned_by="Security Lead"\ntracking_issue="FUL-1"\n`, expect: 1 }],
  ['empty scan + expired waiver -> fail (no stale suppression)', { res: { results: [] }, waiver: `[[waiver]]\nid="GHSA-orphan"\nreason="x"\nsigned_by="Security Lead"\ntracking_issue="FUL-1"\nexpires="2026-06-01"\n`, expect: 1 }],
  ['empty scan + over-90d waiver -> fail (bounded window)', { res: { results: [] }, waiver: `[[waiver]]\nid="GHSA-orphan"\nreason="x"\nsigned_by="Security Lead"\ntracking_issue="FUL-1"\nexpires="2026-12-01"\n`, expect: 1 }],
  ['empty scan + well-formed in-window waiver -> pass (register visible)', { res: { results: [] }, waiver: `[[waiver]]\nid="GHSA-orphan"\nreason="x"\nsigned_by="Security Lead"\ntracking_issue="FUL-1"\nexpires="2026-08-01"\n`, expect: 0, stdoutIncludes: 'WAIVER REGISTER' }],
];

let pass = 0;
for (const [name, cfg] of cases) if (run(name, cfg)) pass++;
console.log(`\n${pass}/${cases.length} cases passed`);
process.exit(pass === cases.length ? 0 : 1);
