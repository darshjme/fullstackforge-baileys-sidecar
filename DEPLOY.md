# Baileys sidecar supply-chain release gate — deployment & evidence

Implements **FUL-23** (child of **FUL-20**). All artifacts are drop-in for the FUL
repo at the paths shown. Place them, open a PR, then enable the branch-protection
toggle (the one repo-admin step — see *Escalation*).

## File map (place at these repo paths)

| Artifact | Repo path | Task |
|---|---|---|
| PR gate workflow | `.github/workflows/baileys-sidecar-ci.yml` | 1, 4, 5 |
| Release gate workflow | `.github/workflows/baileys-sidecar-release.yml` | 2, 3, 4 |
| Weekly scheduled scan | `.github/workflows/baileys-sidecar-scheduled.yml` | 5 |
| Reusable OSV gate action | `.github/actions/osv-gate/action.yml` | 4 |
| OSV policy enforcement script | `router/baileys-sidecar/scripts/osv-gate.mjs` | 4 |
| Vendoring build script | `router/baileys-sidecar/scripts/build-vendored.sh` | 2 |
| Security-signed waiver register | `router/baileys-sidecar/security/osv-waivers.toml` | 4 |
| Dockerfile hardening snippet | merge into sidecar `Dockerfile` | 2 |
| Branch-protection payload | `ops/branch-protection.json` | 1 |
| Branch-protection apply script | `ops/apply-branch-protection.sh` | 1 |
| CODEOWNERS (Security-gates the waiver file) | `.github/CODEOWNERS` | 1, 4 |
| OSV gate self-test | `router/baileys-sidecar/scripts/test/osv-gate.test.mjs` | 4 |

## FUL-24 Security sign-off conditions (folded in)

The Security Lead signed off on [FUL-24](/FUL/issues/FUL-24) with three config-level
conditions, all enforced here:

- **A — `--ignore-scripts` mandatory.** `npm ci --omit=dev --ignore-scripts` in the
  release/Docker build, `npm ci --ignore-scripts` in PR CI, lockfile-only scan in the
  weekly job. Any genuine build step must be added to an explicit allowlist, not by
  dropping the flag.
- **B — exploitation gate.** `osv-gate.mjs` fails on any vuln in the **CISA KEV**
  catalog or with **EPSS >= 0.5**, regardless of CVSS, and these are **not**
  waiver-eligible — they escalate to Security. Enrichment is fetched at runtime and
  the gate is **fail-closed** if KEV/EPSS data is unreachable.
- **C — waiver discipline.** No-fix waivers require recorded approver (`signed_by`)
  and justification (`reason`); max remaining TTL **30 days High / 14 days Critical**;
  default-deny on missing/expired/over-TTL; `runtime_capable` deps require an explicit
  `escalation_ack` from Security. The waiver file is **CODEOWNERS-gated to Security**
  (`.github/CODEOWNERS`), so it cannot merge without Security review.

**Required status check:** the gate is wired as a **merge-blocking** required status
check (`baileys-sidecar-ci / baileys-sidecar-gate`) in `ops/branch-protection.json`
with `enforce_admins: true` — informational mode is not used. Applying it is the one
repo-admin step (see *Escalation*).

## What each task does

**1. CI enablement + merge-blocking.** `baileys-sidecar-ci.yml` runs on every PR
touching `router/baileys-sidecar/**`. Its job `baileys-sidecar-gate` is the exact
status-check context registered in `ops/branch-protection.json`. Running
`ops/apply-branch-protection.sh` (with a repo-admin token) makes that check
**required**, so a failing gate blocks merge. `enforce_admins: true` means even
admins can't bypass it.

**2. Reproducible + hardened build.** Both the release workflow and the
Dockerfile snippet replace `npm install` with `npm ci --omit=dev --ignore-scripts`:
`npm ci` fails on any `package-lock.json` drift; `--omit=dev` ships only the
production tree; `--ignore-scripts` blocks transitive install scripts from running
(critical — the Baileys tree shares a process with the master key). `build-vendored.sh`
packages the exact pinned `node_modules` produced from the locked tree into a
deterministic tarball + sha256 — the payload ships with deps vendored, no install
on the target.

**3. SBOM per release.** The release workflow generates a CycloneDX JSON SBOM with
`@cyclonedx/cyclonedx-npm` (pinned), publishes it as a release asset, carries a copy
inside the payload, and uploads it as a workflow artifact. Also uploaded here as the
FUL-23 work product.

**4. Release-gate SCA.** Both `npm audit --audit-level=high` and OSV-Scanner run in
the **release** gate (not just PR CI). The OSV gate (`osv-gate.mjs`) enforces the
documented thresholds: **fail on CVSS ≥ 7.0 with a fix available** (not waivable —
take the fix); a **no-fix** high passes only with a non-expired, signed waiver in
`security/osv-waivers.toml`, else it fails too.

**5. Cadence.** `baileys-sidecar-scheduled.yml` runs `npm audit` + OSV-Scanner
against the committed lockfile every **Monday 06:00 UTC** and opens/refreshes a
tracking issue on failure. PR runs are scoped to `router/baileys-sidecar/**`.

## Verification performed (this build-out)

Run `node scripts/test/osv-gate.test.mjs` — **16/16 cases green** on `node v24`
(deterministic, offline via injected KEV/EPSS fixtures + pinned `OSV_GATE_TODAY`):

- CVSS gate: 9.8 with fix → fail; 7.5 no-fix/no-waiver → fail; 5.4 sub-threshold → pass.
- Waiver TTL (C): valid 18d → pass; 45d → fail (>30d); 9.8 + 18d → fail (>14d Critical);
  9.8 + 10d → pass; expired → fail; missing `reason` → fail.
- runtime_capable (C): without `escalation_ack` → fail; with it → pass.
- Exploitation gate (B): KEV-listed (even with a waiver) → fail; EPSS 0.91 → fail;
  EPSS 0.10 sub-threshold → pass.
- Fail-closed: KEV/EPSS unreachable → `exit 1`; `OSV_GATE_SKIP_ENRICHMENT=1` → loud
  warning + condition B disabled (offline dev only). ✓
- CVSS base scores computed from the CVSS:3.1 vector (vector authoritative over group
  `max_severity`).
- All 3 workflow YAMLs + composite `action.yml` parse cleanly (PyYAML). ✓
- `branch-protection.json` is valid JSON. ✓
- `build-vendored.sh` + `apply-branch-protection.sh` pass `bash -n`. ✓
- The self-test runs inside the gate action on every PR/release, so a broken policy
  script fails the gate instead of silently passing it. ✓

### Verification still requiring the live repo/CI (cannot run from this workspace)

The FUL git repo + GitHub Actions runner are not reachable from this execution
environment, so a real green/red **workflow run** screenshot and the lockfile-drift
build failure must be captured on the live repo once these files land. Procedure to
reproduce drift failure on the runner:

```bash
# in router/baileys-sidecar on a branch
echo '"_drift":"x"' # hand-edit package.json to desync from the lock, then:
npm ci            # -> exits non-zero: "npm ci can only install with an up to date lock file"
```

## Escalation (FUL-23 task 1 — the one repo-admin step)

Enabling the **required status check / branch protection** mutates repo settings
and needs **admin** permission on the FUL GitHub repo (or the org owner). I have the
config-as-code ready (`ops/branch-protection.json` + `apply-branch-protection.sh`)
but not the admin token. Per the FUL-23 instructions, this is escalated to the
**DevOps Lead** to either run `apply-branch-protection.sh` with an admin token or
provide me a scoped admin token / name the org owner who will.
