# fullstackforge-baileys-sidecar

Supply-chain release gate for the **Baileys sidecar** — the dependency tree that runs
in the same process as the master key and every account's decrypted Signal keys, where a
single malicious transitive dependency can exfiltrate the whole store.

This repository hosts the **config-as-code gate** delivered by FUL-23 (child of FUL-20),
with Security sign-off folded in from FUL-24. It was created to activate **FUL-30**:
making the gate a required, merge-blocking status check on a real repository.

## What's here

| Path | Purpose |
|---|---|
| `.github/workflows/baileys-sidecar-ci.yml` | PR gate — job `baileys-sidecar-gate` (the required status-check context) |
| `.github/workflows/baileys-sidecar-release.yml` | Release gate — SCA + SBOM + hardened build |
| `.github/workflows/baileys-sidecar-scheduled.yml` | Weekly (Mon 06:00 UTC) lockfile scan |
| `.github/actions/osv-gate/` | Reusable OSV-Scanner + policy composite action |
| `router/baileys-sidecar/scripts/osv-gate.mjs` | Zero-dependency CVSS / KEV / EPSS + waiver policy enforcer |
| `router/baileys-sidecar/scripts/test/osv-gate.test.mjs` | Self-test (16/16) — runs inside the gate so a broken policy can't silently pass |
| `router/baileys-sidecar/security/osv-waivers.toml` | Security-signed waiver register (CODEOWNERS-gated) |
| `ops/branch-protection.json` + `ops/apply-branch-protection.sh` | Branch-protection config-as-code |
| `DEPLOY.md` | Full deployment + verification evidence |

## Scope note

The actual Baileys sidecar **application source** lands under
`router/baileys-sidecar/` alongside the gate. The current `package.json` is a
zero-dependency manifest that carries the gate and its self-test, so the
merge-blocking check is **green and meaningful from day one** and immediately
enforces the supply-chain policy the moment real dependencies are added to the
lockfile.

## Branch protection

`main` is protected per `ops/branch-protection.json`: required status check
`baileys-sidecar-ci / baileys-sidecar-gate` (`strict`), `enforce_admins: true`,
and `require_code_owner_reviews: true` (the waiver register is CODEOWNERS-gated).
Changes reach `main` via PR; a failing gate blocks merge.

<!-- FUL-37 reviewer verification #2 (count=1 live): confirm bot approval satisfies the required review. -->
