# Provisioning the dedicated merge-reviewer (FUL-37)

Restores `required_approving_review_count: 1` (defense-in-depth: every merge gets a
second-party review) **without** re-creating the FUL-34 deadlock, by giving the org a
second approving principal that is distinct from the PR author `darshjme`.

## Why a GitHub App (not a workflow with the built-in token)

GitHub **does not count** reviews submitted with the default `GITHUB_TOKEN`
(`github-actions[bot]`) toward `required_approving_review_count`. It **does count**
reviews submitted with a **GitHub App installation token** — the App
(`<app-slug>[bot]`) is a distinct principal. So the second approver must be a GitHub
App (or a separate machine user). We use a GitHub App: no extra seat, scoped
permissions, private key stored as a repo secret.

## What is already in place (landed by this change)

- `.github/workflows/auto-approve-reviewer.yml` — the reviewer workflow. It runs after
  the `baileys-sidecar-ci` gate completes, and **only** approves when:
  - the gate concluded `success`,
  - the PR is open, not a draft, authored by an allow-listed author (`darshjme`),
  - the PR touches **no** CODEOWNERS-protected path (separation of duties — sensitive
    PRs keep their human Security review),
  - it has not already been approved by this automation (idempotent).
  Until the two secrets below exist, the approve job is simply skipped (inert).
- `ops/reviewer-app-manifest.json` — minimal-scope App manifest.

> Note: this PR deliberately does **not** touch `ops/branch-protection.json`. The live
> file is reconciled to the [FUL-36] posture (`count: 0`, context `baileys-sidecar-gate`).
> Flipping to `count: 1` is the **last** step (step 5), done only after the App's approval
> is proven on a real PR — never before, or the FUL-34 deadlock returns.

## Step 1 — Create the GitHub App (one-time, account-owner action)

> This is the only step no agent/CI token can perform: creating an App on the
> `darshjme` account requires that account's interactive GitHub session. The
> `repo`/`workflow` OAuth token used by automation cannot create Apps.

Two ways — pick one:

**A. Manifest flow (fast, pre-fills minimal scopes).** Open a browser as `darshjme` and
POST `ops/reviewer-app-manifest.json` to `https://github.com/settings/apps/new`. The
simplest is a tiny local form:

```html
<!-- save as new-app.html, open in the browser, click the button -->
<form action="https://github.com/settings/apps/new" method="post">
  <input type="hidden" name="manifest" id="m"><button>Create ffr-merge-reviewer</button>
</form>
<script>
  fetch('reviewer-app-manifest.json').then(r=>r.json()).then(j=>{
    delete j._comment; document.getElementById('m').value = JSON.stringify(j);
  });
</script>
```

Click **Create GitHub App**, confirm, done — GitHub creates the App with exactly the
manifest's permissions (`pull_requests: write`, `contents: read`, `metadata: read`,
`checks: read`), no webhook.

**B. Manual.** Settings → Developer settings → GitHub Apps → New GitHub App. Set the
same four permissions, no webhook, "Only on this account".

## Step 2 — Generate a private key

On the new App's page → **Generate a private key**. A `.pem` downloads. Note the
**App ID** (shown at the top of the App page).

## Step 3 — Install the App on the one repo

App page → **Install App** → select `darshjme` → **Only select repositories** →
`fullstackforge-baileys-sidecar` → Install.

## Step 4 — Add the two repo secrets

Agent-doable once the App ID + `.pem` exist (run by anyone with admin + the files):

```bash
export MSYS_NO_PATHCONV=1
REPO=darshjme/fullstackforge-baileys-sidecar
gh secret set REVIEWER_APP_ID          --repo "$REPO" --body "<APP_ID>"
gh secret set REVIEWER_APP_PRIVATE_KEY --repo "$REPO" < path/to/ffr-merge-reviewer.private-key.pem
```

## Step 5 — Restore count=1 and verify (agent-doable, in this order)

1. **Land** this PR (the reviewer workflow + manifest + runbook). At the live `count: 0`
   posture `require_code_owner_reviews` is inert, so a green `baileys-sidecar-gate` is
   sufficient to merge (the gate reports on every PR since FUL-39).
2. **Prove the loop FIRST** (before flipping count): open a trivial routine PR
   (e.g. a README touch) authored by `darshjme`. Expect: gate runs green →
   `merge-reviewer` posts an approving review as `ffr-merge-reviewer[bot]`. Confirm the
   bot review actually appears before changing branch protection.
3. **Edit `count` 0→1 and apply** — only after step 2 is proven:
   ```bash
   export MSYS_NO_PATHCONV=1
   # set required_approving_review_count to 1 in ops/branch-protection.json, then:
   OWNER=darshjme REPO=fullstackforge-baileys-sidecar BRANCH=main \
     ops/apply-branch-protection.sh
   ```
   (Equivalently `gh api --method PUT repos/darshjme/fullstackforge-baileys-sidecar/branches/main/protection --input <(jq 'del(._comment)' ops/branch-protection.json)`.)
4. **Verify** live state:
   ```bash
   gh api repos/darshjme/fullstackforge-baileys-sidecar/branches/main/protection/required_pull_request_reviews --jq .required_approving_review_count   # -> 1
   gh api repos/darshjme/fullstackforge-baileys-sidecar/branches/main/protection/required_status_checks --jq .contexts                               # -> ["baileys-sidecar-gate"]
   ```
   With `count: 1` live, the routine test PR from step 2 must now report **mergeable only
   after** the bot's approving review. Also open a PR touching a CODEOWNERS path
   (e.g. `ops/`) and confirm the bot does **not** approve it and it stays blocked pending
   a human Security review.

## Rollback

`required_approving_review_count: 0` (the FUL-35 interim posture) is the safe fallback if
the App is ever uninstalled — set it via the apply script with a `0` value to avoid an
unmergeable `main`.
