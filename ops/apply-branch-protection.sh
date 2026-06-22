#!/usr/bin/env bash
# apply-branch-protection.sh — make the Baileys sidecar gate merge-blocking
# (FUL-23 task 1). Registers the CI gate as a REQUIRED status check on the
# default branch so a failing gate blocks merge.
#
# REQUIRES: a token (gh auth or $GH_TOKEN) with **admin** on the FUL repo.
# This is the one step the DevOps Engineer cannot perform without repo-admin
# rights / the org owner — see DEPLOY.md "Escalation".
#
# Usage:
#   OWNER=fullstackforge REPO=ful BRANCH=main ./apply-branch-protection.sh
set -euo pipefail

OWNER="${OWNER:?set OWNER (org/user)}"
REPO="${REPO:?set REPO}"
BRANCH="${BRANCH:-main}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "Applying branch protection to ${OWNER}/${REPO}@${BRANCH} ..."

# gh CLI (preferred — uses your gh auth session)
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/${OWNER}/${REPO}/branches/${BRANCH}/protection" \
  --input <(jq 'del(._comment)' "${HERE}/branch-protection.json")

echo "Done. Verify required checks:"
gh api "/repos/${OWNER}/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
  --jq '.contexts'

# --- Pure-curl alternative (if gh is unavailable) ---------------------------
# curl -fsSL -X PUT \
#   -H "Authorization: Bearer ${GH_TOKEN:?}" \
#   -H "Accept: application/vnd.github+json" \
#   "https://api.github.com/repos/${OWNER}/${REPO}/branches/${BRANCH}/protection" \
#   -d "$(jq 'del(._comment)' "${HERE}/branch-protection.json")"
