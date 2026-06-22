#!/usr/bin/env bash
# build-vendored.sh — produce the shipped Baileys sidecar payload with a
# vendored, pinned node_modules built from the locked tree (FUL-20 / FUL-23, task 2).
#
# Pre-req: `npm ci --omit=dev --ignore-scripts` has already run in this dir, so
# node_modules reflects the EXACT locked production tree. This script does not
# re-install; it packages what was deterministically produced.
#
# Output (in dist/):
#   baileys-sidecar-<version>.tar.gz   - app + vendored node_modules + SBOM
#   baileys-sidecar-<version>.sha256   - checksum for integrity verification
set -euo pipefail

VERSION="${1:-$(node -p "require('./package.json').version")}"
DIST="dist"
PAYLOAD="baileys-sidecar-${VERSION}"

cd "$(dirname "$0")/.."   # -> router/baileys-sidecar

if [[ ! -d node_modules ]]; then
  echo "build-vendored: node_modules missing — run 'npm ci --omit=dev --ignore-scripts' first" >&2
  exit 1
fi

# Hard fail if a dev-only dep leaked into the production tree.
if npm ls --omit=dev --all >/dev/null 2>&1; then
  echo "build-vendored: production dependency tree verified against lockfile"
else
  echo "build-vendored: dependency tree does not match lockfile (drift) — aborting" >&2
  exit 1
fi

mkdir -p "$DIST"

# Stage exactly what ships: runtime code + the pinned node_modules + SBOM + lock.
STAGE="$(mktemp -d)/${PAYLOAD}"
mkdir -p "$STAGE"
# Adjust the source list to the sidecar's real layout; these are the standard
# runtime artifacts. node_modules is the vendored, pinned production tree.
cp -r node_modules "$STAGE/"
cp package.json package-lock.json "$STAGE/"
[[ -d src ]] && cp -r src "$STAGE/"
[[ -d dist/build ]] && cp -r dist/build "$STAGE/"
[[ -f index.js ]] && cp index.js "$STAGE/"
# Carry the SBOM inside the payload too, for offline provenance.
[[ -f "$DIST/baileys-sidecar.cdx.json" ]] && cp "$DIST/baileys-sidecar.cdx.json" "$STAGE/"

# Deterministic tarball (sorted, fixed mtime/owner) so identical inputs -> identical bytes.
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$(dirname "$STAGE")" -czf "$DIST/${PAYLOAD}.tar.gz" "${PAYLOAD}"

( cd "$DIST" && sha256sum "${PAYLOAD}.tar.gz" > "${PAYLOAD}.sha256" )

echo "build-vendored: wrote $DIST/${PAYLOAD}.tar.gz"
cat "$DIST/${PAYLOAD}.sha256"
rm -rf "$(dirname "$STAGE")"
