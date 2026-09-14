#!/usr/bin/env bash
# Prints the CHANGELOG.md section of one version — the body of the GitHub
# Release the release workflow creates for that tag. Exits 1 when the version
# has no section, so a release is never published with an empty body.

set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  printf 'usage: scripts/changelog-section.sh <version>\n' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$1"

SECTION="$(awk -v version="$VERSION" '
  index($0, "## [" version "]") == 1 { inside = 1; next }
  inside && /^## \[/ { exit }
  inside { print }
' "$ROOT/CHANGELOG.md")"

if [ -z "$(printf '%s' "$SECTION" | tr -d '[:space:]')" ]; then
  printf 'changelog-section: no section for version %s in CHANGELOG.md\n' "$VERSION" >&2
  exit 1
fi

printf '%s\n' "$SECTION" | awk 'NF { started = 1 } started' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
