#!/usr/bin/env bash
# Builds a release artifact, validates its provenance, and creates its local tag.
# BOUNCER_ARTIFACT_DIR is reserved for tests; normal runs always build dist/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/tag-release.sh

Build, validate, and tag the current bouncer release.

Options:
  -h, --help  Show this help
EOF
}

fail() {
  printf 'bouncer tag-release: %s\n' "$*" >&2
  exit 1
}

case "$#" in
  0) ;;
  1)
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage
        exit 2
        ;;
    esac
    ;;
  *)
    usage
    exit 2
    ;;
esac

cd "$ROOT"

if [ -n "${BOUNCER_ARTIFACT_DIR:-}" ]; then
  ARTIFACT_DIR="$BOUNCER_ARTIFACT_DIR"
else
  bun run build
  ARTIFACT_DIR="$ROOT/dist"
fi

ARTIFACT="$ARTIFACT_DIR/bouncer"
MANIFEST="$ARTIFACT_DIR/bouncer.sha256"
if [ ! -f "$ARTIFACT" ] || [ ! -f "$MANIFEST" ]; then
  fail "artifact directory must contain bouncer and bouncer.sha256: $ARTIFACT_DIR"
fi

if ! shasum -a 256 -c "$MANIFEST" >/dev/null; then
  fail 'artifact checksum verification failed'
fi

if ! ARTIFACT_JSON="$("$ARTIFACT" --version --json)"; then
  fail 'artifact does not support --version --json'
fi
if ! ARTIFACT_FIELDS="$(
  printf '%s' "$ARTIFACT_JSON" | bun -e '
const info = JSON.parse(await Bun.stdin.text());
if (typeof info?.version !== "string" || typeof info?.build?.sha !== "string" || typeof info.build.dirty !== "boolean") {
  process.exit(1);
}
console.log(`${info.version}\t${info.build.sha}\t${info.build.dirty}`);
' 2>/dev/null
)"; then
  fail 'artifact returned invalid version metadata'
fi
IFS=$'\t' read -r ARTIFACT_VERSION ARTIFACT_SHA ARTIFACT_DIRTY <<< "$ARTIFACT_FIELDS"

if [ "$ARTIFACT_DIRTY" = true ]; then
  fail 'a release tag never comes from a dirty tree'
fi

HEAD_SHA="$(git rev-parse --short HEAD)"
if [ "$ARTIFACT_SHA" != "$HEAD_SHA" ]; then
  fail "artifact sha $ARTIFACT_SHA does not match HEAD $HEAD_SHA"
fi

if git rev-parse -q --verify "refs/tags/v$ARTIFACT_VERSION" >/dev/null; then
  fail "tag v$ARTIFACT_VERSION already exists"
fi

git tag -a "v$ARTIFACT_VERSION" -m "bouncer $ARTIFACT_VERSION"
printf 'v%s\n' "$ARTIFACT_VERSION"
"$ARTIFACT" --version
