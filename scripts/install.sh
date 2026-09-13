#!/usr/bin/env bash
# Builds or verifies a bouncer artifact, preserves one installed generation,
# atomically installs it, optionally tags its build, and runs doctor.

set -euo pipefail

CALLER_DIR="$PWD"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DESTINATION=""
FROM_DIR=""
ALLOW_DIRTY=false
CREATE_TAG=false

log() {
  printf '%s\n' "$*" >&2
}

usage() {
  cat >&2 <<'EOF'
Usage: scripts/install.sh [--dest <path>] [--from <dir>] [--allow-dirty] [--tag]

Build and install bouncer, or install a verified artifact from --from.

Options:
  --dest <path>    Installation destination (default: $HOME/.local/bin/bouncer)
  --from <dir>     Directory containing bouncer and bouncer.sha256
  --allow-dirty    Permit an artifact built from a dirty tree
  --tag            Create the local v<version> tag after installation
  -h, --help       Show this help
EOF
}

fail() {
  log "bouncer install: $*"
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dest)
      if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ "$2" = --* ]]; then
        usage
        exit 2
      fi
      DESTINATION="$2"
      shift 2
      ;;
    --from)
      if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ "$2" = --* ]]; then
        usage
        exit 2
      fi
      FROM_DIR="$2"
      shift 2
      ;;
    --allow-dirty)
      ALLOW_DIRTY=true
      shift
      ;;
    --tag)
      CREATE_TAG=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [ -z "$DESTINATION" ]; then DESTINATION="${HOME:-}/.local/bin/bouncer"; fi

case "$DESTINATION" in
  /.local/*) fail "HOME is unset; pass --dest <path>" ;;
  /*) ;;
  *) DESTINATION="$CALLER_DIR/$DESTINATION" ;;
esac
case "$FROM_DIR" in
  ""|/*) ;;
  *) FROM_DIR="$CALLER_DIR/$FROM_DIR" ;;
esac

cd "$ROOT"

if [ "$CREATE_TAG" = true ] && [ -n "$(git status --porcelain)" ]; then
  fail "--tag requires a clean git tree"
fi

if [ -z "$FROM_DIR" ]; then
  log "bouncer install: building artifact"
  bun run build >&2
  ARTIFACT_DIR="$ROOT/dist"
else
  ARTIFACT_DIR="$FROM_DIR"
fi

ARTIFACT="$ARTIFACT_DIR/bouncer"
MANIFEST="$ARTIFACT_DIR/bouncer.sha256"
if [ ! -f "$ARTIFACT" ] || [ ! -f "$MANIFEST" ]; then
  fail "artifact directory must contain bouncer and bouncer.sha256: $ARTIFACT_DIR"
fi

if ! EXPECTED="$(awk 'NR == 1 { print $1 }' "$MANIFEST")"; then
  fail "artifact checksum verification failed"
fi
if ! ACTUAL="$(shasum -a 256 "$ARTIFACT" | awk '{ print $1 }')"; then
  fail "artifact checksum verification failed"
fi
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
  fail "artifact checksum verification failed"
fi

if ! ARTIFACT_JSON="$("$ARTIFACT" --version --json)"; then
  fail "artifact does not support --version --json"
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
  fail "artifact returned invalid version metadata"
fi
IFS=$'\t' read -r ARTIFACT_VERSION ARTIFACT_SHA ARTIFACT_DIRTY <<< "$ARTIFACT_FIELDS"

if [ "$ARTIFACT_DIRTY" = true ] && [ "$ALLOW_DIRTY" = false ]; then
  fail "artifact was built from a dirty tree; pass --allow-dirty to install it"
fi

if [ "$CREATE_TAG" = true ]; then
  if git rev-parse -q --verify "refs/tags/v$ARTIFACT_VERSION" >/dev/null; then
    fail "tag v$ARTIFACT_VERSION already exists"
  fi
  HEAD_SHA="$(git rev-parse --short HEAD)"
  if [ "$ARTIFACT_SHA" != "$HEAD_SHA" ]; then
    fail "artifact sha $ARTIFACT_SHA does not match HEAD $HEAD_SHA"
  fi
fi

mkdir -p "$(dirname "$DESTINATION")"
if [ -e "$DESTINATION" ]; then
  BACKUP_IDENTITY=unknown
  if INSTALLED_JSON="$("$DESTINATION" --version --json 2>/dev/null)"; then
    if INSTALLED_FIELDS="$(
      printf '%s' "$INSTALLED_JSON" | bun -e '
const info = JSON.parse(await Bun.stdin.text());
if (typeof info?.build?.sha !== "string" || typeof info.build.dirty !== "boolean") process.exit(1);
console.log(`${info.build.sha}\t${info.build.dirty}`);
' 2>/dev/null
)"; then
      IFS=$'\t' read -r INSTALLED_SHA INSTALLED_DIRTY <<< "$INSTALLED_FIELDS"
      BACKUP_IDENTITY="$INSTALLED_SHA"
      if [ "$INSTALLED_DIRTY" = true ]; then BACKUP_IDENTITY="${BACKUP_IDENTITY}-dirty"; fi
    fi
  fi

  BACKUP_PATH="${DESTINATION}.${BACKUP_IDENTITY}.bak"
  cp -p "$DESTINATION" "$BACKUP_PATH"
  for backup in "${DESTINATION}".*.bak; do
    [ -e "$backup" ] || continue
    if [ "$backup" != "$BACKUP_PATH" ]; then rm -f "$backup"; fi
  done
else
  log "bouncer install: fresh install"
fi

install -m 0755 "$ARTIFACT" "${DESTINATION}.new"
mv -f "${DESTINATION}.new" "$DESTINATION"

if [ "$CREATE_TAG" = true ]; then
  git tag -a "v$ARTIFACT_VERSION" -m "bouncer $ARTIFACT_VERSION"
fi

"$DESTINATION" doctor
