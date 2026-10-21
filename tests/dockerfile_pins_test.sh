#!/usr/bin/env bash
# tests/dockerfile_pins_test.sh -- build inputs must be pinned.
#
# Every external image a Dockerfile pulls (FROM, COPY --from) must carry an
# explicit tag that is not "latest" AND a sha256 digest. A floating tag lets a
# rebuild change the build tooling with no commit here; the digest is what makes
# the tag immutable. A `git clone --branch/--tag` is refused too: a git tag can be
# moved, so sources are fetched by commit. Stage names (FROM ... AS x,
# COPY --from=x) are not external images and are skipped. Every GitHub Actions
# `uses:` reference in .github must be a full commit SHA. Run with DOCKERFILES to
# point at other files (the self-checks below do).
#
#   bash tests/dockerfile_pins_test.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.." || exit 1

# check_file FILE -> prints one line per offending reference
check_file() {
  local f="$1" ref
  { grep -E '^[[:space:]]*FROM[[:space:]]' "$f" | sed -E 's/^[[:space:]]*FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+).*/\2/'
    grep -oE -e '--from=[^[:space:]]+' "$f" | sed 's/^--from=//'
  } | while IFS= read -r ref; do
    case "$ref" in
      *[/:]*) ;;        # an image reference (registry path or tag): checked below
      *) continue ;;    # a stage name
    esac
    base="${ref%%@*}"
    case "$base" in
      *:latest) echo "$f: floating tag: $ref"; continue ;;
      */*:*|*:*) ;;
      *) echo "$f: no tag: $ref"; continue ;;
    esac
    case "$ref" in
      *@sha256:*) ;;
      *) echo "$f: no digest: $ref" ;;
    esac
  done
  grep -nE 'git[[:space:]]+clone[^|;&]*--(branch|tag)' "$f" | sed "s|^|$f: git clone by branch or tag (use a commit): |"
}

# check_actions DIR -> prints one line per `uses:` reference that is not a full commit SHA
# (local actions, ./path, are fine)
check_actions() {
  grep -rnE '^[[:space:]-]*uses:[[:space:]]*[^[:space:]]+' "$1" --include='*.yml' --include='*.yaml' 2>/dev/null \
    | grep -vE 'uses:[[:space:]]*\./' \
    | grep -vE 'uses:[[:space:]]*[^[:space:]@]+@[0-9a-f]{40}([[:space:]]|$)' \
    | sed 's|^|floating action reference: |'
}

fail=0
for f in ${DOCKERFILES:-Dockerfile Dockerfile.cpu}; do
  out="$(check_file "$f")"
  if [ -n "$out" ]; then printf '%s\n' "$out"; fail=1; fi
done

out="$(check_actions .github)"
if [ -n "$out" ]; then printf '%s\n' "$out"; fail=1; fi

# Self-check: the checker must flag a tag without a digest, a floating tag, a missing tag,
# and a clone by tag, and must accept a tag with a digest and a stage name.
tmp="$(mktemp)"; tdir="$(mktemp -d)"
trap 'rm -rf "$tmp" "$tdir"' EXIT
D="sha256:$(printf '0%.0s' $(seq 1 64))"
printf 'FROM python:3.12-slim\nFROM python:3.12-slim@%s\nCOPY --from=ghcr.io/example/tool:latest /a /b\nCOPY --from=ghcr.io/example/other /c /d\nCOPY --from=builder /e /f\nRUN git clone --depth 1 --branch v1 https://example.invalid/x.git /src\n' "$D" > "$tmp"
n="$(check_file "$tmp" | wc -l)"
if [ "$n" -ne 4 ]; then echo "FAIL: self-check expected 4 findings, got $n"; check_file "$tmp"; fail=1; fi
printf 'jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@%s # v4\n      - uses: ./.github/actions/x\n' "$(printf 'a%.0s' $(seq 1 40))" > "$tdir/w.yml"
n="$(check_actions "$tdir" | wc -l)"
if [ "$n" -ne 1 ]; then echo "FAIL: actions self-check expected 1 finding, got $n"; check_actions "$tdir"; fail=1; fi

[ "$fail" -eq 0 ] && echo "dockerfile pins: ok" || echo "dockerfile pins: FAILED"
exit "$fail"
