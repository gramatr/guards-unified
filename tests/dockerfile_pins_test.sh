#!/usr/bin/env bash
# tests/dockerfile_pins_test.sh -- build inputs must be pinned.
#
# Every external image a Dockerfile pulls (FROM, COPY --from) must carry an
# explicit tag that is not "latest". A floating tag lets a rebuild change the
# build tooling with no commit here. Stage names (FROM ... AS x, COPY --from=x)
# are not external images and are skipped. Run with DOCKERFILES to point at
# other files (the tests below do).
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
      *:latest) echo "$f: floating tag: $ref" ;;
      */*:*|*:*) ;;
      *) echo "$f: no tag: $ref" ;;
    esac
  done
}

fail=0
for f in ${DOCKERFILES:-Dockerfile Dockerfile.cpu}; do
  out="$(check_file "$f")"
  if [ -n "$out" ]; then printf '%s\n' "$out"; fail=1; fi
done

# Self-check: the checker must flag a floating tag and a missing tag.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
printf 'FROM python:3.12-slim\nCOPY --from=ghcr.io/example/tool:latest /a /b\nCOPY --from=ghcr.io/example/other /c /d\nCOPY --from=builder /e /f\n' > "$tmp"
n="$(check_file "$tmp" | wc -l)"
if [ "$n" -ne 2 ]; then echo "FAIL: self-check expected 2 findings, got $n"; fail=1; fi

[ "$fail" -eq 0 ] && echo "dockerfile pins: ok" || echo "dockerfile pins: FAILED"
exit "$fail"
