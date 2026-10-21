#!/usr/bin/env bash
# tests/release_evidence.sh -- the evidence attached to a GitHub Release (issue #52).
#
#   bash tests/release_evidence.sh VERSION IMAGE OUTDIR
#
# VERSION is 0.2.10 (no leading v). IMAGE is the published image to run the redaction
# self-test against (set IMAGE=- to skip that one, for a local run). Writes to OUTDIR:
#   release-notes.md   the "## [VERSION]" section of CHANGELOG.md (exit 1 if there is none)
#   test-counts.txt    one line per suite: its name and its own last summary line
# Exits non-zero if the changelog section is missing or any suite fails, so a release
# page is never created from a red or incomplete run. No network use except the image.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.." || exit 1
VERSION="${1:?usage: release_evidence.sh VERSION IMAGE OUTDIR}"
IMAGE="${2:?usage: release_evidence.sh VERSION IMAGE OUTDIR}"
OUT="${3:?usage: release_evidence.sh VERSION IMAGE OUTDIR}"
mkdir -p "$OUT"

# Release notes: from the "## [VERSION]" heading up to the next "## [" heading.
awk -v v="$VERSION" '
  $0 ~ "^## \\[" { if (on) exit; if (index($0, "## [" v "]") == 1) { on = 1; next } }
  on { print }
' CHANGELOG.md | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' > "$OUT/release-notes.md"
if [ ! -s "$OUT/release-notes.md" ]; then
  echo "release_evidence: CHANGELOG.md has no '## [$VERSION]' section (or it is empty)" >&2
  exit 1
fi

: > "$OUT/test-counts.txt"
fail=0
run() { # run NAME CMD... : record the suite's last non-empty line
  local name="$1" log last
  shift
  log="$(mktemp)"
  if "$@" > "$log" 2>&1; then
    last="$(grep -v '^[[:space:]]*$' "$log" | tail -n 1)"
    printf '%s: %s\n' "$name" "$last" >> "$OUT/test-counts.txt"
  else
    printf '%s: FAILED\n' "$name" >> "$OUT/test-counts.txt"
    echo "release_evidence: $name failed:" >&2
    tail -n 20 "$log" >&2
    fail=1
  fi
  rm -f "$log"
}

run "PII validators" python3 tests/validators_test.py
run "PII merge logic" python3 tests/pii_merge_test.py
run "PII/injection filters" python3 tests/filters_test.py
run "API contract (models stubbed)" python3 tests/api_contract_test.py
run "scan.sh options" bash tests/scan_options_test.sh
run "scan.sh bash compatibility" bash tests/scan_bash_compat_test.sh
run "Dockerfile and workflow pins" bash tests/dockerfile_pins_test.sh
if [ "$IMAGE" != "-" ]; then
  run "Redaction self-test against the published image" python3 tests/redaction_selftest.py --image "$IMAGE"
fi

# Trivy runs with no ignore file only if .trivyignore has no active entries.
if grep -v '^[[:space:]]*#' .trivyignore 2> /dev/null | grep -q '[^[:space:]]'; then
  echo "release_evidence: .trivyignore has active entries; the attached scan would not be unfiltered" >&2
  fail=1
fi
exit "$fail"
