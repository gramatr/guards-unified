#!/usr/bin/env bash
# tests/run-all.sh — run every test the way CI will, before pushing.
#
# The recurring mistake this exists to stop: a test passes on a developer
# machine that has gitleaks installed and fails in CI, which does not (or the
# reverse). So the shell tests run TWICE here: once with gitleaks hidden from
# PATH (what the CI lint job sees) and once with it. The self-test needs
# gitleaks for some shapes, so it runs only in the second mode (CI runs it
# against the built image).
#
#   bash tests/run-all.sh        # exit non-zero on any failure

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.." || exit 1

SHADOW="$(mktemp -d)"
trap 'rm -rf "$SHADOW"' EXIT
for d in /usr/local/bin /usr/bin; do
  for f in "$d"/*; do
    n="$(basename "$f")"
    [ "$n" = gitleaks ] && continue
    [ -e "$SHADOW/$n" ] || ln -s "$f" "$SHADOW/$n" 2>/dev/null
  done
done

fail=0
step() { # step LABEL CMD...
  local label="$1"; shift
  if "$@" >/tmp/run-all.$$.out 2>&1; then
    printf '  ok    %s  (%s)\n' "$label" "$(tail -1 /tmp/run-all.$$.out)"
  else
    printf '  FAIL  %s\n' "$label"; sed 's/^/        /' /tmp/run-all.$$.out | tail -15; fail=1
  fi
  rm -f /tmp/run-all.$$.out
}

echo "lint"
command -v ruff >/dev/null 2>&1 && step "ruff app/ tests/" ruff check app/ tests/
command -v shellcheck >/dev/null 2>&1 && step "shellcheck scripts" shellcheck -S warning app/scan.sh tests/*.sh

echo "API contract (models stubbed; needs fastapi + httpx)"
if python3 -c "import fastapi, httpx" >/dev/null 2>&1; then
  step "api_contract_test" python3 tests/api_contract_test.py
else
  echo "fastapi/httpx not installed here: skipping api_contract_test (CI runs it)"
fi

echo "build inputs"
step "dockerfile_pins_test" bash tests/dockerfile_pins_test.sh

echo "without gitleaks (as the CI lint job sees it)"
step "scan_options_test" env "PATH=$SHADOW" bash tests/scan_options_test.sh

if command -v gitleaks >/dev/null 2>&1; then
  echo "with gitleaks"
  step "scan_options_test" bash tests/scan_options_test.sh
  step "redaction_selftest --scan-sh" python3 -I tests/redaction_selftest.py --scan-sh
else
  echo "gitleaks not installed here: skipping the with-gitleaks suite (CI covers it against the built image)"
fi

[ "$fail" -eq 0 ] && echo "ALL OK" || echo "FAILURES"
exit "$fail"
