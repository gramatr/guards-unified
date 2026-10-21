#!/usr/bin/env bash
# tests/gitleaks_assets_test.sh -- the `check` mode of gitleaks_assets.sh refuses what it must.
# (`build` needs docker and network and runs in CI as the gitleaks-assets job.) The expected
# file is a fixture here, so nothing real is compared. Needs: bash.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/gitleaks_assets.sh"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
VER="$(sed -n 's/^ARG GITLEAKS_VERSION=v//p' "$HERE/../Dockerfile.cpu" | head -n 1)"
H1="$(printf '1%.0s' $(seq 1 64))"; H2="$(printf '2%.0s' $(seq 1 64))"
mkdir -p "$W/out"
printf '%s  linux_x64\n%s  darwin_arm64\n' "$H1" "$H2" > "$W/out/gitleaks-patched_${VER}_binary-sha256.txt"
printf '# comment\n\n%s  darwin_arm64\n%s  linux_x64\n' "$H2" "$H1" > "$W/expected"

run() { EXPECTED="$1" bash "$SCRIPT" check "$W/out" > "$W/log" 2>&1; }
if run "$W/expected"; then ok; else bad "equal hashes (order and comments aside) pass ($(cat "$W/log"))"; fi
printf '%s  linux_x64\n%s  darwin_arm64\n' "$H1" "$H1" > "$W/expected2"
if run "$W/expected2"; then bad "a differing hash must fail"; else ok; fi
grep -q 'differ' "$W/log" && ok || bad "the mismatch is reported"
printf '%s  linux_x64\n' "$H1" > "$W/expected3"
if run "$W/expected3"; then bad "a missing target in the expected file must fail"; else ok; fi
rm "$W/out/gitleaks-patched_${VER}_binary-sha256.txt"
if run "$W/expected"; then bad "check without a build must fail"; else ok; fi
if bash "$SCRIPT" bogus "$W/out" > "$W/log" 2>&1; then bad "an unknown mode must fail"; else ok; fi
# The committed expected file lists the four targets, each a 64-hex hash.
n="$(grep -v '^[[:space:]]*#' "$HERE/../docs/gitleaks-assets.sha256" | grep -c -E '^[0-9a-f]{64}  (linux|darwin)_(x64|arm64)$')"
[ "$n" -eq 4 ] && ok || bad "docs/gitleaks-assets.sha256 has the four targets ($n lines match)"
echo "gitleaks-assets: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
