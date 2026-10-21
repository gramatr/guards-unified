#!/usr/bin/env bash
# tests/release_evidence_test.sh -- release_evidence.sh refuses what it must refuse.
#
# The release page is built from this script's output, so it has to fail (and so stop
# the release job) when the changelog has no section for the version, when a suite
# fails, or when .trivyignore would filter the attached scan; and it must write the
# notes and the counts when everything is fine. Runs against a throwaway copy of the
# repository's tests and changelog, so no real suite is made to fail.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/release_evidence.sh"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/repo/tests"
cp "$SCRIPT" "$W/repo/tests/"
# Stub suites: each prints a summary line and exits 0 (a later case makes one fail).
for t in validators_test pii_merge_test filters_test api_contract_test; do
  printf 'print("%s: ok")\n' "$t" > "$W/repo/tests/$t.py"
done
for t in scan_options_test scan_bash_compat_test dockerfile_pins_test; do
  printf '#!/usr/bin/env bash\necho "%s: ok"\n' "$t" > "$W/repo/tests/$t.sh"
done
printf '# Changelog\n\n## [1.2.3] - 2026-01-01\n\n### guards-unified\n\n- Fixed: something.\n\n## [1.2.2] - 2025-12-01\n\n- Older.\n' > "$W/repo/CHANGELOG.md"
printf '# comment only\n' > "$W/repo/.trivyignore"

run() { (cd "$W/repo" && bash tests/release_evidence.sh "$1" - "$W/out" > "$W/log" 2>&1); }

if run 1.2.3; then ok; else bad "a version with a changelog section succeeds ($(cat "$W/log"))"; fi
grep -q 'Fixed: something' "$W/out/release-notes.md" && ok || bad "the notes hold the section's text"
grep -q 'Older' "$W/out/release-notes.md" && bad "the notes stop at the next version heading" || ok
[ "$(wc -l < "$W/out/test-counts.txt")" -eq 7 ] && ok || bad "one counts line per suite (7), got $(wc -l < "$W/out/test-counts.txt")"
grep -q 'PII validators: validators_test: ok' "$W/out/test-counts.txt" && ok || bad "a counts line carries the suite's own summary"

if run 9.9.9; then bad "a version with no changelog section must fail"; else ok; fi
grep -q "no '## \[9.9.9\]' section" "$W/log" && ok || bad "the missing section is named on stderr"

printf '#!/usr/bin/env bash\necho broken\nexit 1\n' > "$W/repo/tests/scan_options_test.sh"
if run 1.2.3; then bad "a failing suite must fail the script"; else ok; fi
grep -q 'scan.sh options: FAILED' "$W/out/test-counts.txt" && ok || bad "the failing suite is marked FAILED in the counts"
printf '#!/usr/bin/env bash\necho "scan_options_test: ok"\n' > "$W/repo/tests/scan_options_test.sh"

printf 'CVE-2026-0001\n' > "$W/repo/.trivyignore"
if run 1.2.3; then bad "an active .trivyignore entry must fail the script"; else ok; fi
grep -q 'trivyignore has active entries' "$W/log" && ok || bad "the ignore-file entry is named on stderr"

echo "release-evidence: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
