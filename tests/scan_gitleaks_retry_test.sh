#!/usr/bin/env bash
# tests/scan_gitleaks_retry_test.sh -- scan.sh does not read "gitleaks scanned nothing" as clean.
#
# gitleaks (8.30.1 seen) scans ZERO bytes of a file whose NAME looks like an archive
# (tmp.7zAbC..., tmp.xz..., tmp.br..., tmp.gz..., tmp.zip..., tmp.tar...), prints "no leaks
# found", writes an empty report and exits 0. scan.sh named its input with a random mktemp
# suffix, so about 1 scan in 125 got such a name and a vendor token was silently left in
# the text; and it retried only on a non-zero exit. Now the input has a fixed plain name
# in a private directory, and a scan that read nothing is retried and, failing that, said
# out loud. A stub gitleaks on PATH records the name it is asked to scan and scans 0
# bytes a chosen number of times, then reports a finding, so the behaviour is deterministic:
#   - the input is named input.txt (never a random mktemp name);
#   - 0 zero-byte scans: redacted on the first call (baseline);
#   - 2 zero-byte scans: redacted after two retries (3 calls);
#   - always zero bytes: gives up after 3 calls, says so on stderr (a documented
#     fail-open with notice, like "gitleaks failed twice" before it);
#   - an empty input is not retried.
# Set SCAN to run the same checks against another scan.sh (the negative control).
# The key is fabricated. Needs bash, jq.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="${SCAN:-$HERE/../app/scan.sh}"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"
TOK="AKIA""ABCDEFGHIJKLMNOP"

cat > "$BIN/gitleaks" << 'EOF'
#!/bin/sh
# A stand-in for `gitleaks detect --no-git -s FILE --report-format json --report-path R --exit-code 0`.
n=$(( $(cat "$STUB_COUNT" 2> /dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_COUNT"
rp=""
while [ $# -gt 0 ]; do
  case "$1" in --report-path) rp="$2"; shift ;; -s) echo "$2" > "$STUB_SRC"; shift ;; esac
  shift
done
if [ "$n" -le "$STUB_ZERO_TIMES" ]; then
  echo "INF scanned ~0 bytes (0) in 1ms" >&2
  echo "INF no leaks found" >&2
  echo "[]" > "$rp"
  exit 0
fi
printf '[{"RuleID":"aws-access-token","StartLine":1,"Fingerprint":"stub","Secret":"%s"}]' "$STUB_TOKEN" > "$rp"
echo "INF scanned ~30 bytes (30) in 1ms" >&2
exit 0
EOF
chmod +x "$BIN/gitleaks"

# run ZERO_TIMES INPUT -> stdout of scan.sh in $T/out, stderr in $T/err, call count in $T/count
run() {
  : > "$T/count"
  printf '%s' "$2" | env PATH="$BIN:$PATH" STUB_COUNT="$T/count" STUB_SRC="$T/src" STUB_ZERO_TIMES="$1" STUB_TOKEN="$TOK" bash "$SCAN" > "$T/out" 2> "$T/err"
  CALLS="$(cat "$T/count" 2> /dev/null)"; CALLS="${CALLS:-0}"
}
has_token() { grep -qF -- "$TOK" "$T/out"; }

IN="see $TOK here
"
run 0 "$IN"
if ! has_token && [ "$CALLS" = 1 ]; then ok; else bad "baseline: the token is redacted on the first call (calls=$CALLS)"; fi

run 0 "$IN"
if [ "$(basename "$(cat "$T/src" 2> /dev/null)")" = input.txt ]; then ok; else bad "gitleaks is asked to scan a file named input.txt, not a random name that can look like an archive (got: $(cat "$T/src" 2> /dev/null))"; fi

run 2 "$IN"
if ! has_token; then ok; else bad "a gitleaks that scanned nothing twice is retried until it reads the text (token still present, calls=$CALLS)"; fi
if [ "$CALLS" = 3 ]; then ok; else bad "two zero-byte scans mean three calls (calls=$CALLS)"; fi
grep -q 'scanned nothing, retrying' "$T/err" && ok || bad "the retry says so on stderr ($(head -c 200 "$T/err"))"

run 9 "$IN"
if [ "$CALLS" = 3 ]; then ok; else bad "it gives up after three calls (calls=$CALLS)"; fi
grep -q 'failed 3 times or scanned nothing' "$T/err" && ok || bad "giving up is said on stderr, not silent ($(head -c 200 "$T/err"))"
if [ "$(cat "$T/out")" = "${IN%$'\n'}" ] || [ "$(cat "$T/out")" = "$IN" ]; then ok; else bad "when it gives up the text comes through unchanged"; fi

run 9 ""
if [ "$CALLS" -le 1 ]; then ok; else bad "an empty input is not retried (calls=$CALLS)"; fi

echo "scan-gitleaks-retry: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
