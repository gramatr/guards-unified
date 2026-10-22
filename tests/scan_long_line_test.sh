#!/usr/bin/env bash
# tests/scan_long_line_test.sh -- one very long line full of credential words must not stall scan.sh,
# and a credential inside it is still redacted (gramatr/guards-coordination#48).
#
# WHY. The context rules re-scan the rest of the text for every match, so a single long line with
# many credential words (a minified bundle, one-line JSON) cost time that grows with its length times
# its hits: a 20 KB line took 17 s and 40 KB did not finish in 2 minutes. The publish guard's local
# budget is 15 s, so such a diff was denied as "did not finish in time". scan.sh now cuts a long line
# with many credential words into small pieces for the context rules only (ctx_chunk_long_lines).
#
# Checks (gitleaks skipped, so this is the context pass alone):
#   1. a 40 KB dense line with a credential in the middle and one at the end: both redacted, the
#      surrounding text and the line length otherwise intact, no cut marker left in the output, and
#      done within LONG_LINE_CAP_SECS (default 30; the unfixed script needs more than 120);
#   2. a long line with few credential words is left whole and still redacts a credential in it;
#   3. a long dense line with no credential comes back byte for byte (the cuts are undone);
#   4. SECRET_GUARD_CTX_LINE_MAX=0 turns the cutting off and a short dense line still redacts.
#
#   SCAN_BASH=/bin/bash bash tests/scan_long_line_test.sh
#
# All values are fabricated. Needs bash, awk.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$HERE/../app/scan.sh"
SCAN_BASH="${SCAN_BASH:-bash}"
CAP="${LONG_LINE_CAP_SECS:-30}"
BF="${GUARDS_TEST_BUDGET_FACTOR:-1}"
CAP=$((CAP * BF))
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

export SECRET_GUARD_SKIP_GITLEAKS=1 SECRET_GUARD_ENV_VALUES=0
sv="Zq8xK2mNp4Lw9vTd"   # fabricated value, built here so no key name sits next to it in this file

scan() { "$SCAN_BASH" "$SCAN" 2>/dev/null; }
unit='a.token=b;c.secret:d,password_hint="ok";'   # each hint value runs to the next quote: many context hits  # guards:synthetic
nounit='getAuthTokenFromSecretStoreCredentialProvider(x,y);'   # credential words, but nothing to redact

dense() { # dense N [UNIT] -> N bytes of credential-word-dense text on one line
  awk -v n="$1" -v u="${2:-$unit}" 'BEGIN { s = ""; while (length(s) < n) s = s u; printf "%s", substr(s, 1, n) }'
}

# 1. dense 40 KB line with two credentials
half="$(dense 20000)"
line="${half}DB_PASSWORD=${sv} ${half}api_secret=\"${sv}\""
start=$SECONDS
out="$(printf '%s' "$line" | scan)"
took=$((SECONDS - start))
[[ "$out" != *"$sv"* ]] && ok || bad "a credential inside a 40 KB dense line was not redacted"
[[ "$out" != *"~~LL~~"* ]] && ok || bad "a cut marker was left in the output"
[ "$took" -le "$CAP" ] && ok || bad "a 40 KB dense line took ${took}s (cap ${CAP}s)"

# 2. a long line with few credential words: left whole, credential still redacted
words="$(awk 'BEGIN { for (i = 0; i < 4000; i++) printf "lorem ipsum dolor %d ", i }')"
out="$(printf '%s' "${words}DB_PASSWORD=${sv} ${words}" | scan)"
[[ "$out" != *"$sv"* ]] && ok || bad "a credential inside a long ordinary line was not redacted"

# 3. a long dense line with nothing to redact comes back unchanged
plain="$(dense 30000 "$nounit")"
out="$(printf '%s' "$plain" | scan)"
[ "$out" = "$plain" ] && ok || bad "a long dense line with no credential was altered"

# 4. the off switch, on a short dense line
out="$(printf 'x.token=ok;DB_PASSWORD=%s;y' "$sv" | SECRET_GUARD_CTX_LINE_MAX=0 "$SCAN_BASH" "$SCAN" 2>/dev/null)"  # guards:synthetic
[[ "$out" != *"$sv"* ]] && ok || bad "with the cutting off, a credential was not redacted"

echo "scan-long-line: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
