#!/usr/bin/env bash
# tests/scan_long_run_test.sh -- a very long unbroken run before a key must not stall scan.sh,
# and no grep pattern in app/*.sh may use a repetition count macOS grep refuses.
#
# WHY (gramatr/guards-coordination#71). scan.sh masks runs of 256+ name characters for the
# context rules, because those rules are quadratic on one long run (a 20 KB run took 10 s on
# Linux before the masking). It found the runs with grep -oE '[A-Za-z0-9_.-]{256,}'. macOS grep
# stops with "maximum repetition exceeds 255", scan.sh sends grep's errors to /dev/null, and so
# on a Mac nothing was ever masked: the same text took 80 s at 4 KB and did not finish at 8 KB,
# and the Bash output hook withheld the output instead of redacting it. Linux never showed it.
#
# Checks:
#   1. Static: no grep pattern in a non-comment line of app/*.sh has a repetition count above
#      255 or one taken from a variable (so the limit cannot be hidden in ${N}). Works anywhere.
#   2. Timing: for runs of 4 KB, 8 KB and 20 KB followed by a key, scan.sh (gitleaks skipped)
#      redacts the key and finishes within LONG_RUN_CAP_SECS (default 20), under the bash named
#      by SCAN_BASH. CI runs this with /bin/bash on a macOS runner (bash 3.2, BSD grep and awk).
#
#   SCAN_BASH=/bin/bash bash tests/scan_long_run_test.sh
#
# All values are fabricated. Needs bash, awk, grep.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HERE/../app"
SCAN="$APP/scan.sh"
SCAN_BASH="${SCAN_BASH:-bash}"
CAP="${LONG_RUN_CAP_SECS:-20}"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

# --- 1. static -------------------------------------------------------------
# find_big_repeats FILE... -> one line per grep pattern with a count above 255 or a variable count
find_big_repeats() {
  awk '
    /^[[:space:]]*#/ { next }
    /grep/ {
      line = $0
      while (match(line, /\{[^}]*\}/)) {
        t = substr(line, RSTART + 1, RLENGTH - 2)
        rest = substr(line, RSTART + RLENGTH)
        if (t ~ /^[0-9]+(,[0-9]*)?$/) {
          split(t, a, ",")
          if (a[1] + 0 > 255 || a[2] + 0 > 255) print FILENAME ":" FNR ": {" t "}"
        } else if (t ~ /^\$/) {
          print FILENAME ":" FNR ": {" t "} (count from a variable)"
        }
        line = rest
      }
    }' "$@"
}
big="$(find_big_repeats "$APP"/*.sh)"
if [ -z "$big" ]; then ok; else bad "grep patterns macOS cannot compile: $big"; fi

# bash 3.2 keeps the quotes of a quoted replacement inside "${x//pat/"rep"}" as literal
# characters (it wrapped every restored long run in ""): the replacement must be unquoted.
quoted="$(grep -n -E '\$\{[^}]*//?[^/}]*/"[^}]*"\}' "$APP"/*.sh | grep -v -E '^[^:]*:[0-9]+:[[:space:]]*#')"
if [ -z "$quoted" ]; then ok; else bad "a quoted replacement in a pattern substitution (wrong on bash 3.2): $quoted"; fi
qneg="$(printf '%s\n' 'x="${t//"$a"/"b"}"' 'y="${t//"$a"/$b}"' | grep -c -E '\$\{[^}]*//?[^/}]*/"[^}]*"\}')"
if [ "$qneg" = 1 ]; then ok; else bad "the quoted-replacement check flags only the planted bad form (flagged $qneg of 2)"; fi

# The checker must be able to fail: a planted bad pattern and a planted variable count.
neg="$(mktemp)"
trap 'rm -f "$neg"' EXIT
printf '%s\n' "x=\$(grep -oE '[a-z]{256,}' f)" "y=\$(grep -oE \"[a-z]{\${N},}\" f)" "# grep -E '[a-z]{999,}'" "z=\$(grep -E '[a-z]{4,255}' f)" > "$neg"
n="$(find_big_repeats "$neg" | wc -l | tr -d ' ')"
if [ "$n" = 2 ]; then ok; else bad "the static check finds the 2 planted patterns (found $n)"; fi

# --- 2. timing ---------------------------------------------------------------
# run_capped IN OUT -> runs scan.sh on IN into OUT; kills it after CAP seconds (returns 124)
run_capped() {
  SECRET_GUARD_SKIP_GITLEAKS=1 "$SCAN_BASH" "$SCAN" < "$1" > "$2" 2> /dev/null &
  local pid=$! waiter rc
  ( sleep "$CAP"; kill -9 "$pid" 2> /dev/null ) &
  waiter=$!
  wait "$pid" 2> /dev/null
  rc=$?
  kill "$waiter" 2> /dev/null
  wait "$waiter" 2> /dev/null
  [ "$rc" -eq 137 ] && rc=124
  return "$rc"
}

W="$(mktemp -d)"
trap 'rm -rf "$W" "$neg"' EXIT
SECRET="hunter2x" # guards:synthetic
for n in 4000 8000 20000; do
  run="$(head -c "$n" /dev/zero | tr '\0' 'a')"
  printf '%s password: %s\n' "$run" "$SECRET" > "$W/in" # guards:synthetic
  start=$SECONDS
  run_capped "$W/in" "$W/out"
  rc=$?
  took=$((SECONDS - start))
  if [ "$rc" -eq 124 ]; then
    bad "a ${n}-character run before a key did not finish in ${CAP}s"
  elif grep -q "$SECRET" "$W/out"; then
    bad "a ${n}-character run before a key: the key was not redacted (took ${took}s)"
  else
    ok
    echo "  ${n}-character run then a key: redacted in ${took}s (cap ${CAP}s)"
  fi
done

# The run itself is kept: the text around the key is unchanged. Compared as a bash string, not
# with a 3,000-character grep pattern, so a grep limit cannot decide the result.
longb="$(head -c 3000 /dev/zero | tr '\0' 'b')"
printf '%s\n' "x${longb}y password: ${SECRET}" > "$W/in" # guards:synthetic
run_capped "$W/in" "$W/out"
got="$(cat "$W/out")"
want_prefix="x${longb}y "
if [ "${got#"$want_prefix"}" != "$got" ]; then ok; else bad "the long run is restored byte for byte after masking (output starts: $(printf '%s' "$got" | head -c 60))"; fi

echo "scan-long-run: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
