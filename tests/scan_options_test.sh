#!/usr/bin/env bash
# tests/scan_options_test.sh — the two opt-in switches of app/scan.sh.
#
#   SECRET_GUARD_REDACT_KEY_IDS=1  also redact access-key / client IDs.
#       Default OFF: an ID is a semi-public identifier, the secret half is
#       the enforced boundary (guards-coordination#3).
#   SECRET_GUARD_ENV_VALUES=1      exact-match redact values of environment
#       variables whose NAMES look secret (guards-coordination#11).
#       Default OFF: only meaningful where the scanner shares the session's
#       environment.
#
# All values are fabricated. Works with or without gitleaks installed.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$HERE/../app/scan.sh"
pass=0 fail=0

scan() { printf '%s' "$1" | env "${@:2}" bash "$SCAN" 2>/dev/null; }
expect_changed() { # expect_changed DESC INPUT [ENV...]
  if [ "$(scan "$2" "${@:3}")" != "$2" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1 (wanted redaction)"; fi
}
expect_same() {
  if [ "$(scan "$2" "${@:3}")" = "$2" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1 (wanted unchanged)"; fi
}

ID='AccessKey : 48388a15798489a302330828b2388025'
expect_same    "key ID untouched by default"        "$ID"
expect_changed "key ID redacted when opted in"      "$ID" SECRET_GUARD_REDACT_KEY_IDS=1
expect_changed "secret half always redacted"        'SecretKey : Qm4*Xw9%tL2!pR7=zN3^vB8'
expect_same    "client_id untouched by default"     'client_id: 7f3a9c1e5b2d4a60'
expect_changed "client_id redacted when opted in"   'client_id: 7f3a9c1e5b2d4a60' SECRET_GUARD_REDACT_KEY_IDS=1

V='Zq8wXr5tNm2PvKd9'
expect_same    "env value ignored by default"       "bare value $V printed"           MY_SERVICE_TOKEN="$V"
expect_changed "env value redacted when opted in"   "bare value $V printed"           SECRET_GUARD_ENV_VALUES=1 MY_SERVICE_TOKEN="$V"
expect_changed "env value redacted: PASSWORD name"  "x $V y"                           SECRET_GUARD_ENV_VALUES=1 DB_PASSWORD="$V"
expect_same    "short env value skipped"            "x abc123 y"                       SECRET_GUARD_ENV_VALUES=1 DB_PASSWORD=abc123
expect_same    "placeholder env value skipped"      'x ${SOMETHING} y'                 SECRET_GUARD_ENV_VALUES=1 DB_PASSWORD='${SOMETHING}'
expect_same    "_FILE name skipped"                 "x /run/secrets/pw y"              SECRET_GUARD_ENV_VALUES=1 DB_PASSWORD_FILE=/run/secrets/pw
expect_same    "non-secret name skipped"            "x $V y"                           SECRET_GUARD_ENV_VALUES=1 HOSTNAME_LABEL="$V"

# --- robustness: no match cap, no quadratic blow-up --------------------
# 300 distinct secret lines: the loop used to stop after 200 matches per rule
# and leave the rest unredacted.
many="$(for i in $(seq 1 300); do printf 'APP%s_PASSWORD=hunter2-%s\n' "$i" "$i"; done)"
left="$(printf '%s' "$many" | bash "$SCAN" 2>/dev/null | grep -c 'hunter2-' || true)"
if [ "$left" = "0" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $left of 300 secret lines survive redaction (match cap?)"; fi

# ~230 KB of prose with one secret at the end took 19 s when the span split
# was quadratic (1 MB: 447 s, past the service's 15 s timeout, which then
# failed open). Linear it is well under a second or two; allow 15 s for slow CI.
big="$(python3 -I -c "
import random, string
random.seed(1)
print(' '.join(''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(3, 9))) for _ in range(34000)))
print('DB_PASSWORD=Tq7vN2xLm9Kd4RzP8wYb')")"
start=$SECONDS
out="$(printf '%s' "$big" | bash "$SCAN" 2>/dev/null)"
took=$((SECONDS - start))
if [[ "$out" != *Tq7vN2xLm9Kd4RzP8wYb* ]] && [ "$took" -le 15 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: large input with a secret: redacted=$([[ "$out" != *Tq7vN2xLm9Kd4RzP8wYb* ]] && echo yes || echo NO) took ${took}s (limit 15s)"; fi

echo "scan options: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
