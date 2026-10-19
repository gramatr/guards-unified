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

echo "scan options: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
