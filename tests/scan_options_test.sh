#!/usr/bin/env bash
# tests/scan_options_test.sh — the two opt-in switches of app/scan.sh.
#
#   SECRET_GUARD_REDACT_KEY_IDS=1  also redact access-key / client IDs.
#       Default OFF: an ID is a semi-public identifier, the secret half is
#       the enforced boundary.
#   SECRET_GUARD_ENV_VALUES=1      exact-match redact values of environment
#       variables whose NAMES look secret.
#       Default OFF: only meaningful where the scanner shares the session's
#       environment.
#
# All values are fabricated. Works with or without gitleaks installed.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$HERE/../app/scan.sh"
# Timing limits below are multiplied by GUARDS_TEST_BUDGET_FACTOR (default 1); only the shared macOS CI runner sets it.
BF="${GUARDS_TEST_BUDGET_FACTOR:-1}"
pass=0 fail=0

scan() { printf '%s' "$1" | env "${@:2}" bash "$SCAN" 2>/dev/null; }
expect_changed() { # expect_changed DESC INPUT [ENV...]
  if [ "$(scan "$2" "${@:3}")" != "$2" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1 (wanted redaction)"; fi
}
expect_same() {
  if [ "$(scan "$2" "${@:3}")" = "$2" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1 (wanted unchanged)"; fi
}

# Quote-wrapped key word with its colon: the key's closing quote is not the
# opening quote of a value (real quoted values are pinned in redaction_selftest.py).
expect_same    "wrapped key word in prose is not a value"   'the "password:" field, then "some text here"'
# Accepted limitation (docs/TRADEOFFS.md): the same shape with a value glued on
# is indistinguishable from the prose above, so it is NOT redacted.
expect_same    "accepted: wrapped key + glued value"        'x "pw:"abcdefgh"'
expect_changed "nested shell quoting still redacted"        'bash -c "PASSWORD="abcdefgh" ./run"'

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
# The shell's current directory lives in PWD, a name that matches the PW alias.
# Live testing found every mention of the working directory redacted.
cwd_here="$(pwd)"
expect_same    "PWD (the working directory) is never treated as a secret" "ls of $cwd_here: proj" SECRET_GUARD_ENV_VALUES=1 PWD="$cwd_here"
expect_same    "OLDPWD is never treated as a secret"                     "back to $cwd_here done" SECRET_GUARD_ENV_VALUES=1 OLDPWD="$cwd_here"
expect_same    "a secret-named var whose value is an existing path is skipped" "dir /tmp listed" SECRET_GUARD_ENV_VALUES=1 MY_SERVICE_TOKEN=/tmp

# --- a heading that ends in a keyword and a colon is not a key (found live) ---
# A line ending in "secret:" followed by an indented line used to redact the
# first word of that next line, because the delimiter allowed newlines.
expect_same    "heading ending in secret: then an indented line" $'Rotate the secret:\n  kubectl delete secret old'  # guards:synthetic
expect_same    "heading ending in token: then a labelled line"   $'About the token:\n  local: running'  # guards:synthetic
expect_same    "heading ending in password: then prose"          $'Reset the password:\n    follow the steps below'  # guards:synthetic
# Same-line forms are still redacted.
expect_changed "same-line key: value still redacts"              'secret: Tq7vN2xLm9Kd4RzP8wYb'  # guards:synthetic
expect_changed "same-line key=value with blanks still redacts"   $'password =\tTq7vN2xLm9Kd4RzP8wYb'  # guards:synthetic

# The ONE next-line form that is a value: a YAML scalar under a line that is only
# the key and a colon, as a single bare token.
expect_changed "yaml scalar on the line after a bare key"        $'password:\n  Tq7vN2xLm9Kd4RzP8wYb'  # guards:synthetic
expect_changed "same, under a list item"                         $'- password:\n    hunter2xyz\n'  # guards:synthetic
expect_changed "same, nested deeper"                             $'config:\n  api_token:\n    Xk9mQ4vT2pLw8RzN5bJc'  # guards:synthetic
expect_same    "a nested key on the next line is not a value"    $'secret:\n  name: db-creds'  # guards:synthetic
expect_same    "a multi-word next line is not a value"           $'token:\n  one two three'  # guards:synthetic
expect_same    "two keys in a row"                               $'password:\nuser: bob'  # guards:synthetic

# --- a value that is an existing path is not a password (found live) ----------
# `env`/`printenv`/`export -p` print PWD=<working directory>; PWD is also a real
# password alias, so the key-name rule used to redact the directory.
expect_same    "PWD=<existing dir> (what env prints)"        "PWD=$cwd_here"
expect_same    "pwd: <existing dir>"                          "pwd: $cwd_here"
expect_same    "export OLDPWD=<existing dir>"                 "declare -x OLDPWD=\"$cwd_here\""
expect_same    "a quoted DB path under a password-ish key"     "password_file: /usr/bin"
expect_changed "PWD=<something that is NOT a path> still redacts" "PWD=Tq7vN2xLm9Kd4RzP8wYb"  # guards:synthetic
expect_changed "a path-looking value that does not exist still redacts" "DB_PASSWORD=/not/a/real/path/Tq7vN2xLm9Kd4RzP8wYb"  # guards:synthetic

# --- SECRET_GUARD_SKIP_GITLEAKS=1: deterministic passes only -------------
DSN='postgresql://svc:Tq7vN2xLm9Kd4RzP8wYb@db.internal:5432/app'
expect_changed "skip-gitleaks still redacts a DSN password" "$DSN" SECRET_GUARD_SKIP_GITLEAKS=1
# The code-shape rule must not read a value inside a string as code: a JSON body, a
# quoted command, and mixed-case random values on a line with braces stay secrets
# (context pass only, so the check does not depend on gitleaks).
JV='Zq8wXr5tNm2PvKd9Lb4s'  # guards:synthetic
expect_changed "skip-gitleaks: value inside a JSON string" "{\"body\":\"password: $JV\",\"n\":1}" SECRET_GUARD_SKIP_GITLEAKS=1  # guards:synthetic
expect_changed "skip-gitleaks: letters-only mixed-case value, braces" "{ token: KdZqMwLpXrVtNbHgFs }" SECRET_GUARD_SKIP_GITLEAKS=1  # guards:synthetic
expect_changed "skip-gitleaks: camel-looking value with a digit" "const x = { secret: kdZqMwLp4Xr };" SECRET_GUARD_SKIP_GITLEAKS=1  # guards:synthetic
expect_same    "skip-gitleaks: property holding a variable is code" "  accessToken: accessToken," SECRET_GUARD_SKIP_GITLEAKS=1  # guards:synthetic
# Text that merely contains a key, a colon and an identifier-looking word is not code:
# a log line, a shell string, a markdown or issue body, a message. Context pass only.
G=SECRET_GUARD_SKIP_GITLEAKS=1
expect_changed "skip-gitleaks: log line"                  '2026-10-20 12:00:01 INFO retry password: old_pass_word;' $G  # guards:synthetic
expect_changed "skip-gitleaks: log line, trailing comma"  'WARN login failed token: refresh_token_val,' $G  # guards:synthetic
expect_changed "skip-gitleaks: double-quoted shell string" 'echo "password: old_pass_word,"' $G  # guards:synthetic
expect_changed "skip-gitleaks: single-quoted shell string" "curl -d 'password: old_pass_word,' host" $G  # guards:synthetic
expect_changed "skip-gitleaks: markdown bullet"           '- The password: old_pass_word, as sent' $G  # guards:synthetic
expect_changed "skip-gitleaks: issue body sentence"       'Steps: set secret: my_secret_value; then restart' $G  # guards:synthetic
expect_same    "skip-gitleaks: object literal member chain" '  const o = { token: this.cfg.apiToken, n: 1 };' $G  # guards:synthetic
expect_same    "skip-gitleaks: call argument"             '  login(user, { password: userPassword });' $G  # guards:synthetic

# Very long unbroken runs (a base64 blob, a hash, a bundle without spaces) used to
# take seconds per 10 KB in the context pass. They must scan quickly, a secret
# after one must still be redacted, and the run itself must come back unchanged.
LONG="$(head -c 20000 /dev/zero | tr '\0' 'a')"
start=$SECONDS
out="$(scan "$LONG" $G)"
took=$((SECONDS - start))
if [ "$out" = "$LONG" ] && [ "$took" -le $((3 * BF)) ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: long unbroken run: unchanged=$([ "$out" = "$LONG" ] && echo y || echo n) took ${took}s (limit 3s)"; fi
expect_changed "secret after a long run is redacted"  "$LONG password: hunter2x" $G  # guards:synthetic
expect_changed "long run as the value is redacted"    "password=$LONG" $G  # guards:synthetic
if [ "$(scan "x $LONG y" $G)" = "x $LONG y" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: long run in a sentence changed"; fi
expect_changed "skip-gitleaks + env values still redacts"   "x $V y" SECRET_GUARD_SKIP_GITLEAKS=1 SECRET_GUARD_ENV_VALUES=1 DB_PASSWORD="$V"
if command -v gitleaks >/dev/null 2>&1; then
  TOK='ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'
  expect_changed "gitleaks (default) redacts a vendor token"        "token is $TOK"
  expect_same    "skip-gitleaks leaves a vendor-only token alone"   "token is $TOK" SECRET_GUARD_SKIP_GITLEAKS=1
fi

# --- base64 pass (SECRET_GUARD_B64, default on) ---------------------------
B64DSN="$(printf 'postgresql://svc:Tq7vN2xLm9Kd4RzP8wYb@db.internal:5432/app' | base64 -w0)"
expect_changed "a DSN hidden in base64 under an innocent key" "{\"conn\": \"$B64DSN\"}"
expect_same    "SECRET_GUARD_B64=0 turns the pass off"         "{\"conn\": \"$B64DSN\"}" SECRET_GUARD_B64=0
expect_same    "a git hash line is untouched"                  "commit 3f2a9c1e5b7d4a6082f1c3e5a7b9d1f3e5a7c9b1 Author: x"
expect_same    "base64 of ordinary prose is untouched"         "{\"note\": \"$(printf 'The quick brown fox jumps over the lazy dog and keeps running far away' | base64 -w0)\"}"

# Hash-heavy text (a git log) must not pay for the base64 pass. A bounded
# {44,4096} regex in bash itself cost +2.9 s per scan; with one grep it is
# a few ms. Fail if a 100 KB hash-heavy scan takes more than 2 s.
hashy="$(python3 -I -c "
import random
random.seed(7)
h = lambda n: ''.join(random.choice('0123456789abcdef') for _ in range(n))
print('\n'.join('commit %s\nAuthor: dev\n\n    change %d see %s tree %s\n' % (h(40), i, h(64), h(40)) for i in range(450)))")"
start=$SECONDS
printf '%s' "$hashy" | bash "$SCAN" >/dev/null 2>&1
took=$((SECONDS - start))
if [ "$took" -le $((2 * BF)) ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: hash-heavy 100 KB scan took ${took}s (limit 2s)"; fi

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
# The limit is multiplied by GUARDS_TEST_BUDGET_FACTOR (default 1). Only the shared macOS CI runner sets it
# (2): the same case took 16 s and 17 s there against the 15 s limit, and passes in about 1 s on a real Mac.
limit=$((15 * BF))
start=$SECONDS
out="$(printf '%s' "$big" | bash "$SCAN" 2>/dev/null)"
took=$((SECONDS - start))
if [[ "$out" != *Tq7vN2xLm9Kd4RzP8wYb* ]] && [ "$took" -le "$limit" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: large input with a secret: redacted=$([[ "$out" != *Tq7vN2xLm9Kd4RzP8wYb* ]] && echo yes || echo NO) took ${took}s (limit ${limit}s)"; fi

echo "scan options: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
