#!/usr/bin/env bash
# tests/license_test.sh -- LICENSE stays the plain MIT text, and NOTICE carries the note.
#
# GitHub reports a license as "Other" when text follows the MIT license in LICENSE, which
# hides the license from every reader and tool that relies on that detection. Notes about
# what the license does not cover (here: the separately licensed Llama model) belong in
# NOTICE, which the images also ship in /app/licenses. Needs: bash.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.." || exit 1
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

head -n 1 LICENSE | grep -q '^MIT License$' && ok || bad "LICENSE starts with 'MIT License'"
if grep -q -E '^(---|This license covers)' LICENSE; then bad "LICENSE holds only the license text (notes belong in NOTICE)"; else ok; fi
last="$(grep -v '^[[:space:]]*$' LICENSE | tail -n 1)"
[ "$last" = "SOFTWARE." ] && ok || bad "LICENSE ends with the MIT warranty text, got: $last"
grep -q 'Llama-Prompt-Guard-2-86M' NOTICE && ok || bad "NOTICE names the Llama model"
grep -q 'does NOT cover' NOTICE && ok || bad "NOTICE says the MIT license does not cover the model"
grep -q 'COPY LICENSE NOTICE' Dockerfile.cpu && grep -q 'COPY LICENSE NOTICE' Dockerfile && ok || bad "both Dockerfiles ship LICENSE and NOTICE"

echo "license: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
