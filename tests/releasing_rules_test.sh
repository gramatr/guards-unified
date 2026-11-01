#!/usr/bin/env bash
# docs/RELEASING.md is the one place that states the release rules. This checks
# that it still says which tag needs the explicit go, which does not, what
# evidence goes with the request, and that the epic-level hold is gone. Negative
# control: the same checks run against a copy with the rules removed must fail.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOC="${1:-$HERE/../docs/RELEASING.md}"
pass=0; fail=0
ok() { pass=$((pass+1)); }
no() { fail=$((fail+1)); echo "FAIL: $1"; }

rules_ok() { # rules_ok FILE -- succeeds when every rule is stated
  local f="$1" miss=0
  grep -q '^## Release rules' "$f" || miss=1
  grep -q 'explicit go applies to the `guards-unified` tag only' "$f" || miss=1
  grep -q 'plugin tag needs \*\*no\*\* go\|`claude-plugin-guards` tag needs \*\*no\*\* go' "$f" || miss=1
  grep -q 'tests/image_smoke.sh' "$f" || miss=1
  grep -q '/about' "$f" || miss=1
  grep -q 'every claim in this' "$f" || miss=1
  grep -q 'no epic-level hold' "$f" || miss=1
  grep -q '\*\*fails\*\*' "$f" || miss=1
  return "$miss"
}

rules_ok "$DOC" && ok || no "RELEASING.md does not state every release rule"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# Negative control: drop the whole rules section; the check must notice.
awk '/^## Release rules/{skip=1} /^## 1\. Bump/{skip=0} !skip' "$DOC" > "$T/norules.md"
rules_ok "$T/norules.md" && no "negative control: a doc without the rules passed" || ok
# Negative control: the plugin-tag statement removed.
sed 's/needs \*\*no\*\* go/needs a go/' "$DOC" > "$T/plugingo.md"
rules_ok "$T/plugingo.md" && no "negative control: a doc asking a go for the plugin tag passed" || ok
# Epic-hold wording must not come back.
grep -qiE 'hold the (lockstep )?release until every' "$DOC" && no "the epic-level hold is back in RELEASING.md" || ok

echo "releasing-rules: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
