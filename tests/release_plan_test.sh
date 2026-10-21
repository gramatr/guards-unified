#!/usr/bin/env bash
# tests/release_plan_test.sh -- the release plan and the tags it may write.
#
# The Publish workflow can be run as a rehearsal (a manual run on a scratch tag, from any branch) so that a
# real release is not the first time it runs end to end. The one property that matters is that a rehearsal
# cannot touch what users and the updater pull. This pins it three ways:
#   1. tests/release_plan.sh: which run is a release, a rehearsal or a recovery, and what it refuses.
#   2. tests/release_tags.sh: a rehearsal's tag lists contain only scratch-tagged names, a release's keep
#      the names they always had, and a mode/tag mismatch is refused.
#   3. the workflow itself: it names no bare :cpu/:gpu tag and reads the tag only from the plan job.
# All values are fabricated. Needs bash and grep.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN="$HERE/release_plan.sh"
TAGS="$HERE/release_tags.sh"
WF="$HERE/../.github/workflows/publish.yml"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
SHA="$(printf 'a1%.0s' $(seq 1 20))"

# --- 1. the plan ----------------------------------------------------------------
plan() { bash "$PLAN" "$@" 2> "${TMPDIR:-/tmp}/rp.err"; }
eq() { # eq DESCRIPTION WANT GOT
  if [ "$2" = "$3" ]; then ok; else bad "$1 (wanted '$2', got '$3')"; fi
}
eq "a tag push is a release"          "mode=release tag=v0.2.10 ver=0.2.10" "$(plan push v0.2.10 '' '' 7 0.2.9 | tr '\n' ' ' | sed 's/ $//')"
eq "a rehearsal gets a scratch tag and the VERSION file's version" "mode=rehearsal tag=rehearsal-42 ver=0.2.9" "$(plan workflow_dispatch main true '' 42 0.2.9 | tr '\n' ' ' | sed 's/ $//')"
eq "a recovery names a real tag"      "mode=recovery tag=v0.2.9 ver=0.2.9" "$(plan workflow_dispatch main false v0.2.9 42 0.2.9 | tr '\n' ' ' | sed 's/ $//')"
for bad_case in \
  "push main '' '' 7 0.2.9" \
  "push v0.2 '' '' 7 0.2.9" \
  "push v0.2.10-rc1 '' '' 7 0.2.9" \
  "push rehearsal-5 '' '' 7 0.2.9" \
  "workflow_dispatch main false '' 42 0.2.9" \
  "workflow_dispatch main false rehearsal-5 42 0.2.9" \
  "workflow_dispatch main false v0.2 42 0.2.9" \
  "workflow_dispatch main true '' abc 0.2.9" \
  "workflow_dispatch main true '' 42 notaversion" \
  "pull_request main '' '' 1 0.2.9" \
  "schedule main '' '' 1 0.2.9"; do
  if eval "bash '$PLAN' $bad_case" > /dev/null 2>&1; then bad "release_plan accepted: $bad_case"; else ok; fi
done
# a rehearsal run ignores a version input (it cannot be steered at a real tag)
eq "a rehearsal ignores a version input" "mode=rehearsal tag=rehearsal-9 ver=0.2.9" "$(plan workflow_dispatch main true v0.2.9 9 0.2.9 | tr '\n' ' ' | sed 's/ $//')"

# --- 2. the tags -----------------------------------------------------------------
list() { bash "$TAGS" "$@" 2> /dev/null | tr '\n' ' ' | sed 's/ $//'; }
eq "release amd64 build tags"   "cpu-amd64-v0.2.10 cpu-amd64 cpu-sha-$SHA" "$(list build release cpu amd64 v0.2.10 "$SHA")"
eq "release arm64 build tags"   "gpu-arm64-v0.2.10 gpu-arm64 gpu-arm64-sha-$SHA" "$(list build release gpu arm64 v0.2.10 "$SHA")"
eq "release staging tag"        "cpu-staging-v0.2.10" "$(list staging release cpu v0.2.10)"
eq "release promote tags"       "cpu-v0.2.10 cpu" "$(list promote release cpu v0.2.10)"
eq "recovery promote tags"      "gpu-v0.2.9 gpu" "$(list promote recovery gpu v0.2.9)"
eq "rehearsal amd64 build tags" "cpu-amd64-rehearsal-3" "$(list build rehearsal cpu amd64 rehearsal-3 "$SHA")"
eq "rehearsal arm64 build tags" "gpu-arm64-rehearsal-3" "$(list build rehearsal gpu arm64 rehearsal-3 "$SHA")"
eq "rehearsal staging tag"      "cpu-staging-rehearsal-3" "$(list staging rehearsal cpu rehearsal-3)"
eq "rehearsal promote tags"     "cpu-rehearsal-3" "$(list promote rehearsal cpu rehearsal-3)"
# the property: no rehearsal output, for any variant or architecture, is a bare tag, a per-arch latest or a sha tag
for v in cpu gpu; do
  out="$(list build rehearsal $v amd64 rehearsal-3 "$SHA") $(list build rehearsal $v arm64 rehearsal-3 "$SHA") $(list staging rehearsal $v rehearsal-3) $(list promote rehearsal $v rehearsal-3)"
  for t in $out; do
    case "$t" in
      "$v"|"$v-amd64"|"$v-arm64"|*-sha-*) bad "a rehearsal would write '$t' ($v)" ;;
      *rehearsal-3) ok ;;
      *) bad "a rehearsal tag without the scratch name: '$t'" ;;
    esac
  done
done
# refusals
for bad_case in \
  "promote rehearsal cpu v0.2.10" \
  "promote release cpu rehearsal-3" \
  "promote recovery cpu rehearsal-3" \
  "promote release cpu latest" \
  "promote release latest v0.2.10" \
  "promote nonsense cpu v0.2.10" \
  "build release cpu amd64 v0.2.10 notasha" \
  "build rehearsal cpu ppc64 rehearsal-3 $SHA" \
  "staging rehearsal cpu v0.2.10"; do
  if eval "bash '$TAGS' $bad_case" > /dev/null 2>&1; then bad "release_tags accepted: $bad_case"; else ok; fi
done

# --- 3. the workflow -------------------------------------------------------------------
# It must not name a bare :cpu/:gpu tag itself (a bare name is only ever produced by release_tags.sh in
# release or recovery mode), and the tag must come from the plan job, not from the ref.
if grep -n -E 'guards-unified:(\$\{\{ *matrix\.variant *\}\}|cpu|gpu)([^-A-Za-z0-9{$]|$)' "$WF" | grep -v -E '^[0-9]+:[[:space:]]*#' > /dev/null; then
  bad "publish.yml names a bare image tag: $(grep -n -E 'guards-unified:(\$\{\{ *matrix\.variant *\}\}|cpu|gpu)([^-A-Za-z0-9{$]|$)' "$WF" | head -n 2)"
else ok; fi
refs="$(grep -c 'github\.ref_name' "$WF")"
eq "github.ref_name is read once, by the plan job" "1" "$refs"
grep -q 'tests/release_plan.sh' "$WF" && ok || bad "publish.yml runs tests/release_plan.sh"
grep -q 'tests/release_tags.sh' "$WF" && ok || bad "publish.yml takes its tag lists from tests/release_tags.sh"
# the planted fault: a workflow that writes a bare tag is caught by the same grep
planted="$(printf 'x: ghcr.io/gramatr/guards-unified:${{ matrix.variant }}\n' | grep -c -E 'guards-unified:(\$\{\{ *matrix\.variant *\}\}|cpu|gpu)([^-A-Za-z0-9{$]|$)')"
eq "the bare-tag check flags a planted bare tag" "1" "$planted"

echo "release-plan: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
