#!/usr/bin/env bash
# tests/release_plan.sh -- decide what the Publish workflow is being asked to do.
#
#   bash tests/release_plan.sh EVENT REF_NAME REHEARSAL VERSION_INPUT RUN_NUMBER VERSION_FILE
#
# Prints three lines on stdout (written to $GITHUB_OUTPUT by the workflow):
#   mode=release|rehearsal|recovery
#   tag=<the tag every image name and the release page use>
#   ver=<the version whose changelog section must exist>
# and exits non-zero, with the reason on stderr, for anything it does not recognise.
#
#   release    a push of a tag vX.Y.Z: the real thing.
#   rehearsal  a manual run (workflow_dispatch) with rehearsal=true, from any branch: the same jobs on a
#              scratch tag `rehearsal-<run number>`. It never writes a bare :cpu/:gpu tag, a per-architecture
#              "latest" tag or a per-commit tag (see tests/release_tags.sh), and its release is a draft.
#   recovery   a manual run with rehearsal=false and a version: re-run merge-multiarch for a real tag whose
#              build jobs already finished (the pre-existing manual recovery path).
#
# Why a script: this decides which tags may be written, so it is unit-tested (tests/release_plan_test.sh).
set -uo pipefail
EVENT="${1:-}" REF_NAME="${2:-}" REHEARSAL="${3:-}" VERSION_INPUT="${4:-}" RUN_NUMBER="${5:-}" VERSION_FILE="${6:-}"
fail() { echo "release_plan: $*" >&2; exit 1; }
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+$'

case "$EVENT" in
  push)
    [[ "$REF_NAME" =~ $TAG_RE ]] || fail "a tag push must be vX.Y.Z, got '$REF_NAME'"
    echo "mode=release"
    echo "tag=$REF_NAME"
    echo "ver=${REF_NAME#v}"
    ;;
  workflow_dispatch)
    if [ "$REHEARSAL" = true ]; then
      [[ "$RUN_NUMBER" =~ ^[0-9]+$ ]] || fail "a rehearsal needs the run number, got '$RUN_NUMBER'"
      [[ "$VERSION_FILE" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "VERSION file is not X.Y.Z: '$VERSION_FILE'"
      echo "mode=rehearsal"
      echo "tag=rehearsal-$RUN_NUMBER"
      echo "ver=$VERSION_FILE"
    else
      [[ "$VERSION_INPUT" =~ $TAG_RE ]] || fail "recovery needs version=vX.Y.Z (or set rehearsal=true), got '$VERSION_INPUT'"
      echo "mode=recovery"
      echo "tag=$VERSION_INPUT"
      echo "ver=${VERSION_INPUT#v}"
    fi
    ;;
  *)
    fail "unsupported event '$EVENT'"
    ;;
esac
