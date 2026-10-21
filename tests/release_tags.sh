#!/usr/bin/env bash
# tests/release_tags.sh -- which image tags the Publish workflow may write. One tag per line.
#
#   bash tests/release_tags.sh build   MODE VARIANT ARCH TAG SHA   per-architecture build (ARCH amd64|arm64)
#   bash tests/release_tags.sh staging MODE VARIANT TAG            the merged image before scan and signing
#   bash tests/release_tags.sh promote MODE VARIANT TAG            the tags users pull, written last
#
# MODE is release|rehearsal|recovery (tests/release_plan.sh). VARIANT is cpu|gpu. TAG is vX.Y.Z or rehearsal-N.
#
# The rule this file exists to hold: in a rehearsal, ONLY tags that carry the scratch TAG are written. Never
# the bare :cpu/:gpu (what hosts and the updater pull), never a per-architecture "latest" (:cpu-amd64,
# :cpu-arm64), never a per-commit tag. The workflow names no bare tag itself; they come from here, and
# tests/release_plan_test.sh checks both.
set -uo pipefail
CMD="${1:-}" MODE="${2:-}" VARIANT="${3:-}"
fail() { echo "release_tags: $*" >&2; exit 1; }
case "$MODE" in release|rehearsal|recovery) ;; *) fail "unknown mode '$MODE'" ;; esac
case "$VARIANT" in cpu|gpu) ;; *) fail "unknown variant '$VARIANT'" ;; esac
tag_ok() { [[ "$1" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+|rehearsal-[0-9]+)$ ]] || fail "unexpected tag '$1'"; }
# a rehearsal must carry a rehearsal tag, and a release a version tag: no cross-over
mode_matches_tag() {
  case "$MODE" in
    rehearsal) [[ "$1" == rehearsal-* ]] || fail "a rehearsal may only use a rehearsal-N tag, got '$1'" ;;
    *) [[ "$1" == v* ]] || fail "mode $MODE needs a vX.Y.Z tag, got '$1'" ;;
  esac
}

case "$CMD" in
  build)
    ARCH="${4:-}" TAG="${5:-}" SHA="${6:-}"
    case "$ARCH" in amd64|arm64) ;; *) fail "unknown arch '$ARCH'" ;; esac
    tag_ok "$TAG"; mode_matches_tag "$TAG"
    echo "$VARIANT-$ARCH-$TAG"
    if [ "$MODE" != rehearsal ]; then
      # the latest per-architecture build, and the per-commit build (names kept from before)
      echo "$VARIANT-$ARCH"
      [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || fail "a release build needs the commit sha, got '$SHA'"
      if [ "$ARCH" = amd64 ]; then echo "$VARIANT-sha-$SHA"; else echo "$VARIANT-arm64-sha-$SHA"; fi
    fi
    ;;
  staging)
    TAG="${4:-}"
    tag_ok "$TAG"; mode_matches_tag "$TAG"
    echo "$VARIANT-staging-$TAG"
    ;;
  promote)
    TAG="${4:-}"
    tag_ok "$TAG"; mode_matches_tag "$TAG"
    echo "$VARIANT-$TAG"
    [ "$MODE" = rehearsal ] || echo "$VARIANT"
    ;;
  *)
    fail "usage: release_tags.sh build|staging|promote MODE VARIANT ..."
    ;;
esac
