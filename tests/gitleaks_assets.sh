#!/usr/bin/env bash
#
#   bash tests/gitleaks_assets.sh build OUTDIR   build the four binaries, package them
#   bash tests/gitleaks_assets.sh check OUTDIR   compare their hashes with docs/gitleaks-assets.sha256
#
# `build` needs docker and network. It builds from Dockerfile.cpu's `gitleaks` stage (the
# same recipe as the image's gitleaks: pinned commit, patched Go modules, pinned Go image)
# for linux and darwin on amd64 and arm64, and writes to OUTDIR:
#   gitleaks-patched_<ver>_<os>_<arch>.tar.gz    one `gitleaks` binary each (arch x64|arm64)
#   gitleaks-patched_<ver>_checksums.txt         sha256 of the tarballs
#   gitleaks-patched_<ver>_binary-sha256.txt     sha256 of the binaries inside: what the plugin carries
# The tarballs are made deterministically (sorted, mtime 0, owner 0, gzip -n).
#
# `check` fails unless the binary hashes equal docs/gitleaks-assets.sha256. The build is
# reproducible, so a mismatch means the recipe, the Go image, a module or the commit
# changed: update that file, and the copy in claude-plugin-guards, in the same change.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.." || exit 1
MODE="${1:?usage: gitleaks_assets.sh build|check OUTDIR}"
OUT="${2:?usage: gitleaks_assets.sh build|check OUTDIR}"
EXPECTED="${EXPECTED:-docs/gitleaks-assets.sha256}"
VER="$(sed -n 's/^ARG GITLEAKS_VERSION=v//p' Dockerfile.cpu | head -n 1)"
[ -n "$VER" ] || { echo "gitleaks_assets: cannot read GITLEAKS_VERSION from Dockerfile.cpu" >&2; exit 1; }
BINSUMS="$OUT/gitleaks-patched_${VER}_binary-sha256.txt"

case "$MODE" in
  build)
    command -v docker > /dev/null || { echo "gitleaks_assets: docker is required" >&2; exit 1; }
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    mkdir -p "$OUT"
    : > "$BINSUMS"
    for t in linux:amd64:x64 linux:arm64:arm64 darwin:amd64:x64 darwin:arm64:arm64; do
      IFS=: read -r os goarch name <<< "$t"
      dest="$work/${os}_${name}"
      DOCKER_BUILDKIT=1 docker build -q --target gitleaks-bin -f Dockerfile.cpu \
        --build-arg GOOS="$os" --build-arg GOARCH="$goarch" --output "type=local,dest=$dest" . > /dev/null || {
        echo "gitleaks_assets: build failed for $os/$goarch" >&2
        exit 1
      }
      chmod 0755 "$dest/gitleaks"
      printf '%s  %s_%s\n' "$(sha256sum "$dest/gitleaks" | cut -d' ' -f1)" "$os" "$name" >> "$BINSUMS"
      tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' -C "$dest" -cf - gitleaks \
        | gzip -n -9 > "$OUT/gitleaks-patched_${VER}_${os}_${name}.tar.gz"
    done
    (cd "$OUT" && sha256sum ./*.tar.gz | sed 's|  \./|  |' > "gitleaks-patched_${VER}_checksums.txt")
    echo "gitleaks_assets: built gitleaks $VER for 4 targets in $OUT"
    ;;
  check)
    [ -s "$BINSUMS" ] || { echo "gitleaks_assets: $BINSUMS missing (run build first)" >&2; exit 1; }
    want="$(grep -v '^[[:space:]]*#' "$EXPECTED" | grep . | sort)"
    got="$(sort "$BINSUMS")"
    if [ "$want" = "$got" ]; then
      echo "gitleaks_assets: binary hashes match $EXPECTED"
    else
      echo "gitleaks_assets: the built binaries differ from $EXPECTED" >&2
      diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") >&2
      echo "If the gitleaks recipe changed on purpose, update $EXPECTED and the copy in claude-plugin-guards." >&2
      exit 1
    fi
    ;;
  *)
    echo "usage: gitleaks_assets.sh build|check OUTDIR" >&2
    exit 2
    ;;
esac
