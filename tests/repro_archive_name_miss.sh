#!/usr/bin/env bash
# tests/repro_archive_name_miss.sh -- reproduce the scanner miss fixed in v0.2.10.
#
# In v0.2.9 and earlier, app/scan.sh gave gitleaks its input in a temp file named by mktemp. gitleaks decides
# that a file is an archive from its NAME and then scans nothing, so a vendor-shaped value standing alone in a
# sentence came back unredacted when the random name began like an archive extension (about 1 in 156).
#
#   bash tests/repro_archive_name_miss.sh names SCAN_SH [GITLEAKS_DIR]
#       Forces the input file name the script uses and prints REDACTED or LEAKED for each name.
#   bash tests/repro_archive_name_miss.sh rate  SCAN_SH [GITLEAKS_DIR] [N]
#       Runs the script N times (default 400) with the real mktemp and counts unredacted outputs.
#
# SCAN_SH is the script under test: `git show v0.2.9:app/scan.sh > /tmp/scan-v0.2.9.sh` for the old one.
# GITLEAKS_DIR is a directory holding the gitleaks binary to use (default: the one on PATH); the released
# image carries its own at /usr/bin/gitleaks (`docker cp`). Expected: v0.2.9 LEAKS for names starting 7z, br,
# bz2, gz, lz4, rar, s2, sz, tar, xz, zip, zst, zz, and not for the two ordinary names; v0.2.10 and later never.
# The value is fabricated and assembled at run time. It stands alone in a sentence on purpose: written as
# `token = value`, a different rule redacts it and hides the miss.
set -uo pipefail

MODE="${1:-}"
SCAN="${2:-}"
GLDIR="${3:-}"
[ -n "$MODE" ] && [ -f "$SCAN" ] || { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
if [ -n "$GLDIR" ]; then PATH="$GLDIR:$PATH"; fi
command -v gitleaks > /dev/null 2>&1 || { echo "repro: gitleaks is not on PATH (and none in GITLEAKS_DIR)" >&2; exit 2; }
command -v jq > /dev/null 2>&1 || { echo "repro: jq is required by scan.sh" >&2; exit 2; }

VAL="ghp_""a1B2c3D4e5""a1B2c3D4e5""a1B2c3D4e5""a1B2c3D4e5"
TEXT="see $VAL here"

scan_once() { # scan_once [FORCED_NAME] -> prints REDACTED or LEAKED
  local out
  out="$(printf '%s' "$TEXT" | bash "$SCAN" 2> /dev/null)"
  case "$out" in *"$VAL"*) echo LEAKED ;; *) echo REDACTED ;; esac
}

case "$MODE" in
  once) scan_once ;;
  names)
    W="$(mktemp -d)"
    trap 'rm -rf "$W"' EXIT
    mkdir -p "$W/shim"
    REAL="$(command -v mktemp)"
    # A stand-in mktemp that returns the chosen name for the FIRST plain call (scan.sh's input file).
    cat > "$W/shim/mktemp" << EOF
#!/usr/bin/env bash
if [ "\$#" -eq 0 ] && [ -n "\${FORCE_NAME:-}" ] && [ ! -e "\$FORCE_DONE" ]; then
  : > "\$FORCE_DONE"; p="\${TMPDIR:-/tmp}/\$FORCE_NAME"; : > "\$p"; printf '%s\n' "\$p"; exit 0
fi
exec "$REAL" "\$@"
EOF
    chmod +x "$W/shim/mktemp"
    printf '%-22s %s\n' "forced name" "result"
    leaked=0
    for name in tmp.AbCdEfGhIj tmp.zAbCdEfGhI tmp.7zAbCdEfGh tmp.brAbCdEfGh tmp.bz2AbCdEfG tmp.gzAbCdEfGh \
      tmp.lz4AbCdEfG tmp.rarAbCdEfG tmp.s2AbCdEfGhI tmp.szAbCdEfGhI tmp.tarAbCdEfG tmp.xzAbCdEfGh \
      tmp.zipAbCdEfG tmp.zstAbCdEfG tmp.zzAbCdEfGh; do
      rm -f "$W/done"
      r="$(PATH="$W/shim:$PATH" FORCE_NAME="$name" FORCE_DONE="$W/done" scan_once)"
      printf '%-22s %s\n' "$name" "$r"
      [ "$r" = LEAKED ] && leaked=$((leaked + 1))
    done
    echo "leaked for $leaked of 15 names (the first two are ordinary names)"
    ;;
  rate)
    N="${4:-400}"
    echo "running $N scans with the real mktemp (this takes a while)"
    seq "$N" | xargs -P 8 -I{} bash "$0" once "$SCAN" "$GLDIR" | sort | uniq -c
    ;;
  *) echo "usage: $0 names|rate SCAN_SH [GITLEAKS_DIR] [N]" >&2; exit 2 ;;
esac
