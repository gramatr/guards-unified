#!/usr/bin/env bash
# tests/release_body_test.sh -- the release page promises what a reader needs.
#
# Runs tests/release_body.sh on synthetic scan data (no real image, no real finding) and checks:
# the verify section says to check the exit code and shows the JSON form; each HIGH advisory is
# listed once however many packages and both images carry it; an advisory with no reviewed note is
# shown as "not yet assessed" and not left out; a finding with a published fix is called out as our
# defect; nothing from the scan except advisory ids, package names and counts reaches the page.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/release_body.sh"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
has() { grep -qF -- "$2" "$1"; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
A="$W/assets"
mkdir -p "$A"
printf '## [9.9.9] - 2026-01-01\n\n- Fixed: something.\n' > "$A/release-notes.md"
printf 'suite one: 3 passed\n' > "$A/test-counts.txt"

python3 -I - "$A" <<'PY'
import json, sys

d = sys.argv[1]


def vuln(vid, pkg, sev, status="affected", fixed=None):
    v = {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "Severity": sev,
        "Status": status,
        "PkgPath": "/synthetic/path/that/must/not/appear",
    }
    if fixed:
        v["FixedVersion"] = fixed
    return v


def report(extra=()):
    rows = [vuln("CVE-0000-0001", p, "HIGH") for p in ("pkg-a", "pkg-b", "pkg-c", "pkg-d", "pkg-e", "pkg-f")]
    rows += [vuln("CVE-0000-0002", "pkg-g", "HIGH", "fix_deferred")]
    rows += [vuln("CVE-0000-0003", "pkg-h", "MEDIUM"), vuln("CVE-0000-0004", "pkg-i", "LOW")]
    rows += list(extra)
    return {"Results": [{"Vulnerabilities": rows}]}


json.dump(report(), open(f"{d}/trivy-cpu.json", "w"))
json.dump(report(), open(f"{d}/trivy-gpu.json", "w"))
json.dump(
    report([vuln("CVE-0000-0005", "pkg-j", "MEDIUM", "fixed", "2.0")]),
    open(f"{d}/trivy-cpu-fixable.json", "w"),
)
PY

printf '# test notes\nCVE-0000-0001\tA reviewed sentence for the first advisory.\n' > "$W/notes.tsv"
body() { bash "$SCRIPT" v9.9.9 sha256:cpudigest sha256:gpudigest "$A" "$W/notes.tsv" > "$W/body.md" 2> "$W/err"; }

body && ok || bad "release_body.sh runs on a clean fixture ($(cat "$W/err"))"
has "$W/body.md" '## [9.9.9]' && ok || bad "the changelog section opens the page"
has "$W/body.md" 'ghcr.io/gramatr/guards-unified:cpu-v9.9.9` (`sha256:cpudigest`)' && ok || bad "the cpu digest is listed"
has "$W/body.md" 'ghcr.io/gramatr/guards-unified:gpu-v9.9.9` (`sha256:gpudigest`)' && ok || bad "the gpu digest is listed"
has "$W/body.md" 'check the exit code' && ok || bad "the verify section says to check the exit code"
has "$W/body.md" 'prints nothing when its output is not a terminal' && ok || bad "the verify section says why"
has "$W/body.md" '--format json' && ok || bad "the verify section shows the JSON form"
has "$W/body.md" 'suite one: 3 passed' && ok || bad "the test counts are included"

# Once each, however many packages and both images carry it.
[ "$(grep -c '^| CVE-0000-0001 ' "$W/body.md")" -eq 1 ] && ok || bad "a flaw in six packages and two images is one row"
has "$W/body.md" '`pkg-a`, `pkg-b`, `pkg-c`, `pkg-d` and 2 more' && ok || bad "a long package list is shortened and counted"
has "$W/body.md" 'A reviewed sentence for the first advisory.' && ok || bad "a reviewed note is shown"
# Negative control: no note, so it must be called out, not omitted.
grep '^| CVE-0000-0002 ' "$W/body.md" | grep -qF 'not yet assessed' && ok || bad "an advisory with no reviewed note says 'not yet assessed'"
grep '^| CVE-0000-0002 ' "$W/body.md" | grep -qF 'fix deferred' && ok || bad "a deferred fix is described as deferred"
! grep -qF 'CVE-0000-0003' "$W/body.md" && ok || bad "a MEDIUM advisory is counted, not listed"
has "$W/body.md" 'Distinct advisories by severity: 2 HIGH, 1 MEDIUM, 1 LOW.' && ok || bad "the severity counts are right"
has "$W/body.md" '0 of them have a fixed version published' && ok || bad "no fixable advisory is reported as none"
! has "$W/body.md" 'our defect' && ok || bad "no 'our defect' section when nothing is fixable"
! has "$W/body.md" '/synthetic/path/that/must/not/appear' && ok || bad "no path from the scan reaches the page"

# A finding with a published fix is called out.
cp "$A/trivy-cpu-fixable.json" "$A/trivy-cpu.json"
body && ok || bad "release_body.sh runs when something is fixable"
has "$W/body.md" 'Fixed upstream but still in the image' && ok || bad "a fixable finding is called out"
has "$W/body.md" '- CVE-0000-0005 (MEDIUM): `pkg-j`' && ok || bad "the fixable advisory is named"

echo "release-body: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
