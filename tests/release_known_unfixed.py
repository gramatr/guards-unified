#!/usr/bin/env python3
"""Markdown section for the release page: what the image scans still report, and why.

    python3 tests/release_known_unfixed.py NOTES.tsv TRIVY.json [TRIVY.json ...]

Reads the full Trivy reports attached to a release (all severities, no ignore file) and
prints a section that counts the findings, lists every HIGH or CRITICAL flaw once (not once
per package that ships it), says whether a fix is published, and adds a short reviewed
assessment from NOTES.tsv (CVE id, a tab, one sentence). A flaw with no reviewed note is
shown as "not yet assessed", never left out. Anything with a published fix that is still in
the image is listed on its own, because that one is a defect of ours, not of Debian.

Counts only and advisory ids: no path, host or value from the image is printed.
"""

import json
import sys
from pathlib import Path

ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
STATUS_TEXT = {
    "affected": "no fix published",
    "fix_deferred": "fix deferred by the distribution",
    "will_not_fix": "distribution will not fix",
    "fixed": "fix available",
}


def load_notes(path):
    notes = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cve, _, note = line.partition("\t")
        notes[cve.strip()] = note.strip()
    return notes


def load_rows(paths):
    rows = []
    for p in paths:
        data = json.loads(Path(p).read_text())
        for result in data.get("Results") or []:
            rows.extend(result.get("Vulnerabilities") or [])
    return rows


def packages(pkgs):
    names = sorted(pkgs)
    if len(names) <= 4:
        return ", ".join(f"`{n}`" for n in names)
    return ", ".join(f"`{n}`" for n in names[:4]) + f" and {len(names) - 4} more"


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    notes = load_notes(argv[1])
    per_image = [load_rows([p]) for p in argv[2:]]
    rows = load_rows(argv[2:])
    # The same flaw in the cpu and the gpu image is one flaw: key on the advisory id.
    flaws = {}
    for r in rows:
        f = flaws.setdefault(
            r["VulnerabilityID"],
            {"sev": r["Severity"], "pkgs": set(), "status": set(), "fixed": False},
        )
        f["pkgs"].add(r["PkgName"])
        f["status"].add(r.get("Status") or "affected")
        f["fixed"] = f["fixed"] or bool(r.get("FixedVersion"))
        if ORDER.get(r["Severity"], 9) < ORDER.get(f["sev"], 9):
            f["sev"] = r["Severity"]

    rows_per_image = max((len(r) for r in per_image), default=0)
    fixable = {k: f for k, f in flaws.items() if f["fixed"]}
    by_sev = {}
    for f in flaws.values():
        by_sev[f["sev"]] = by_sev.get(f["sev"], 0) + 1

    out = ["", "### What the image scans still report", ""]
    out.append(
        f"The attached Trivy scans list {rows_per_image} rows per image, which are "
        f"{len(flaws)} distinct advisories: a flaw is listed once for every package that ships it. "
        f"{len(fixable)} of them have a fixed version published; "
        f"{len(flaws) - len(fixable)} do not. The ones without a fix are in the base image's "
        "Debian packages and cannot be patched by rebuilding. Nothing is suppressed: "
        "`.trivyignore` is empty and the scans use every severity."
    )
    out.append("")

    high = sorted(
        (k for k, f in flaws.items() if f["sev"] in ("CRITICAL", "HIGH")),
        key=lambda k: (ORDER[flaws[k]["sev"]], k),
    )
    if high:
        out += [
            "| Advisory | Severity | Packages | Status | Assessment |",
            "|---|---|---|---|---|",
        ]
        for k in high:
            f = flaws[k]
            status = ", ".join(
                STATUS_TEXT.get(str(s), str(s)) for s in sorted(f["status"])
            )
            note = notes.get(k, "not yet assessed")
            out.append(
                f"| {k} | {f['sev']} | {packages(f['pkgs'])} | {status} | {note} |"
            )
        out += [
            "",
            (
                "Assessments are read from the advisory text and the container's setup (one "
                "non-root process, loopback only in the plugin's compose file). They were not "
                "tested against the image."
            ),
            "",
        ]
    else:
        out += ["No HIGH or CRITICAL advisories.", ""]

    rest = ", ".join(
        f"{by_sev[s]} {s}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        if s in by_sev
    )
    out.append(f"Distinct advisories by severity: {rest or 'none'}.")
    if fixable:
        out += [
            "",
            "**Fixed upstream but still in the image** (this is our defect to fix):",
            "",
        ]
        for k in sorted(fixable):
            out.append(f"- {k} ({fixable[k]['sev']}): {packages(fixable[k]['pkgs'])}")
    out.append("")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
