#!/usr/bin/env bash
# tests/release_body.sh -- the GitHub Release page body, assembled from the run's outputs.
#
#   bash tests/release_body.sh TAG CPU_DIGEST GPU_DIGEST ASSETS_DIR NOTES_TSV > release-body.md
#
# ASSETS_DIR holds what the evidence and scan steps wrote: release-notes.md, trivy-cpu.json,
# trivy-gpu.json and test-counts.txt. The body is the changelog section, the image digests, how to
# verify them (including that `gh attestation verify` prints nothing when it is not a terminal),
# what the image scans still report and why, and the attached evidence.
#
# It lives in a script, not inline in publish.yml, so tests/release_body_test.sh can check the
# text a reader is promised.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${1:?usage: release_body.sh TAG CPU_DIGEST GPU_DIGEST ASSETS_DIR NOTES_TSV}"
CPU="${2:?}"
GPU="${3:?}"
DIR="${4:?}"
NOTES="${5:?}"
IMG="ghcr.io/gramatr/guards-unified"

cat "$DIR/release-notes.md"
printf '\n---\n\n### Images\n\n'
printf -- '- `%s:cpu-%s` (`%s`)\n' "$IMG" "$TAG" "$CPU"
printf -- '- `%s:gpu-%s` (`%s`)\n' "$IMG" "$TAG" "$GPU"

printf '\n### Verify where it came from\n\n```\n'
printf 'gh attestation verify oci://%s:cpu-%s --repo gramatr/guards-unified\n' "$IMG" "$TAG"
printf 'gh attestation verify oci://%s:cpu-%s --repo gramatr/guards-unified --predicate-type https://spdx.dev/Document/v2.3\n' "$IMG" "$TAG"
printf '```\n\n'
printf 'Attestations show which workflow built the image and what is in it. They do not show that the code is free of bugs or malice.\n\n'
printf '**In a script, check the exit code.** `gh attestation verify` prints nothing when its output is not a terminal, even when it succeeds. Exit code 0 means it verified; anything else means it did not. To see what was verified, ask for JSON:\n\n```\n'
printf 'gh attestation verify oci://%s:cpu-%s --repo gramatr/guards-unified --format json \\\n' "$IMG" "$TAG"
printf '  | jq -r '"'"'.[0].verificationResult | .statement.subject[0].digest.sha256, .signature.certificate.buildSignerURI'"'"'\n'
printf '```\n\n'
printf 'The first line is the image digest, which must equal the one listed under Images. The second names the workflow that built it.\n'

python3 "$HERE/release_known_unfixed.py" "$NOTES" "$DIR/trivy-cpu.json" "$DIR/trivy-gpu.json"

printf '### Attached evidence\n\n'
printf -- '- `trivy-cpu.json`, `trivy-gpu.json`: full Trivy image scans, all severities, no ignore file.\n'
printf -- '- `sbom-cpu.spdx.json`, `sbom-gpu.spdx.json`: SPDX SBOMs.\n'
printf -- '- `gitleaks-patched_*`: standalone patched gitleaks for hosts without Docker (linux and darwin, amd64 and arm64), their checksums and binary hashes, with build provenance. `gh attestation verify <file> --repo gramatr/guards-unified` checks one.\n'
printf -- '- `test-counts.txt`: suite results for this commit:\n\n```\n'
cat "$DIR/test-counts.txt"
printf '```\n'
