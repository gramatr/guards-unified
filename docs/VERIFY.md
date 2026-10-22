# Verify it yourself

You do not have to trust this page. Every release of guards-unified is built by one
GitHub Actions workflow, and the image and the standalone gitleaks files carry signed
statements about how they were built and what is in them. This page shows how to check
those statements, what each one proves, and what none of them proves.

Every command below was run against the v0.2.10 release on 2026-10-22. The output you
get for a later release will show its own version and digest. You need the
[GitHub CLI](https://cli.github.com/) (`gh`; these were run with 2.100.0) signed in with
`gh auth login`, and `docker` for the image checks.

## 1. Was this image built by this repository's workflow?

```
gh attestation verify oci://ghcr.io/gramatr/guards-unified:cpu-v0.2.10 --repo gramatr/guards-unified
echo "exit code: $?"
```

Exit code `0` means the signature checks out and names this repository. **`gh` prints
nothing when its output is not a terminal, even on success**, so in a script look at the
exit code, or ask for JSON to see what was verified:

```
gh attestation verify oci://ghcr.io/gramatr/guards-unified:cpu-v0.2.10 --repo gramatr/guards-unified --format json \
  | jq -r '.[0].verificationResult | .statement.subject[0].digest.sha256, .signature.certificate.buildSignerURI'
```

For v0.2.10 the second line was
`https://github.com/gramatr/guards-unified/.github/workflows/publish.yml@refs/tags/v0.2.10`:
the publish workflow, run for that tag. Check that the repository, the workflow file and
the tag are the ones you expect. The first line is the image digest the statement is
about; it should equal the digest in step 3.

A wrong claim must fail. Asking for a different repository exits non-zero (it exited `1`
for `--repo gramatr/not-this-repo`).

The same works for the GPU image (`gpu-v0.2.10`).

## 2. What is inside it?

The SBOM (software bill of materials, SPDX 2.3, written by syft) is signed against the
same image digest:

```
gh attestation verify oci://ghcr.io/gramatr/guards-unified:cpu-v0.2.10 --repo gramatr/guards-unified \
  --predicate-type https://spdx.dev/Document/v2.3 --format json \
  | jq '.[0].verificationResult.statement.predicate.packages | length'
```

For v0.2.10 that is 1,406 packages, and it equals the count in `sbom-cpu.spdx.json`
attached to the release. You can search it for a package you care about, for example
`jq -r '.packages[].name' sbom-cpu.spdx.json | grep -i openssl`.

## 3. Is the image I run the one I verified?

```
docker buildx imagetools inspect ghcr.io/gramatr/guards-unified:cpu-v0.2.10
```

The `Digest:` line (`sha256:310ea771...` for v0.2.10 cpu) must equal the one in the
attestation (step 1), the release page, and the floating `:cpu` tag when that release is
the latest. A tag is a name that can be moved; the digest is the fingerprint of the content.

## 4. The standalone gitleaks for hosts without Docker

Each release also carries a patched gitleaks for linux and darwin, amd64 and arm64, built from
the same recipe as the image. Each file has its own attestation:

```
gh release download v0.2.10 -R gramatr/guards-unified -p 'gitleaks-patched_8.30.1_linux_x64.tar.gz'
gh attestation verify gitleaks-patched_8.30.1_linux_x64.tar.gz --repo gramatr/guards-unified
```

Changing one byte of the file makes this exit `1` (tested). The plugin's self-heal script
additionally checks the unpacked binary against SHA-256 values that ship with the plugin
(`guards/vendor/secret-guard-core/gitleaks-assets.sha256`), not against a value served beside
the download.

## 5. What do the vulnerability scans say?

The release page lists what the image scans still report, and the full Trivy reports are
attached (`trivy-cpu.json`, `trivy-gpu.json`: every severity, no ignore file). To redo the
scan yourself:

```
trivy image --scanners vuln ghcr.io/gramatr/guards-unified:cpu-v0.2.10
```

## What this proves, and what it does not

| It proves | It does not prove |
|---|---|
| This repository's `publish.yml` produced this image, for this tag, from this commit. | That the code is free of bugs or malice. A signed build of bad code is still signed. |
| The contents listed in the SBOM were in the image when it was built. | That every component is free of vulnerabilities. See the scan, and the table on the release page. |
| The file or image you hold is byte-for-byte what was signed. | That GitHub, Sigstore or the runner were not themselves compromised. |
| The build inputs were fixed: base images by digest, gitleaks by commit, Actions by SHA. | That the injection model you download at runtime is the one that was evaluated: model weights are not signed or hash-checked by this project. |

Images before the release that first carried attestations (v0.2.10) have none.

## Running what you verified

The default setup favours getting fixes quickly: the plugin's Docker Compose file runs the
floating `:cpu` tag, and a Watchtower container pulls it every five minutes. That means you
trust the registry and the workflow **at every pull**, and you are not checking each new image
yourself. The release notes for v0.2.10 show why that matters: a scanner fix reached users
within minutes of the publish.

If you would rather decide when to move, run the service from a digest:

- Start it yourself, outside the plugin's cache directory, from an image reference of the form
  `ghcr.io/gramatr/guards-unified@sha256:<digest you verified>`, on `127.0.0.1:8700`, with your
  own env file for `HF_TOKEN`, **without** the Watchtower label, and with no Watchtower.
- The plugin's self-heal script leaves a guards-unified container that is not from its own
  compose file alone (`tests/guards-selfheal.test.sh`: "a guards-unified container outside the
  plugin cache is not removed"). Point `GUARDS_ENDPOINT` at yours if it is not on the default port.
- To update, verify the new release (steps 1 to 3), then change the digest and restart.

This recipe is assembled from those pieces. The pieces are tested; running a digest-pinned
container end to end was not done for this page, because the service needs a gated model
download and a token.

## Decision for the maintainer

The default is the floating tag with automatic updates, and a digest pin is the documented way
out. A third option, having the self-heal script verify the attestation before it starts a newly
pulled image, would remove the trust-at-every-pull gap for users who want it, at the cost of
requiring `gh` on every host. It is not built. See [TRADEOFFS.md](TRADEOFFS.md) for the recorded
decision and its cost.
