# Releasing a new version

Publishing is fully automated from a tag push. A release is cut jointly with
`claude-plugin-guards` (the two packages move in lockstep, see
[below](#versions-move-in-lockstep-with-claude-plugin-guards)), so the human
steps are a version bump in **both** repos, then a tag in each. Add the
release to [CHANGELOG.md](../CHANGELOG.md) in the same pull request as the bump.

## 1. Bump VERSION and tag, in both repos

1. In **each** repo (`guards-unified` and `claude-plugin-guards`), open a pull
   request that sets `VERSION` to the same `X.Y.Z` (and makes whatever code
   change prompted the release, or no code change if this is just a rebuild to
   pick up a base-image security patch). In this repo's PR, also add the
   CHANGELOG entry.
2. Merge both to `main`. Before tagging, confirm `VERSION` is identical in
   the two repos: neither repo's CI can see the other.
3. Tag the exact merge commit in each repo, not just whatever is on `main`.
   Tag the plugin first (its tag is only a label and its tag-check CI is
   cheap), then this repo, whose tag push is the one that publishes:
   ```
   git tag -a vX.Y.Z -m "..." <merge-commit-sha>
   git push origin vX.Y.Z
   ```
   Both repos have a check that the pushed tag equals `VERSION` on that commit
   (`verify-tag-matches-version` in this repo's `publish.yml`) and fail loudly
   if not.

## 2. What happens automatically

The tag push in this repo triggers `publish.yml`, which:

1. **`build-amd64`**: GitHub-hosted runners build both `cpu`/`gpu`
   variants for `linux/amd64`, publish to `:<variant>-amd64-vX.Y.Z` (not the
   bare tag, see "Why not the bare tag" below), and Trivy-scan each.
2. **`build-arm64`**: a self-hosted arm64 GPU runner builds both variants
   natively (no QEMU), publishes to `:<variant>-arm64-vX.Y.Z`, and Trivy-scans
   each. Runs in parallel with `build-amd64`.
3. **`merge-multiarch`**: once both succeed, combines each variant's amd64 and
   arm64 image into one multi-arch image under a staging tag
   (`:<variant>-staging-vX.Y.Z`) via `docker buildx imagetools create`, and then,
   in this order:
   1. Trivy-scans the merged image.
   2. Generates an SBOM (Syft, SPDX JSON) and attests build provenance and the
      SBOM against the merged image's digest (GitHub attestations, signed through
      Sigstore, pushed to the registry), then verifies both with
      `gh attestation verify`.
   3. Only then promotes the same digest to `:<variant>-vX.Y.Z` and the floating
      `:cpu` / `:gpu`, and checks that both tags point at the attested digest.

   A failed scan, a failed attestation or a failed verification fails the job
   before either tag moves, so an unscanned or unsigned image is never the one
   users pull (decided 2026-10-21, issue #51). The cost: an outage of the signing
   service blocks a release until the job is re-run (see the manual recovery path).
   The `build-*` jobs still publish per-architecture tags that carry no
   attestation; only the merged index is attested. This applies to releases built
   after this pipeline change, starting with the release after v0.2.9; images
   from earlier releases carry no attestation.

4. **`release`**: after `merge-multiarch` succeeds for both variants, creates the
   GitHub Release for the tag, from CI and not by hand. It runs
   `tests/release_evidence.sh` (the `## [X.Y.Z]` section of `CHANGELOG.md` as the
   notes, and the test suites with their own summary lines, including the redaction
   self-test run against the published CPU image), runs a full Trivy scan of each
   published image with every severity and no ignore file, downloads the SBOMs
   written by the signing step, and attaches `trivy-cpu.json`, `trivy-gpu.json`,
   `sbom-cpu.spdx.json`, `sbom-gpu.spdx.json` and `test-counts.txt`. The page also
   lists the image digests and the `gh attestation verify` commands. Only this job
   has `contents: write`. A failed publish therefore leaves no release page. A
   re-run after this job failed part-way updates the existing page instead of
   failing on it.

   The changelog check runs first, in `verify-tag-matches-version`: a tag whose
   version has no `## [X.Y.Z]` section in `CHANGELOG.md` stops the run before any
   image is published. Add the section in the version-bump PR.

Nothing to do here but watch the Actions run go green.

### Tags that exist

For each variant (`cpu`, `gpu`):

| Tag | Meaning |
|---|---|
| `<variant>` | Floats to the latest release. Written only by `merge-multiarch`. |
| `<variant>-vX.Y.Z` | The multi-arch image for that release. Pin this for reproducible deployments. Written only after the image is scanned and attested. |
| `<variant>-staging-vX.Y.Z` | The merged image before scanning and attestation. Not for deployment; a leftover one means a release run stopped before promotion. |
| `<variant>-amd64`, `<variant>-arm64` | Latest per-architecture build. |
| `<variant>-amd64-vX.Y.Z`, `<variant>-arm64-vX.Y.Z` | Per-architecture build for a release (the inputs to the merge). |
| `<variant>-sha-<commit>`, `<variant>-arm64-sha-<commit>` | Per-commit builds. |

A deployment that auto-updates from the floating tag (the `claude-plugin-guards`
Compose file runs Watchtower for this) follows `:cpu` as soon as
`merge-multiarch` finishes.

### Manual recovery path

If `merge-multiarch` itself needs re-running (both halves already built and
pushed, but the merge step failed or needs a retry) without rebuilding either
half:

```
gh workflow run publish.yml -f version=vX.Y.Z
```

### After release, confirm running hosts actually picked it up

`docker compose pull` on a running host will not necessarily recreate the
container just because the registry's tag changed: if the platform-specific
manifest for that host's architecture is byte-identical to what is already
cached, `up -d` may report "Running" rather than "Recreated". That is correct,
not a bug, but do not assume a pull alone proves the host is current. Confirm
with:

```
docker inspect ghcr.io/gramatr/guards-unified:cpu --format '{{index .RepoDigests 0}}'
curl -s http://127.0.0.1:8700/about   # should reflect the version just released
```

Also check that both architectures are in the merged manifest:

```
docker buildx imagetools inspect ghcr.io/gramatr/guards-unified:cpu-vX.Y.Z
```

## Why not the bare tag for the amd64-only build

Publishing straight to the bare `:cpu` / `:gpu` tag from `build-amd64` is a bug
that has shipped once: an amd64-only image became "the" `:cpu` tag and broke
every arm64 consumer, and the plugin's self-heal (which fails open on arm64
hosts) silently kept serving a stale cached image instead of erroring loudly.
The bare tags are now only ever written by `merge-multiarch`, as a real
multi-arch manifest.

## The arm64 runner

GitHub will not schedule a job from a public repo on a self-hosted runner in a
runner group that disallows public repositories, and that is a real security
boundary: a public repo's CI running on a self-hosted runner means anyone who can
get a workflow to execute against the repo gets code execution on that host.
So the arm64 build runs on a runner in a narrowly scoped runner group that
contains only that runner and is restricted to exactly this repo and
`claude-plugin-guards`; the organisation's default runner group stays closed to
public repositories. The `Pipeline check` workflow (below) is `workflow_dispatch`
only, with no `pull_request` trigger, for the same reason.

## Releases that were never made

### `v0.2.0` was never released

The `v0.2.0` tag was pushed before the work for that release was finished, and
its Publish run was cancelled before `merge-multiarch`, so `:cpu` / `:gpu` never
moved. The tag still points at an older commit and the cancelled run left two
amd64-only images in the package, `cpu-amd64-v0.2.0` and `gpu-amd64-v0.2.0`,
which contain **old code**. Do not use that tag or those images. As of v0.2.3
they were still in the package. A published tag is never deleted and re-created
here: it would rewrite a ref other people may have fetched, so a burned version
number is simply skipped. The two stray images can be deleted in the package UI
(select the versions tagged `*-v0.2.0`).

### `0.2.1` was never tagged

`0.2.1` was only ever the `VERSION` value on `main` for a few hours. Both
numbers are skipped, and the next release is `v0.2.2`, which is also the first
release under the lockstep rule below.

## Versions move in lockstep with claude-plugin-guards

`guards-unified` and `claude-plugin-guards` are one product shipped as two
packages, so **they carry the same version and the same tag**: a release is
`vX.Y.Z` on both repos, cut together. Nobody should have to know which package
is "the highest". The rules:

- Cut a release by bumping `VERSION` in **both** repos in a PR each, merging
  both, then tagging each merge commit `vX.Y.Z` (step 1 above). This repo's tag
  push publishes the image; the plugin repo's tag is a label (plugin installs
  track `main` and are identified by commit).
- Both repos have a CI check that a pushed `vX.Y.Z` tag equals `VERSION` at the
  tagged commit, so a mismatched tag fails loudly. Neither repo's CI can see the
  other, so keeping the two numbers equal is a release-checklist step.
- Plugin-only or service-only changes between releases do not get their own
  number; they ride the next joint release.
- Because the plugin carries a vendored copy of `app/scan.sh`, every change to
  `scan.sh` here needs a matching sync in the plugin repo. The plugin's CI job
  `scan-sh-drift` (`guards/tests/scan-sh-drift.sh` there) fetches `app/scan.sh`
  from this repo's `main` (or, on a plugin tag build, the same tag when it
  exists) and fails if the vendored copy differs by even one character, apart
  from its two-line header. Merge order for a scanner change: this repo's PR
  first, then re-run the plugin PR's checks. Run it locally with
  `SERVER_REF=<branch> bash guards/tests/scan-sh-drift.sh` in the plugin repo.

## If this repo is ever deleted and recreated

This happened once, on 2026-10-19, and PR numbers in this repo restarted at #1.
Two settings live outside the code and are lost with the repo. Neither has a
REST API, so both are manual:

1. **Package link.** In the `guards-unified` package page
   (`github.com/orgs/gramatr/packages/container/guards-unified`):
   *Connect repository* to this repo, then under the package's
   *Settings → Manage Actions access* add this repo with the **Write** role.
2. **Runner group.** An org admin must add this repo to the restricted runner
   group that holds the arm64 runner (org *Settings → Actions → Runner
   groups*), or `build-arm64` waits forever for a runner.

Then run the **Pipeline check** workflow (Actions tab → *Pipeline check* →
*Run workflow*). It tests both settings without publishing a release or
touching `:cpu` / `:gpu`: one job pushes an empty scratch image to `:link-check`
using `GITHUB_TOKEN`, the other runs on the arm64 runner. If the registry job
fails with `permission_denied: write_package`, re-check step 1.

## Verify where an image came from

For a release built with the attestation step, with `gh` installed and logged in:

```
gh attestation verify oci://ghcr.io/gramatr/guards-unified:cpu-vX.Y.Z --repo gramatr/guards-unified
gh attestation verify oci://ghcr.io/gramatr/guards-unified:cpu-vX.Y.Z --repo gramatr/guards-unified --predicate-type https://spdx.dev/Document/v2.3
```

The first checks the build provenance, the second the SBOM attestation. Replace
`cpu` with `gpu` for the GPU image. To read the SBOM itself, add `--format json`
and read the predicate, or download the `sbom-<variant>.spdx.json` artifact from
the Publish run.

What this proves: the image was built by this repository's `publish.yml` from
the tagged commit, and the SBOM lists what the build put into it. What it does
not prove: that the code is free of bugs or malice, or that the image has no
vulnerabilities (the Trivy scan covers known ones). Do not rely on a
release for this until the Publish run for it shows the attestation steps green;
`pipeline-check` (the `attest-check` job) proves the signing path without a
release.

## Verify a release live

After the hosts have updated (`/about` shows the new version on each), run the
self-test against the running service, not just CI's copy of the image:

```
python3 tests/redaction_selftest.py --endpoint http://127.0.0.1:8700
```

Every required case must pass: a secret finding must never come back with
unchanged text, and the key, DSN, header, flag and credential-file shapes must
all be redacted. The harmless-lookalike cases must stay byte-identical. The
opt-in switches `SECRET_GUARD_REDACT_KEY_IDS` and `SECRET_GUARD_ENV_VALUES`
(along with `SECRET_GUARD_B64` and `SECRET_GUARD_SKIP_GITLEAKS`) are covered by
`tests/scan_options_test.sh`; `tests/run-all.sh` runs everything CI can run
locally.

Note what this does not verify: the self-test asserts on the secret axis only.
The PII and injection axes are covered by the real-model E2E below. See
[LIMITS.md](LIMITS.md#testing-gaps).

### Release checklist: real-model E2E

`.github/workflows/e2e.yml` builds the CPU image on the arm64 runner, starts
it with the repository secret `HF_TOKEN` (the injection model is gated) and
runs `tests/e2e_real_models_test.py`. A tag push starts it alongside
`publish.yml`, but it is **advisory, not a `needs:` of publish**: a missing or
expired `HF_TOKEN` would otherwise block every release. So, as a checklist
step: open the "E2E (real models)" run for the tag and confirm it is green
(re-run it with workflow_dispatch if it is not). If it fails with "HF_TOKEN
missing", a maintainer has to create that secret first. Against an already
running service the same test is
`python3 tests/e2e_real_models_test.py --endpoint http://127.0.0.1:8700`.

Cancelling a release: cancel the Publish run before `merge-multiarch` finishes.
The bare `:cpu` / `:gpu` tags change only in that final step, so nothing running
on a host is affected. A pushed tag is not deleted by cancelling the run.
