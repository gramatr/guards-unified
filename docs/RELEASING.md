# Releasing a new version

Fully automated as of 2026-10-19 (see "History" below). You only do
step 1; the rest happens from a tag push.

## 1. Bump VERSION and tag

1. Open a PR that bumps `VERSION` (and makes whatever code change
   prompted the release — or no code change, if this is just a
   rebuild to pick up a base-image security patch).
2. Merge it to `main`.
3. Tag that exact merge commit, not just whatever's on `main`:
   ```
   git tag -a vX.Y.Z -m "..." <merge-commit-sha>
   git push origin vX.Y.Z
   ```
   `publish.yml`'s `verify-tag-matches-version` job fails loudly if
   the tag doesn't match `VERSION` on that commit.

## 2. What happens automatically

The tag push triggers `publish.yml`, which:

1. **`build-amd64`** — GitHub-hosted runners build both `cpu`/`gpu`
   variants for `linux/amd64`, publish to `:<variant>-amd64-vX.Y.Z`
   (not the bare tag — see "Why not the bare tag" below), Trivy-scans
   each.
2. **`build-arm64`** — `dgx-spark-01` (real arm64 + GPU hardware, a
   self-hosted Actions runner) builds both variants natively, no
   QEMU, publishes to `:<variant>-arm64-vX.Y.Z`, Trivy-scans each.
   Runs in parallel with `build-amd64`.
3. **`merge-multiarch`** — once both succeed, combines each variant's
   amd64 + arm64 image into the real multi-arch `:cpu`/`:gpu` tags
   every consumer (e.g. `claude-plugin-guards`'
   `guards/docker/docker-compose.yml`) actually pulls, via
   `docker buildx imagetools create`. Trivy-scans the merged result
   too.

Nothing to do here but watch the Actions run go green.

### Manual recovery path

If `merge-multiarch` itself needs re-running (both halves already
built and pushed, but the merge step failed or needs a retry) without
rebuilding either half:

```
gh workflow run publish.yml -f version=vX.Y.Z
```

### After release, confirm running hosts actually picked it up

`docker compose pull` on a running host won't necessarily recreate
the container just because the registry's tag changed — if the
underlying platform-specific manifest for that host's architecture is
byte-identical to what's already cached, `up -d` may report "Running"
rather than "Recreated." That's correct, not a bug — but don't assume
a pull alone proves the host is current. Confirm with:

```
docker inspect ghcr.io/gramatr/guards-unified:cpu --format '{{index .RepoDigests 0}}'
curl -s http://127.0.0.1:8700/about   # should reflect the version just released
```

## Why not the bare tag for the amd64-only build

Publishing straight to the bare `:cpu`/`:gpu` tag from `build-amd64`
is the exact bug that shipped and broke every arm64 consumer on
2026-10-19 — an amd64-only image became "the" `:cpu` tag, and
`claude-plugin-guards`' self-heal fail-open design on arm64 hosts
silently kept serving a stale cached image instead of erroring loudly.
The bare tags are now only ever written by `merge-multiarch`, as a
real multi-arch manifest.

## History: why this used to be manual, and how it got fixed

`dgx-spark-01` is a registered, online, self-hosted GitHub Actions
runner (`gramatr` org, labels `self-hosted, Linux, ARM64, local-gpu,
sm87`). Until 2026-10-19 it sat in the org's **Default** runner group,
which has `allows_public_repositories: false` (the same policy that
keeps `secret-guard`/`pii-guard`'s own CI on GitHub-hosted runners
instead of the `arc-runner-gramatr` pool) — GitHub refused to schedule
a workflow job there for this public repo regardless of how
`publish.yml` was written, so the arm64 build was done by SSHing into
the box by hand for every release.

That's a real security boundary, not something to route around
casually: a public repo's own CI workflow running on a self-hosted
runner means anyone who can get a workflow to execute against the repo
gets arbitrary code execution on real infrastructure. The fix wasn't
to flip `allows_public_repositories` on the Default group — that would
have exposed every runner in it, including `kub-ai-01` and the whole
`arc-runner-gramatr` ARC pool, not just this one build step.

Instead: filed a request with Argo (`n90-co/prod-argocd-v2#3207`) for
a narrowly-scoped runner group. They created `dgx-arm64-public`,
containing only `dgx-spark-01`, `allows_public_repositories: true`,
restricted to exactly this repo and `claude-plugin-guards` — confirmed
live via the GitHub API (`dgx-spark-01` out of Default, `kub-ai-01`
and the ARC pool untouched, still `allows_public_repositories: false`)
before `publish.yml` was updated to actually use the runner
(`runs-on: [self-hosted, ARM64, local-gpu]` in `build-arm64`).

## If this repo is ever deleted and recreated

Two settings live outside the code and are lost with the repo (this
happened 2026-10-19). Neither has a REST API, so both are manual:

1. **Package link.** In the `guards-unified` package page
   (`github.com/orgs/gramatr/packages/container/guards-unified`):
   *Connect repository* to this repo, then under the package's
   *Settings → Manage Actions access* add this repo with the **Write**
   role.
2. **Runner group.** An org admin must add this repo to the
   `dgx-arm64-public` runner group (org *Settings → Actions → Runner
   groups*), or `build-arm64` waits forever for a runner.

Then run the **Pipeline check** workflow (Actions tab → *Pipeline
check* → *Run workflow*). It tests both settings without publishing a
release or touching `:cpu`/`:gpu`: one job pushes an empty scratch image
to `:link-check` using `GITHUB_TOKEN`, the other runs on the arm64
runner. If the registry job fails with `permission_denied:
write_package`, re-check step 1.
