# Releasing a new version

Three stages. The first two are automated; the third requires real
arm64+GPU hardware, which GitHub Actions can't provide here (see
"Why the arm64 step isn't automated" below).

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

## 2. amd64 build (automated — triggered by the tag push)

The `push: tags: v*` trigger in `publish.yml` builds both `cpu` and
`gpu` variants for `linux/amd64` on GitHub-hosted runners and
publishes them to `:<variant>-amd64` / `:<variant>-amd64-vX.Y.Z` —
**not** the bare `:cpu`/`:gpu` tag. Publishing straight to the bare
tag here is the exact bug that shipped and broke every arm64 consumer
on 2026-10-19 (see that date's commits for the incident) — an
amd64-only image became "the" `:cpu` tag, and self-heal's fail-open
design on arm64 hosts silently kept serving a stale cached image
instead of erroring loudly.

Nothing to do here but wait for the Actions run to go green.

## 3. arm64 build (manual — do this yourself, or ask Claude to)

Build natively on real arm64+GPU hardware (`dgx-spark-01` is the
current one), tagged to match:

```
ssh dgx-spark-01
cd /tmp/guards-unified-build   # or wherever you keep the checkout
git fetch && git checkout vX.Y.Z   # or the tagged commit sha
echo "$(gh auth token)" | docker login ghcr.io -u <your-github-username> --password-stdin

docker build -f Dockerfile.cpu \
  -t ghcr.io/gramatr/guards-unified:cpu-arm64 \
  -t ghcr.io/gramatr/guards-unified:cpu-arm64-vX.Y.Z \
  -t ghcr.io/gramatr/guards-unified:cpu-arm64-sha-<commit> .
docker push ghcr.io/gramatr/guards-unified:cpu-arm64-vX.Y.Z

docker build -f Dockerfile \
  -t ghcr.io/gramatr/guards-unified:gpu-arm64 \
  -t ghcr.io/gramatr/guards-unified:gpu-arm64-vX.Y.Z \
  -t ghcr.io/gramatr/guards-unified:gpu-arm64-sha-<commit> .
docker push ghcr.io/gramatr/guards-unified:gpu-arm64-vX.Y.Z

docker logout ghcr.io   # shared host -- don't leave a token sitting in ~/.docker/config.json
```

Then merge the two halves into real multi-arch `:cpu`/`:gpu` tags:

```
gh workflow run publish.yml -f version=vX.Y.Z
```

That dispatches `merge-multiarch`, which runs
`docker buildx imagetools create` to combine `:<variant>-amd64-vX.Y.Z`
+ `:<variant>-arm64-vX.Y.Z` into the real multi-arch `:cpu`/`:gpu`
tags every consumer (e.g. `claude-plugin-guards`'
`guards/docker/docker-compose.yml`) actually pulls, then Trivy-scans
the result.

### After the merge, actually refresh running hosts

`docker compose pull` on a running host won't necessarily recreate
the container just because the registry's tag changed — if the
underlying platform-specific manifest for that host's architecture is
byte-identical to what's already cached (e.g. a merge that only added
a *different* architecture's image to the index), `up -d` may report
"Running" rather than "Recreated." That's correct, not a bug — but
don't assume a pull alone proves the host is current. Confirm with:

```
docker inspect ghcr.io/gramatr/guards-unified:cpu --format '{{index .RepoDigests 0}}'
curl -s http://127.0.0.1:8700/about   # should reflect the version just released
```

## Why the arm64 step isn't automated

`dgx-spark-01` **is** a registered, online, self-hosted GitHub Actions
runner (`gramatr` org, labels `self-hosted, Linux, ARM64, local-gpu,
sm87`) — it's not that no such runner exists. It's in the org's
**Default** runner group, which has `allows_public_repositories:
false` (confirmed via the GitHub API, 2026-10-19) — the same policy
that keeps `secret-guard`/`pii-guard`'s own CI on GitHub-hosted
runners instead of the `arc-runner-gramatr` pool. This repo is public,
so GitHub won't schedule a workflow job on `dgx-spark-01` for it
regardless of how `publish.yml` is written.

That's a real security boundary, not an oversight to route around: a
public repo's own CI workflow running on a self-hosted runner means
anyone who can get a workflow to execute against this repo (in the
worst case, a malicious fork PR, though this repo doesn't currently
run untrusted PR code) gets arbitrary code execution on real
infrastructure. Flipping `allows_public_repositories` to fix this
would expose every runner in the Default group — including
`kub-ai-01` and the whole `arc-runner-gramatr` ARC pool — not just
this one build step.

Plain SSH to the box, as described above, isn't a GitHub Actions job
at all, so this policy doesn't apply to it — which is why that's the
path here, not a self-hosted-runner `publish.yml` job. The "real" fix,
if this becomes enough of a bottleneck to justify it, is a separate
private repo that owns the arm64 build step and gets triggered via
`repository_dispatch` from this repo's `publish.yml` — keeping the
self-hosted runner's exposure scoped to a private, access-controlled
trigger rather than this public repo's own workflow surface. Not
built, since the manual SSH step works today and that's more
infrastructure than the problem currently justifies.
