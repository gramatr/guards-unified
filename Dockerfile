# guards-unified/Dockerfile — GPU-capable default. Same app code as
# Dockerfile.cpu, but installs the default torch wheel (bundles the
# full NVIDIA CUDA runtime) instead of the CPU-only index, so
# injection-guard's model can opt into a real GPU via
# INJECTION_GUARD_DEVICE=auto (default — see app/injection_guard/config.py)
# wherever one is actually visible to torch. Falls back to CPU
# automatically when no GPU is present, same "auto" logic as standalone
# injection-guard. Use Dockerfile.cpu instead on a host with no GPU and
# no plan to ever add one (smaller image, no CUDA packages).
#
# Multi-arch (linux/amd64, linux/arm64) — DO NOT cross-build this one
# under QEMU emulation (`docker buildx build --platform amd64,arm64`
# in one invocation): a CUDA-bundled torch install under emulation is
# extremely slow and was abandoned after running far longer than the
# equivalent native build on real hardware. Build each architecture
# NATIVELY on its own real hardware instead, then combine:
#   # on an amd64 host with an NVIDIA GPU:
#   docker build -t ghcr.io/gramatr/guards-unified:gpu-amd64 -f Dockerfile . && docker push ...
#   # on an arm64 host with an NVIDIA GPU (e.g. a GB10/Grace-Blackwell node):
#   docker build -t ghcr.io/gramatr/guards-unified:gpu-arm64 -f Dockerfile . && docker push ...
#   # then, from either host:
#   docker buildx imagetools create -t ghcr.io/gramatr/guards-unified:gpu \
#     ghcr.io/gramatr/guards-unified:gpu-amd64 ghcr.io/gramatr/guards-unified:gpu-arm64
#
# Verified for real on BOTH architectures, not just "it builds": built
# and ran this exact image on an x86_64 host with an NVIDIA RTX 4090
# attached, and separately, natively (not emulated), on an aarch64
# self-hosted runner (NVIDIA GB10 / Grace-Blackwell). On both, the
# startup log line from injection_guard.model's own device resolution reads
# "Loading ... on cuda" (not "cpu"), and a real /v1/scan call returns
# correct results. The standard PyPI torch wheel's CUDA support DOES
# work on GB10 natively — that was an open question before this was
# tested, not an assumption.
#
# Each install step below reuses the EXACT recipe already proven in
# that project's own Dockerfile, not a guess at how to combine them:
#   - gitleaks binary copy: secret-guard's docker/Dockerfile
#   - default (CUDA-bundled) torch wheel: injection-guard's own
#     docker/Dockerfile (the non-.cpu variant)
#   - en_core_web_lg as a direct wheel URL, not `spacy download`:
#     pii-guard's pyproject.toml comment explains why the download-step
#     form breaks under `uv`/non-interactive installs

# Base images are pinned by tag and digest; refresh with docs/CONFIGURATION.md, Supply chain.
FROM golang:1.26-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS gitleaks
ARG GITLEAKS_VERSION=v8.30.1
# The commit the release tag points at (checked 2026-10-21). A tag can be moved; a commit cannot.
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
# Built from the release tag with fixed Go modules instead of copying the
# official image's binary: v8.30.1 is the latest release but bundles
# klauspost/compress, x/crypto, x/text and a Go stdlib with known HIGH CVEs. The
# xz and rardecode bumps and x/crypto v0.56.0 clear the MEDIUM findings Trivy reported
# on the v0.2.10 rehearsal image.
# Drop the `go get` once gitleaks ships a release that carries the fixes.
RUN git init -q /src && cd /src \
    && git remote add origin https://github.com/gitleaks/gitleaks.git \
    && git fetch -q --depth 1 origin "${GITLEAKS_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD
WORKDIR /src
# GOOS/GOARCH are unset for the image build (Go then builds for this machine). The release
# workflow sets them to build the standalone binaries it attaches for hosts without Docker
# (issue #55); the recipe below is the same one that builds the image's binary.
ARG GOOS
ARG GOARCH
RUN go get github.com/klauspost/compress@v1.18.7 golang.org/x/crypto@v0.56.0 golang.org/x/text@v0.41.0 \
       github.com/ulikunitz/xz@v0.5.15 github.com/nwaples/rardecode/v2@v2.2.0 github.com/mholt/archives@v0.1.5 \
    && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" -o /usr/bin/gitleaks .

# Export-only stage: just the binary, for `docker build --target gitleaks-bin --output ...`
# (the release workflow's standalone gitleaks assets, issue #55). Not part of the image.
FROM scratch AS gitleaks-bin
COPY --from=gitleaks /usr/bin/gitleaks /gitleaks

FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/gitleaks
# upgrade, not just install -- see Dockerfile.cpu's comment
# (CVE-2026-84782 in libssl3t64, found the same way).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends jq bash \
    && rm -rf /var/lib/apt/lists/*

# Remove the base image's own pip. It is 25.0.1 with six published CVEs, and upgrading it is no fix:
# pip 26.2 bundles urllib3, setuptools and msgpack copies that Trivy reports (3 HIGH) and that
# cannot be updated separately. The service installs with uv into /app/.venv and never calls
# this pip (found by the v0.2.10 rehearsal scan).
RUN python -m pip uninstall -y pip

# Pinned by tag and digest; bump both together (docs/CONFIGURATION.md, Supply chain).
COPY --from=ghcr.io/astral-sh/uv:0.13.3@sha256:bee0a2a458fd956c5df7b8b4c5fed2257b0af34866e3da7b51db0be3acb375d1 /uv /uvx /usr/local/bin/

WORKDIR /app
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Default torch wheel (CUDA-bundled) — no CPU-only index override, so
# the resolver pulls whatever torch's own default distribution ships,
# same as injection-guard's own GPU-capable Dockerfile.
# cryptography/setuptools/wheel/jaraco.context floors below aren't
# app dependencies -- they're pulled in transitively, and CI's Trivy
# image scan (2026-10-18, against Dockerfile.cpu) found each one's
# resolved version behind a disclosed CVE (CVE-2026-69247/69249,
# CVE-2025-47273, CVE-2026-24049, CVE-2026-23949). Pinning floors here
# too, not just letting the resolver pick, so this variant can't
# silently regress to the same vulnerable versions.
# filelock joined them on 2026-10-25: 3.32.3 was behind CVE-2026-112940 (HIGH,
# fixed in 4.2.1, which needs Python 3.11+; the image runs 3.12).
RUN uv pip install --python /app/.venv/bin/python \
      "fastapi>=0.115" "uvicorn[standard]>=0.30" "torch>=2.2" "transformers>=4.44" \
      "presidio-analyzer>=2.2" "presidio-anonymizer>=2.2" "spacy>=3.7" \
      "cryptography>=50.0.0" "setuptools>=78.1.1" "wheel>=0.46.2" "jaraco.context>=6.1.0" \
      "filelock>=4.2.1" \
      "en-core-web-lg @ https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"

COPY app/ ./
# So a running container can report what it actually is via /about --
# see app/main.py's GUARDS_UNIFIED_VERSION. Without this, a stale pull
# is invisible from the outside: /health only ever says "ok."
COPY VERSION ./
RUN chmod +x scan.sh report.sh

# The Llama 4 Community License requires a copy of the license text to
# accompany any redistribution. The /about endpoint (app/main.py) only
# covers the *runtime-visible* half of that obligation -- someone who
# `docker pull`s this image, never the git repo, needs these files
# inside the image itself, not just committed to the repo they'll
# never clone. Into /app/licenses/, not /app/ root, so they can't
# collide with or be mistaken for application files.
COPY LICENSE NOTICE /app/licenses/
COPY THIRD_PARTY_LICENSES/ /app/licenses/THIRD_PARTY_LICENSES/

# Non-root — same fix and same fixed UID/GID as Dockerfile.cpu (see its
# comment for why). Verified this doesn't break GPU device access as a
# non-root user before shipping it, not assumed — see this PR's own
# description for the real nvidia-smi/CUDA confirmation.
RUN groupadd -g 1000 guards && useradd -u 1000 -g guards -d /app -s /usr/sbin/nologin guards \
    && mkdir -p /app/.cache/huggingface /app/metrics \
    && chown -R guards:guards /app
USER guards

ENV HF_HOME=/app/.cache/huggingface
# "auto": use a GPU if torch actually sees one, CPU otherwise — see
# app/injection_guard/config.py. Deliberately NOT forced to cpu here,
# unlike Dockerfile.cpu.

EXPOSE 8700

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8700/health', timeout=3)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8700"]
