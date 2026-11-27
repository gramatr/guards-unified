import os

# Env-driven config so the SAME container image serves both deployment
# targets: local `docker run` (auth off, loopback-bound) and the scaled
# grāmatr platform service (auth required, fronted by a load balancer).

HOST = os.environ.get("INJECTION_GUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("INJECTION_GUARD_PORT", "8730"))
MODEL_ID = os.environ.get(
    "INJECTION_GUARD_MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M"
)

# The model download is pinned to the revision this project evaluated, so an
# upstream change to the model repository cannot change the detector without a
# commit here. It applies only to the default model; another INJECTION_GUARD_MODEL_ID
# follows the repository default branch unless INJECTION_GUARD_MODEL_REVISION is set.
RECOMMENDED_MODEL_REVISION = "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"
_default_revision = (
    RECOMMENDED_MODEL_REVISION
    if MODEL_ID == "meta-llama/Llama-Prompt-Guard-2-86M"
    else "main"
)
MODEL_REVISION = os.environ.get("INJECTION_GUARD_MODEL_REVISION", _default_revision)

# When set, every request must carry `Authorization: Bearer <token>`.
# Leave unset for local trusted use (advanced Docker tier).
AUTH_TOKEN = os.environ.get("INJECTION_GUARD_AUTH_TOKEN")

# "auto" (default): use a GPU if one is actually visible to torch, CPU
# otherwise — opt-in, never required. "cpu"/"cuda" force a choice (cuda
# on a host with no GPU fails loudly at load time rather than silently
# falling back, so a misconfigured "cuda" is caught immediately).
# Measured on an RTX 4090 (see eval/compare_models.py --device cuda):
# ~59ms CPU vs ~12ms GPU per classification, ~1GB VRAM. Real speedup,
# but CPU is fine for the synchronous-hook use case — GPU only matters
# at the hosted tier's request volume. See README "CPU vs GPU".
DEVICE = os.environ.get("INJECTION_GUARD_DEVICE", "auto")


# --- Injection backend selection (local Prompt Guard 2 vs Azure Prompt Shields) ---
#
# The local Llama Prompt Guard 2 model is CPU-bound (~1,500 chars/sec) and the
# full-scan route hard-refuses text over SCAN_FULL_MAX_BYTES; a 210,909-char
# workbook was refused twice in prod (issue #101). Azure AI Content Safety
# Prompt Shields windows and parallelises large documents, so it can handle
# inputs the local model cannot.
#
# This was validated on only 28 synthetic cases, so Shields does NOT silently
# replace the local verdict. The backend is explicit:
#   "local"    (default) — only the local model; current behaviour, nothing changes.
#   "shields"            — Prompt Shields is the authoritative injection verdict.
#   "fallback"           — local model is authoritative, but Shields handles any
#                          input the local model cannot (too large, unavailable, or errors).
#   "parallel"           — both run; local stays authoritative, Shields runs
#                          alongside for comparison (divergences are logged, not acted on).
BACKEND = os.environ.get("INJECTION_GUARD_BACKEND", "local")

# Azure Content Safety Prompt Shields endpoint, e.g.
# "https://<resource-name>.cognitiveservices.azure.com". No default: production
# needs its own Content Safety resource + credentials (issue #101 open question),
# NOT the shared gramatr-phi4-test-resource raven evaluated against. Left unset,
# the Shields backends fail explicit (never "clean"), same posture as the rest
# of this service.
# TODO(#101): production resource + Bitwarden secret + ExternalSecret in
# prod-argocd-v2 pending Brian's decision on which Azure resource to use.
SHIELDS_ENDPOINT = os.environ.get("INJECTION_GUARD_SHIELDS_ENDPOINT")

# The key is read from the environment only, never hardcoded — same discipline
# as AUTH_TOKEN above. In the cluster this arrives via Bitwarden → ESO → k8s
# secret → env var.
SHIELDS_API_KEY = os.environ.get("INJECTION_GUARD_SHIELDS_API_KEY")

SHIELDS_API_VERSION = os.environ.get(
    "INJECTION_GUARD_SHIELDS_API_VERSION", "2024-09-01"
)

# Prompt Shields' real limit is 10,000 characters of documents per request in
# total (confirmed empirically in #101: 10,001 chars = HTTP 400). Window well
# under that, one window per request, with overlap so an injection phrase split
# at a boundary is still seen whole in the neighbouring window — same concern as
# the local model's CHUNK_OVERLAP, scaled for this much larger window.
SHIELDS_WINDOW_CHARS = int(
    os.environ.get("INJECTION_GUARD_SHIELDS_WINDOW_CHARS", "9000")
)
SHIELDS_WINDOW_OVERLAP = int(
    os.environ.get("INJECTION_GUARD_SHIELDS_WINDOW_OVERLAP", "200")
)

# Bounded fan-out: a large document becomes many windows, but we never open more
# than this many concurrent Azure calls at once (its own throughput limit, and
# ours — this process should not saturate the endpoint or itself).
SHIELDS_MAX_CONCURRENCY = int(
    os.environ.get("INJECTION_GUARD_SHIELDS_MAX_CONCURRENCY", "8")
)

# Per-request HTTP timeout (seconds). An uncapped call to a degraded endpoint is
# a latency cliff; a timeout surfaces as a non-clean "error" verdict, never "clean".
SHIELDS_TIMEOUT_SECONDS = float(
    os.environ.get("INJECTION_GUARD_SHIELDS_TIMEOUT_SECONDS", "10")
)
