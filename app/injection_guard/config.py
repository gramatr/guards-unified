import os

# Env-driven config so the SAME container image serves both deployment
# targets: local `docker run` (auth off, loopback-bound) and the scaled
# grāmatr platform service (auth required, fronted by a load balancer).

HOST = os.environ.get("INJECTION_GUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("INJECTION_GUARD_PORT", "8730"))
MODEL_ID = os.environ.get("INJECTION_GUARD_MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")

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
