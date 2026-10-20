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
