"""
Loads Llama Prompt Guard 2 ONCE at process startup and classifies text as
benign or malicious (prompt injection / jailbreak attempt). Binary
classifier, no injection sub-labels (per Meta's model card).

512-token input limit — longer text is split into chunks and classified
independently; ANY chunk flagged malicious flags the whole input, same
"any match flags it" posture as secret-guard's redaction logic.
"""

import logging

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from injection_guard import config
from injection_guard.config import MODEL_ID

logger = logging.getLogger("injection_guard")

_tokenizer = None
_model = None
_device = None


def _resolve_device() -> str:
    """"auto": use CUDA if torch actually sees a GPU, else CPU — opt-in,
    never required (see config.py). "cpu"/"cuda" force the choice; a
    forced "cuda" with no GPU present fails loudly here rather than
    silently falling back, so a misconfigured deploy is caught at
    startup, not discovered later as "why is this slow"."""
    if config.DEVICE == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    if config.DEVICE == "cuda" and not torch.cuda.is_available():
        raise RuntimeError(
            "INJECTION_GUARD_DEVICE=cuda but torch.cuda.is_available() is False — "
            "no GPU visible to this process. Fix the deployment (GPU not "
            "passed through, drivers missing, wrong base image) or set "
            "INJECTION_GUARD_DEVICE=auto/cpu instead of forcing cuda."
        )
    return config.DEVICE

MAX_TOKENS = 512
CHUNK_OVERLAP = 32  # avoid splitting an injection phrase exactly at a chunk boundary

# eval/compare_models.py: 86M scores 93.8% accuracy (1 FN) vs 22M's 68.8%
# (5 FN, including 2/3 non-English cases) for ~40ms of latency that
# doesn't matter in a synchronous hook. INJECTION_GUARD_MODEL_ID stays
# overridable (useful once a future Prompt Guard version exists) but
# ANY value other than this one downgrades real detection coverage with
# no eval behind it — that must be loud, never silent.
RECOMMENDED_MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"


def load_model() -> None:
    """Called once at daemon startup — this is the only place model weights
    are loaded. Never call this per-request."""
    global _tokenizer, _model, _device
    if _model is not None:
        return
    if MODEL_ID != RECOMMENDED_MODEL_ID:
        logger.warning(
            "INJECTION_GUARD_MODEL_ID=%s overrides the eval-verified default (%s). "
            "No accuracy data exists for this model in this project — see "
            "eval/compare_models.py before trusting it in production.",
            MODEL_ID, RECOMMENDED_MODEL_ID,
        )
    _device = _resolve_device()
    logger.info(
        "Loading %s on %s (this happens once, not per request)", MODEL_ID, _device
    )
    _tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    _model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID).to(_device)
    _model.eval()


#  model.config.id2label on this checkpoint is the generic {0: "LABEL_0",
#  1: "LABEL_1"} placeholder, NOT "BENIGN"/"MALICIOUS" as Meta's model
#  card text implies — confirmed empirically (not from docs) against
#  both the 86M and 22M checkpoints: index 0 is benign, index 1 is
#  malicious, consistently. A string match against "MALICIOUS" here
#  silently never fires — this is exactly that bug, fixed.
MALICIOUS_INDEX = 1
BENIGN_INDEX = 0


def _classify_chunk(text: str) -> tuple[str, float]:
    inputs = _tokenizer(
        text, return_tensors="pt", truncation=True, max_length=MAX_TOKENS
    ).to(_device)
    with torch.no_grad():
        logits = _model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    pred_id = int(probs.argmax().item())
    label = "MALICIOUS" if pred_id == MALICIOUS_INDEX else "BENIGN"
    score = float(probs[pred_id].item())
    return label, score


def classify(text: str) -> dict:
    """Returns {malicious: bool, label: str, score: float, chunks_scanned: int}.
    `label`/`score` describe the highest-confidence malicious chunk if any
    chunk was flagged, otherwise the first chunk's result."""
    if _model is None:
        raise RuntimeError("load_model() was not called before classify()")

    token_ids = _tokenizer(text, add_special_tokens=False)["input_ids"]
    if len(token_ids) <= MAX_TOKENS:
        chunks = [text]
    else:
        step = MAX_TOKENS - CHUNK_OVERLAP
        chunks = [
            _tokenizer.decode(token_ids[i : i + MAX_TOKENS])
            for i in range(0, len(token_ids), step)
        ]

    results = [_classify_chunk(chunk) for chunk in chunks]
    malicious_results = [r for r in results if r[0].upper() == "MALICIOUS"]

    if malicious_results:
        label, score = max(malicious_results, key=lambda r: r[1])
        return {
            "malicious": True,
            "label": label,
            "score": score,
            "chunks_scanned": len(chunks),
        }

    label, score = results[0]
    return {
        "malicious": False,
        "label": label,
        "score": score,
        "chunks_scanned": len(chunks),
    }
