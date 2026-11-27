"""
Azure AI Content Safety Prompt Shields as a pluggable injection-detection
backend, alongside the local Llama Prompt Guard 2 model (model.py).

Why this exists: the local model is CPU-bound (~1,500 chars/sec) and the full
scan route hard-refuses text over SCAN_FULL_MAX_BYTES, which refused a
210,909-char workbook twice in production (issue #101). Prompt Shields windows a
large document into pieces and classifies them in parallel, so it handles inputs
the local model cannot.

Strict contract, identical to the rest of this service: anything other than an
explicit clean verdict means NO verdict. A call that errors, times out, returns
an unexpected shape, or returns a non-boolean `attackDetected` is raised, not
treated as clean — the caller (`main._classify_injection`) turns any exception
into verdict "error", which is non-clean by design. Only when EVERY window
returns an explicit `attackDetected: false` is the text clean. ANY window with
`attackDetected: true` flags the whole input ("any match flags it").

Returns the same dict shape as model.classify() so the two backends are
interchangeable at the call site:
    {malicious: bool, label: str, score: float, chunks_scanned: int}
`score` is not meaningful for Shields (it returns a boolean, not a probability);
it is reported as 1.0 for a detected attack and 0.0 otherwise, for shape parity.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

import httpx

from injection_guard import config

logger = logging.getLogger("injection_guard.prompt_shields")

VALID_BACKENDS = frozenset({"local", "shields", "fallback", "parallel"})

# Prompt Shields' documented path; the api-version the service was built against
# is config.SHIELDS_API_VERSION.
_SHIELD_PATH = "/contentsafety/text:shieldPrompt"


def active_backend() -> str:
    """The configured injection backend, validated. An unrecognised value is a
    misconfiguration we refuse to guess through: fall back to "local" (the safe,
    unchanged behaviour) and say so loudly, rather than silently sending traffic
    to an endpoint the operator did not mean to enable."""
    backend = config.BACKEND
    if backend not in VALID_BACKENDS:
        logger.warning(
            "INJECTION_GUARD_BACKEND=%r is not one of %s — falling back to 'local'",
            backend,
            sorted(VALID_BACKENDS),
        )
        return "local"
    return backend


def shields_handles_injection() -> bool:
    """True when the active backend routes any injection decision through Prompt
    Shields. Used by the scan route to decide whether the SCAN_FULL_MAX_BYTES
    ceiling still needs to refuse large text for the injection axis."""
    return active_backend() in ("shields", "fallback", "parallel")


def _windows(text: str) -> list[str]:
    """Split text into overlapping windows no larger than SHIELDS_WINDOW_CHARS.
    Whitespace-only windows are dropped: an empty document is a 400 from Shields
    and cannot carry an injection anyway."""
    size = config.SHIELDS_WINDOW_CHARS
    overlap = config.SHIELDS_WINDOW_OVERLAP
    if size <= 0:
        raise ValueError("INJECTION_GUARD_SHIELDS_WINDOW_CHARS must be positive")
    if overlap < 0 or overlap >= size:
        raise ValueError(
            "INJECTION_GUARD_SHIELDS_WINDOW_OVERLAP must be in [0, window_chars)"
        )
    if len(text) <= size:
        return [text] if text.strip() else []
    step = size - overlap
    windows = [text[i : i + size] for i in range(0, len(text), step)]
    return [w for w in windows if w.strip()]


def _shield_window(client: httpx.Client, window: str) -> bool:
    """POST one window to Prompt Shields and return its attackDetected boolean.
    Raises on any non-clean outcome (HTTP error, timeout, unexpected shape,
    missing/non-boolean verdict) so the strict contract holds: the caller must
    never read a thrown error as clean."""
    url = config.SHIELDS_ENDPOINT.rstrip("/") + _SHIELD_PATH
    response = client.post(
        url,
        params={"api-version": config.SHIELDS_API_VERSION},
        headers={"Ocp-Apim-Subscription-Key": config.SHIELDS_API_KEY},
        json={"documents": [window]},
        timeout=config.SHIELDS_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    analyses = payload.get("documentsAnalysis")
    if not isinstance(analyses, list) or len(analyses) != 1:
        raise ValueError(
            "Prompt Shields response missing a single-element documentsAnalysis"
        )
    detected = analyses[0].get("attackDetected")
    if detected is True or detected is False:
        return detected
    raise ValueError("Prompt Shields attackDetected is missing or not a boolean")


def classify(text: str) -> dict:
    """Classify text via Prompt Shields, windowing and fanning out large inputs.

    Raises if Shields is not configured or any window fails to return an explicit
    verdict — the caller converts that into a non-clean "error" result."""
    if not config.SHIELDS_ENDPOINT or not config.SHIELDS_API_KEY:
        raise RuntimeError(
            "Prompt Shields backend selected but "
            "INJECTION_GUARD_SHIELDS_ENDPOINT / INJECTION_GUARD_SHIELDS_API_KEY "
            "are not set — refusing to return a verdict without a configured endpoint"
        )

    windows = _windows(text)
    if not windows:
        # Empty / whitespace-only input carries no injection. Explicitly clean.
        return {
            "malicious": False,
            "label": "BENIGN",
            "score": 0.0,
            "chunks_scanned": 0,
        }

    workers = max(1, min(config.SHIELDS_MAX_CONCURRENCY, len(windows)))
    with httpx.Client() as http_client, ThreadPoolExecutor(max_workers=workers) as pool:
        # map() re-raises the first worker exception here, so one failed window
        # aborts the whole classification into a non-clean error.
        detections = list(pool.map(lambda w: _shield_window(http_client, w), windows))

    malicious = any(detections)
    return {
        "malicious": malicious,
        "label": "MALICIOUS" if malicious else "BENIGN",
        "score": 1.0 if malicious else 0.0,
        "chunks_scanned": len(windows),
    }
