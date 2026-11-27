"""The injection axis through Azure AI Content Safety Prompt Shields instead of the local model.

Selected with INJECTION_GUARD_BACKEND=azure_prompt_shields (see docs/CONFIGURATION.md). The default backend is still the local Llama Prompt Guard 2 model; nothing here runs unless
that variable is set.

What it does with a text:
  * Cuts it into windows of at most WINDOW_CHARS UTF-16 code units (the service refuses more than 10,000 characters of documents in one request; 9,000 leaves room), each window
    overlapping the one before by OVERLAP_CHARS so an instruction cannot hide on a boundary.
  * Asks the service about the windows a few at a time (CONCURRENCY). One flagged window flags the whole text at once.
  * Fails closed: ANY failure (no endpoint or key, a timeout, a non-200, an answer that is not the expected JSON, a window the service refuses) raises, and the caller turns that into
    verdict `error`, which no caller may read as clean. There is no path from a failure to `malicious=False`.

It never logs or returns the text, a window or the key; an exception names only a short fixed code.

What leaves the process: every window of the text goes to the configured Azure endpoint over HTTPS (plain HTTP is accepted only for a loopback address, for tests). That is the one thing
this backend changes about the service's data handling; see docs/THREAT-MODEL.md.
"""

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import urlparse

BACKEND_NAME = "azure_prompt_shields"
# The service's own limit is 10,000 characters of documents per request. Stay under it; counted in UTF-16 code units, which is the stricter way to count an emoji.
SERVICE_LIMIT_CHARS = 10_000
USER_PROMPT = "Summarize the document."  # the API requires a user prompt; this one is fixed and carries nothing about the file


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return min(max(value, low), high)


def _env_float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        return default
    return min(max(value, low), high)


def _settings() -> dict:
    endpoint = (
        (os.environ.get("INJECTION_GUARD_AZURE_ENDPOINT") or "").strip().rstrip("/")
    )
    key = os.environ.get("INJECTION_GUARD_AZURE_KEY") or ""
    return {
        "endpoint": endpoint,
        "key": key,
        "api_version": (
            os.environ.get("INJECTION_GUARD_AZURE_API_VERSION") or "2024-09-01"
        ).strip(),
        "window": _env_int("INJECTION_GUARD_AZURE_WINDOW_CHARS", 9000, 1000, 9500),
        "overlap": _env_int("INJECTION_GUARD_AZURE_OVERLAP_CHARS", 500, 0, 2000),
        "concurrency": _env_int("INJECTION_GUARD_AZURE_CONCURRENCY", 8, 1, 32),
        "timeout": _env_float(
            "INJECTION_GUARD_AZURE_TIMEOUT_SECONDS", 15.0, 1.0, 120.0
        ),
        "total": _env_float("INJECTION_GUARD_AZURE_TOTAL_SECONDS", 120.0, 1.0, 900.0),
    }


def load() -> None:
    """Called once at startup, like model.load_model(): checks the configuration and raises if it cannot work, so GUARDS_REQUIRE_AXES decides what happens. No call is made to Azure."""
    s = _settings()
    if not s["endpoint"] or not s["key"]:
        raise RuntimeError(
            "azure_prompt_shields needs INJECTION_GUARD_AZURE_ENDPOINT and INJECTION_GUARD_AZURE_KEY"
        )
    parsed = urlparse(s["endpoint"])
    loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise RuntimeError("INJECTION_GUARD_AZURE_ENDPOINT must be an https:// address")
    if not parsed.hostname:
        raise RuntimeError("INJECTION_GUARD_AZURE_ENDPOINT is not an address")
    if s["overlap"] >= s["window"]:
        raise RuntimeError(
            "INJECTION_GUARD_AZURE_OVERLAP_CHARS must be smaller than the window"
        )


def _units(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def windows(text: str, size: int, overlap: int) -> list:
    """Cut `text` into overlapping windows of at most `size` UTF-16 code units. Every character is inside at least one window; neighbours share about `overlap` characters."""
    if not text.strip():
        return []
    out, start, n = [], 0, len(text)
    while start < n:
        end = min(n, start + size)
        while (
            end > start + 1 and _units(text[start:end]) > size
        ):  # astral characters count twice
            end = start + max(
                1, (end - start) * size // max(_units(text[start:end]), 1)
            )
        out.append(text[start:end])
        if end >= n:
            break
        start = max(start + 1, end - overlap)
    return out


class _Refused(Exception):
    pass


def _ask(window: str, s: dict, deadline: float) -> bool:
    """True if the service says this window is an attack. Raises on anything else."""
    url = f"{s['endpoint']}/contentsafety/text:shieldPrompt?api-version={s['api_version']}"
    body = json.dumps({"userPrompt": USER_PROMPT, "documents": [window]}).encode(
        "utf-8"
    )
    attempt = 0
    while True:
        left = deadline - time.monotonic()
        if left <= 0.05:
            raise _Refused("azure_deadline")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Ocp-Apim-Subscription-Key": s["key"],
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=min(s["timeout"], left)) as resp:
                if getattr(resp, "status", 200) != 200:
                    raise _Refused("azure_status")
                answer = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if (
                attempt == 0
                and exc.code in (429, 500, 502, 503, 504)
                and deadline - time.monotonic() > 2.0
            ):
                attempt = 1
                time.sleep(1.0)
                continue
            raise _Refused(f"azure_http_{exc.code}") from None
        except (OSError, TimeoutError, ValueError):
            if attempt == 0 and deadline - time.monotonic() > 2.0:
                attempt = 1
                time.sleep(1.0)
                continue
            raise _Refused("azure_unreachable") from None
        docs = answer.get("documentsAnalysis") if isinstance(answer, dict) else None
        if (
            not isinstance(docs, list)
            or len(docs) != 1
            or not isinstance(docs[0], dict)
            or not isinstance(docs[0].get("attackDetected"), bool)
        ):
            raise _Refused("azure_bad_answer")
        return docs[0]["attackDetected"]


def classify(text: str) -> dict:
    """Same shape as model.classify(): {malicious, label, score, chunks_scanned}. `score` is None (the service gives a yes or no). Raises on any failure."""
    s = _settings()
    load()
    parts = windows(text, s["window"], s["overlap"])
    if not parts:
        return {
            "malicious": False,
            "label": "BENIGN",
            "score": None,
            "chunks_scanned": 0,
        }
    deadline = time.monotonic() + s["total"]
    pool = ThreadPoolExecutor(max_workers=min(s["concurrency"], len(parts)))
    try:
        pending = {pool.submit(_ask, w, s, deadline) for w in parts}
        while pending:
            left = deadline - time.monotonic()
            done, pending = wait(
                pending, timeout=max(left, 0), return_when=FIRST_COMPLETED
            )
            if not done:
                raise _Refused("azure_deadline")
            for fut in done:
                if fut.result():  # raises the first failure
                    return {
                        "malicious": True,
                        "label": "MALICIOUS",
                        "score": None,
                        "chunks_scanned": len(parts),
                    }
        return {
            "malicious": False,
            "label": "BENIGN",
            "score": None,
            "chunks_scanned": len(parts),
        }
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
