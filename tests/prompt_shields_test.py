#!/usr/bin/env python3
"""Unit tests for the Azure Prompt Shields injection backend (issue #101).

Exercises the windowing, parallel fan-out and — most importantly — the strict
"anything other than an explicit clean verdict means no verdict" contract, with
httpx stubbed so no network or Azure credentials are needed. Fabricated values
only. Needs httpx (already a CI dependency).

    python3 tests/prompt_shields_test.py
"""

import sys
from pathlib import Path
from unittest import mock

APP = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP))

from injection_guard import config, prompt_shields

failures = []


def check(label, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}" + ("" if ok else f"  {detail}"))
    if not ok:
        failures.append(label)


# --- httpx stub -----------------------------------------------------------
# The module calls httpx.Client() as a context manager and client.post(...),
# then response.raise_for_status() and response.json(). The handler maps a
# single document (the window text) to a (status, payload) pair.


class FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, handler):
        self._handler = handler

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def post(self, url, params, headers, json, timeout):
        return self._handler(json["documents"][0])


def with_handler(handler):
    return mock.patch.object(
        prompt_shields.httpx, "Client", lambda: FakeClient(handler)
    )


def clean_payload(_window):
    return FakeResponse(200, {"documentsAnalysis": [{"attackDetected": False}]})


def attack_if_contains(needle):
    def handler(window):
        hit = needle in window
        return FakeResponse(200, {"documentsAnalysis": [{"attackDetected": hit}]})

    return handler


# --- config for the tests -------------------------------------------------
config.SHIELDS_ENDPOINT = "https://fake-resource.example"
config.SHIELDS_API_KEY = "fake-key-not-a-secret"
config.SHIELDS_WINDOW_CHARS = 10
config.SHIELDS_WINDOW_OVERLAP = 3
config.SHIELDS_MAX_CONCURRENCY = 4
config.SHIELDS_TIMEOUT_SECONDS = 1.0


print("backend selection")
config.BACKEND = "local"
check(
    "active_backend returns a valid configured backend",
    prompt_shields.active_backend() == "local",
)
check(
    "local backend does not route to Shields",
    not prompt_shields.shields_handles_injection(),
)
config.BACKEND = "parallel"
check("parallel backend routes to Shields", prompt_shields.shields_handles_injection())
config.BACKEND = "nonsense"
check(
    "an unknown backend falls back to local, not an error",
    prompt_shields.active_backend() == "local",
)
config.BACKEND = "shields"

print("windowing")
windows = prompt_shields._windows(
    "abcdefghijklmnopqrstuvwxyz"
)  # 26 chars, size 10, step 7
check("long text is split into overlapping windows", len(windows) > 1, len(windows))
check(
    "no window exceeds the configured size",
    all(len(w) <= 10 for w in windows),
    [len(w) for w in windows],
)
check(
    "consecutive windows overlap so a boundary phrase stays whole",
    any("gh" in w for w in windows) and windows[0].endswith("ghij"),
    windows,
)
check("short text is a single window", prompt_shields._windows("abc") == ["abc"])
check("empty text yields no windows", prompt_shields._windows("   ") == [])

print("clean and malicious verdicts")
with with_handler(clean_payload):
    res = prompt_shields.classify("abcdefghijklmnopqrstuvwxyz")
check("all-clean windows → not malicious", res["malicious"] is False, res)
check(
    "chunks_scanned reflects the window count",
    res["chunks_scanned"] == len(windows),
    res,
)

with with_handler(attack_if_contains("stuv")):
    res = prompt_shields.classify("abcdefghijklmnopqrstuvwxyz")
check(
    "any window flagged → malicious (any match flags it)", res["malicious"] is True, res
)
check("a malicious verdict carries the parity score", res["score"] == 1.0, res)

with with_handler(clean_payload):
    res = prompt_shields.classify("")
check(
    "empty input is explicitly clean, zero chunks",
    res == {"malicious": False, "label": "BENIGN", "score": 0.0, "chunks_scanned": 0},
    res,
)

print("strict contract: nothing but an explicit clean verdict is clean")


def _raises(handler, label):
    try:
        with with_handler(handler):
            prompt_shields.classify("abcdefghijklmnopqrstuvwxyz")
    except Exception:  # noqa: BLE001 — the contract is "raises something, not clean"
        check(label, True)
    else:
        check(label, False, "expected an exception, got a verdict")


_raises(lambda w: FakeResponse(400, {}), "an HTTP 400 raises (never clean)")
_raises(
    lambda w: FakeResponse(200, {"wrong": "shape"}),
    "a response without documentsAnalysis raises",
)
_raises(
    lambda w: FakeResponse(200, {"documentsAnalysis": [{"attackDetected": "yes"}]}),
    "a non-boolean attackDetected raises",
)
_raises(
    lambda w: FakeResponse(200, {"documentsAnalysis": []}),
    "an empty documentsAnalysis raises",
)


def _one_window_fails(window):
    # The last window errors; the strict contract says the whole call must fail.
    if window == windows[-1]:
        return FakeResponse(503, {})
    return FakeResponse(200, {"documentsAnalysis": [{"attackDetected": False}]})


_raises(
    _one_window_fails, "one failing window fails the whole classification, not clean"
)

print("not configured fails explicit")
saved = config.SHIELDS_ENDPOINT
config.SHIELDS_ENDPOINT = None
try:
    prompt_shields.classify("abc")
    check("an unconfigured endpoint raises rather than returning clean", False)
except RuntimeError:
    check("an unconfigured endpoint raises rather than returning clean", True)
finally:
    config.SHIELDS_ENDPOINT = saved

print("FAIL" if failures else "ok", f"- {len(failures)} failure(s)")
sys.exit(1 if failures else 0)
