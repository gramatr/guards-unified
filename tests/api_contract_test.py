#!/usr/bin/env python3
"""API contract tests for app/main.py with the two models stubbed out.

The real PII and injection models are gated and heavy, so CI cannot start the
full service. These tests pin the parts of the contract that do not depend on a
model: request size limits and what happens when an axis fails. Needs fastapi,
httpx and pydantic; needs neither the models nor gitleaks. Fabricated values
only.

    python3 tests/api_contract_test.py
"""

import datetime
import importlib
import os
import sys
import tempfile
import types
from pathlib import Path

from fastapi.testclient import TestClient

if not hasattr(datetime, "UTC"):  # python < 3.11
    datetime.UTC = datetime.timezone.utc  # noqa: UP017

APP = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP))
os.environ["METRICS_PATH"] = str(Path(tempfile.mkdtemp()) / "metrics.jsonl")
os.environ["SCAN_FULL_MAX_BYTES"] = "2000"
os.environ["SCAN_SECRET_MAX_BYTES"] = "5000"

pii_fail = {"on": False}


def _analyze_and_redact(text):
    if pii_fail["on"]:
        raise ValueError("stubbed PII engine failure")
    return {
        "found": "Alice Example" in text,
        "redacted_text": text.replace("Alice Example", "<PERSON>"),
        "entities": [{"entity_type": "PERSON"}] if "Alice Example" in text else [],
    }


def _stub(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    sys.modules[name] = mod


_stub("pii_guard")
_stub("pii_guard.engine", analyze_and_redact=_analyze_and_redact)
_stub("injection_guard")
_stub(
    "injection_guard.model",
    classify=lambda t: {"malicious": False, "score": 0.99, "chunks_scanned": 1},
    config=types.SimpleNamespace(MODEL_ID="stub/model", MODEL_REVISION="stub-revision"),
)

main = importlib.import_module("main")  # after the stubs are in place

client = TestClient(main.app, raise_server_exceptions=False)
TEXT = "owner: Alice Example\n"
failures = []


def check(label, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}" + ("" if ok else f"  {detail}"))
    if not ok:
        failures.append(label)


def verdicts(resp):
    return {f["type"]: f["verdict"] for f in resp.json()["findings"]}


print("about")
r = client.get("/about")
check("/about reports the model and the pinned revision", r.status_code == 200 and r.json().get("model") == "stub/model" and r.json().get("model_revision") == "stub-revision", r.text[:120])

print("size limits")
r = client.post("/v1/scan", json={"text": "x" * 2001})
check("full route refuses a body over its cap with 413", r.status_code == 413, r.status_code)
check("413 body names the limit and the setting", r.json()["detail"]["limit_bytes"] == 2000 and r.json()["detail"]["setting"] == "SCAN_FULL_MAX_BYTES")
r = client.post("/v1/scan", json={"text": "x" * 2000})
check("full route accepts a body exactly at its cap", r.status_code == 200, r.status_code)
r = client.post("/v1/scan", json={"text": "é" * 1001})  # 2002 bytes, 1001 characters
check("the cap counts UTF-8 bytes, not characters", r.status_code == 413, r.status_code)
r = client.post("/v1/scan/secret", json={"text": "x" * 4000})
check("credential-only route takes more than the full route's cap", r.status_code == 200, r.status_code)
r = client.post("/v1/scan/secret", json={"text": "x" * 5001})
check("credential-only route refuses a body over its own cap", r.status_code == 413, r.status_code)

print("a failing PII engine")
pii_fail["on"] = True
r = client.post("/v1/scan", json={"text": TEXT})
check("full route still answers 200", r.status_code == 200, r.status_code)
if r.status_code == 200:
    check("the pii finding reports verdict error", verdicts(r)["pii"] == "error", verdicts(r))
    check("the other two axes still report", verdicts(r)["secret"] == "clean" and verdicts(r)["injection"] == "clean", verdicts(r))
    check("redacted_text falls back to the credential-redacted text", r.json()["redacted_text"] == TEXT)
r = client.post("/v1/scan/secret", json={"text": TEXT})
check("credential-only route is unaffected", r.status_code == 200, r.status_code)
pii_fail["on"] = False

print("a failing credential scan")
real_scan = main._scan_secrets
main._scan_secrets = lambda t: {"type": "secret", "verdict": "error", "reason_code": ["SECRET_SCAN_TIMEOUT"], "detail": {"error": "timeout"}}
r = client.post("/v1/scan", json={"text": TEXT})
check("full route answers 200 with verdict error", r.status_code == 200 and verdicts(r)["secret"] == "error", r.status_code)
if r.status_code == 200:
    check("PII is still redacted in redacted_text", r.json()["redacted_text"] == "owner: <PERSON>\n", r.json()["redacted_text"])
main._scan_secrets = real_scan

print("FAIL" if failures else "ok", f"- {len(failures)} failure(s)")
sys.exit(1 if failures else 0)
