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
import logging
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

if not hasattr(datetime, "UTC"):  # python < 3.11
    datetime.UTC = datetime.timezone.utc  # noqa: UP017

APP = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP))
os.environ["METRICS_PATH"] = str(Path(tempfile.mkdtemp()) / "metrics.jsonl")
os.environ["SCAN_FULL_MAX_BYTES"] = "2000"
os.environ["SCAN_SECRET_MAX_BYTES"] = "5000"

pii_fail = {"on": False}
# Which model loaders raise at startup, to test starting without an axis.
load_fail = {"pii": False, "injection": False}


def _load_engines():
    if load_fail["pii"]:
        raise RuntimeError("stubbed PII load failure")


def _load_model():
    if load_fail["injection"]:
        raise RuntimeError("stubbed injection model load failure (gated, 401)")


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
_stub(
    "pii_guard.engine",
    analyze_and_redact=_analyze_and_redact,
    load_engines=_load_engines,
)
_stub("injection_guard")
_stub(
    "injection_guard.model",
    classify=lambda t: {
        "malicious": "IGNORE PREVIOUS" in t,
        "score": 0.99,
        "chunks_scanned": 1,
    },
    load_model=_load_model,
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
check(
    "/about reports the model and the pinned revision",
    r.status_code == 200
    and r.json().get("model") == "stub/model"
    and r.json().get("model_revision") == "stub-revision",
    r.text[:120],
)

print("size limits")
r = client.post("/v1/scan", json={"text": "x" * 2001})
check(
    "full route refuses a body over its cap with 413",
    r.status_code == 413,
    r.status_code,
)
check(
    "413 body names the limit and the setting",
    r.json()["detail"]["limit_bytes"] == 2000
    and r.json()["detail"]["setting"] == "SCAN_FULL_MAX_BYTES",
)
r = client.post("/v1/scan", json={"text": "x" * 2000})
check(
    "full route accepts a body exactly at its cap", r.status_code == 200, r.status_code
)
r = client.post("/v1/scan", json={"text": "é" * 1001})  # 2002 bytes, 1001 characters
check("the cap counts UTF-8 bytes, not characters", r.status_code == 413, r.status_code)
r = client.post("/v1/scan/secret", json={"text": "x" * 4000})
check(
    "credential-only route takes more than the full route's cap",
    r.status_code == 200,
    r.status_code,
)
r = client.post("/v1/scan/secret", json={"text": "x" * 5001})
check(
    "credential-only route refuses a body over its own cap",
    r.status_code == 413,
    r.status_code,
)

print("a failing PII engine")
pii_fail["on"] = True
r = client.post("/v1/scan", json={"text": TEXT})
check("full route still answers 200", r.status_code == 200, r.status_code)
if r.status_code == 200:
    check(
        "the pii finding reports verdict error",
        verdicts(r)["pii"] == "error",
        verdicts(r),
    )
    check(
        "the other two axes still report",
        verdicts(r)["secret"] == "clean" and verdicts(r)["injection"] == "clean",
        verdicts(r),
    )
    check(
        "redacted_text falls back to the credential-redacted text",
        r.json()["redacted_text"] == TEXT,
    )
r = client.post("/v1/scan/secret", json={"text": TEXT})
check("credential-only route is unaffected", r.status_code == 200, r.status_code)
pii_fail["on"] = False

print("a failing credential scan")


def _timed_out_scan(_text):
    return {
        "type": "secret",
        "verdict": "error",
        "reason_code": ["SECRET_SCAN_TIMEOUT"],
        "detail": {"error": "timeout"},
    }


with mock.patch.object(main, "_scan_secrets", _timed_out_scan):
    r = client.post("/v1/scan", json={"text": TEXT})
    check(
        "full route answers 200 with verdict error",
        r.status_code == 200 and verdicts(r)["secret"] == "error",
        r.status_code,
    )
    if r.status_code == 200:
        check(
            "PII is still redacted in redacted_text",
            r.json()["redacted_text"] == "owner: <PERSON>\n",
            r.json()["redacted_text"],
        )


print("a lone surrogate in the text")
# A JSON string may carry half of a surrogate pair (the escape \ud800). Python parses it, but it cannot be
# encoded as UTF-8, so the scan input and the JSON response both failed and the caller got a 500.
seen = []


def _recording_scan(text):
    seen.append(text)
    return {
        "type": "secret",
        "verdict": "clean",
        "reason_code": None,
        "detail": {"redacted_text": text, "rule_count": 0},
    }


for route in ("/v1/scan", "/v1/scan/secret"):
    del seen[:]
    body = '{"text": "owner: Alice Example \\ud800 tail"}'
    with mock.patch.object(main, "_scan_secrets", _recording_scan):
        r = client.post(
            route, content=body, headers={"content-type": "application/json"}
        )
    check(f"{route} answers 200, not 500", r.status_code == 200, r.status_code)
    if r.status_code == 200:
        out = r.json()["redacted_text"]
        check(
            f"{route} returns text without the lone surrogate",
            "\ud800" not in out and "\ufffd" in out,
            ascii(out),
        )
        check(
            f"{route} keeps the text around the surrogate",
            out.startswith("owner: ") and out.endswith(" tail"),
            ascii(out),
        )
    check(
        f"{route} hands the credential scan valid text",
        len(seen) == 1 and "\ud800" not in seen[0],
        ascii(seen),
    )
r = client.post(
    "/v1/scan",
    content=b'{"text": "ok \\ud83d\\ude00 emoji"}',
    headers={"content-type": "application/json"},
)
check(
    "a proper surrogate pair (an emoji) is left alone",
    r.status_code == 200 and "\U0001f600" in r.json()["redacted_text"],
    r.text[:120],
)


print("starting without a model axis (GUARDS_REQUIRE_AXES)")


class _Records(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def start(env, **fails):
    """Run the lifespan with the given environment and loader failures. Returns
    (client context result or None, exception or None, log records)."""
    handler = _Records()
    main.logger.addHandler(handler)
    load_fail.update({"pii": False, "injection": False})
    load_fail.update(fails)
    err = None
    try:
        with mock.patch.dict(os.environ, env, clear=False):
            if "GUARDS_REQUIRE_AXES" not in env:
                os.environ.pop("GUARDS_REQUIRE_AXES", None)
            with TestClient(main.app, raise_server_exceptions=False) as c:
                about = c.get("/about").json()
                health = c.get("/health")
                scans = [
                    c.post("/v1/scan", json={"text": t})
                    for t in (TEXT + "k=SECRETVALUE\n", TEXT, TEXT)
                ]
                secret = c.post("/v1/scan/secret", json={"text": TEXT})
                result = (about, health, scans, secret)
    except RuntimeError as e:  # a loader raised: the process would not start
        err, result = e, None
    finally:
        main.logger.removeHandler(handler)
        load_fail.update({"pii": False, "injection": False})
    return result, err, handler.records


def count(records, needle):
    return sum(1 for r in records if needle in r.getMessage())


# Default: the injection model cannot load (no token, gated 401); secrets and PII still serve.
res, err, logs = start({}, injection=True)
check(
    "default: a missing injection model does not stop the service",
    err is None,
    repr(err),
)
if res:
    about, health, scans, secret = res
    check(
        "default: /health answers",
        health.status_code == 200 and health.json() == {"status": "ok"},
    )
    check(
        "default: /about lists the injection axis as unavailable, not required, with its code",
        about["axes"]["injection"]
        == {
            "state": "unavailable",
            "required": False,
            "reason_code": "INJECTION_UNAVAILABLE",
        },
        about.get("axes"),
    )
    check(
        "default: /about lists secret and PII as ok, PII as required",
        about["axes"]["secret"] == {"state": "ok"}
        and about["axes"]["pii"]
        == {"state": "ok", "required": True, "reason_code": None},
        about.get("axes"),
    )
    check(
        "default: /about keeps its earlier fields",
        about["service"] == "guards-unified" and about["model"] == "stub/model",
    )
    f = scans[0].json()["findings"]
    check(
        "default: PII is still found",
        {x["type"]: x["verdict"] for x in f}["pii"] == "found",
        f,
    )
    inj = next(x for x in f if x["type"] == "injection")
    check(
        "default: injection answers verdict error with the stable reason code",
        inj["verdict"] == "error" and inj["reason_code"] == ["INJECTION_UNAVAILABLE"],
        inj,
    )
    check(
        "default: the other axes still run (secret clean, pii found)",
        {x["type"]: x["verdict"] for x in f}["secret"] in ("clean", "found"),
    )
    check(
        "default: the secret-only route is unaffected",
        secret.status_code == 200 and secret.json()["findings"][0]["type"] == "secret",
    )
    check(
        "default: the log says the axis is unavailable once, however many requests follow",
        count(logs, "injection axis unavailable") == 1,
        count(logs, "injection axis unavailable"),
    )
    check(
        "default: the redacted text still has PII removed",
        "<PERSON>" in scans[0].json()["redacted_text"],
    )

# Strict value: the earlier behaviour exactly - the process does not start.
res, err, logs = start({"GUARDS_REQUIRE_AXES": "pii,injection"}, injection=True)
check(
    "pii,injection: a missing injection model stops the process, as before",
    err is not None and "injection model load failure" in str(err),
    repr(err),
)
res, err, logs = start({"GUARDS_REQUIRE_AXES": "pii,injection"}, pii=True)
check(
    "pii,injection: a missing PII engine stops the process",
    err is not None and "PII load failure" in str(err),
    repr(err),
)
# A required PII engine stops the process by default too (a build defect).
res, err, logs = start({}, pii=True)
check(
    "default: a PII engine that cannot load stops the process",
    err is not None and "PII load failure" in str(err),
    repr(err),
)
# Empty and unknown values fail closed to strict.
for bad in ("", "  ", "bogus", "pii,bogus", "secret"):
    res, err, logs = start({"GUARDS_REQUIRE_AXES": bad}, injection=True)
    check(
        f"GUARDS_REQUIRE_AXES={bad!r} fails closed: an unavailable injection model stops the process",
        err is not None,
        repr(err),
    )
    check(
        f"GUARDS_REQUIRE_AXES={bad!r} logs that it was not understood",
        count(logs, "treating every axis as required") == 1,
        count(logs, "treating every axis as required"),
    )
# Only injection required: PII may be missing, injection may not.
res, err, logs = start({"GUARDS_REQUIRE_AXES": "injection"}, pii=True)
check(
    "injection only: a missing PII engine does not stop the service",
    err is None,
    repr(err),
)
if res:
    check(
        "injection only: PII reports unavailable with its code",
        next(x for x in res[2][0].json()["findings"] if x["type"] == "pii")[
            "reason_code"
        ]
        == ["PII_UNAVAILABLE"],
    )
    check(
        "injection only: the final redacted_text still builds",
        res[2][0].status_code == 200 and "redacted_text" in res[2][0].json(),
    )
res, err, logs = start({"GUARDS_REQUIRE_AXES": "injection"}, injection=True)
check(
    "injection only: a missing injection model stops the process",
    err is not None,
    repr(err),
)
# Case and spacing are tolerated.
res, err, logs = start({"GUARDS_REQUIRE_AXES": " PII , Injection "}, injection=True)
check("' PII , Injection ' is read as pii,injection", err is not None, repr(err))
# Everything loads: axes ok, nothing changes in the answers.
res, err, logs = start({"GUARDS_REQUIRE_AXES": "pii,injection"})
check("all axes load: the process starts", err is None, repr(err))
if res:
    about, _, scans, _ = res
    check(
        "all axes load: /about lists both ok and required",
        about["axes"]["pii"] == {"state": "ok", "required": True, "reason_code": None}
        and about["axes"]["injection"]
        == {"state": "ok", "required": True, "reason_code": None},
        about["axes"],
    )
    check(
        "all axes load: no axis reports an error",
        all(x["verdict"] != "error" for x in scans[0].json()["findings"]),
    )
    check(
        "all axes load: nothing is logged as unavailable",
        count(logs, "axis unavailable") == 0,
    )
main._axes.clear()

print("FAIL" if failures else "ok", f"- {len(failures)} failure(s)")
sys.exit(1 if failures else 0)
