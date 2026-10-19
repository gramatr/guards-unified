"""
guards-unified — ONE image, ONE process, ONE API wrapping secret-guard,
pii-guard, and injection-guard's own detection logic directly (not by
calling three separate containers over HTTP — that's what guards-stack
already does). This vendors each project's actual detection code
(pii_guard/, injection_guard/ packages; secret-guard's scan.sh/report.sh
scripts) into one FastAPI app.

Three independent axes, same as the hook/MCP front-ends — this endpoint
runs all three unconditionally and reports a result per axis, it does
not let one gate or short-circuit another.

Unified response shape, per finding: {type, verdict, reason_code, detail}.
"malicious"/"found" collapse to a single `verdict` field so a caller
doesn't need three different per-tool vocabularies. `reason_code` is
always present and machine-stable:
  - secret:    SECRET_<gitleaks RuleID, uppercased>
  - pii:       PII_<Presidio entity_type>
  - injection: INJECTION_OVERRIDE_OR_JAILBREAK (binary classifier, no
               sub-labels — Prompt Guard 2's own model card is explicit
               that a finer-grained label was "too broad to be useful,"
               see injection-guard's README; do not invent sub-codes
               this classifier cannot actually distinguish)

Scope caveats carried over from every other front-end in this stack,
restated here because this is a new entry point and the caveats don't
travel with the code automatically:
  - injection detection is jailbreak/override detection ONLY. Measured
    recall on indirect/tool-output injection is 6% (InjecAgent, n=200).
    Do not treat "injection": {"verdict": "clean"} as a guarantee against
    content manipulating an agent without override language.
  - PII detection covers Presidio's configured entity set only.
  - Fails EXPLICIT, not open: if a sub-detector errors, that finding's
    verdict is "error" with the exception message in `detail`, and the
    other two axes still run and report normally. A caller must not
    treat one axis's failure as "the whole request is clean."
"""

import json
import logging
import os
import subprocess
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import injection_guard.model as injection_model
import pii_guard.engine as pii_engine
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guards_unified")

APP_DIR = Path(__file__).parent
SCAN_SH = APP_DIR / "scan.sh"

# Returned in place of the text whenever a confirmed secret finding could not
# be redacted. Failing closed: never ship text we know contains a secret.
REDACTION_WITHHELD = "***REDACTED:SECRET*** (secret-guard could not safely redact this output; withheld)"

# Purely local, personal-use metrics — never transmitted anywhere, never
# shared. Distinct from PROPOSAL.md's Track A (community telemetry) and
# Track B (cpp-dwa governance telemetry), both still gated behind a
# legal/product review that hasn't happened: this writes ONLY to a local
# file on whatever host runs the container, nothing leaves this process.
# Same discipline DATA_HANDLING.md already names as safe for the hosted
# tier's own metrics: aggregate counts only, NEVER the scanned text, not
# even redacted_text or a detail field that could carry a substring of
# it. One JSON line per finding: {ts, type, verdict, reason_code}.
METRICS_PATH = Path(os.environ.get("METRICS_PATH", "/app/metrics/metrics.jsonl"))

# Baked in at build time (Dockerfile COPYs the repo's VERSION file in)
# so a running container can report what it actually is -- without
# this, a stale pull is invisible from the outside: /health only ever
# says "ok," whether or not it's ok on a 2026-10-17 image or today's.
# Read once at import time, not per-request: it's immutable for the
# life of the container.
VERSION_PATH = APP_DIR / "VERSION"
try:
    GUARDS_UNIFIED_VERSION = VERSION_PATH.read_text().strip()
except FileNotFoundError:
    GUARDS_UNIFIED_VERSION = "unknown"


def _log_metric(finding: dict) -> None:
    try:
        METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "type": finding["type"],
            "verdict": finding["verdict"],
            "reason_code": finding.get("reason_code"),
        }
        with open(METRICS_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        # Metrics are a convenience, never a reason to fail a scan --
        # same fail-open-for-side-effects posture as everything else in
        # this stack that isn't the detection result itself.
        logger.exception("failed to write local metrics (non-fatal)")


@asynccontextmanager
async def _lifespan(_: FastAPI):
    logger.info("Loading pii-guard (Presidio) and injection-guard (Prompt Guard 2) once at startup")
    pii_engine.load_engines()
    injection_model.load_model()
    yield


app = FastAPI(title="guards-unified", lifespan=_lifespan)


class ScanRequest(BaseModel):
    text: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/about")
def about() -> dict:
    """Llama 4 Community License requires "Built with Llama" to be
    displayed prominently wherever this ships -- this endpoint is the
    runtime-visible half of that, same pattern as injection-guard's own
    /about (this image vendors that code and carries the same
    obligation). NOTICE/THIRD_PARTY_LICENSES/README cover the static
    half. A product website/about page display is a separate,
    not-yet-done requirement -- see README."""
    return {
        "service": "guards-unified",
        "version": GUARDS_UNIFIED_VERSION,
        "model": injection_model.config.MODEL_ID,
        "attribution": "Built with Llama",
        "license_notice": "Llama 4 is licensed under the Llama 4 Community License, "
                           "Copyright © Meta Platforms, Inc. All Rights Reserved.",
        "license_url": "https://www.llama.com/llama4/license/",
    }


def _scan_secrets(text: str) -> dict:
    """Shells out to the vendored scan.sh (gitleaks) rather than
    reimplementing its logic — same binary-detection behavior as
    secret-guard's own daemon, not a reimplementation that could drift
    from it. Findings JSON (RuleID only, never the matched value) is
    captured via SECRET_GUARD_FINDINGS_JSON for reason codes."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        findings_path = f.name
    try:
        env = dict(os.environ, SECRET_GUARD_FINDINGS_JSON=findings_path)
        result = subprocess.run(
            ["bash", str(SCAN_SH)],
            input=text,
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
            check=False,
        )
        redacted_text = result.stdout
        findings = []
        try:
            raw = Path(findings_path).read_text()
            if raw.strip() and raw.strip() != "null":
                findings = json.loads(raw)
        except (FileNotFoundError, json.JSONDecodeError):
            findings = []
        detail = {"redacted_text": redacted_text, "rule_count": len(findings)}
        if findings and redacted_text == text:
            # Second line of defence behind scan.sh's own check: a
            # confirmed finding must never ship back unchanged text
            # (guards-coordination#5). Withhold instead.
            logger.error("secret finding with unchanged redacted_text, withholding output")
            detail["redacted_text"] = REDACTION_WITHHELD
            detail["redaction_failed"] = True
        return {
            "type": "secret",
            "verdict": "found" if findings else "clean",
            "reason_code": [f"SECRET_{f.get('RuleID', 'UNKNOWN').upper()}" for f in findings] or None,
            "detail": detail,
        }
    except subprocess.TimeoutExpired:
        # Same outcome as any other scan error (the caller keeps the original
        # text); logged so a slow scan is visible instead of silent. Withholding
        # the output instead was tried and dropped: it takes a user's whole
        # result away, which is a worse trade than a rare unscanned output.
        logger.error("secret scan timed out after 15s, text left unscanned")
        return {"type": "secret", "verdict": "error", "reason_code": ["SECRET_SCAN_TIMEOUT"], "detail": {"error": "timeout"}}
    except Exception as e:
        logger.exception("secret scan failed")
        return {"type": "secret", "verdict": "error", "reason_code": None, "detail": {"error": str(e)}}
    finally:
        Path(findings_path).unlink(missing_ok=True)


def _scan_pii(text: str) -> dict:
    try:
        result = pii_engine.analyze_and_redact(text)
        reason_codes = sorted({f"PII_{e['entity_type']}" for e in result["entities"]}) or None
        return {
            "type": "pii",
            "verdict": "found" if result["found"] else "clean",
            "reason_code": reason_codes,
            "detail": {"redacted_text": result["redacted_text"], "entities": result["entities"]},
        }
    except Exception as e:
        logger.exception("pii scan failed")
        return {"type": "pii", "verdict": "error", "reason_code": None, "detail": {"error": str(e)}}


def _classify_injection(text: str) -> dict:
    try:
        result = injection_model.classify(text)
        return {
            "type": "injection",
            "verdict": "malicious" if result["malicious"] else "clean",
            "reason_code": ["INJECTION_OVERRIDE_OR_JAILBREAK"] if result["malicious"] else None,
            "detail": {"score": result["score"], "chunks_scanned": result["chunks_scanned"]},
        }
    except Exception as e:
        logger.exception("injection classification failed")
        return {"type": "injection", "verdict": "error", "reason_code": None, "detail": {"error": str(e)}}


@app.post("/v1/scan/secret")
def scan_secret(req: ScanRequest) -> dict:
    """The secret axis alone. Use this where secrets are what matter (tool
    output, commits, anything about to be published): it is roughly 30 ms
    inside the container, while the full /v1/scan also runs the PII and
    prompt-injection models, which cost about 0.25 s per KB of text and are
    flag-only. The secret scan must never wait on them.

    Same finding shape as /v1/scan; redacted_text is the text with secrets
    redacted (no PII redaction)."""
    secret_result = _scan_secrets(req.text)
    _log_metric(secret_result)
    redacted = secret_result["detail"]["redacted_text"] if secret_result["verdict"] == "found" else req.text
    return {"findings": [secret_result], "redacted_text": redacted}


@app.post("/v1/scan")
def scan(req: ScanRequest) -> dict:
    """Runs all three detectors unconditionally — none gates or
    short-circuits another (three independent axes, not a pipeline).
    Redaction is still applied in sequence for the final redacted_text
    field (secrets first, then PII on the already-secret-redacted
    text) purely so one surviving secret value can't reappear in a PII
    redaction pass's untouched copy — the per-finding verdicts above
    are computed independently on the ORIGINAL text, not on each
    other's output, so one detector's redaction never hides a finding
    from another."""
    secret_result = _scan_secrets(req.text)
    pii_result = _scan_pii(req.text)
    injection_result = _classify_injection(req.text)

    for finding in (secret_result, pii_result, injection_result):
        _log_metric(finding)

    current = req.text
    if secret_result["verdict"] == "found":
        current = secret_result["detail"]["redacted_text"]
    pii_on_current = pii_engine.analyze_and_redact(current) if secret_result["verdict"] != "error" else None
    final_redacted_text = pii_on_current["redacted_text"] if pii_on_current else current

    return {
        "findings": [secret_result, pii_result, injection_result],
        "redacted_text": final_redacted_text,
    }
