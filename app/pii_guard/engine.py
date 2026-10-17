"""
Loads Presidio's AnalyzerEngine + AnonymizerEngine ONCE at daemon startup
(spaCy's en_core_web_lg load cost is real — measured ~1.6s cold, see
README "Startup cost" — same "load once, serve resident" shape as
injection-guard's transformer, unlike secret-guard's zero-model-weight
gitleaks case).

Redacts by default (not flag-only): unlike injection-guard's classifier,
Presidio gives exact character spans for each entity, so blanking them
is as safe as secret-guard's precise-span secret redaction — there's no
"might break legitimate content" risk the way there is for injection-
guard's whole-chunk judgment.
"""

import logging

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

from pii_guard.config import LANGUAGE

logger = logging.getLogger("pii_guard")

_analyzer = None
_anonymizer = None

# Presidio's full default entity set includes DATE_TIME, URL, and NRP
# (nationality/religious/political group) — found empirically by running
# this for real: "The quarterly report is due next Friday." gets flagged
# as containing PII (DATE_TIME matched "quarterly" and "next Friday").
# A plain date is not sensitive on its own, and that false-positive rate
# would make this tool noise, not signal. Restricted to the entity types
# the design spec actually called for — deliberately excludes DATE_TIME,
# URL, NRP, CRYPTO, and other low-signal defaults Presidio ships but
# this tool never asked for.
#
# ORGANIZATION is NOT in this list, even though the design spec called
# for it — found empirically: Presidio's default SpacyRecognizer's
# `supported_entities` is `['PERSON', 'DATE_TIME', 'LOCATION', 'NRP']`.
# There is no ORG/ORGANIZATION in that list at all. Requesting it in
# `analyze(entities=...)` doesn't error, it just silently never fires —
# exactly the "looks right, wrong in a way only running it reveals"
# failure the verify-by-running-not-reading standard exists to catch.
# Enabling it requires adding a custom NlpEngine entity mapping, not
# done here — tracked in README "Known limitations," not silently
# claimed as supported.
ENTITIES = [
    "PERSON",
    "LOCATION",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
]


def load_engines() -> None:
    """Called once at daemon startup — this is the only place the spaCy
    model loads. Never call this per-request."""
    global _analyzer, _anonymizer
    if _analyzer is not None:
        return
    logger.info("Loading Presidio AnalyzerEngine + AnonymizerEngine (this happens once, not per request)")
    _analyzer = AnalyzerEngine()
    _anonymizer = AnonymizerEngine()


def analyze_and_redact(text: str) -> dict:
    """Returns {found: bool, redacted_text: str, entities: [...]}.
    entities carry entity_type/start/end/score but never the original
    matched substring — same "report metadata, not the value" posture
    as secret-guard's findings log."""
    if _analyzer is None or _anonymizer is None:
        raise RuntimeError("load_engines() was not called before analyze_and_redact()")

    results = _analyzer.analyze(text=text, language=LANGUAGE, entities=ENTITIES)
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=results)

    return {
        "found": len(results) > 0,
        "redacted_text": anonymized.text,
        "entities": [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score}
            for r in results
        ],
    }
