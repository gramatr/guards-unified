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

from pii_guard.config import ENTITIES, LANGUAGE, MIN_SCORE

logger = logging.getLogger("pii_guard")

_analyzer = None
_anonymizer = None

# The entity list and the minimum score come from pii_guard.config (PII_ENTITIES,
# PII_MIN_SCORE). Presidio's full default set also includes DATE_TIME, URL and
# NRP, which would flag "next Friday" as PII, and its pattern-only driver licence
# and bank number recognizers fire on any long digit string; both are left out by
# default (see config.py). ORGANIZATION is not supported by the default spaCy
# recognizer (requesting it silently never fires), so it is not in the list.


# spaCy's name recognizer reads identifiers such as a hyphenated pod name or a
# resource id as a person (score 0.85). A name has no digit, underscore or slash
# in it, so a PERSON span that does is an identifier and is dropped.
_NOT_IN_A_NAME = set("0123456789_/\\")


def _is_identifier_not_a_person(text: str, result) -> bool:
    return result.entity_type == "PERSON" and any(
        c in _NOT_IN_A_NAME for c in text[result.start : result.end]
    )


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

    results = _analyzer.analyze(
        text=text, language=LANGUAGE, entities=ENTITIES, score_threshold=MIN_SCORE
    )
    results = [r for r in results if not _is_identifier_not_a_person(text, r)]
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=results)

    return {
        "found": len(results) > 0,
        "redacted_text": anonymized.text,
        "entities": [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score}
            for r in results
        ],
    }
