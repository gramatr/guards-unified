"""
Finds PII in two parts: Presidio (loaded ONCE at daemon startup, spaCy's
en_core_web_lg load cost is real, measured ~1.6s cold, see README "Startup
cost") for PERSON and LOCATION, which need a statistical model, and the
deterministic checks in pii_guard.validators for the structured kinds (cards,
IBANs, SSNs, passports, phone numbers, IPv4, email). Presidio's own pattern
recognizers for those kinds score any long digit string, so they flagged ids and
timestamps in tool output; see gramatr/guards-coordination#46.
PII_ENGINE=presidio restores the previous all-Presidio behavior.

Redacts by default (not flag-only): both parts give exact character spans, so
blanking them is as safe as secret-guard's precise-span secret redaction.
"""

import logging

from pii_guard import validators
from pii_guard.config import ENGINE, ENTITIES, LANGUAGE, MIN_SCORE

logger = logging.getLogger("pii_guard")

_analyzer = None
_anonymizer = None

# The entity list and the minimum score come from pii_guard.config (PII_ENTITIES,
# PII_MIN_SCORE). Presidio's full default set also includes DATE_TIME, URL and
# NRP, which would flag "next Friday" as PII, and its pattern-only driver licence
# and bank number recognizers fire on any long digit string; both are left out by
# default (see config.py). ORGANIZATION is not supported by the default spaCy
# recognizer (requesting it silently never fires), so it is not in the list.


# spaCy's name recognizer reads identifiers such as a hyphenated pod name, a
# resource id or a key=value pair as a person (score 0.85). A name has no digit,
# underscore, slash, "=", "@" or ":" in it, so a PERSON span that does is an
# identifier and is dropped.
_NOT_IN_A_NAME = set("0123456789_/\\=@:")


def _is_identifier_not_a_person(text: str, result) -> bool:
    return result.entity_type == "PERSON" and any(
        c in _NOT_IN_A_NAME for c in text[result.start : result.end]
    )


def merge_spans(presidio_spans, validator_spans) -> list:
    """Combine both parts into one list of non-overlapping Span, sorted by start.
    A validator span beats a Presidio span it overlaps (a checksum is stronger
    evidence than a statistical guess); among spans of the same origin the
    longer one wins, then the earlier."""
    tagged = [(1, s) for s in validator_spans] + [(0, s) for s in presidio_spans]
    tagged.sort(key=lambda t: (-t[0], -(t[1].end - t[1].start), t[1].start))
    kept: list = []
    for _, s in tagged:
        if s.end > s.start and all(s.end <= k.start or k.end <= s.start for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: (s.start, s.end))


def redact(text: str, spans) -> str:
    """Replace each span (non-overlapping, sorted) with <ENTITY_TYPE>, the same
    placeholder Presidio's anonymizer uses."""
    out, pos = [], 0
    for s in spans:
        out.append(text[pos : s.start])
        out.append(f"<{s.entity_type}>")
        pos = s.end
    out.append(text[pos:])
    return "".join(out)


def load_engines() -> None:
    """Called once at daemon startup — this is the only place the spaCy
    model loads. Never call this per-request."""
    global _analyzer, _anonymizer
    if _analyzer is not None:
        return
    from presidio_analyzer import AnalyzerEngine

    logger.info("Loading Presidio AnalyzerEngine (this happens once, not per request); PII_ENGINE=%s", ENGINE)
    _analyzer = AnalyzerEngine()
    if ENGINE == "presidio":
        from presidio_anonymizer import AnonymizerEngine

        _anonymizer = AnonymizerEngine()


def _analyze_validators(text: str) -> tuple[str, list]:
    wanted = [e for e in ENTITIES if e not in validators.KINDS]
    presidio = []
    if wanted:
        results = _analyzer.analyze(
            text=text, language=LANGUAGE, entities=wanted, score_threshold=MIN_SCORE
        )
        presidio = [
            validators.Span(r.entity_type, r.start, r.end, r.score)
            for r in results
            if not _is_identifier_not_a_person(text, r)
        ]
    spans = merge_spans(presidio, validators.find_pii(text, [e for e in ENTITIES if e in validators.KINDS]))
    return redact(text, spans), spans


def _analyze_presidio(text: str) -> tuple[str, list]:
    results = _analyzer.analyze(
        text=text, language=LANGUAGE, entities=ENTITIES, score_threshold=MIN_SCORE
    )
    results = [r for r in results if not _is_identifier_not_a_person(text, r)]
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text, [validators.Span(r.entity_type, r.start, r.end, r.score) for r in results]


def analyze_and_redact(text: str) -> dict:
    """Returns {found: bool, redacted_text: str, entities: [...]}.
    entities carry entity_type/start/end/score but never the original
    matched substring — same "report metadata, not the value" posture
    as secret-guard's findings log."""
    if _analyzer is None or (ENGINE == "presidio" and _anonymizer is None):
        raise RuntimeError("load_engines() was not called before analyze_and_redact()")

    redacted, spans = (_analyze_presidio if ENGINE == "presidio" else _analyze_validators)(text)
    return {
        "found": len(spans) > 0,
        "redacted_text": redacted,
        "entities": [
            {"entity_type": s.entity_type, "start": s.start, "end": s.end, "score": s.score}
            for s in spans
        ],
    }
