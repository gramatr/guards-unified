"""
Output filters for what Presidio reports as PERSON or LOCATION. spaCy reads
tool and product names as people ("Jenkins", "Grafana Tempo") and key=value
pairs, hashes and bare words as places ("max_position_embeddings=131072", a
16-character hex id, "Washington"); these rules drop those. They only ever
remove results, never add, and only for these two kinds: the structured kinds
come from pii_guard.validators and are not touched.

The rules are shape-based first (a place has no "=", "_" or long digit run; a
lone lowercase word is not a name) and use a name list second
(pii_guard.ignore_names plus PII_IGNORE_NAMES). Known cost, written down in
docs/TRADEOFFS.md: a person whose whole name is a listed word, mentioned alone
and without a title, is not flagged.
"""

import re

from pii_guard.config import IGNORE_NAMES_EXTRA
from pii_guard.ignore_names import IGNORE_NAMES, PRODUCT_WORDS

_DIGIT_RUN = re.compile(r"\d{4,}")
# A house number before a street name and a ZIP after a state code are digit
# runs of an address, not of an identifier; they are taken out before the check.
_HOUSE_NUMBER = re.compile(r"^\d{1,6}[A-Za-z]?\s+(?=[A-Za-z])")
_ZIP_AFTER_STATE = re.compile(r"(?<=\b[A-Z]{2})\s+\d{5}(?:-\d{4})?$")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{12,}")
_TITLE_BEFORE = re.compile(
    r"\b(?:dr|mr|mrs|ms|miss|mx|prof|professor|sir|dame|rev|hon|sen|rep|gov|capt|col|gen|sgt|lt)\.?\s+$",
    re.IGNORECASE,
)
_WORD_SPLIT = re.compile(r"[\s\-]+")


def _drop_location(span: str) -> bool:
    if "=" in span or "_" in span:
        return True
    if _HEX_RUN.search(span):
        return True
    if _DIGIT_RUN.search(_ZIP_AFTER_STATE.sub("", _HOUSE_NUMBER.sub("", span))):
        return True
    if not any(c.isalpha() for c in span):
        return True
    words = span.split()
    return len(words) == 1 and span.islower()


def _is_ignored_name(span: str) -> bool:
    """True if the span is only listed tool/product names (and generic product
    words such as "Lab"), at least one of them a listed name."""
    s = span.strip().casefold()
    if s.endswith(("'s", "’s")):
        s = s[:-2]
    if s in IGNORE_NAMES or s in IGNORE_NAMES_EXTRA:
        return True
    tokens = [t for t in _WORD_SPLIT.split(s) if t]
    known = [t in IGNORE_NAMES or t in IGNORE_NAMES_EXTRA for t in tokens]
    return (
        bool(tokens)
        and any(known)
        and all(k or t in PRODUCT_WORDS for k, t in zip(known, tokens))
    )


def _drop_person(text: str, start: int, end: int) -> bool:
    span = text[start:end]
    words = span.split()
    if len(words) == 1 and span.islower():
        return True
    # "Dr. Jenkins" is a person even though "jenkins" is also a tool.
    if _TITLE_BEFORE.search(text[max(0, start - 12) : start]):
        return False
    return _is_ignored_name(span)


def keep_result(text: str, result) -> bool:
    """False for a Presidio PERSON or LOCATION result that is noise."""
    if result.entity_type == "LOCATION":
        return not _drop_location(text[result.start : result.end])
    if result.entity_type == "PERSON":
        return not _drop_person(text, result.start, result.end)
    return True
