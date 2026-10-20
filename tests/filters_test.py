#!/usr/bin/env python3
"""Tests for app/pii_guard/filters.py: the rules that drop what Presidio reports
as PERSON or LOCATION but is a tool name, an identifier or a bare word. Pure
python: the filters take a span of text, so no Presidio and no models are needed.

    python3 tests/filters_test.py
"""

import importlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace as NS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from pii_guard import filters, ignore_names

failures = []


def check(name, cond, detail=""):
    if not cond:
        failures.append(name)
        print(f"  FAIL  {name} {detail}")


def kept(kind, text, span=None):
    """Would a Presidio result of this kind over `span` (default: all of `text`) survive?"""
    span = span or text
    i = text.index(span)
    return filters.keep_result(text, NS(entity_type=kind, start=i, end=i + len(span)))


def dropped(kind, text, span=None):
    return not kept(kind, text, span)


# ---- LOCATION: dropped
for t in [
    "max_position_embeddings=131072",
    "trace_id=00a26bcca6ccdca785345f37ce4f053d",
    "bd2977b1259b6951",  # a bare 16-hex id
    "bucket_name",
    "12345",  # no letter
    "2026/10/03",
    "washington",  # a single lowercase word
    "localhost",
    "Lincoln-9999",  # a 4-digit run
]:
    check(f"LOCATION dropped: {t}", dropped("LOCATION", t))

# ---- LOCATION: kept (addresses and places)
for t in [
    "Washington",
    "Springfield",
    "New York",
    "Westbrook, ME",
    "Westbrook, ME 04092",  # a ZIP after a state code
    "2280 Birchwood Drive",  # a house number
    "6719 Cedar Boulevard, Lakeside",
    "12B Station Street",
    "Marchbury, MB1 9XA",
    "Lincoln-163",  # 3 digits: not an identifier by the digit rule; known miss, see LIMITS.md
]:
    check(f"LOCATION kept: {t}", kept("LOCATION", t))
check(
    "LOCATION: 12 hex chars inside a longer span is dropped",
    dropped("LOCATION", "build 0123456789ab done", "build 0123456789ab"),
)
check("LOCATION: 11 hex chars is not a hex run", kept("LOCATION", "Cafe Decadebabe"))
check(
    "LOCATION: a 4-digit run that is not a house number is dropped",
    dropped("LOCATION", "Plaza 2026"),
)

# ---- PERSON: dropped
for t in [
    "kube",
    "arn",
    "flask",
    "Kubernetes",  # the tool, alone
    "Jenkins",
    "Flask",
    "KUBERNETES",
    "Jupyter Lab",
    "Grafana Tempo",
    "Kafka Streams",
    "Ansible Tower",
    "Kube-Proxy",
    "Docker Compose",
]:
    check(f"PERSON dropped: {t}", dropped("PERSON", t))

# ---- PERSON: kept (ordinary names, including near misses)
for t in [
    "Alice Example",
    "Mary-Jane Smith-Jones",
    "Wei Zhang",
    "Zhang",
    "Nguyen Thi Lan",
    "Oluwaseun Adeyemi",
    "Mohammed Al-Farsi",
    "José García-López",
    "O'Brien",
    "Peter Jenkins",  # first name makes it not a tool
    "Jenkins Okafor",
    "Kubernetes Smith",  # one token is not a listed word
    "Docker Smith",
]:
    check(f"PERSON kept: {t}", kept("PERSON", t))

# a title just before the span keeps a name that is also a tool name
for pre in ["Dr. ", "Mr. ", "Mrs. ", "Ms. ", "Prof. ", "dr ", "Miss "]:
    check(
        f"PERSON kept after title {pre!r}",
        kept("PERSON", f"Please ask {pre}Jenkins about it", "Jenkins"),
    )
check(
    "PERSON dropped without title",
    dropped("PERSON", "Please ask Jenkins about it", "Jenkins"),
)
check(
    "PERSON dropped after a non-title word ending in the letters of one",
    dropped("PERSON", "The sandr Jenkins job", "Jenkins"),
)
check(
    "a name that is a single capitalised unknown word is kept",
    kept("PERSON", "Thanks Gerrit for the review", "Gerrit"),
)
check("the possessive is ignored", dropped("PERSON", "Jenkins's", "Jenkins's"))

# ---- other kinds pass through untouched
check("EMAIL_ADDRESS untouched", kept("EMAIL_ADDRESS", "kube@example.invalid"))
check("IP_ADDRESS untouched", kept("IP_ADDRESS", "10.0.0.1"))

# ---- the built-in list is well formed
names = ignore_names.IGNORE_NAMES
check("list entries are lowercase", all(n == n.casefold() for n in names))
check(
    "list entries have no surrounding space",
    all(n == n.strip() and "  " not in n for n in names),
)
check("list size is broad", len(names) >= 250, str(len(names)))
for common in [
    "hugo",
    "linus",
    "chandler",
    "jordan",
    "julia",
    "ruby",
    "grace",
    "mark",
    "paul",
    "lee",
    "kim",
]:
    check(f"list leaves out the given name or surname {common}", common not in names)
check("product words alone never drop a span", kept("PERSON", "Lab Server"))

# ---- PII_IGNORE_NAMES
os.environ["PII_IGNORE_NAMES"] = " Gerrit , Acme  Deploy,,"
config = importlib.import_module("pii_guard.config")

importlib.reload(config)
importlib.reload(filters)
check(
    "PII_IGNORE_NAMES parsed",
    config.IGNORE_NAMES_EXTRA == {"gerrit", "acme deploy"},
    str(config.IGNORE_NAMES_EXTRA),
)
check(
    "PII_IGNORE_NAMES drops an added name, any case",
    dropped("PERSON", "GERRIT") and dropped("PERSON", "Gerrit"),
)
check("PII_IGNORE_NAMES drops an added phrase", dropped("PERSON", "Acme Deploy"))
check("PII_IGNORE_NAMES keeps names not added", kept("PERSON", "Alice Example"))
del os.environ["PII_IGNORE_NAMES"]
importlib.reload(config)
importlib.reload(filters)
check("PII_IGNORE_NAMES unset adds nothing", config.IGNORE_NAMES_EXTRA == frozenset())

print(f"\n{'FAILED: ' + str(len(failures)) if failures else 'all filter tests passed'}")
sys.exit(1 if failures else 0)
