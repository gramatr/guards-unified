#!/usr/bin/env python3
"""Tests for how app/pii_guard/engine.py combines Presidio's PERSON/LOCATION with
the validators: which entities Presidio is asked for, the PERSON identifier
filter, overlap resolution, and that redacted_text replaces every reported span.
Presidio is stubbed, so this needs neither Presidio nor the models.

    python3 tests/pii_merge_test.py
"""

import itertools
import sys
from pathlib import Path
from types import SimpleNamespace as NS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from pii_guard import engine, validators

failures = []


def check(name, cond, detail=""):
    if not cond:
        failures.append(name)
        print(f"  FAIL  {name} {detail}")


class StubAnalyzer:
    """Returns canned Presidio results for fixed substrings, like a model would,
    and records the entity list it was asked for."""

    def __init__(self, table):
        self.table = table  # {substring: (entity_type, score)}
        self.asked = None

    def analyze(self, text, language, entities, score_threshold):
        self.asked = list(entities)
        out = []
        for sub, (etype, score) in self.table.items():
            i = text.find(sub)
            if i >= 0 and etype in entities and score >= score_threshold:
                out.append(
                    NS(entity_type=etype, start=i, end=i + len(sub), score=score)
                )
        return out


def run(text, table):
    stub = StubAnalyzer(table)
    engine._analyzer = stub
    return engine.analyze_and_redact(text), stub


def spans_of(r):
    return [(e["entity_type"], e["start"], e["end"]) for e in r["entities"]]


# ------------------------------------------------ merge_spans on its own
S = validators.Span
m = engine.merge_spans([S("PERSON", 0, 10, 0.85)], [S("EMAIL_ADDRESS", 5, 30, 0.9)])
check(
    "validator beats an overlapping Presidio span",
    [s.entity_type for s in m] == ["EMAIL_ADDRESS"],
    str(m),
)
m = engine.merge_spans([S("PERSON", 0, 5, 0.85)], [S("EMAIL_ADDRESS", 5, 30, 0.9)])
check(
    "touching spans are both kept",
    [s.entity_type for s in m] == ["PERSON", "EMAIL_ADDRESS"],
    str(m),
)
m = engine.merge_spans(
    [], [S("IP_ADDRESS", 10, 20, 0.85), S("EMAIL_ADDRESS", 0, 40, 0.9)]
)
check(
    "longer validator span wins an overlap",
    [s.entity_type for s in m] == ["EMAIL_ADDRESS"],
    str(m),
)
m = engine.merge_spans([S("LOCATION", 8, 9, 0.5), S("PERSON", 0, 3, 0.9)], [])
check("sorted by start", [s.start for s in m] == [0, 8], str(m))
check("empty spans dropped", engine.merge_spans([S("PERSON", 4, 4, 0.9)], []) == [])
check("redact with no spans", engine.redact("abc", []) == "abc")
check(
    "redact placeholders",
    engine.redact("ab cd ef", [S("PERSON", 0, 2, 1), S("LOCATION", 6, 8, 1)])
    == "<PERSON> cd <LOCATION>",
)

# ------------------------------------------------ engine with a stubbed analyzer
ssn = "078-05-1120"  # guards:synthetic
text = f"Alice Example lives in Springfield, mail alice@example.invalid, ssn {ssn}, host 10.11.0.230."
table = {
    "Alice Example": ("PERSON", 0.85),
    "Springfield": ("LOCATION", 0.85),
    "alice@example.invalid": (
        "PERSON",
        0.85,
    ),  # Presidio misreads it: dropped by the filter, and overlaps
    "078": ("US_SSN", 0.9),  # Presidio's own SSN recognizer must not be consulted
}
r, stub = run(text, table)
check(
    "Presidio asked only for PERSON and LOCATION",
    sorted(stub.asked) == ["LOCATION", "PERSON"],
    str(stub.asked),
)
got = {(t, text[a:b]) for t, a, b in spans_of(r)}
want = {
    ("PERSON", "Alice Example"),
    ("LOCATION", "Springfield"),
    ("EMAIL_ADDRESS", "alice@example.invalid"),
    ("US_SSN", ssn),
    ("IP_ADDRESS", "10.11.0.230"),
}
check("expected entities", got == want, str(got ^ want))
check("found flag", r["found"] is True)
red = r["redacted_text"]
for _, a, b in spans_of(r):
    check(f"span {text[a:b]!r} gone from redacted_text", text[a:b] not in red)
check(
    "redacted text exact",
    red
    == "<PERSON> lives in <LOCATION>, mail <EMAIL_ADDRESS>, ssn <US_SSN>, host <IP_ADDRESS>.",
    red,
)
ents = r["entities"]
check(
    "entity shape",
    all(set(e) == {"entity_type", "start", "end", "score"} for e in ents),
)
check(
    "entities sorted and non-overlapping",
    all(a["end"] <= b["start"] for a, b in itertools.pairwise(ents)),
)

# identifier filter: '=', '@', ':' now drop a PERSON span as well
for ident in ("user=bob", "bob:smith", "bob@host", "pod_name", "node-1", "a/b"):
    r, _ = run(f"see {ident} here", {ident: ("PERSON", 0.9)})
    check(f"PERSON identifier dropped: {ident}", not r["found"], str(r["entities"]))
r, _ = run(
    "signed Mary-Jane Smith-Jones today", {"Mary-Jane Smith-Jones": ("PERSON", 0.9)}
)
check("hyphenated real name kept", spans_of(r) == [("PERSON", 7, 28)], str(r))

# the configured minimum score is applied by the analyzer call
r, _ = run("Alice Example", {"Alice Example": ("PERSON", 0.1)})
check("score below the minimum not reported", not r["found"])

# noise stays silent even if Presidio would have called it a phone/passport
noise = "run 39442632382 ts 1760972400123 offset=4155550132 id 912345678"
r, _ = run(
    noise, {"4155550132": ("PHONE_NUMBER", 0.5), "912345678": ("US_PASSPORT", 0.5)}
)
check(
    "engineering noise not flagged",
    not r["found"] and r["redacted_text"] == noise,
    str(r),
)

# the output filters are wired in: a tool name read as PERSON and a key=value
# read as LOCATION are dropped, a real name and a street address are kept
tool = "Jenkins build 20 finished; max_position_embeddings=131072; Alice Example lives at 12 Maple Avenue"
r, _ = run(
    tool,
    {
        "Jenkins": ("PERSON", 0.85),
        "max_position_embeddings=131072": ("LOCATION", 0.85),
        "Alice Example": ("PERSON", 0.85),
        "12 Maple Avenue": ("LOCATION", 0.85),
    },
)
got = [(t, tool[a:b]) for t, a, b in spans_of(r)]
check(
    "filters drop a tool name and a key=value",
    got == [("PERSON", "Alice Example"), ("LOCATION", "12 Maple Avenue")],
    str(r),
)

# PII_ENTITIES narrowing: only the requested validator kinds run
saved = engine.ENTITIES
engine.ENTITIES = ["EMAIL_ADDRESS"]
r, stub = run(
    f"a@example.org {ssn} 10.0.0.1 Alice Example", {"Alice Example": ("PERSON", 0.9)}
)
check(
    "PII_ENTITIES limits validator kinds",
    [t for t, _, _ in spans_of(r)] == ["EMAIL_ADDRESS"],
    str(r),
)
check(
    "no Presidio call when it has nothing to look for",
    stub.asked is None,
    str(stub.asked),
)
# a non-validator, non-default Presidio kind passes through to Presidio
engine.ENTITIES = ["PERSON", "US_DRIVER_LICENSE", "EMAIL_ADDRESS"]
r, stub = run("Alice Example a@example.org", {"Alice Example": ("PERSON", 0.9)})
check(
    "other Presidio kinds still asked of Presidio",
    sorted(stub.asked) == ["PERSON", "US_DRIVER_LICENSE"],
    str(stub.asked),
)
engine.ENTITIES = saved

engine._analyzer = None
try:
    engine.analyze_and_redact("x")
    check("raises before load_engines", False)
except RuntimeError:
    pass

print(f"\n{'FAILED: ' + str(len(failures)) if failures else 'all merge tests passed'}")
sys.exit(1 if failures else 0)
