import os

# No AUTH_TOKEN branch here, deliberately — pii-guard has no hosted tier
# (see README "Why no hosted tier"). secret-guard's threat model applies:
# this tool exists to keep literal sensitive values from leaving the
# machine, so there is no "remote, with a token" deployment target to
# configure in the first place.

HOST = os.environ.get("PII_GUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("PII_GUARD_PORT", "8731"))

# "en" only for v1 — en_core_web_lg is English-only; Presidio's
# multi-language support requires explicitly configuring additional
# per-language spaCy models, not done here. See README "Language scope."
LANGUAGE = "en"

# Entity types to look for (comma-separated PII_ENTITIES overrides). The default
# leaves out US_DRIVER_LICENSE and US_BANK_NUMBER: Presidio's recognizers for them
# are pattern-only and match any long digit string at a score of 0.01 to 0.05, so
# run ids, epoch timestamps, PR numbers and similar noise in tool output raised a
# notice on almost every command. Add them back with PII_ENTITIES if you handle
# text where those numbers appear with context.
DEFAULT_ENTITIES = (
    "PERSON,LOCATION,EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,US_PASSPORT,"
    "CREDIT_CARD,IBAN_CODE,IP_ADDRESS"
)
ENTITIES = [
    e.strip().upper()
    for e in os.environ.get("PII_ENTITIES", DEFAULT_ENTITIES).split(",")
    if e.strip()
]

# Minimum Presidio score for a match to be reported (PII_MIN_SCORE). Presidio
# returns weak pattern matches at scores near zero; 0.4 keeps names (about 0.85),
# IP addresses (0.6), emails and phone numbers and drops those.
try:
    MIN_SCORE = float(os.environ.get("PII_MIN_SCORE", "0.4"))
except ValueError:
    MIN_SCORE = 0.4

# Which engine finds the structured kinds. "validators" (default): PERSON and
# LOCATION from Presidio, CREDIT_CARD / IBAN_CODE / US_SSN / US_PASSPORT /
# PHONE_NUMBER / IP_ADDRESS / EMAIL_ADDRESS from the deterministic checks in
# pii_guard.validators. "presidio": Presidio's own recognizers for everything,
# the behavior before v0.3.0, kept for one release (PII_ENGINE=presidio).
ENGINE = os.environ.get("PII_ENGINE", "validators").strip().lower()
if ENGINE not in ("validators", "presidio"):
    ENGINE = "validators"
