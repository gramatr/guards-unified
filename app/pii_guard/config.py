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
