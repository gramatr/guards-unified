#!/usr/bin/env bash
# Starts the part of the service that can break on a dependency change without a model download:
# the Presidio analyzer and its spaCy model. The injection model is a gated Hugging Face download,
# so CI cannot start the full service; this still catches a binary-incompatible spaCy dependency
# (v0.2.13: preshed 3.0.14 made the tokenizer fail with OverflowError at startup).
#
#   bash tests/image_smoke.sh IMAGE
set -uo pipefail
image="${1:?usage: image_smoke.sh IMAGE}"
out="$(docker run --rm --entrypoint /app/.venv/bin/python "$image" -c \
  'import pii_guard.engine as e; e.load_engines(); print("nlp engine loaded")' 2>&1)"
rc=$?
if [ "$rc" -ne 0 ] || ! grep -q '^nlp engine loaded$' <<<"$out"; then
  echo "image smoke: FAIL ($image): the NLP engine did not load (exit $rc)" >&2
  printf '%s\n' "$out" | tail -15 >&2
  exit 1
fi
echo "image smoke: ok ($image)"
