#!/usr/bin/env bash
# core/report.sh — report a redaction event as compliance evidence.
#
# Posts the findings metadata to a Kestra webhook flow (the receiving side
# is up to whoever runs it; it is typically a ticket plus an audit row).
#
# Usage:
#   SECRET_GUARD_SOURCE=claude-code-live-session \
#   SECRET_GUARD_FILE="Bash tool output" \
#   core/report.sh < findings.json
#
# findings.json is the array scan.sh writes when SECRET_GUARD_FINDINGS_JSON
# is set: [{"RuleID": "...", "StartLine": ..., "Fingerprint": "..."}, ...]
# — no secret values, by construction (scan.sh never writes them there).
#
# Required env: SECRET_GUARD_SOURCE (ci | pr | claude-code-live-session | ...)
# Optional env: SECRET_GUARD_FILE, SECRET_GUARD_REPO, SECRET_GUARD_CONTEXT,
# REPORT_WEBHOOK_PATH (the webhook flow path under /api/v1/executions/webhook/,
# default soc2/secret-leak-to-zammad)
#
# Fail-open: if KESTRA_PUBLIC_URL / KESTRA_WEBHOOK_KEY_SECRET_LEAK aren't
# set, this logs a line to SECRET_GUARD_LOCAL_LOG (default
# /tmp/secret-guard-events.jsonl) and exits 0 — a missing credential must
# never block the caller or the redaction that already happened.

set -uo pipefail

LOCAL_LOG="${SECRET_GUARD_LOCAL_LOG:-/tmp/secret-guard-events.jsonl}"
FINDINGS="$(cat)"

if [ -z "${SECRET_GUARD_SOURCE:-}" ]; then
  echo "secret-guard report.sh: SECRET_GUARD_SOURCE not set, skipping report" >&2
  exit 0
fi

if [ -z "${FINDINGS}" ] || [ "${FINDINGS}" = "[]" ]; then
  exit 0
fi

if [ -z "${KESTRA_PUBLIC_URL:-}" ] || [ -z "${KESTRA_WEBHOOK_KEY_SECRET_LEAK:-}" ]; then
  echo "secret-guard report.sh: KESTRA_PUBLIC_URL/KESTRA_WEBHOOK_KEY_SECRET_LEAK not set — logging locally only (${LOCAL_LOG}), nothing posted" >&2
  echo "{\"ts\":\"$(date -Iseconds)\",\"source\":\"${SECRET_GUARD_SOURCE}\",\"findings\":${FINDINGS}}" >> "$LOCAL_LOG"
  exit 0
fi

echo "$FINDINGS" | jq -c '.[]' | while read -r finding; do
  payload=$(jq -n \
    --arg source "${SECRET_GUARD_SOURCE}" \
    --arg repo "${SECRET_GUARD_REPO:-}" \
    --arg file "${SECRET_GUARD_FILE:-unknown}" \
    --arg rule_id "$(echo "$finding" | jq -r '.RuleID')" \
    --arg line "$(echo "$finding" | jq -r '.StartLine // ""')" \
    --arg context "${SECRET_GUARD_CONTEXT:-}" \
    --arg fingerprint "$(echo "$finding" | jq -r '.Fingerprint // ""')" \
    '{source: $source, repo: $repo, file: $file, rule_id: $rule_id, line: $line, context: $context, fingerprint: $fingerprint}')

  curl -sS -X POST \
    "${KESTRA_PUBLIC_URL}/api/v1/executions/webhook/${REPORT_WEBHOOK_PATH:-soc2/secret-leak-to-zammad}/${KESTRA_WEBHOOK_KEY_SECRET_LEAK}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    >/dev/null \
    || echo "secret-guard report.sh: failed to POST to the webhook, logging locally (${LOCAL_LOG})" >&2
done

exit 0
