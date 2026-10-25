#!/usr/bin/env bash
# Starts the real service from an image, the way it ships (its own entrypoint, both models), and
# asks it to scan. If the server fails to start, or any axis answers "error", this fails.
#
#   HF_TOKEN=... bash tests/image_service_smoke.sh IMAGE      # run IMAGE in Docker, then check it
#   SERVICE_URL=https://host bash tests/image_service_smoke.sh # check a running service only
#
# The injection model is a gated Hugging Face download, so starting an image needs HF_TOKEN
# (read from the environment, never put on a command line). Without it: exit 2 and say so, unless
# SMOKE_SKIP_WITHOUT_TOKEN=1 (pull requests from forks have no secrets), which prints SKIP and exits 0.
# All test values are made up at run time.
set -uo pipefail

url="${SERVICE_URL:-}"
name="guards-smoke-$$"
cleanup() { [ -n "${started:-}" ] && docker rm -f "$name" >/dev/null 2>&1; }
trap cleanup EXIT
fail() { echo "service smoke: FAIL: $*" >&2; exit 1; }

if [ -z "$url" ]; then
  image="${1:?usage: image_service_smoke.sh IMAGE (or set SERVICE_URL)}"
  if [ -z "${HF_TOKEN:-}" ]; then
    if [ "${SMOKE_SKIP_WITHOUT_TOKEN:-0}" = 1 ]; then echo "service smoke: SKIP (no HF_TOKEN in this run)"; exit 0; fi
    echo "service smoke: no HF_TOKEN; the injection model cannot be downloaded, so the service cannot start" >&2; exit 2
  fi
  port="${SMOKE_PORT:-18700}"
  docker run -d --name "$name" -e HF_TOKEN -p "127.0.0.1:${port}:8700" "$image" >/dev/null || fail "docker run"
  started=1
  url="http://127.0.0.1:${port}"
fi

# Model load takes a while on a cold start; give it five minutes, and stop early if the container died.
ok=""
for _ in $(seq 1 100); do
  if [ -n "${started:-}" ] && [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != true ]; then
    docker logs "$name" 2>&1 | tail -20 >&2; fail "the container exited during startup"
  fi
  if curl -fsS -m 5 "$url/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 3
done
[ -n "$ok" ] || { [ -n "${started:-}" ] && docker logs "$name" 2>&1 | tail -20 >&2; fail "/health never answered"; }

version="$(curl -fsS -m 10 "$url/about" | jq -r .version)" || fail "/about"
echo "service smoke: up, version $version"

# A made-up email and a made-up credential-shaped value, assembled here so no literal sits in the repo.
key="api_""key=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
body="$(jq -n --arg t "contact jane.doe@example.com then $key" '{text:$t}')"
resp="$(curl -fsS -m 60 -X POST "$url/v1/scan" -H 'content-type: application/json' -d "$body")" || fail "POST /v1/scan"
errs="$(jq -r '[.findings[] | select(.verdict=="error") | .type] | join(",")' <<<"$resp")"
[ -z "$errs" ] || fail "axis in error: $errs"
[ "$(jq '.findings|length' <<<"$resp")" = 3 ] || fail "expected 3 findings, got $(jq '.findings|length' <<<"$resp")"
[ "$(jq -r '.findings[]|select(.type=="pii")|.verdict' <<<"$resp")" = found ] || fail "the made-up email was not flagged as PII"
jq -e '.redacted_text | contains("jane.doe@example.com") | not' >/dev/null <<<"$resp" || fail "the email is still in redacted_text"
curl -fsS -m 30 -X POST "$url/v1/scan/secret" -H 'content-type: application/json' -d "$body" >/dev/null || fail "POST /v1/scan/secret"
echo "service smoke: ok (all three axes answered, email redacted)"
