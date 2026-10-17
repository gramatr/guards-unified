# guards-unified

One image, one process, one API — secret-guard, pii-guard, and
injection-guard's detection logic combined behind a single `POST
/v1/scan` endpoint, instead of three separate Docker containers on
three separate ports (that's [gramatr/guards-stack](https://github.com/gramatr/guards-stack)).

## Why this exists

Each of the three sibling projects — [secret-guard](https://github.com/gramatr/secret-guard),
[pii-guard](https://github.com/gramatr/pii-guard),
[injection-guard](https://github.com/gramatr/injection-guard) — is its
own repo with its own Dockerfile, license, and HTTP daemon. That's the
right shape for each project owning its own detection logic. It is
**not** the right shape for a caller that always wants all three
checked on the same text, every time: calling three separate endpoints
for one logical "is this content safe to act on" question is three
round trips and three client-side call sites for no benefit, when the
caller never wanted a partial answer anyway.

This repo vendors each project's actual detection code (not a
re-implementation — the real `pii_guard`/`injection_guard` packages and
secret-guard's `scan.sh`/`report.sh`) into one FastAPI app, so **any**
caller — a Claude Code hook, an MCP server, a different harness
entirely, a future grāmatr platform service — makes one call and gets
back a result for all three axes at once.

## Three independent axes, not a pipeline

secret-guard, pii-guard, and injection-guard protect against three
unrelated things (credential leaks, personal-data leaks,
jailbreak/override attempts). `/v1/scan` runs all three unconditionally
on the *same original text* — none gates, waits on, or depends on
another. Secret and PII findings redact (exact character spans);
injection only ever flags, because its judgment is a whole-chunk
probability with no span to blank — redacting it risks destroying
legitimate content, so it only prepends a warning for the caller to
act on.

## API

```
POST /v1/scan
{"text": "..."}
```

Response:
```json
{
  "findings": [
    {"type": "secret", "verdict": "found|clean|error", "reason_code": ["SECRET_<gitleaks rule>"] | null, "detail": {...}},
    {"type": "pii", "verdict": "found|clean|error", "reason_code": ["PII_<entity type>"] | null, "detail": {...}},
    {"type": "injection", "verdict": "malicious|clean|error", "reason_code": ["INJECTION_OVERRIDE_OR_JAILBREAK"] | null, "detail": {"score": 0.0, "chunks_scanned": 1}}
  ],
  "redacted_text": "secrets then PII redacted in sequence; injection never alters the text"
}
```

`GET /health` for liveness.

## Scope — read before relying on this for anything

- **Injection detection is jailbreak/override detection only.** Per
  injection-guard's own `RESEARCH-SPIKE-classification.md` and Meta's
  own model card for the underlying Llama Prompt Guard 2 model: this
  does **not** reliably catch indirect injection (malicious instructions
  embedded in data with no override language). Measured recall on that
  case is 6% (InjecAgent, n=200, real tool-output injections). A
  `"clean"` injection verdict is not a safety guarantee for content an
  agent is about to act on.
- **PII detection covers Presidio's configured entity set only** — not
  all PII. ~63% of PII in one real-world sample fell outside this
  entity set in pii-guard's own benchmark.
- **Fails explicit, not open.** If a sub-detector errors, that
  finding's `verdict` is `"error"` with the exception message in
  `detail` — the other two axes still run and report normally. A
  caller must not treat one axis's failure as "the whole request is
  clean."

## Building and running

```
docker build -t guards-unified:local .
docker run -p 127.0.0.1:8700:8700 \
  --env-file ~/.config/gramatr-guards/injection-guard.env \
  guards-unified:local
```

The injection-guard model (`meta-llama/Llama-Prompt-Guard-2-86M`) is
gated on Hugging Face — the env file must carry `HF_TOKEN=<token with
the Llama 4 Community License accepted>`. See injection-guard's own
README, "The HF_TOKEN problem," for how to get one.

Verified end to end (not just "it builds"): all three detectors load
at startup (gitleaks binary via `scan.sh`, Presidio's full recognizer
set, the gated Llama model), and `POST /v1/scan` returns correct
per-finding verdicts and a correctly-chained `redacted_text` against
real test input.

## Relationship to the other guard repos

- [secret-guard](https://github.com/gramatr/secret-guard),
  [pii-guard](https://github.com/gramatr/pii-guard),
  [injection-guard](https://github.com/gramatr/injection-guard) remain
  the source of truth for each detector's own logic, licensing, and
  standalone daemon — this repo vendors their code, it doesn't replace
  or fork their projects. A fix to detection logic belongs upstream in
  the relevant project, then gets re-vendored here.
- [guards-stack](https://github.com/gramatr/guards-stack) is the
  three-separate-containers Compose deployment. This repo is an
  alternative backend for the same three detectors, not a replacement —
  callers that already depend on guards-stack's three ports are
  unaffected.
- [claude-plugin-guards](https://github.com/gramatr/claude-plugin-guards)
  is the Claude Code integration (hooks + MCP server) and is the first
  consumer of this image's `/v1/scan` endpoint.

## License

MIT for this repository's own code. The vendored `pii_guard` and
`injection_guard` packages carry their own upstream licenses (MIT and
MIT respectively — the model weights injection-guard loads at runtime
are licensed separately under Meta's Llama 4 Community License, same
as in injection-guard's own repo; see that project's README for the
attribution requirements this image inherits).
