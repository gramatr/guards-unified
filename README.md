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

## What the secret axis detects

Three layers, in order, all in `app/scan.sh`:

1. **Private keys, deterministic.** A pure-bash pass redacts
   `-----BEGIN ... PRIVATE KEY-----` and its body (END marker optional, so
   truncated keys are covered), independent of gitleaks.
2. **Context-aware rules, deterministic.** A value is redacted by what it
   sits next to, whatever it looks like: after a key name containing
   `secret`, `password`, `passwd`, `pwd`, `passphrase`, `token`, `api_key`,
   `private_key` or `credential`; after a whole-segment alias (`PW`, `PWD`,
   `PASS`, `CRED`, `PAT`, `client-key-data`); in `scheme://user:PASSWORD@host`
   URLs and DSNs; in secret-ish query parameters; after `Authorization:`
   `Basic|Bearer|Token|Digest`; in `Cookie:` / `Set-Cookie:` headers; in CLI
   flags (`--password X`, `mysql -pX`, `redis-cli -a X`, `sshpass -p X`,
   `docker login -p X`, `mc alias set A URL KEY SECRET`); in `.netrc` and
   `.pgpass` lines; for a name/value pair split across lines (Kubernetes
   `env`, Bitwarden-style JSON); and a few vendor shapes gitleaks lacks
   (Azure client secrets, gcloud `ya29.` tokens, bcrypt hashes). ANSI colour
   codes are ignored when matching. Placeholders (`${VAR}`, `<x>`, `***`,
   `true`/`null`) and keys that merely name a secret (`secretName`,
   `token_type`) are skipped. The bias is toward over-redaction.
3. **gitleaks**, retried once on error, for vendor token formats.

After redaction the script verifies that no confirmed secret survived and
withholds the whole output if one did. A finding never comes back with the
text unchanged.

Two opt-in switches, both off by default:

| Variable | Effect |
|---|---|
| `SECRET_GUARD_REDACT_KEY_IDS=1` | Also redact access-key and client IDs. Off by default: an ID is a semi-public identifier and the secret half is the enforced boundary. |
| `SECRET_GUARD_ENV_VALUES=1` | Exact-match redact the values of environment variables whose names look secret (`*TOKEN*`, `*PASSWORD*`, `*SECRET*`, `PW`, ...). Only meaningful where the scanner shares the session's environment (the Claude Code plugin's hooks and fallback), not in this service's container. |

Not detectable by any rule: a bare high-entropy value with no key name,
prefix or surrounding context. Tests: `tests/redaction_selftest.py` (run in
CI against the built image) and `tests/scan_options_test.sh`.

## Local metrics — purely personal, nothing transmitted

Every `/v1/scan` call appends one JSON line per finding to
`$METRICS_PATH` (default `/app/metrics/metrics.jsonl` inside the
container — mount a host volume there to persist it):

```json
{"ts": "2026-10-18T02:28:07.396580+00:00", "type": "secret", "verdict": "found", "reason_code": ["SECRET_GITHUB-PAT"]}
```

**Only `ts`/`type`/`verdict`/`reason_code` — never the scanned text,
never `redacted_text`, never anything from `detail`.** Confirmed by
running real scans containing a name, an email, and a live-shaped
token and reading the resulting file directly: none of it appears
anywhere in the metrics output.

This is deliberately **not** the same thing as the community/platform
telemetry proposed in `gramatr/guards-stack`'s `PROPOSAL.md` (Track A,
opt-in community reporting; Track B, `cpp-dwa`'s internal governance
telemetry) — both of those are still gated behind a legal/product
review that hasn't happened, and neither is implemented anywhere. This
writes to a local file on whatever host runs the container and goes
nowhere else; it needs no review because nothing leaves this process.

To mount it, **pre-create the host directory first and `chmod 777`
it** — the container runs as a non-root user (fixed UID/GID 1000,
confirmed GPU device access still works for this user on real
hardware before this shipped), and a bind-mounted directory Docker
auto-creates on first run comes back owned by root, which silently
breaks every metrics write (confirmed by testing: the scan itself
still succeeds, fail-open, but zero lines land — nothing erred loudly
to tell you):

```
mkdir -p ~/.local/share/gramatr-guards/metrics
chmod 777 ~/.local/share/gramatr-guards/metrics
docker run ... -v ~/.local/share/gramatr-guards/metrics:/app/metrics ...
```

`chmod 777` rather than trying to match the container's UID exactly —
simpler and host-portable, and the only thing that directory ever
holds is the metrics file above, which carries no scanned text, so the
broad permission costs nothing real. Directory write permission (not
file ownership) governs whether you can delete files inside it, so
this also fixes the original problem: no more `sudo` needed to manage
the metrics file.

(Already wired into the Compose files in `claude-plugin-guards` and
`platform-guards`, which pre-create and `chmod` this directory
automatically — see those repos' own `guards-selfheal.sh` or README.)

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

Two Dockerfiles, published as two image tags:

| Tag | File | Use when |
|---|---|---|
| `ghcr.io/gramatr/guards-unified:cpu` | `Dockerfile.cpu` | No GPU, or never will be one — smaller image, no CUDA packages |
| `ghcr.io/gramatr/guards-unified:gpu` | `Dockerfile` | A GPU might be available now or later — falls back to CPU automatically via `INJECTION_GUARD_DEVICE=auto` when none is visible |

Both tags are real multi-arch manifests (`linux/amd64` + `linux/arm64`).

```
docker build -t guards-unified:local -f Dockerfile.cpu .   # or -f Dockerfile for GPU-capable
docker run -p 127.0.0.1:8700:8700 \
  --env-file ~/.config/gramatr-guards/injection-guard.env \
  guards-unified:local
```

The injection-guard model (`meta-llama/Llama-Prompt-Guard-2-86M`) is
gated on Hugging Face — the env file must carry `HF_TOKEN=<token with
the Llama 4 Community License accepted>`. See injection-guard's own
README, "The HF_TOKEN problem," for how to get one.

**Multi-arch GPU builds: build natively per architecture, never
cross-build CUDA under QEMU emulation** — a CUDA-bundled torch install
under emulation is extremely slow (abandoned after it ran far longer
than a native build). Build on real hardware for each arch, then
combine:

```
# on an amd64 host with an NVIDIA GPU:
docker build -t ghcr.io/gramatr/guards-unified:gpu-amd64 -f Dockerfile . && docker push ghcr.io/gramatr/guards-unified:gpu-amd64
# on an arm64 host with an NVIDIA GPU:
docker build -t ghcr.io/gramatr/guards-unified:gpu-arm64 -f Dockerfile . && docker push ghcr.io/gramatr/guards-unified:gpu-arm64
# then, from either host:
docker buildx imagetools create -t ghcr.io/gramatr/guards-unified:gpu \
  ghcr.io/gramatr/guards-unified:gpu-amd64 ghcr.io/gramatr/guards-unified:gpu-arm64
```

Verified end to end on real hardware, both architectures, not just "it
builds": all three detectors load at startup (gitleaks binary via
`scan.sh`, Presidio's full recognizer set, the gated Llama model), and
`POST /v1/scan` returns correct per-finding verdicts and a
correctly-chained `redacted_text` against real test input — on an
x86_64 host with an NVIDIA RTX 4090 (confirmed GPU execution via the
`"Loading ... on cuda"` startup log line), and separately, natively,
on an aarch64 host with an NVIDIA GB10 (Grace-Blackwell) GPU, same
confirmation. The standard PyPI `torch` wheel's CUDA support on GB10
was an open question before this was tested — it works, confirmed, not
assumed.

**macOS / Apple Silicon**: the `:gpu`/`:cpu` multi-arch manifests both
resolve to the `arm64` image on an Apple Silicon Mac and run correctly
— but **without acceleration**. This build's GPU path is CUDA-only
(NVIDIA); Apple's GPU is Metal, and Docker Desktop on macOS does not
pass the host GPU through to its Linux VM at all (no `--gpus`
equivalent for Metal). `INJECTION_GUARD_DEVICE=auto` correctly falls
back to CPU on Mac, silently. Real Metal acceleration would require
two separate things neither of which exist yet: an MPS branch in
`injection_guard/model.py`'s device resolution (straightforward —
MPS ships in the standard macOS torch wheel already), and running the
process natively on the Mac host instead of inside Docker (MPS is
unreachable from inside any container on macOS, same reasoning as the
CUDA passthrough limit above).

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

MIT for this repository's own code — see `LICENSE`. The vendored
`pii_guard` and `injection_guard` packages carry their own upstream
licenses (MIT and MIT respectively).

**Built with Llama.** The model weights `injection_guard` loads at
runtime (`meta-llama/Llama-Prompt-Guard-2-86M`) are licensed separately
under Meta's Llama 4 Community License — this image carries the same
redistribution obligation as `injection-guard`'s own repo, satisfied
here the same way: `NOTICE` and `THIRD_PARTY_LICENSES/
LLAMA4_COMMUNITY_LICENSE.txt` ship with this repo (byte-identical to
`injection-guard`'s own copies, same model, same license), and the
running service's `GET /about` endpoint carries the same attribution
at runtime. A product website/about page display is a separate,
not-yet-done requirement, same open item `injection-guard`'s own
README tracks for itself.
