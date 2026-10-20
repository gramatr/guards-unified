# guards-unified

One image, one process, one API: secret, PII and prompt-injection detection
behind a single `POST /v1/scan` endpoint (and a secret-only `POST
/v1/scan/secret`), instead of three separate containers on three separate
ports.

Current version: see [`VERSION`](VERSION) (also served by `GET /about`).
What changed in each release: [CHANGELOG.md](CHANGELOG.md).

| Read this | For |
|---|---|
| [docs/API.md](docs/API.md) | Routes, request and response shapes, reason codes, when `redacted_text` can be trusted |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every environment variable the server reads, budgets and limits |
| [docs/LIMITS.md](docs/LIMITS.md) | What it does not catch |
| [docs/TRADEOFFS.md](docs/TRADEOFFS.md) | What was hardened, what was loosened, and why |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Assets, actors, trust boundaries, and what is and is not defended |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately |
| [docs/RELEASING.md](docs/RELEASING.md) | Cutting a release |

## Why this exists

[secret-guard](https://github.com/gramatr/secret-guard),
[pii-guard](https://github.com/gramatr/pii-guard) and
[injection-guard](https://github.com/gramatr/injection-guard) are each their
own project with their own Dockerfile, licence and HTTP daemon. That is the
right shape for each project owning its detection logic. It is not the right
shape for a caller that always wants all three checked on the same text:
that is three round trips and three call sites for one question, "is this
content safe to act on".

This repo vendors each project's detection code (the `pii_guard` and
`injection_guard` packages, and secret-guard's `scan.sh` and `report.sh`) into
one FastAPI app, so any caller (a Claude Code hook, an MCP server, another
harness) makes one call and gets a result for all three axes at once. The
[guards-stack](https://github.com/gramatr/guards-stack) repo is the
three-separate-containers alternative.

## Three independent axes, not a pipeline

Secrets, personal data and prompt injection are three unrelated problems.
`POST /v1/scan` runs all three unconditionally on the same original text;
none gates, waits on or depends on another. Secret and PII findings come with
a redacted copy of the text. Injection only ever flags: its judgement is a
whole-chunk probability with no span to blank, and redacting it risks
destroying legitimate content.

## API

Four routes. The full contract is in [docs/API.md](docs/API.md).

| Route | What it does |
|---|---|
| `POST /v1/scan` | All three axes. Body `{"text": "..."}`. Returns `findings` (always `[secret, pii, injection]`) and `redacted_text` (secrets, then PII; injection never alters text). |
| `POST /v1/scan/secret` | The secret axis alone, same finding shape. Tens of milliseconds (the code says about 30 ms; the release measurement was 55 to 60 ms through the service), because it does not run the PII and injection models. Use it wherever secrets are what matter (tool output, commits, anything about to be published). |
| `GET /health` | Liveness. Always `{"status": "ok"}`; it does not check the models. |
| `GET /about` | `service`, `version` (the `VERSION` file baked into the image), `model`, and the Llama licence attribution. Use it to confirm which release a running container is. |

The PII and injection models cost about 0.25 s per KB of text (2 KB about
0.5 s, 24 KB about 5 s, as measured by the maintainers; not guaranteed), and
do not get faster by splitting the text across parallel requests. A caller
that cannot wait on them should call `/v1/scan/secret` and decide separately
how much text to send for the other two axes. The server itself always scans
whatever it is sent.

**There is no authentication.** Bind it to loopback or an equally private
network. Request bodies are capped (`/v1/scan` at 64 KiB of text,
`/v1/scan/secret` at 1 MiB; over the cap is HTTP 413), both adjustable. See
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## What the secret axis detects

Five layers, run in this order, all in `app/scan.sh` (a bash script the
service shells out to; `gitleaks` and `jq` must be on `PATH`):

1. **Private keys, deterministic.** A pure-bash pass redacts
   `-----BEGIN ... PRIVATE KEY-----` and the body that follows. The END marker
   is optional, so truncated keys are covered. It does not depend on gitleaks
   and runs even if gitleaks or `jq` is missing. Rule ID `private-key-fallback`.
2. **Context-aware rules, deterministic.** A value is redacted by what it sits
   next to, whatever it looks like. Matching is done on a copy of the text
   with ANSI colour codes and zero-width characters removed and fullwidth `=`
   and `:` mapped to ASCII. Rules:
   - after a key name containing `secret`, `password`, `passwd`, `pwd`,
     `passphrase`, `token`, `api_key`, `private_key` or `credential`
     (`secret-lead-in`); the value must be at least 4 characters, quoted or bare;
   - after a whole-segment alias (`PW`, `PWD`, `PASS`, `CRED`, `CREDS`, `PAT`,
     `client-key-data`); `compass` or `bypass` do not match;
   - the one YAML next-line form: a line that is only `password:` (optionally
     `- ` before it) followed by an indented line holding one bare token
     (below);
   - the password in `scheme://user:PASSWORD@host` URLs and DSNs
     (`url-password`) and in secret-ish query parameters (`url-query-secret`);
   - the credential after an `Authorization` header scheme (Basic, Bearer,
     Token or Digest; 8 or more characters; `auth-header`) and the value of
     `Cookie` and `Set-Cookie` headers (`cookie-header`);
   - credentials given on a command line (`cli-password-flag`): the value
     after `--password`, `--token`, `--secret`, `--api-key` and similar flags,
     and the password argument of `mysql`, `redis-cli`, `sshpass`,
     `docker login` and `mc alias set`; the `--flag=value` form is handled by
     the key rules;
   - `.netrc` and `.pgpass` lines (`netrc-password`, `pgpass-password`);
   - a name/value pair split across lines: Kubernetes `env`, Bitwarden-style
     JSON (`k8s-env-value`, `json-key-value`);
   - a few vendor shapes the default gitleaks ruleset lacks: Azure client
     secrets, gcloud `ya29.` and `1//0` tokens, bcrypt hashes
     (`azure-client-secret`, `gcloud-oauth-token`, `bcrypt-hash`).

   The bias is toward over-redaction: a leaked credential costs more than a
   redacted harmless value. See [what is deliberately skipped](#what-the-context-rules-deliberately-skip).
3. **Base64 blobs, on by default.** A secret hiding under an innocent key
   name (`{"conn": "cG9zdGdyZXM6Ly8..."}`, a Kubernetes Secret) is invisible
   to key-name rules, so long base64-looking tokens are decoded and the
   deterministic passes run on the decoded text. A hit redacts the whole token
   (`base64-secret`). Hex digests, one-word tokens, binary decodes and
   decodes that are mostly non-printable are skipped; at most 25 candidate
   tokens (44 to 65,536 characters each) are tried per scan.
   `SECRET_GUARD_B64=0` turns it off.
4. **Environment-value pass, opt-in.** With `SECRET_GUARD_ENV_VALUES=1`, the
   values of exported environment variables whose names look secret are
   redacted wherever they appear (`env-value`). Off by default and
   meaningless inside this service's container; see the switches below.
5. **gitleaks**, for vendor token formats (default ruleset, v8.30.1 in the
   image). Retried once if it exits non-zero.

After redaction the script re-checks that no confirmed gitleaks secret (or
16-character line of one) survives, and withholds the whole output if one
does. A finding never comes back with the text unchanged.

### What the context rules deliberately skip

- Placeholders and references: values starting with `$`, `<`, `{`, `%(`, `***`
  or `...`; values that are only a run of `x`, `*`, `.`, `-` or `_`; and
  (case-insensitively) the exact words `true`, `false`, `null`, `none`, `nil`,
  `yes`, `no`, `undefined`, `empty`, `redacted`, `changeme`, `example`, `todo`,
  `tbd`, `string`, `password`, `secret`, `token`.
- Keys that only describe a secret rather than hold one, for example
  `secretName`, `token_type`, `token_count` or `secretKeyRef`: a secret, token
  or credential word followed by name, ref, id, type, path, file, version,
  count, ttl, namespace, store, manager, provider, url or arn.
- A value that is an absolute path which exists on the machine running the
  scan. The `PWD` lines that `env`, `printenv` and `export -p` print are
  the working directory, not a password. A path that does not exist, or a
  non-path value under a `PWD` key, is still redacted. The check runs where
  `scan.sh` runs, so a path that exists only on a client's machine is not
  recognised by the service.
- A plural heading (`tokens`, `secrets`, `passwords`, `credentials`,
  `passphrases`) followed by a markdown code span.
- A heading that ends in a keyword and a colon, followed by prose on the next
  line. The key rules allow blanks after the `:` or `=`, never a newline.
- Access-key IDs and client IDs, unless `SECRET_GUARD_REDACT_KEY_IDS=1`.

### The narrow YAML next-line rule

YAML puts a scalar on the line after its key:

```
password:
  <the-value>
```

The rule matches only when the key line holds nothing but the key (optionally
`- ` before it) and a colon, and the next line is indented and holds a single
token of at least 4 characters with no colon. It does not match a heading
followed by a command or sentence, a nested key (`secret:` then `name: x`), a
multi-word line, or two keys in a row. Residual: a keyword-and-colon heading
followed by exactly one word on the next line cannot be told apart from a YAML
scalar by pattern, so that word is redacted. The alias keys (`PW`, `PASS`,
...) are not covered by the next-line form.

### Switches

These are environment variables read by `scan.sh`. In the service they are
process environment of the container (`docker run -e NAME=value`); there is no
per-request parameter.

| Variable | Default | Effect |
|---|---|---|
| `SECRET_GUARD_B64` | on | `0` turns off the base64-blob pass. |
| `SECRET_GUARD_SKIP_GITLEAKS` | off | `1` runs only the deterministic passes (private key, context rules, base64, and env values if enabled) and skips gitleaks. For callers that already got gitleaks' answer from `/v1/scan/secret`. |
| `SECRET_GUARD_REDACT_KEY_IDS` | off | `1` also redacts access-key and client IDs. Off because an ID is a semi-public identifier and the secret half is the enforced boundary. |
| `SECRET_GUARD_ENV_VALUES` | off | `1` exact-match redacts the values of environment variables whose names look secret (`*TOKEN*`, `*PASSWORD*`, `*SECRET*`, `PW`, ...; names ending `_FILE`, `_PATH`, `_DIR`, `_URL`, `_URI`, `_NAME`, `_ID`, `_TYPE`, `_HOST`, `_PORT`, `_USER` are skipped, as are values under 8 characters, placeholders, existing paths, `PWD` and `OLDPWD`). Only meaningful where the scanner shares the session's environment, such as a Claude Code plugin's local hooks. In this service it would match the container's own environment, so leave it off. |

Plugin-side settings such as `FLAG_MAX_BYTES` and `FLAG_BUDGET` (how much of
a tool output is sent for the PII and injection notices, and how long to wait
for them) belong to the Claude Code plugin's hook, not to this server. This
server has no such settings and scans everything it is sent.

Not detectable by any rule: a bare high-entropy value with no key name, prefix
or surrounding context. The full list of known misses is in
[docs/LIMITS.md](docs/LIMITS.md).

### Tests

`tests/run-all.sh` runs everything CI can: lint, the option tests with and
without gitleaks on `PATH`, and the redaction self-test. The self-test
(`tests/redaction_selftest.py`) asserts that a `found` secret verdict always
changes the text and leaves no fragment behind, that each required shape is
redacted, and that harmless lookalikes come back byte-identical. It runs in CI
against the built CPU image's `scan.sh` and secret route; it does not start the
full service, because the injection model is a gated download. So the PII and
injection axes are not tested end to end in this repo's CI.

## Failure behaviour: fail-open vs fail-closed

Each choice below is deliberate.

| Situation | Behaviour |
|---|---|
| A confirmed secret could not be removed from the output | **Closed.** The text is replaced by `***REDACTED:SECRET*** (secret-guard could not safely redact this output; withheld)`. If `scan.sh` produced unchanged text for a non-empty finding list, `main.py` does the same and sets `detail.redaction_failed: true`. |
| The secret scan takes longer than 15 s | **Open.** The text is left unscanned; the secret finding has verdict `error`, reason code `SECRET_SCAN_TIMEOUT` and `detail: {"error": "timeout"}`. Withholding the output instead was tried and dropped: it takes a user's whole result away to guard a rare case. |
| `gitleaks` or `jq` missing, or gitleaks fails twice | **Open for the gitleaks layer.** The deterministic layers still run; a line is logged. |
| The PII or injection model raises on a request | That axis reports verdict `error` with the exception message in `detail`; the other axes still run. A caller must not read one axis's `error` as "the whole request is clean". |
| A model fails to load at startup | The process does not start. |
| Writing a metrics line fails | Logged and ignored. |

## Local metrics: nothing transmitted

Both `POST /v1/scan` and `POST /v1/scan/secret` append one JSON line per
finding to `$METRICS_PATH` (default `/app/metrics/metrics.jsonl` inside the
container; mount a host volume there to persist it). `/v1/scan` writes three
lines per call, `/v1/scan/secret` writes one.

```json
{"ts": "2026-10-18T02:28:07.396580+00:00", "type": "secret", "verdict": "found", "reason_code": ["SECRET_GITHUB-PAT"]}
```

Only `ts`, `type`, `verdict` and `reason_code`: never the scanned text, never
`redacted_text`, nothing from `detail`. The file is not rotated, so it grows
without bound. It is a local file on whatever host runs the container;
nothing is sent anywhere.

The container runs as a non-root user (fixed UID and GID 1000). A bind-mounted
directory that Docker creates on first run is owned by root, which silently
breaks every metrics write (the scan itself still succeeds, so nothing errs
loudly). Pre-create the host directory and make it writable:

```
mkdir -p ~/.local/share/gramatr-guards/metrics
chmod 777 ~/.local/share/gramatr-guards/metrics
docker run ... -v ~/.local/share/gramatr-guards/metrics:/app/metrics ...
```

`chmod 777` is the simple, host-portable choice rather than matching UID
1000 exactly; on a shared host, `chown 1000:1000` the directory instead. The
file holds no scanned text. The `claude-plugin-guards` self-heal script creates
this directory for you.

## Scope: read before relying on this

The short version; the long version with the evidence is
[docs/LIMITS.md](docs/LIMITS.md).

- **Injection detection is jailbreak and override detection only.** It does
  not reliably catch indirect injection (malicious instructions embedded in
  data, with no override language). Measured recall on that case was 6%
  (InjecAgent, n=200, real tool-output injections). A `clean` injection
  verdict is not a safety guarantee for content an agent is about to act on.
- **PII detection covers 11 Presidio entity types, English only.** Not all PII.
- **Injection is flag-only.** The service never alters text for it. PII
  comes with a best-effort redacted copy, but callers decide what to do with
  either.
- **Secrets are the one hard rule.** Everything else is best-effort.

## Building and running

Two Dockerfiles, published as two image tags. Both are multi-arch manifests
(`linux/amd64` and `linux/arm64`), built natively per architecture and merged.

| Tag | File | Use when |
|---|---|---|
| `ghcr.io/gramatr/guards-unified:cpu` | `Dockerfile.cpu` | No GPU, or never will be one: smaller image, no CUDA packages |
| `ghcr.io/gramatr/guards-unified:gpu` | `Dockerfile` | A GPU might be available now or later: falls back to CPU automatically via `INJECTION_GUARD_DEVICE=auto` when none is visible |

`:cpu` and `:gpu` float to the latest release. For reproducible deployments
pin `cpu-vX.Y.Z` or `gpu-vX.Y.Z`; per-architecture tags
(`cpu-amd64-vX.Y.Z`, `cpu-arm64-vX.Y.Z`, ...) also exist and are what the
merge step combines. Releases are described in
[docs/RELEASING.md](docs/RELEASING.md).

```
docker build -t guards-unified:local -f Dockerfile.cpu .   # or -f Dockerfile for GPU-capable
docker run -p 127.0.0.1:8700:8700 \
  --env-file ~/.config/gramatr-guards/injection-guard.env \
  guards-unified:local
```

Publish the port on `127.0.0.1` as shown. The server listens on `0.0.0.0`
inside the container, has no authentication, caps request bodies only at the
sizes in [docs/CONFIGURATION.md](docs/CONFIGURATION.md), and
receives raw text that may contain secrets.

The injection model (`meta-llama/Llama-Prompt-Guard-2-86M`) is gated on
Hugging Face. The first start needs network access and an `HF_TOKEN=<token>`
environment variable (the standard Hugging Face variable, read by the
`transformers` library) for an account that has accepted the Llama 4 Community
License, for example in the env file above. The model is cached under
`HF_HOME` (`/app/.cache/huggingface`). If either model fails to load, the
process does not start.

Sizing: the PII and injection models are CPU-bound without a GPU. The
`claude-plugin-guards` Compose file runs the image with a 4 GB memory limit
(its comments record that 2 GB was OOM-killed) and a generous CPU allowance;
use it as a starting point and measure on your hardware.

**Multi-arch GPU builds: build natively per architecture, never cross-build
CUDA under QEMU emulation.** A CUDA-bundled torch install under emulation is
extremely slow. CI builds amd64 on a GitHub-hosted runner and arm64 on a
self-hosted arm64 GPU runner, then merges the two (see
[docs/RELEASING.md](docs/RELEASING.md)). By hand:

```
# on an amd64 host with an NVIDIA GPU:
docker build -t ghcr.io/gramatr/guards-unified:gpu-amd64 -f Dockerfile . && docker push ghcr.io/gramatr/guards-unified:gpu-amd64
# on an arm64 host with an NVIDIA GPU:
docker build -t ghcr.io/gramatr/guards-unified:gpu-arm64 -f Dockerfile . && docker push ghcr.io/gramatr/guards-unified:gpu-arm64
# then, from either host:
docker buildx imagetools create -t ghcr.io/gramatr/guards-unified:gpu \
  ghcr.io/gramatr/guards-unified:gpu-amd64 ghcr.io/gramatr/guards-unified:gpu-arm64
```

The GPU path was exercised on an x86_64 host with an NVIDIA RTX 4090 and,
natively, on an aarch64 host with an NVIDIA GB10 GPU, when the multi-arch
build was first introduced (v0.1.x). It has not been re-verified for every
release.

**macOS and Apple Silicon.** Both multi-arch manifests resolve to the `arm64`
image on an Apple Silicon Mac and run correctly, but without acceleration: the
GPU path is CUDA-only (NVIDIA), and Docker Desktop on macOS does not pass the
host GPU through to its Linux VM. `INJECTION_GUARD_DEVICE=auto` falls back to
CPU. Real Metal acceleration would need an MPS branch in
`injection_guard/model.py`'s device resolution and running the process
natively on the Mac host instead of in Docker. Neither exists today.

## Relationship to the other repos

- [secret-guard](https://github.com/gramatr/secret-guard),
  [pii-guard](https://github.com/gramatr/pii-guard) and
  [injection-guard](https://github.com/gramatr/injection-guard) are the
  standalone projects this code was vendored from. `app/scan.sh` here has since
  diverged from secret-guard's: it carries the rules and passes described above
  that the standalone copy lacks, so for the current script this repo is the
  reference.
- [guards-stack](https://github.com/gramatr/guards-stack) is the
  three-separate-containers Compose deployment, an alternative backend for the
  same three detectors.
- [claude-plugin-guards](https://github.com/gramatr/claude-plugin-guards) is
  the Claude Code integration (hooks and an MCP server) and the first consumer
  of this image's endpoints. The two packages are one product and move in
  lockstep: same version, same tag. The rule is written in
  [docs/RELEASING.md](docs/RELEASING.md#versions-move-in-lockstep-with-claude-plugin-guards).
  The plugin carries a vendored copy of `app/scan.sh` for its local fallback
  passes.

Issues are disabled on this repository.

## Licence

MIT for this repository's own code; see `LICENSE`. The vendored `pii_guard`
and `injection_guard` packages carry their own upstream licences (MIT and MIT
respectively).

**Built with Llama.** The model weights `injection_guard` loads at runtime
(`meta-llama/Llama-Prompt-Guard-2-86M`) are licensed separately under Meta's
Llama 4 Community License. This image carries the same redistribution
obligation as `injection-guard`'s own repo, satisfied the same way: `NOTICE`
and `THIRD_PARTY_LICENSES/LLAMA4_COMMUNITY_LICENSE.txt` ship with this repo
and inside the image under `/app/licenses/`, and the running service's
`GET /about` carries the attribution at runtime. A product website or about
page display is a separate, not-yet-done requirement.
