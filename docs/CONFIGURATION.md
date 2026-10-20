# Configuration

Everything the server can be configured with, what it defaults to, and who
reads it. All of it is process environment of the container (`docker run -e
NAME=value` or an env file); there are no per-request parameters and no config
file. Defaults below are read from the code at v0.2.3.

"Owner" says which part of the image reads the variable:

- **scan.sh**: `app/scan.sh`, the secret scanner `main.py` shells out to. The
  service passes its whole environment to it.
- **server**: `app/main.py` and the vendored packages it imports.
- **library**: a third-party library (Hugging Face, PyTorch) that reads it on
  its own.

## Variables the server reads

| Variable | Default | Owner | Effect |
|---|---|---|---|
| `METRICS_PATH` | `/app/metrics/metrics.jsonl` | server | File that `POST /v1/scan` and `POST /v1/scan/secret` append one JSON line per finding to (`ts`, `type`, `verdict`, `reason_code` only). The parent directory is created if missing; a write failure is logged and ignored. Never rotated. |
| `INJECTION_GUARD_DEVICE` | `auto` (`cpu` in the `:cpu` image) | server | `auto` uses CUDA if PyTorch sees a GPU, else CPU. `cpu` forces CPU. `cuda` forces GPU and makes startup fail if none is visible. |
| `INJECTION_GUARD_MODEL_REVISION` | the commit this project evaluated (for the default model), else `main` | server | Hugging Face revision of the model to download. Pinned so a change upstream cannot change the detector without a commit here. Reported by `GET /about` as `model_revision`. To bump: load the new revision, run the live self-test and the end-to-end test, then change `RECOMMENDED_MODEL_REVISION` in `app/injection_guard/config.py`. |
| `INJECTION_GUARD_MODEL_ID` | `meta-llama/Llama-Prompt-Guard-2-86M` | server | Hugging Face model for the injection axis. Any other value logs a warning at startup: nothing in this project has evaluated it. Reported by `GET /about` as `model`. |
| `PII_ENTITIES` | `PERSON,LOCATION,EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,US_PASSPORT,CREDIT_CARD,IBAN_CODE,IP_ADDRESS` | server | Comma-separated entity types to look for (Presidio's names; the validator kinds are described under `PII_ENGINE`). The default leaves out `US_DRIVER_LICENSE` and `US_BANK_NUMBER`: their recognizers are pattern-only and matched any long digit string at a score of 0.01 to 0.05. Add them back if you handle text where those numbers appear with context. |
| `PII_ENGINE` | `validators` | server | Which code finds the structured kinds. `validators`: Presidio supplies `PERSON` and `LOCATION` only; `CREDIT_CARD`, `IBAN_CODE`, `US_SSN`, `US_PASSPORT`, `PHONE_NUMBER`, `IP_ADDRESS` and `EMAIL_ADDRESS` come from the deterministic checks in `app/pii_guard/validators.py` (Luhn, IBAN mod 97, SSN issued ranges, structured phone numbers, parseable IPv4, email pattern, a passport number only right after the word "passport", a bare SSN only right after "SSN"). `presidio`: Presidio's own recognizers for every kind, as before; kept for one release, then removed. Any other value means `validators`. `PII_ENTITIES` still selects which kinds are reported in either mode, and a kind outside the validator set (such as `US_DRIVER_LICENSE`) is always asked of Presidio. |
| `PII_MIN_SCORE` | `0.4` | server | Lowest Presidio score a match needs to be reported. Applies to `PERSON` and `LOCATION` (and any other Presidio kind) only; validator matches are not scored statistically. Names score about 0.85, IP addresses 0.6, phone numbers 0.4; weak pattern matches score near zero. Raise it for fewer notices, lower it for more. |
| `PII_IGNORE_NAMES` | empty | server | Comma-separated names, matched case-insensitively and as a whole, that are never reported as a `PERSON`, added to the built-in list of about 300 software, tool and product names in `app/pii_guard/ignore_names.py` (Jenkins, Grafana, Kafka, ...). Use it for a tool or product name your team uses that is being read as a person, for example `PII_IGNORE_NAMES=Acme Deploy,Orbit`. A name written after a title (`Dr. Jenkins`) is still reported. The cost: a real person with exactly that name, mentioned alone, is not flagged. |
| `SCAN_FULL_MAX_BYTES` | `65536` | server | Largest `text` (UTF-8 bytes) `POST /v1/scan` accepts; larger gets HTTP 413. Low on purpose: the PII and injection models cost about 0.25 s per KB and a running request cannot be cancelled. Callers that want the model axes should send a short prefix. |
| `SCAN_SECRET_MAX_BYTES` | `1048576` | server | Largest `text` `POST /v1/scan/secret` accepts; larger gets HTTP 413. Higher because this route is cheap and callers send whole tool outputs. |
| `SECRET_GUARD_B64` | `1` | scan.sh | `0` turns off the base64-blob pass. |
| `SECRET_GUARD_SKIP_GITLEAKS` | `0` | scan.sh | `1` skips gitleaks and runs only the deterministic passes. |
| `SECRET_GUARD_REDACT_KEY_IDS` | `0` | scan.sh | `1` also redacts access-key and client IDs. |
| `SECRET_GUARD_ENV_VALUES` | `0` | scan.sh | `1` redacts the values of the scanner's own secret-named environment variables wherever they appear. In this service that means the container's environment, which is almost never what you want; leave it off. |
| `HF_TOKEN` | unset | library | Hugging Face access token, needed on first start to download the gated injection model (the account must have accepted the Llama 4 Community License). Not needed once the model is cached. |
| `HF_HOME` | `/app/.cache/huggingface` (set in both Dockerfiles) | library | Where the model and tokenizer are cached. Mount a volume here to avoid re-downloading on every container creation. |

The effects of the four `SECRET_GUARD_*` switches are described in the
[README](../README.md#switches). They are read on every scan, but since the
container's environment is fixed at start, changing one means restarting the
container.

Internal, not for you to set: `SECRET_GUARD_B64_DEPTH` (set by `scan.sh` when it
recurses to scan decoded base64; any non-empty value disables the base64 pass)
and `SECRET_GUARD_FINDINGS_JSON` (`main.py` sets it to a temporary file on every
scan to collect rule IDs, overriding any value you pass).

## Settings that belong to the plugin, not the server

The Claude Code plugin's hooks have their own settings, for example
`FLAG_MAX_BYTES` and `FLAG_BUDGET` (how many bytes of a tool output are sent
for the PII and injection notices, and how long the hook waits for them),
`SECRET_MAX_BYTES`, `GUARDS_ENDPOINT` and `PII_GUARD_MODE`. They are read by
shell scripts in `claude-plugin-guards`, in the environment Claude Code starts
from. **This server reads none of them** and has no equivalent: it scans
whatever text it is sent, in full. See that repository's documentation.

## Vendored settings that nothing reads

These come from the standalone projects this code was vendored from. They
still exist in the vendored config modules, but nothing in this image uses
them. Setting them has no effect.

| Variable | Vendored default | Why it does nothing |
|---|---|---|
| `INJECTION_GUARD_HOST`, `INJECTION_GUARD_PORT` | `127.0.0.1`, `8730` | The image starts `uvicorn main:app --host 0.0.0.0 --port 8700`. |
| `PII_GUARD_HOST`, `PII_GUARD_PORT` | `127.0.0.1`, `8731` | Same. |
| `INJECTION_GUARD_AUTH_TOKEN` | unset | Defined in the injection config, but no code in this app reads it. **The server enforces no authentication whatsoever**, whatever you set. |

`app/report.sh` is also shipped in the image but is not called by the server. If you use it, `REPORT_WEBHOOK_PATH` sets the webhook flow path it posts to (default `soc2/secret-leak-to-zammad`).
It is a reporting helper inherited from secret-guard. Given findings metadata,
it posts it to a workflow webhook if its `KESTRA_*` webhook variables are set,
and otherwise appends it to a local log (`SECRET_GUARD_LOCAL_LOG`). It also
reads `SECRET_GUARD_SOURCE`, `SECRET_GUARD_FILE`, `SECRET_GUARD_REPO` and
`SECRET_GUARD_CONTEXT`. None of this is in the request path.

The scan language for PII is fixed at English (`en`) in code.

## Network and security posture

- **No authentication.** Every route is open to anyone who can reach the port.
- **Request size is capped per route** (`SCAN_FULL_MAX_BYTES`,
  `SCAN_SECRET_MAX_BYTES`, see above). The check runs after the body has been
  parsed, so a very large body still costs memory to read; it no longer costs
  model time. There is no rate limit and no per-request time budget for the
  model axes.
- **Binds to `0.0.0.0` inside the container, on port 8700.** Publish it to the
  host on loopback only: `-p 127.0.0.1:8700:8700`. Do not expose it to a
  network you do not fully trust: it receives raw text that may contain
  secrets, and anyone who reaches it can use it as a free CPU sink.
- FastAPI's default interactive documentation routes (`/docs`, `/redoc`,
  `/openapi.json`) are not disabled in the code, so they should exist
  (inferred from FastAPI's defaults; not tested against a running container).
- The container runs as a non-root user (`guards`, UID and GID 1000).
- A liveness check hits `GET /health` every 30 s (5 s timeout, 60 s start
  period). `/health` returns `ok` without checking the models.

## Supply chain

Build inputs are pinned so a rebuild cannot change the image without a commit:

- **`uv`** (copied into both images): tag and digest, in `Dockerfile` and
  `Dockerfile.cpu`. To bump, pick a release, read its digest with
  `docker buildx imagetools inspect ghcr.io/astral-sh/uv:<version>`, and change
  tag and digest together in both files.
- **Base images and gitleaks:** explicit tags (`python:3.12-slim`, gitleaks by
  release).
- **The injection model:** the revision above.
- `tests/dockerfile_pins_test.sh` fails on a floating `latest` tag or a missing
  tag for any external image, in `run-all.sh` and in CI.

Python packages are still installed by version floor, not by hash.

## Budgets and limits

Hard-coded; none is configurable.

| What | Value | Behaviour at the limit |
|---|---|---|
| Secret scan wall time | 15 s (subprocess timeout in `main.py`) | **Fails open.** The text is left unscanned; the secret finding has verdict `error`, reason code `SECRET_SCAN_TIMEOUT`, and `redacted_text` is the original. This was a deliberate decision: withholding the whole output was tried and dropped. |
| Base64 candidates per scan | 25 distinct tokens, each 44 to 65,536 characters | The rest are not decoded. Longer tokens are skipped. |
| Base64 decode size | at least 16 bytes, at least 95% printable | Smaller or binary-looking decodes are skipped. |
| Private-key matches per scan | 100,000 loop iterations | Past that, further keys are not redacted by the deterministic pass. |
| Context rules | no cap on matches | Linear time; 300 distinct secret lines are all redacted (tested). Thousands of matches are still slow (about 22 s for 500 KB with 2,000 secrets in one measurement by the maintainers; not re-measured). |
| Injection window | 512 tokens, 32-token overlap (480-token step) | Longer text is split into windows; every window is classified, and any malicious window flags the whole input. There is no cap on the number of windows, so cost grows with input size. Each window is also truncated to 512 tokens. |
| PII text length | 64 KiB on `/v1/scan` by default (`SCAN_FULL_MAX_BYTES`) | Not verified: the underlying NLP library has its own maximum text length, and an input beyond it may make the PII axis return verdict `error`. |
| `/v1/scan/secret` latency | tens of milliseconds | The code's docstring says about 30 ms; the maintainers measured 55 to 60 ms per call in the production image. Neither was re-measured here. Grows with input size and with the number of rules that match. |
| `/v1/scan` latency | about 0.25 s per KB | Dominated by the PII and injection models on CPU. A GPU speeds up the injection model only. |

CPU is the constraint for the two models. Without a GPU, give the container
enough CPUs and at least 4 GB of memory; a 2 GB limit was seen to get the
process OOM-killed under load in the plugin's Compose setup.
