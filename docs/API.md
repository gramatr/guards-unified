# API reference

The contract of guards-unified v0.2.3, from `app/main.py`. The service is a
FastAPI app, listens on port 8700 in the container, speaks JSON, and has **no
authentication**; bind it to loopback (see
[CONFIGURATION.md](CONFIGURATION.md)). Request size is capped per route.

| Route | Method | Purpose |
|---|---|---|
| `/v1/scan` | POST | Secret, PII and injection axes. |
| `/v1/scan/secret` | POST | The secret axis alone. |
| `/health` | GET | Liveness. |
| `/about` | GET | Version and licence attribution. |

There are no other routes of the app's own. FastAPI's default documentation
routes (`/docs`, `/redoc`, `/openapi.json`) are not disabled in the code.

## Request

Both POST routes take the same body.

```json
{"text": "the text to scan"}
```

`text` is a required string. Its size is capped in UTF-8 bytes: 65,536 on
`/v1/scan` and 1,048,576 on `/v1/scan/secret` by default (settings
`SCAN_FULL_MAX_BYTES` and `SCAN_SECRET_MAX_BYTES`). Over the cap the route
answers `413` with `{"detail": {"error": "text_too_large", "bytes": ..., "limit_bytes": ..., "setting": ...}}`
and scans nothing. There is no other field and no way
to select rules or switches per request (those are
[container environment](CONFIGURATION.md)). A body that is not valid JSON of
this shape gets FastAPI's standard `422` response.

## Responses

### `POST /v1/scan`

All three axes run unconditionally, each on the **original** text. None gates
or depends on another.

```json
{
  "findings": [
    {"type": "secret",    "verdict": "...", "reason_code": null, "detail": {}},
    {"type": "pii",       "verdict": "...", "reason_code": null, "detail": {}},
    {"type": "injection", "verdict": "...", "reason_code": null, "detail": {}}
  ],
  "redacted_text": "..."
}
```

`findings` always has exactly these three entries in this order.
`redacted_text` is built in sequence: start from the original text; if the
secret verdict is `found`, take the secret-redacted text; then run PII
redaction on that, unless the secret verdict is `error`. Injection never
changes the text.

### `POST /v1/scan/secret`

The secret axis alone, same finding shape.

```json
{"findings": [{"type": "secret", "...": "..."}], "redacted_text": "..."}
```

`redacted_text` is the secret-redacted text when the verdict is `found`, and
the original text otherwise (including on `error`). No PII redaction happens.

### `GET /health`

Always `{"status": "ok"}`. It does not check that the models loaded (a process
whose models failed to load never starts, so it would not answer at all).

### `GET /about`

```json
{
  "service": "guards-unified",
  "version": "0.2.3",
  "model": "meta-llama/Llama-Prompt-Guard-2-86M",
  "model_revision": "a8ded8e697ce7c355e395a0df51f94adb4a2fd27",
  "attribution": "Built with Llama",
  "license_notice": "Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved.",
  "license_url": "https://www.llama.com/llama4/license/"
}
```

`version` is the `VERSION` file baked into the image (`unknown` if the file is
missing). It is how you tell which release a running container is: `/health`
says `ok` for any image.

## Finding shape

Every finding is `{type, verdict, reason_code, detail}`.

| Field | Meaning |
|---|---|
| `type` | `secret`, `pii` or `injection`. |
| `verdict` | `found` or `clean` for secret and PII; `malicious` or `clean` for injection; `error` for any axis whose detector raised. |
| `reason_code` | A list of machine-stable strings when something was found, otherwise `null`. See [Reason codes](#reason-codes). On a secret `error` from a timeout it is `["SECRET_SCAN_TIMEOUT"]`; on any other `error` it is `null`. |
| `detail` | Axis-specific, below. |

### `detail` per axis

**secret**

```json
{"redacted_text": "...", "rule_count": 2}
```

- `redacted_text`: the secret-redacted text (identical to the input when
  clean). It contains no PII redaction.
- `rule_count`: the number of entries scan.sh reported, counting repeats of
  the same rule.
- `redaction_failed: true` is added only when scan.sh reported findings but
  returned text identical to the input. In that case `redacted_text` is the
  withheld placeholder (below).
- On `error`: `{"error": "timeout"}` or `{"error": "<exception message>"}`.

**pii**

```json
{"redacted_text": "...", "entities": [{"entity_type": "EMAIL_ADDRESS", "start": 12, "end": 30, "score": 1.0}]}
```

`entities` carry type, character offsets and Presidio's score. They never carry
the matched text. `redacted_text` here is the PII redaction of the **original**
text: any secret in it is still there (see the warning below). On `error`:
`{"error": "<exception message>"}`.

**injection**

```json
{"score": 0.99, "chunks_scanned": 1}
```

`score` is the model's softmax probability for the winning class. When the
verdict is `malicious` it is the highest-confidence malicious window; when
`clean` it is the first window's *benign* confidence, so a high number means
confidently clean. Read it only for malicious verdicts. `chunks_scanned` is the
number of 512-token windows classified. The model's label is not returned.
On `error`: `{"error": "<exception message>"}`.

## Reason codes

| Axis | Format | Notes |
|---|---|---|
| secret | `SECRET_<RuleID uppercased>` | One entry per scan.sh finding, **not de-duplicated**; hyphens in rule IDs are kept. gitleaks supplies its own rule IDs (`github-pat` becomes `SECRET_GITHUB-PAT`); the scripts' own rules are listed below. `SECRET_UNKNOWN` if a finding had no rule ID. |
| secret (timeout) | `SECRET_SCAN_TIMEOUT` | Verdict is `error`; the text was not scanned. |
| pii | `PII_<entity type>` | Sorted and de-duplicated. Entity types: `PERSON`, `LOCATION`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`, `US_DRIVER_LICENSE`, `US_PASSPORT`, `US_BANK_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `IP_ADDRESS`. |
| injection | `INJECTION_OVERRIDE_OR_JAILBREAK` | The only code. The classifier is binary and cannot distinguish sub-kinds, so none are invented. |

Rule IDs from `scan.sh` itself (reported alongside gitleaks' own):

| Rule ID | Covers |
|---|---|
| `private-key-fallback` | PEM private keys, including truncated ones. |
| `secret-lead-in` | A value after a secret-ish key name or alias, and the YAML next-line form. |
| `url-password` | Password in URL userinfo or a DSN. |
| `url-query-secret` | Secret-ish query parameter values. |
| `auth-header` | Credential after an `Authorization` scheme. |
| `cookie-header` | Value of `Cookie` and `Set-Cookie`. |
| `cli-password-flag` | Credentials given as command-line flags or arguments. |
| `netrc-password`, `pgpass-password` | `.netrc` and `.pgpass` entries. |
| `k8s-env-value`, `json-key-value` | Name/value pairs split across lines or JSON members. |
| `azure-client-secret`, `gcloud-oauth-token`, `bcrypt-hash` | Vendor shapes. |
| `base64-secret` | A secret found inside a decoded base64 token. |
| `env-value` | An exported environment variable's value (opt-in switch; normally absent in the service). |

## The redaction marker

Secrets are replaced by the literal string `***REDACTED:SECRET***`, with any
surrounding prefix (such as the key name) kept.

PII is replaced by Presidio's default anonymizer operator, which substitutes
each span with its entity type in angle brackets. (That is the library's
default; this document did not run Presidio.)

When a confirmed secret could not be removed, the whole text is replaced by:

```
***REDACTED:SECRET*** (secret-guard could not safely redact this output; withheld)
```

This appears in two ways. `scan.sh` produces it when its post-redaction check
finds a confirmed gitleaks secret (or a 16-character line of one) still
present; the finding then has verdict `found` and `detail.redacted_text` is the
placeholder. `main.py` produces the same text and sets
`detail.redaction_failed: true` as a second line of defence when scan.sh
reported findings but returned the input unchanged. A finding is never returned
with the original text standing in for a redaction.

## When `redacted_text` is not trustworthy

1. **Any finding with verdict `error`.** A secret `error` (including the 15 s
   timeout) means the text was not scanned for secrets: on `/v1/scan/secret`
   `redacted_text` is the original. On `/v1/scan` it still has PII redacted,
   but any secret in it is not. If the PII pass fails, it holds only what the
   secret axis redacted. Do not use `redacted_text` as safe output when any
   finding has verdict `error`.
2. **The withheld placeholder.** If `redacted_text` is the placeholder above (or
   `redaction_failed` is true), the content is safe but gone; there is no
   partial result.
3. **The per-axis copies leak the other axes.** Because every axis scans the
   original, `findings[pii].detail.redacted_text` still contains any secret in
   the text, and `findings[secret].detail.redacted_text` still contains any
   PII. Use the top-level `redacted_text`, never a per-axis copy, as the safe
   output of `/v1/scan`.
4. **Side effect of redaction: normalisation.** When at least one context rule
   redacts something, the output is built from a normalised copy of the text,
   so ANSI colour sequences, zero-width characters and fullwidth `=` and `:`
   are changed across the **whole** output, not just near the secret. When
   nothing is redacted the original is returned byte for byte.
5. **Redaction is best-effort.** A `clean` secret verdict is not a guarantee;
   see [LIMITS.md](LIMITS.md).

## Errors and failure modes

| Situation | Result |
|---|---|
| Invalid body | `422` (FastAPI default). |
| `text` over the route's size cap | `413`, nothing scanned. Body: `{"detail": {"error": "text_too_large", "bytes", "limit_bytes", "setting"}}`. |
| Secret scan exceeds 15 s | `200`; secret finding verdict `error`, `SECRET_SCAN_TIMEOUT`. Fails open. |
| Secret scan raises | `200`; secret finding verdict `error`, `reason_code` null, message in `detail.error`. |
| PII or injection detector raises on the first call | `200`; that finding has verdict `error`, the other axes still report. |
| PII redaction raises in the final pass of `/v1/scan` | `200`. The error is logged and `redacted_text` is the text as redacted by the secret axis. (Before the request-limit fix this was an HTTP 500.) |
| A model failed to load | The process does not start. |

The size-cap, secret-error and PII-fault rows are pinned by
`tests/api_contract_test.py` (models stubbed). The rest is read from the code;
the `422` path was not run for this document.

## Metrics

Each call writes one line per finding to a local file
([README](../README.md#local-metrics-nothing-transmitted)): `/v1/scan` three,
`/v1/scan/secret` one. Only `ts`, `type`, `verdict` and `reason_code`.
