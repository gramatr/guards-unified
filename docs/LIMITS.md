# What it does not catch

This is a best-effort filter, not a guarantee. A `clean` verdict means "none of
these detectors fired", never "this text is safe". Everything below is read
from the code at v0.2.3 or pinned by a test; items that were checked by running
`scan.sh` say so, and anything not verified is marked.

The design, in one paragraph: **secrets are the one hard rule** (deterministic,
fast, biased toward over-redaction, fails closed when it knows a secret
survived); PII and prompt injection are best-effort notices. Policy, org-wide
rules, async delivery and audit sinks are out of scope for this repo. The
rationale behind individual choices is in [TRADEOFFS.md](TRADEOFFS.md).

## Secrets

The secret axis is gitleaks' default ruleset plus a set of context rules (what a
value sits next to). It cannot find a secret that has neither a known vendor
shape nor a telling neighbour.

**Not detected by any rule**

- A bare high-entropy value with no key name, prefix or surrounding context
  (`echo $SOME_VAR` printing just the value). The only mitigation is the
  opt-in environment-value pass, which needs the scanner to share the
  environment of the process that produced the text, so it does nothing in this
  service.
- Short values. Key-name rules need 4 or more characters, `scheme://user:PW@`
  passwords 3 or more, `Authorization` credentials 8 or more (a short bearer
  value is left alone), cookie values 8 or more. A value that is a placeholder
  word is never redacted, so a real credential that is literally `changeme`,
  `password`, `secret`, `token`, `example`, `true`, `none` and the like is
  skipped.
- Secrets in query parameters other than the listed names (`password`,
  `passwd`, `pwd`, `secret`, `token`, `access_token`, `api_key`, `apikey`,
  `x-amz-signature`, `x-amz-security-token`). For example a `key=` or `sig=`
  parameter is left alone (checked).
- Credentials given to `curl -u user:pass` (checked: not covered), and password
  flags of tools other than those listed in the README.
- Passwords containing a raw `@` or `/` inside a URL: the match stops at the
  first one, so the part after it stays visible (checked with a throwaway
  value).
- Access-key and client IDs, by default. They are treated as semi-public
  identifiers; the secret half is the boundary. `SECRET_GUARD_REDACT_KEY_IDS=1`
  changes that.
- A value that is an existing absolute path on the machine running the scan is
  never treated as a password. A secret that happens to equal such a path is
  missed, and a path that exists only on the caller's machine but not in the
  container is judged by the container's filesystem.
- A quoted value that contains its own closing quote unescaped is cut short at
  the first one.
- A key and value separated by a newline, except the one narrow YAML form:
  the key line must be only the key and a colon, and the next line a single
  bare token. A multi-word or multi-line value, a nested mapping, or an alias
  key (`PW`, `PASS`, ...) in that form is not redacted.
- Legacy encrypted PEM keys with `Proc-Type` / `DEK-Info` header lines: the
  deterministic pass stops at the first dash in those headers, so the rest is
  left to gitleaks.
- Public keys and certificates are intentionally not matched (the rule requires
  `PRIVATE KEY`).

**Encodings**

- Base64 decoding looks at no more than 25 distinct candidate tokens per scan,
  each 44 to 65,536 characters. Beyond that, nothing is decoded.
- It does not decode double-encoded base64, hex, URL-encoding or compressed
  data. It skips pure-hex tokens, single-word tokens, decodes under 16 bytes and
  decodes that are less than 95% printable.
- Decoded text goes through the deterministic passes only. A vendor token
  format that only gitleaks recognises is not found inside a base64 blob.

**Scope of the input**

- Text only. No files, images or binary content.
- Each request is independent: a secret split across two calls is invisible to
  both.
- The scanner is the default gitleaks ruleset (v8.30.1 in the image). Nothing in
  this repo extends or tunes it.

**What the post-redaction check covers**

The check that withholds the whole output when a secret survives only covers
secrets gitleaks confirmed. Values redacted by the context, base64 and
environment passes are not re-verified.

## Rules over-redact on purpose

The flip side of the bias toward over-redaction: harmless text can be redacted.
Known cases: a heading that ends in a keyword and a colon followed by exactly
one word on the next line (cannot be told from a YAML scalar by pattern); any
value after a key whose name merely contains a keyword (`secret`, `token`,
`credential`, ...) unless the key reads as a descriptor such as `secretName`
or `token_count`; and prose that wraps a key word and its colon in
quotes, when a second quote follows on the same line (the text between the
quotes is taken for a quoted value; a quoted value never crosses a line).
When anything is redacted, ANSI colour codes, zero-width
characters and fullwidth `=` and `:` are normalised across the whole output
(see [API.md](API.md#when-redacted_text-is-not-trustworthy)).

## PII

- **English only**, with 11 entity types: `PERSON`, `LOCATION`,
  `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`, `US_DRIVER_LICENSE`,
  `US_PASSPORT`, `US_BANK_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `IP_ADDRESS`.
  Dates, URLs, nationality or religious or political group, crypto addresses
  and everything else Presidio can find are excluded on purpose (they
  produced false positives on engineering text). Organisation names are not
  supported at all by the recogniser in use.
- The standalone pii-guard project reported that about 63% of the PII in one
  real-world sample fell outside this entity set. That figure comes from that
  project's benchmark and was not reproduced here.
- Name and place detection is statistical (a spaCy model); it has misses and
  false positives. No score threshold is configured.
- The service returns a redacted copy, but a caller that redacts wholesale is
  likely to damage ordinary technical output (git remotes read as emails,
  timestamps as phone numbers, tool names as people). The Claude Code plugin
  therefore flags PII instead of redacting by default.
- Not verified: how very large inputs behave (the NLP library has its own length
  limit).

## Prompt injection

- **Jailbreak and override detection only.** The model is Llama Prompt Guard 2
  (86M), a binary classifier. It does not reliably catch indirect injection:
  instructions embedded in data (a web page, a tool result, a file) with no
  override language. Measured recall on that case was **6%** (InjecAgent, n=200,
  real tool-output injections), as recorded in the code. A `clean` verdict is
  not a safety guarantee for content an agent is about to act on.
- No categories: the only reason code is `INJECTION_OVERRIDE_OR_JAILBREAK`.
- **Flag-only.** The service never modifies text for injection: its judgement is
  a whole-window probability with no span to blank.
- Text is classified in 512-token windows with a 32-token overlap; any malicious
  window flags the whole input, so a long benign document with one hostile
  paragraph is flagged, and nothing says which paragraph.
- False positives happen. The service applies no threshold: it returns the
  model's verdict. Callers that must avoid noise should filter on
  `detail.score` for `malicious` verdicts. (The plugin does; it reported benign
  security-themed development text scoring as malicious in the high 0.8s and
  low 0.9s, and real attacks higher.)
- The model is a gated download: the first start needs network access and a
  Hugging Face token for an account that accepted the licence.
- The accuracy comparison quoted in the code between the 86M and a 22M model
  (93.8% against 68.8% on a small set) is a comment; the evaluation is not in
  this repo.

## Cost, not just coverage

PII and injection cost about 0.25 s per KB on CPU, and splitting a request
across parallel calls does not make them faster. That is why callers that
cannot wait should send only a prefix to `/v1/scan` and use `/v1/scan/secret`
for the rest (the Claude Code plugin does exactly this: PII and injection
notices cover only the first part of a tool output, and everything beyond it is
never flagged for PII or injection). The server itself has no such cap.

## Failure modes

- **Fails open on timeout.** A secret scan that takes more than 15 s returns the
  text unscanned, verdict `error` with `SECRET_SCAN_TIMEOUT`. This is deliberate
  (withholding the output was tried and dropped) and it means an adversary, or
  just a huge input, can push text past the scanner. Thousands of matches are
  slow even below the limit.
- **No gitleaks or `jq`**: the deterministic passes still run; gitleaks'
  vendor-format coverage is lost, with a log line.
- **A secret `error` leaves secrets in `/v1/scan`'s `redacted_text`** (the
  caller keeps the original text); PII is still redacted there.
- **A PII fault in the final pass of `/v1/scan`** is logged and
  `redacted_text` falls back to the secret-redacted text (200, not a 500).
- **No authentication, no TLS, no rate limit, and no per-request time budget
  for the model axes.** Request size is capped (413 over 64 KiB on `/v1/scan`,
  1 MiB on `/v1/scan/secret`), but the body is read before it is checked. Treat
  the port as an internal, loopback-only interface.
- The metrics file is never rotated.

## Testing gaps

- CI cannot start the full service: the injection model is a gated download.
  CI builds the CPU image and runs the redaction self-test against its
  `scan.sh`, and calls the secret route function directly inside the image.
  **No automated test exercises the real PII engine or injection model end to
  end.** `tests/api_contract_test.py` covers the size caps and what a failing
  axis does, with both models stubbed. A live
  `tests/redaction_selftest.py --endpoint` run after a release covers the
  secret axis only.
- The tests use only fabricated values. They pin what is covered (a required
  case must be found and redacted) and what must not be (23 harmless lookalikes
  must come back byte-identical), but they cannot prove that a real credential
  of a shape nobody thought of is caught.
- Timing is tested (a 100 KB hash-heavy scan within 2 s, about 230 KB of prose
  with one secret within 15 s, 300 distinct secret lines all redacted), not
  measured on a range of hardware. The quoted latencies are the maintainers'
  measurements and are not guaranteed.
- The plugin's vendored copy of `scan.sh` is kept in sync by hand; no check
  compares the two.
- The GPU path was exercised on two hardware families when it was introduced and
  is not tested per release.
