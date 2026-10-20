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
- A malformed `"pw:"value"` (a key word wrapped in quotes with its colon inside
  them and the value glued on after the closing quote) is not redacted: it is
  indistinguishable from prose that quotes a key word with a colon, which is
  deliberately left alone (the text up to the next quote is not a value). Valid
  forms (`"pw": "value"`, `"pw":"value"`, `pw="value"`) are redacted.
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
or `token_count`.
When anything is redacted, ANSI colour codes, zero-width
characters and fullwidth `=` and `:` are normalised across the whole output
(see [API.md](API.md#when-redacted_text-is-not-trustworthy)).

## PII

- **English only**, with 9 entity types by default, from two sources:
  - Presidio (a spaCy model, statistical): `PERSON` and `LOCATION`. A `PERSON`
    span containing a digit, underscore, slash, `=`, `@` or `:` is treated as an
    identifier and dropped.
  - Deterministic checks in `app/pii_guard/validators.py` (since the release
    after v0.2.6; `PII_ENGINE=presidio` restores Presidio for these for one
    release): `CREDIT_CARD` (Luhn, a known issuer and length, or a grouped 4-4-4-4
    or 4-6-5 shape), `IBAN_CODE` (country length and mod 97), `US_SSN`
    (`ddd-dd-dddd` outside the never-issued ranges 000, 666, group 00, serial
    0000; `9xx` areas are kept because ITINs and test data use them; nine bare
    digits only straight after "SSN" or "social security"), `US_PASSPORT` (nine
    digits, or a letter and eight, only straight after the word "passport"),
    `PHONE_NUMBER` (North American numbers with parentheses or separators, `+`
    international numbers with separators, compact `+E.164` away from the start of
    a line), `IP_ADDRESS` (IPv4), `EMAIL_ADDRESS`.
  - Not reported, on purpose: loopback (`127.0.0.0/8`) and `0.0.0.0`, the
    broadcast address and netmasks; `noreply@`, `no-reply@` and `donotreply@`
    senders; the `git` user of an ssh remote (`git@github.com:org/repo.git`);
    `name@2x.png` asset names. Still reported: private-range IPv4 addresses
    (an internal host address is what a leak looks like) and other role
    mailboxes such as `security@` and `support@`.
  - Known misses: phone numbers written as bare digits or in national formats
    outside North America (`020 7946 0958`); IPv6; a card number with an unusual
    issuer prefix, or written unseparated with a stray prefix; an IBAN written in
    lower case; an SSN or passport number with no keyword and no dashes;
    non-English text. Known false positives: an IPv4-shaped version string
    (`1.2.3.4`), a 16-digit id that starts like a card issuer and passes Luhn by
    chance (about one in ten of such ids; the issuer-and-length rule cuts this
    to a small fraction), and the `PERSON`/`LOCATION` noise below.
  - What changed: on the bake-off corpus (a fabricated set of 324 PII lines and
    624 ordinary engineering lines, gramatr/guards-coordination#46) 43 of 1000
    ordinary lines still raise a notice, down from 109; overall recall is 0.96.
    All of what remains is Presidio reading an engineering word (Jenkins, Darwin,
    Phoenix) as a person or a hex id as a place. Address recall (Presidio
    `LOCATION`) is 0.69.
  `US_DRIVER_LICENSE` and `US_BANK_NUMBER` are off by
  default (see [CONFIGURATION.md](CONFIGURATION.md): `PII_ENTITIES`) because their
  recognizers are pattern-only and matched run ids, timestamps and PR numbers. A
  Presidio match (`PERSON`, `LOCATION`) must score at least 0.4 (`PII_MIN_SCORE`).
  Dates, URLs, nationality or religious or political group, crypto addresses
  and everything else Presidio can find are excluded on purpose (they
  produced false positives on engineering text). Organisation names are not
  supported at all by the recogniser in use.
- The standalone pii-guard project reported that about 63% of the PII in one
  real-world sample fell outside this entity set. That figure comes from that
  project's benchmark and was not reproduced here.
- Name and place detection is statistical (a spaCy model); it has misses and
  false positives. Only the 0.4 minimum score applies.
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
  `tests/e2e_real_models_test.py` is the one test that runs the real PII engine
  and injection model end to end through `/v1/scan` (five fabricated cases);
  `.github/workflows/e2e.yml` runs it weekly, on tag pushes and on demand, on
  the self-hosted arm64 runner. It needs a `HF_TOKEN` repository secret that a
  maintainer must create, and it is advisory, not a gate on `publish.yml`
  (see [RELEASING.md](RELEASING.md#release-checklist-real-model-e2e)). It is
  five cases, not a measurement of detection quality, and it does not run in
  `tests/run-all.sh` or on pull requests. `tests/api_contract_test.py` covers the
  size caps and what a failing axis does, with both models stubbed. A live
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
