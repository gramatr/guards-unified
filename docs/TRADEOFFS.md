# Hardening and loosening: the trade-offs behind the server

Every detection rule trades missed secrets against redacted harmless text. This
page records what was made stricter, what was relaxed, and what each choice
cost, for the server in this repository, so you can judge whether the defaults
suit you and so a future change does not silently undo one.

**About the numbering.** This repository was deleted and recreated on
2026-10-19; its pull request numbers restarted at #1. The numbers below are the
current repository's. Changes made before the recreation (v0.1.0 to v0.1.4)
survive only as commits and have no PR number. The tags `v0.1.5` onward exist
here; `v0.1.0` to `v0.1.4` do not. Dates are 2026-10-18 to 2026-10-19. "Live in"
is the first release that carried the change: `v0.2.0` was tagged too early and
never published, and `0.2.1` was never tagged, so work merged for them first
shipped in `v0.2.2`. See [CHANGELOG.md](../CHANGELOG.md) and
[RELEASING.md](RELEASING.md).

The Claude Code plugin has its own hooks and its own trade-offs (ask versus
deny, advisory prompt checks, confidence floors); those are in that repository.

## Hardening

Changes that made the server catch more, or fail more safely.

| PR | Live in | Change | Why | Cost |
|---|---|---|---|---|
| #3 | v0.1.6 | Quote the redaction pattern; read secrets NUL-delimited so a multi-line secret is replaced as one unit; second pass on 16-plus-character per-line fragments (CRLF); re-check afterwards and withhold the whole output if a confirmed secret survives; `main.py` backstop sets `redaction_failed` and withholds when a finding comes back with unchanged text; the redaction self-test and a CI job that runs it in the real image. | The pattern was unquoted, so bash treated the secret as a glob: a backslash, `*`, `?` or `[` in it silently stopped matching. A private key inside JSON came back unchanged with verdict `found`. 8 of 24 required key checks failed before the change, none after. | When redaction cannot be made safe the caller gets a placeholder and no content at all. |
| #3 | v0.1.6 | A deterministic pure-bash private-key pass that does not depend on gitleaks, covers keys with no END marker, and a single retry when gitleaks exits non-zero. | gitleaks occasionally (about once per few hundred scans in CI) returned no findings for a key it normally detects, and the script read that as clean; its rule also needs the END marker, so truncated output was never detected. | Matches greedily to the end of the key body; legacy encrypted PEM with `Proc-Type` headers stops at the first dash and is left to gitleaks. |
| #5 | v0.2.2 | Context rules: redact a value by what it sits next to (secret-ish key names, `user:password@` URLs, secret-ish query parameters, `Authorization` headers). Also: gitleaks' empty `[]` report is treated as no findings, so clean input keeps its trailing newline. | gitleaks keys on a value's shape. Real credentials break the shape: punctuation-heavy passwords, short human-chosen ones, passwords inside connection strings. | **Stated bias: over-redact**, because a leaked credential costs more than a redacted harmless value. Needs a skip list for placeholders and for keys that merely name a secret, and a benign-lookalike test for every rule. |
| #6 | v0.2.2 | Whole-segment aliases (`PW`, `PWD`, `PASS`, `CRED`, `PAT`, `client-key-data`), `Cookie` and `Set-Cookie`, command-line flags, `.netrc` and `.pgpass`, name/value pairs split across lines, Azure, gcloud and bcrypt shapes; ANSI colour codes ignored when matching; opt-in environment-value redaction. | Gaps found by a review of what the first rules missed. Table-driven rule helpers make a new rule one line. | More rules, more false-positive surface (`compass` and `ssh -p` have to stay untouched). Alias keys are matched as whole segments only. |
| #7 | v0.2.2 | Linear-time span splitting (no leading-`*` globs); removed the per-rule match cap (200) and private-key cap (50); one `jq` call for logging instead of two per finding; zero-width characters dropped and fullwidth `=` and `:` mapped to ASCII for matching. | Found by measuring large inputs. Every one of these was a way for a secret to come back unredacted: 232 KB with one secret took 19 s and 1 MB took 447 s, past the 15 s timeout; matches 201 onward were returned as-is (100 of 300 secrets survived). | After any redaction, the output comes from the normalised copy, so ANSI codes, zero-width characters and fullwidth delimiters are changed across the whole output. Thousands of matches are still slow. |
| #9 | v0.2.2 | `POST /v1/scan/secret` and `SECRET_GUARD_SKIP_GITLEAKS`. | The PII and injection models cost about 0.25 s per KB and do not speed up when the request is split. A caller that needs secrets redacted should not wait on them. | A second code path that callers must choose deliberately; PII is not redacted on it. |
| #10 | v0.2.2 | A base64 pass that decodes long base64-looking tokens and runs the deterministic passes on the decoded text; a hit redacts the whole token. Switch `SECRET_GUARD_B64=0`. | A secret under an innocent key name (`{"conn": "<base64>"}`, a Kubernetes Secret) is invisible to key-name rules. | The first version used a bounded regex in bash and added 2.9 s to every scan; a timing test would have caught it, and now does. Limits: 25 tokens per scan, only the deterministic passes on the decoded text. |
| (before recreation) | v0.1.0 to v0.1.3 | Run as a non-root user; local metrics that never contain scanned text; licence files and `GET /about` (so a stale pull is visible); `apt-get upgrade` in the build; version floors for dependencies with known CVEs; Trivy scan on every image and a weekly scheduled scan. | Supply-chain and operational hygiene. | A metrics directory bind-mounted by Docker is root-owned and silently breaks metrics writes (documented in the README). |

## Loosening and walk-backs

Changes that deliberately accepted a miss, or removed over-eager detection.

| PR | Live in | Change | Why | What was given up |
|---|---|---|---|---|
| #6 | v0.2.2 | Access-key and client IDs are **not** redacted by default; `SECRET_GUARD_REDACT_KEY_IDS=1` opts in. | An ID is a semi-public identifier. The secret half is the boundary that must hold. | A visible ID can be correlated with a leaked secret; documented, not ambiguous. |
| #6 | v0.2.2 | Environment-value redaction is opt-in and meaningless in the service container. | It is only correct where the scanner shares the environment of the process that produced the text. | The one mitigation for a bare value with no neighbouring key does not run in the service. |
| #7 (commit reverted inside it) | v0.2.2 | Failing **closed** (withholding the whole output) when the 15 s scan times out was tried and dropped. A timeout is logged as `SECRET_SCAN_TIMEOUT` and the caller keeps the original text. | It takes a user's entire result away to guard against a rare unscanned output; a policy decision had been made inside a bug fix. The speed fixes in the same PR remove the common cause of timeouts. | A very large or adversarial input can slip past the scanner on timeout. |
| #12 | v0.2.2 | The environment-value pass skips `PWD` and `OLDPWD` by name, and any value that is an existing file or directory. | The shell's current-directory variable matched the `PW` alias, so every mention of the working directory in output was redacted. Found by running the hooks live; no test had used a realistic environment. | A secret that is also a real path on the scanning host is missed. |
| #13 | v0.2.2 | Same rule in the key-name rules: an absolute path that exists is not a password. | `PWD` is a genuine password alias (ODBC), so the `PWD=...` lines that `env` and `export -p` print were still redacted. The value is checked, not just the key. | Depends on what exists where the scan runs; a path that exists only on the caller's machine is judged by the container's filesystem. A non-existent path-shaped value, and a non-path `PWD` value, are still redacted (tested). |
| #15 | v0.2.3 | Key/value delimiter allows blanks (space, tab) only, never a newline. | A heading ending in a keyword and a colon, followed by an indented line, had the next line's first word redacted. | **Removed real protection**: a YAML scalar on the line after its key stopped being caught. The PR text called it rare for credentials and far more common for headings. |
| #16 | v0.2.3 | A narrow YAML next-line rule restores the scalar case: the key line is only the key and a colon (optionally after `- `), the next line one indented bare token with no colon. | Recover what #15 removed without bringing the false positive back. Cost within noise (about -9 to +12 ms on 24 KB and 100 KB). | Residual: a heading that ends in a keyword and a colon followed by exactly one word is indistinguishable from a YAML scalar and still redacts that word. Alias keys are not covered by this form. |
| (before recreation) | v0.1.0 | Accepted risk: about 34 HIGH-severity CVEs in Go libraries bundled inside the upstream gitleaks binary are suppressed in `.trivyignore`. | No newer gitleaks release existed to upgrade to; the service only scans text and never feeds gitleaks an attacker-supplied module. | Revisit when gitleaks ships a fix; the suppression file records the rationale. |

## Design lessons that apply to the server

1. **One hard rule: no secrets.** It is the only control that must be fast and
   synchronous. PII and injection are best-effort notices, because their models
   cost about 0.25 s per KB and parallelism does not help. Policy, async
   delivery, audit sinks and graded modes do not belong in this open-source
   server.
2. **Context beats shape.** gitleaks keys on what a value looks like; real
   credentials often do not look like anything. Rules key on what a value is next
   to. The price is false positives, so every context rule needs a skip list and
   benign lookalike tests.
3. **Bias toward over-redaction for secrets, toward flagging for PII.** A leaked
   credential is permanent and a redacted harmless value is recoverable. The
   reverse holds for PII on engineering text, where wholesale redaction wrecks
   output.
4. **Every false-positive fix removes some protection; say what.** #15 removed
   the YAML next-line case and #16 restored it narrowly; #12 and #13 declared
   that an existing path is never a password. Write the residual in the docs and
   keep a "must stay unchanged" test next to every "must redact" test.
5. **Judge the value as well as the key.** Both `PWD` bugs came from trusting the
   name alone. Check what the value is (an existing path, a placeholder, too
   short) too.
6. **A detection that does not redact is worse than none.** `verdict: found` with
   unchanged text (unquoted glob, match caps, quadratic timeout, a silent
   gitleaks miss) gives a false sense of safety. Tests assert that `found`
   implies changed text with no fragment left, and the scanner fails closed when
   it knows a secret survived.
7. **Fail-open versus fail-closed is a per-surface decision and must be
   explicit.** Here: unredactable output fails closed; a scan timeout fails open
   on purpose; a model fault yields an `error` verdict for that axis only. Never
   change that inside a bug fix.
8. **Speed bugs are leak bugs.** Timeouts and caps return the original text.
   Never cap matches. Avoid leading-`*` globs and large bounded regex repeats in
   bash on large text (quadratic time, or an automaton blow-up that cost 2.9 s per
   scan once).
9. **Hot-path changes need numbers.** Measure before and after on the real
   service, keep an off switch (`SECRET_GUARD_B64=0`,
   `SECRET_GUARD_SKIP_GITLEAKS`), and keep timing tests in the suite.
10. **Test against reality.** The `PWD` bugs and the heading false positive were
    found by running live, not by unit tests. `tests/run-all.sh` mirrors CI
    (gitleaks hidden from `PATH`, no host paths) because a test that passed on a
    laptop failed in CI more than once.
11. **Vendored copy parity.** The plugin carries a copy of `app/scan.sh`. A change
    here needs a matching sync there; no check compares them.
12. **Version and tag discipline.** A tag push is the only thing that publishes.
    Versions move in lockstep with the plugin. A burned number is skipped, never
    deleted or re-created.
13. **Writing about secrets trips the guards.** Use fabricated values only, never
    a rotated or lookalike of a real one, and describe shapes rather than quoting
    them in issues, commits and documents. Fixture lines in a commit can carry the
    `guards:synthetic` marker.
