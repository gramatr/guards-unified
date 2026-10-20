# Changelog

Covers both packages of the guards line, `guards-unified` (the server image,
this repository) and [`claude-plugin-guards`](https://github.com/gramatr/claude-plugin-guards)
(the Claude Code plugin), from the first tagged release to v0.2.3.

## How the versions work

- **Lockstep from 0.2.2.** The two packages are one product. From v0.2.2 they
  carry the same version and the same tag, cut together; the rule is in
  [docs/RELEASING.md](docs/RELEASING.md). Only a `guards-unified` tag push
  publishes the image; the plugin's tag is a label (plugin installs track
  `main`).
- **Before 0.2.2 the numbers were independent.** The plugin's `v0.1.0` to
  `v0.1.4` and the server's `v0.1.x` are different number spaces.
- **`v0.2.0` was burned, `0.2.1` was never tagged.** `v0.2.0` was tagged on the
  server before the release was finished and its publish run was cancelled, so
  no image was released under it; do not use that tag or the two amd64-only
  `*-v0.2.0` images it left behind. `0.2.1` was only ever a `VERSION` value on
  `main`. Neither number was reused; the next release is `v0.2.2`. The plugin
  has no tag between `v0.1.4` and `v0.2.2`.
- **The server repository was recreated on 2026-10-19**, so its pull request
  numbers restart at #1 and the server tags `v0.1.0` to `v0.1.3` (which appear
  in the commit history) no longer exist. Server pull request references below
  are to the current repository; entries from before the recreation have none.
  Plugin pull request numbers were not affected.
- All dates are 2026-10-18 or 2026-10-19.

What was hardened, what was loosened and why is in
[docs/TRADEOFFS.md](docs/TRADEOFFS.md). What the server does not catch is in
[docs/LIMITS.md](docs/LIMITS.md).

---

## [0.2.3] - 2026-10-19

### guards-unified (#15, #16)

- Fixed: a heading that ends in a secret-ish word and a colon, followed by an
  indented line, had the first word of the next line redacted. The key rules'
  delimiter now allows blanks (space, tab) only, never a newline (#15).
- Added: a narrow YAML next-line rule to win back the one case that change
  dropped, a scalar on the line after its key. The key line must be only the
  key and a colon (optionally after `- `), and the next line one bare token with
  no colon. Headings, nested keys and multi-word lines are left alone (#16).
- Known residual: a heading that ends in a keyword and a colon followed by
  exactly one word is still redacted.
- Tests: 43 option checks (41 without gitleaks); redaction self-test at 96 cases.

### claude-plugin-guards (#65, #66)

- Synced the vendored `scan.sh` with the two changes above; version 0.2.3.

## [0.2.2] - 2026-10-19

The first lockstep release, and the first release to carry the whole
redaction-posture work (the contents of the unreleased `0.2.0` and `0.2.1`).

### guards-unified (#5, #6, #7, #9, #10, #12, #13, #14)

- Added: **context-aware secret rules** that redact a value by what it sits next
  to: after a key name containing secret, password, passwd, pwd, passphrase,
  token, api_key, private_key or credential; in `user:password@host` URLs and
  DSNs; in secret-ish query parameters; after `Authorization` schemes (#5).
- Added: whole-segment key aliases (`PW`, `PWD`, `PASS`, `CRED`, `PAT`,
  `client-key-data`), `Cookie` and `Set-Cookie`, command-line password flags,
  `.netrc` and `.pgpass`, name/value pairs split across lines (Kubernetes
  `env`, Bitwarden-style JSON), and Azure, gcloud and bcrypt shapes;
  ANSI colour codes are ignored when matching (#6).
- Added: opt-in `SECRET_GUARD_REDACT_KEY_IDS` and `SECRET_GUARD_ENV_VALUES`
  (#6). Access-key and client IDs are **not** redacted unless the first is set.
- Added: **base64 pass** that decodes long tokens and scans the decoded text;
  on by default, `SECRET_GUARD_B64=0` turns it off (#10).
- Added: **`POST /v1/scan/secret`**, the secret axis alone, and
  `SECRET_GUARD_SKIP_GITLEAKS` (#9).
- Fixed: clean input lost its trailing newline because gitleaks' empty `[]`
  report was read as a finding; it is now read as no findings (#5).
- Fixed: redaction was quadratic in input size (232 KB took 19 s, 1 MB took
  447 s, past the 15 s timeout), had a per-rule cap that let match 201 onward
  through, and spawned two `jq` processes per finding. Now linear, uncapped and
  one `jq`; zero-width characters and fullwidth `=` and `:` are normalised
  for matching (#7).
- Changed: a scan timeout is logged as `SECRET_SCAN_TIMEOUT` and the caller
  keeps the original text; failing closed on timeout was tried and dropped (#7).
- Fixed: the environment-value pass and the key-name rules redacted `PWD` and
  other values that are existing paths, so the working directory was redacted
  everywhere. A value that is an existing absolute path is no longer treated as
  a password (#12, #13).
- Process: a live release-verification procedure and a smoke-test workflow for
  the publish pipeline (#8); version bumps (#11, #14).

### claude-plugin-guards (#48 to #64)

- Added: **`credfile-guard`**, which denies Read, Grep and Bash reads of
  credential files before any content exists (#51); **`publish-guard`**, which
  blocks credentials in `gh` commands, `git commit` and GitHub MCP writes (#54);
  **`mcp-output-guard`**, which redacts secrets in MCP tool results (#56).
- Added: a fast secret path for the Bash hook, so secrets (up to 256 KB) are
  redacted through the secret-only route without waiting on the PII and
  injection models, which now cover only a leading prefix of the output (#58, #59).
- Added: in-session notices when the image or plugin version updates (#48) and
  automatic image updates through Watchtower (#49).
- Changed: ambiguous publish and credential-file matches ask a human instead of
  hard-blocking, while sure things still block (#60); the publish guard denies
  instead of asking in modes where nobody can answer (#62).
- Synced the vendored `scan.sh` with each server change above (#52, #53, #55,
  #57, #61, #62, #63); put the plugin on the same version and tag as the server
  (#64).

## [0.2.1] - never tagged

A `VERSION` value on `main` for a few hours; the work it names shipped as 0.2.2.

## [0.2.0] - burned

Tagged before the release was finished on the server (only #5 and #6 had
merged);
the publish run was cancelled, so no release was made. Its contents shipped in
0.2.2. Do not use the tag or the `*-v0.2.0` images.

## [0.1.6] - 2026-10-19 (guards-unified only)

### guards-unified (#3, #4)

- Fixed: **a secret could come back with verdict `found` and unchanged text.**
  The redaction pattern was unquoted, so bash treated the secret as a glob and a
  backslash, `*`, `?` or `[` in it stopped matching (a private key inside JSON
  came back as-is). The pattern is quoted, multi-line secrets are replaced as
  one unit, a second pass covers 16-character line fragments (CRLF), and the
  output is re-checked afterwards.
- Added: if a confirmed secret still survives, the whole output is replaced
  by a withheld placeholder; `main.py` does the same and sets
  `detail.redaction_failed` when a finding returns unchanged text.
- Added: a deterministic private-key pass independent of gitleaks, which also
  covers keys with no END marker, and one retry when gitleaks exits non-zero.
- Added: the redaction self-test (`tests/redaction_selftest.py`) and a CI job
  that runs it against the built image.

## [0.1.5] - 2026-10-19 (guards-unified only)

### guards-unified (#1, #2)

- No code change: the first release from the recreated repository. Publishing
  switched to `GITHUB_TOKEN`, and a manual Pipeline check workflow tests the
  settings that live outside the code.

## [0.1.4] - 2026-10-18 (claude-plugin-guards)

### claude-plugin-guards (#43 to #47)

- Fixed: a scan input around 128 KB crashed argument passing and silently
  dropped redaction; large values now go through files (#43).
- Fixed: a 15 s image-pull timeout inside a 30 s hook meant a fixed image was
  never picked up; the pull timeout is now 240 s (#47).
- Added: license and dependency CVE audit (#44), shellcheck, hadolint and a
  weekly Trivy scan in CI (#46).
- Changed: the container's CPU allowance was raised from 1 to 16 (a 20 KB scan
  never finished at 1) and a 24 KB scan cap was introduced, later replaced by
  the secret fast path in 0.2.2 (#43).

## [0.1.3] - 2026-10-18 (claude-plugin-guards)

### claude-plugin-guards (#35 to #42, among others)

- Fixed: stderr of Bash commands was never scanned; now both streams are (#42).
- Fixed: a malformed or truncated backend response was treated as clean; it is
  now treated as backend-down (#36). An empty `message` no longer skips scanning
  the other SendMessage fields (#40), and the fallback status text no longer says
  "no secret found" after redacting one (#39).
- Fixed: self-heal migrated the old three-container stack by port and could
  remove unrelated containers; it now removes only provably stale instances,
  so an unmanaged container started by hand needs manual cleanup (#37, #38).
  A self-heal locking fix (#41).
- Changed: SendMessage flags PII instead of redacting it by default (#35).

## [0.1.2] - 2026-10-18 (claude-plugin-guards)

### claude-plugin-guards (#27)

- Changed: injection warnings need a confidence of at least 0.95
  (`INJECTION_MIN_SCORE`); benign security-themed development text had scored
  as malicious below that.

## [0.1.1] - 2026-10-18 (claude-plugin-guards)

### claude-plugin-guards (#26)

- Fixed: the SendMessage hook copied one field's redacted text over the others;
  each field is now redacted independently.

## [0.1.0] - 2026-10-18

### claude-plugin-guards (#1 to #24)

- Added: the plugin: a combined Bash output hook that redacts secrets and flags
  PII and injection, a SendMessage guard that redacts outgoing agent messages,
  a prompt check that is advisory only, a single `scan` MCP tool, a Docker
  Compose stack with a self-heal script, and local metrics.
- Added: consolidation of the three guards onto the single `guards-unified`
  image (#13); systemd hardening for the earlier daemon mode (#1).
- Changed: PII is flagged rather than redacted by default (#20), because
  Presidio false positives destroyed real output; SendMessage degrades to a
  local secret scan when the service is down instead of blocking (#21);
  container memory limit raised to 4 GB (#22).

## guards-unified 0.1.0 to 0.1.3 - 2026-10-18 to 2026-10-19

Released before the repository was recreated; the tags are gone and these
entries come from the surviving commit history, so they have no pull request
numbers.

- Added: the combined image (secret, PII and injection behind one API), GPU and
  CPU variants with real multi-arch builds, local-only metrics that never
  contain scanned text, a non-root user, `LICENSE`, `NOTICE` and the Llama 4
  licence files, and `GET /about` so a stale pull is visible.
- Added: CI with ruff and Trivy, a weekly scheduled scan, and a tag-triggered
  publish; dependency version floors for packages with known CVEs; `apt-get
  upgrade` in the build; known-unfixable CVEs in the bundled gitleaks binary
  suppressed with a recorded rationale.
- Fixed: publishing failed because the package was not linked to the repository,
  and the GPU variant was being cross-built under emulation; an automated
  multi-arch merge step fixed a stale-image bug in which an amd64-only build
  became the `:cpu` tag; the arm64 build was automated on a self-hosted runner;
  release runbook added.
