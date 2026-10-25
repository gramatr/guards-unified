# Changelog

Covers both packages of the guards line, `guards-unified` (the server image,
this repository) and [`claude-plugin-guards`](https://github.com/gramatr/claude-plugin-guards)
(the Claude Code plugin), from the first tagged release to v0.2.13.

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
- All dates are 2026-10-18 to 2026-10-22.

What was hardened, what was loosened and why is in
[docs/TRADEOFFS.md](docs/TRADEOFFS.md). What the server does not catch is in
[docs/LIMITS.md](docs/LIMITS.md).

---

## [0.2.13] - 2026-10-25

### guards-unified

- Fixed: text containing a lone UTF-16 surrogate (the JSON escape `\ud800`, half of a pair with no partner) no longer makes `/v1/scan` and `/v1/scan/secret` answer 500. The credential scan could not take it as input and the response could not be serialized, so the caller got an error and a hook that fails open let the whole output through unscanned. Each lone surrogate is now replaced with U+FFFD when the request is parsed, so every axis sees valid text; a real surrogate pair (an emoji) is left alone. In `redacted_text` the surrogate shows as U+FFFD (#77, coordination #122).
- Security: the image scan reported `filelock` 3.32.3, pulled in by `huggingface-hub` and `transformers`, as HIGH (CVE-2026-112940, arbitrary file overwrite through an insecure lock file) and failed the image gate on every build. Both Dockerfiles now floor it at 4.2.1, which needs Python 3.11 or newer; the image runs 3.12 (#78).

### claude-plugin-guards

- Fixed: when `GUARDS_ENDPOINT` is not the local stack (loopback, port 8700), the SessionStart self-heal no longer pulls, starts or updates a local container; it only checks the endpoint's `/health` and warns if it does not answer. It used to ignore the setting and keep a local container running next to a remote service. The local secret scan is still the fallback when the endpoint is unreachable (#150, coordination #119).
- Changed: `guards/docker/SERVER-SIDE.md` says how to run one shared instance on a private network (requirements: private network only, trusted TLS, no body capture on the path, image pinned by digest, at least two replicas) and records a log audit of v0.2.12: marker strings and an email address sent through both scan routes, including malformed, oversized and error-triggering requests, appeared in no log (#151).

## [0.2.12] - 2026-10-22

### guards-unified

- Fixed: one very long line with many credential words no longer stalls the context pass. A 20 KB line took 17 s and a 40 KB line did not finish, so a diff holding a minified bundle was denied by the publish guard as "did not finish in time". A line over 2 KB with 150 or more credential words is now cut into pieces of about 1 KB for the context rules only; the private-key pass, gitleaks and the vendor shapes still see the whole line. A 20 KB line takes about 1 s, 40 KB about 2 s. Known limit: a context-rule credential whose quoted value contains spaces and straddles a cut is not found by those rules. `SECRET_GUARD_CTX_LINE_MAX=0` turns it off. The self-test grew from 181 to 183 cases (#73, coordination #48).
- Changed: the threat model records that `bypassPermissions` lets the agent write where the guards live, with what Claude Code's documentation says and what it does not (#72, coordination #88).

### claude-plugin-guards

- Fixed: a document that only names a private-key header in a sentence can be read; a file is a key only when a header starts or ends its line, sits in JSON with escaped newlines, or comes with a base64 body. `GUARDS_CRED_SNIFF_STRICT=1` restores the old rule (#144, coordination #86).
- Changed: every deny, ask and withhold message carries a `Fix:` clause with the exact thing to do. A withhold notice now says the command ran and only its output was withheld, so it does not read as a failure. `docs/AGENTS-GUIDE.md` and `guards_status` give a table of message prefixes that tells a guards message from another hook's (#143, coordination #100).
- Fixed: the plugin's scan image patches the same six gitleaks Go modules as the server image, and a CI check fails if the two lists differ (#141, coordination #118).
- Changed: docs for organisations (managed hooks for `bypassPermissions`), the Hugging Face token prerequisite (a missing token also costs PII detection), and the vendored `scan.sh` synced with the server (#142, #140, #145).

## [0.2.11] - 2026-10-22

### guards-unified

- Added: `docs/VERIFY.md`, a verify-it-yourself page with commands run against v0.2.10 (provenance, SBOM, digest, the standalone gitleaks files, the scan), what each proves and does not, and how to run a digest-pinned container. `docs/TRADEOFFS.md` records the default (floating tag, automatic updates) with its cost, and `docs/THREAT-MODEL.md` T13 is brought up to date (#61).
- Added: `tests/repro_archive_name_miss.sh` and `docs/security/archive-name-miss-reproduction-2026-10-22.md`, so anyone can reproduce the scanner miss in v0.2.9 and earlier and check that v0.2.10 does not have it.
- Changed: both CVE gates in CI now fail on fixable MEDIUM findings as well as CRITICAL and HIGH, with unfixed findings still ignored and `.trivyignore` still empty (#63). The macOS option tests take a time-budget factor so a slow shared runner does not fail them (#62).
- Added: the release page now says that `gh attestation verify` prints nothing outside a terminal (check the exit code, or use `--format json`, with a command that prints the verified digest and the building workflow), and has a section on what the image scans still report: each HIGH or CRITICAL advisory once with its fix status and a reviewed one-sentence assessment from `docs/known-unfixed-notes.tsv`, or "not yet assessed". The page body is built by `tests/release_body.sh`, which has a test.
- Fixed: a credential word that is a path segment followed by a colon (an API custom-method suffix, or a sentence about a route) is no longer read as a key and its tail redacted. An equals sign after the segment and every key that is not a path segment still redact. The self-test grew from 174 to 181 cases (#70, coordination#99).
- Changed: the server documents were brought up to date after the 2026-10-22 documentation audit (#69).

### claude-plugin-guards

- Added: `GUARDS_PII_IGNORE_ENTITIES` (launch environment only) filters the PII types a note names, and a PII type is now named once per session (`GUARDS_PII_NOTE_ONCE=0` restores a note on every command; `GUARDS_STATE_DIR` holds the per-session state, type names only). Secret redaction is untouched (#132).
- Added: `docs/DATA-FLOW.md`, what the guards read, send, keep and download, with what was and was not checked (#129); the server PII settings and how to set them, with a recorded run, in `docs/CONFIGURATION.md` (#131); the decision not to build a file-write guard for now, with a replay of 1,500 real writes, in `docs/TRADEOFFS.md` and `docs/LIMITS.md` (#130).
- Fixed: the credential-file guard no longer treats a heredoc that only writes data (`cat > f <<EOF`, `tee f <<EOF`) as a read of a key path named in its text. A heredoc fed to an interpreter, a shell or a pipe is still scanned. `GUARDS_CRED_HEREDOC_STRIP=0` turns it off (#137, coordination#98).
- Fixed: a `git commit` is judged on its message and staged diff, not on unrelated commands chained on the same line: a heredoc that only writes a file is dropped from the scanned command text, only when nothing on the line can pull that file into the commit. `GUARDS_PUBLISH_COMMIT_SCOPE=0` turns it off. The vendored `scan.sh` carries the route-string fix (#138, coordination#99).
- Changed: the plugin documents were brought up to date after the 2026-10-22 documentation audit (#136).

## [0.2.10] - 2026-10-21

### Security note for v0.2.9 and earlier

In guards-unified v0.2.9 and every earlier release, and in the scanner copy inside claude-plugin-guards v0.2.9 and earlier, about 1 scan in 155 could return text with a vendor-shaped secret (a token gitleaks recognises) **unredacted**, with no error and no notice. `scan.sh` gave gitleaks its input in a temporary file with a random name; gitleaks decides a file is an archive from its name and then scans nothing, and about 1 random name in 155 begins like an archive extension (`.7z`, `.br`, `.bz2`, `.gz`, `.lz4`, `.rar`, `.s2`, `.sz`, `.tar`, `.xz`, `.zip`, `.zst`, `.zz`; case is ignored). The service and the plugin's local fallback were both affected. The private-key, key-name-context and session-environment passes do not use gitleaks and were not. In testing, 10 of 1,600 scans by the released v0.2.9 left a fabricated token unredacted, and the released v0.2.10 left none in 1,600. It was found by our own testing, first blamed on CPU load, and traced to the file name later. Because the miss is silent, it cannot be known afterwards whether it happened in a given deployment: **update to v0.2.10, and treat output that passed through a scan in an affected version as possibly unredacted.** v0.2.10 uses a private directory with a fixed, plain input name and also retries when gitleaks scans zero bytes; against the running v0.2.10 service, 1,500 scans of a fabricated token left none unredacted. Advisories: [GHSA-5g92-g3j3-2g22](https://github.com/gramatr/guards-unified/security/advisories/GHSA-5g92-g3j3-2g22) (this repository) and [GHSA-h5rq-hrxc-f3vm](https://github.com/gramatr/claude-plugin-guards/security/advisories/GHSA-h5rq-hrxc-f3vm) (the plugin's copy of the scanner).

### guards-unified

- Changed: the default `PII_ENTITIES` is now the structured kinds a validator can confirm (`EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`, `US_PASSPORT`, `CREDIT_CARD`, `IBAN_CODE`). `IP_ADDRESS`, `LOCATION` and `PERSON` are off by default: an address, a host or city-like name and a tool name are routine in operator and infrastructure output, and on one set of real transcripts these three were 96% of all PII notices. With no `PERSON` or `LOCATION` the model is not run, so a scan is also faster. Restore the old default with `PII_ENTITIES=PERSON,LOCATION,EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,US_PASSPORT,CREDIT_CARD,IBAN_CODE,IP_ADDRESS`. Secret detection is unchanged.
- Fixed: a dependency line whose package name holds a credential word, with a version specifier as its value (a scoped `credentials-lifecycle` at `^0.2.0`), is no longer redacted as a secret (#56). The key must be a package-name segment and the value an operator-prefixed range, a protocol (`workspace:`, `link:`, `file:`) or, for a scoped package, a bare three-part version; near-misses still redact. The self-test grew from 160 to 174 cases.
- Fixed: stock macOS bash 3.2 redacts again. `scan.sh` no longer uses bash 4 syntax (#43), and long unbroken runs are found with `awk` because macOS `grep` refuses a repetition count above 255, which had silently turned the long-run masking off (#53).
- Fixed: gitleaks skipped an input whose random temp name looked like an archive extension and scanned nothing; the input now has a fixed name (#44). See the security note above.
- Added: every release is attested. Build provenance and an SBOM are generated and verified against the merged image's digest before any release tag moves (#45), and the GitHub Release page is created from CI with the scan output, SBOMs, test counts and notes (#49), plus standalone patched `gitleaks` binaries for linux and darwin on amd64 and arm64 (#50). The first release built this way is the first to carry attestations.
- Added: a release can be rehearsed end to end on a scratch tag from any branch without touching what users pull (#54).
- Security: base images are pinned by digest, gitleaks by commit and Actions by SHA (#46), with Dependabot for the SHAs and digests (#47, #48).
- Changed: `LICENSE` is the plain MIT text; the Llama notice moved to `NOTICE` (#52).
- Security: the full Trivy scan on the release rehearsal showed 10 findings with a published fix that the CI gate (CRITICAL and HIGH only) never looked at. The gitleaks build now also bumps `golang.org/x/crypto` to v0.56.0, `ulikunitz/xz` to v0.5.15, `nwaples/rardecode/v2` to v2.2.0 and `mholt/archives` to v0.1.5 (rardecode 2.2.0 does not compile against the archives version gitleaks 8.30.1 ships), and the image removes the base image's `pip` 25.0.1, which carried six CVEs and which the service never calls (upgrading it instead would pull in bundled copies with three HIGH findings). The standalone gitleaks hashes in `docs/gitleaks-assets.sha256` changed accordingly. What remains in the scan is what nobody can patch yet: 44 HIGH rows (8 flaws) and MEDIUM and LOW rows in Debian 13.7 system packages, and one UNKNOWN `x/crypto` advisory with no fixed version.

### claude-plugin-guards

- Added: the outbound guard. A command that would send credential material to a remote host (`curl`, `wget` and similar) is stopped before it runs, with a teaching message for the safe form, a literal-credential path, an awk command parser with an adversarial corpus run under three awks, and the documented safe forms verified against real `curl` and `wget` (#91 to #93, #99, #101 to #103).
- Added: `GUARDS_ALLOW_CRED_PATHS`, a colon-separated list of exact absolute paths the credential-file guard lets through, set in the launch environment only; the narrow alternative to `GUARDS_ALLOW_CRED_READ=1` (#122). A tested registry of tools that use a credential without printing it (`age -i`, `ssh -i`, `kubectl --kubeconfig` and others) means a reader word elsewhere on the same line no longer turns the use into a deny (#112, #115, #117).
- Added: the patched gitleaks is installed by self-heal on hosts without Docker, verified against hashes the plugin carries (#111); a GitHub Release page is created for each plugin tag from CI (#110).
- Fixed: the credential-file guard resolves symlinks on macOS (no GNU `realpath -m`) (#95); the deadline watchdog no longer reports a timeout that did not happen (#94) and a deny is no longer lost under load when `timeout` is missing (#98); a glob in a command is expanded in sorted order (#104).
- Fixed: on macOS the publish guard now finds and scans a file the command names (`git commit -F msg.txt`, `--body-file`, `cat X`); before, the relative path was never resolved, so a secret in that file was not scanned there (#124).
- Fixed: self-heal no longer makes the metrics directory world-writable. It is mode 0700 for a host user with uid 1000, 0700 plus an ACL entry where `setfacl` exists, and 0777 with a warning only otherwise (#126, issue 92).
- Changed: the vendored `scan.sh` is synced with the server's (#100, #105, #116, #125).
- Changed: the Mac-sensitive hook suites run on macOS in CI; the job now covers 20 suites under the system bash 3.2, and the portability defects it found in the tests are fixed (#100, #120, #124).
- Changed: docs state the limits of the registry exemption, that the credential-file guard checks only the first 60 path-like words, and that without a Hugging Face token the service does not start (#118, #119, #121); the plugin ships its license and the marketplace has a README (#113, #114).
- Security: the vendored Dockerfile and the workflows' Actions are pinned, with Dependabot (#106, #107).

## [0.2.9] - 2026-10-20

### guards-unified

- Added: required self-test cases that a credential next to or inside a very long line is still redacted (after, before and between 20 KB runs, in JSON, and a long run as the value), and docs/LIMITS.md describes the long-run masking (issue 48).
- Fixed: a key that names an identifier or reference of a secret is no longer redacted when the descriptor (`id`, `ref`, `arn`, `name`, `type`, `path`, `file`, `version`, `count`, `ttl`, `namespace`, `store`, `manager`, `provider`, `url`) is the last segment but not adjacent to the credential word: `client_secret_bws_id`, `clientSecretBwsId`, `CLIENT_SECRET_BWS_ID`, `secret_vault_id`, `token_store_ref`, `credential_provider_arn`. This applies to the context pass (`secret-lead-in`) and to gitleaks' `generic-api-key` findings, which are dropped for such a key so the two passes agree. A key whose last segment is the credential or a value word (`AUTH_TOKEN`, `db_password`, `api_secret`, `client_secret_value`, `secret_key`) still redacts, as does `secretValid` (a camelCase `Id` must be capitalized). Found when a publish guard denied a commit of a test fixture holding a vault secret id.
- Fixed: ordinary source code is no longer redacted by the context pass. An UNQUOTED value that is a call (`createSignedToken(userId)`), an identifier or member chain (`accessToken`, `this.cfg.apiToken`), `await`/`new` before a call, or a type (`string`, `Promise<TokenSet>`) is not a credential when the line is code: after `:` or a spaced `=`, and either after a declaration or modifier keyword (`const`, `readonly`, `private`, `val`, ...), or a call, or a primitive type, or an identifier with a separator or camelCase and no digits plus code punctuation or a trailing `,` `;` `)` `}`. In a real commit of TypeScript, 32 of 685 added lines were redacted and 30 of them are now left alone; the 2 left are string literals assigned to token-named constants, which stay secrets. Unspaced `NAME=value` (env, shell, `export`, `readonly NAME=...`), INI and YAML values, CLI flags, quoted values and plain words such as `hunter2x` are unchanged. The 1007-text bake-off corpus (PII-focused) is unchanged.
- Added: self-test cases both ways (reference keys must pass unchanged, last-segment keys must redact).
- Fixed: the code-shape rule is stricter, after the plugin's CI (which runs without gitleaks) showed a password inside a JSON string no longer being redacted. A key inside a quoted string (JSON string content, a shell string, a log message in quotes) is text, not code. Braces and commas alone no longer count as "the line is code": a line needs a semicolon, `=>` or `) {`, or the key must sit in property position (first on its line, or after `{`, `(`, `[` or `,`). Log lines, sentences and issue bodies that contain a key, a colon and an identifier-looking word still redact. A type name or camelCase variable needs humps with at least two lowercase letters (no digits for a variable), so random mixed-case values are never read as code.
- Fixed: a long unbroken run of name characters (a base64 blob, a hash, a bundle without spaces) no longer makes the context pass quadratic. Runs of 256 or more are masked for the context rules and restored afterwards; a secret after one, or a long run as the value of a key, is still redacted. A 20 KB run scanned in 9.7 s before and in 0.06 s after, which is what made the publish guard deny commits with "did not finish in time". Ordinary text is unaffected (27 KB of minified JSON: 70 ms before, 96 ms after).
- Changed: CI pins ruff 0.17.1 and checks formatting as well as lint, and the server code is formatted (no behavior change; `tests/redaction_selftest.py` is excluded from the formatter). `app/report.sh` takes its webhook flow path from `REPORT_WEBHOOK_PATH`, default unchanged.
- Security: gitleaks is built from its v8.30.1 tag in `Dockerfile` and `Dockerfile.cpu` with `klauspost/compress` v1.18.7, `golang.org/x/crypto` v0.55.0, `golang.org/x/text` v0.41.0 and a Go 1.26 toolchain, instead of copying the binary out of the upstream image. The upstream binary bundles Go modules with known HIGH CVEs (a new one, CVE-2026-63209, turned the CVE scan red). Trivy reports no findings in the resulting binary with no ignore file, and `.trivyignore` no longer suppresses any of its 35 IDs. The self-heal download for a host without Docker is still the unpatched upstream release.

### claude-plugin-guards

- Changed: a publish-guard deny now says where each match is (up to 5: the command text, a named file, or the staged diff with file and line), with each line shown as the scanner redacts it and never the value, and states what `guards:synthetic` covers (added lines of a commit's staged diff only) and that `GUARDS_ALLOW_PUBLISH_SECRETS=1` works only from the environment Claude Code started in (claude-plugin-guards#84).
- Fixed: the publish guard scanned the wrong repository after `cd 'quoted dir'`, `pushd` or `GIT_DIR=`; saw a stale index for `git add ... && git commit` in one command (a marker added since the last add did not count, a new file was not seen); did not inspect `git -c k=v commit`; and read ` -a` inside a commit message as the flag.
- Added: the MCP server carries `instructions`, four `guards://guide/...` resources and a `check_before_publish` tool that runs the publish guard offline.
- Changed (user-visible): a line marked `guards:synthetic` is still denied in a commit if it matches a sure-thing vendor shape: a private-key header, an AWS access key id, a GitHub token, a Slack token or a live Stripe or OpenAI-style key. Documented example ids and values containing EXAMPLE or FAKE, JWT-shaped strings and ordinary fixtures are still accepted by the marker. Build vendor-shaped fakes at run time.
- Added: MCP tools `explain_block`, `prepare_publication`, `guards_status`, `mark_synthetic` (refuses vendor-shaped tokens and private-key headers) and `report_false_positive`; MCP prompts `fix_a_block`, `safe_pr_body` and `fake_fixture_checklist`; a `guards-for-agents` skill; and `docs/AGENTS-GUIDE.md` with a snippet for a project's CLAUDE.md or AGENTS.md. No tool disables or weakens a guard, and no tool returns a matched value.
- Fixed: the hooks no longer turn the guards off silently when `jq` is missing. The publish guard, the output hooks and the SendMessage hook read the payload without `jq` or fail visibly with a reason that says to install it, and `check_before_publish` answers `unknown` instead of allow when it could not inspect.
- Changed: ruff (check and format) now runs on the plugin's Python in CI; `guards/vendor` is excluded.
- Security: the vendored scan image builds gitleaks the same way (v8.30.1 tag, fixed Go modules, Go 1.26) instead of copying the upstream binary, and `.trivyignore` is emptied, so the CVE scan runs unfiltered (plugin #90).

## [0.2.8] - 2026-10-20

### guards-unified

- Changed: Presidio's `PERSON` and `LOCATION` results go through new output filters (`app/pii_guard/filters.py`). A `LOCATION` with `=`, `_`, a run of four or more digits, a run of twelve or more hex characters or no letter, or a lone lowercase word, is dropped; so is a `PERSON` that is a lone lowercase word or only names from a built-in list of about 300 software and tool names (Jenkins, Grafana Tempo, Kafka Streams, `kube`, `arn`). A title before the span (`Dr. Jenkins`) keeps it. Measured in the published image, ordinary engineering lines flagged: 43 to 11 in 1000 on the bake-off corpus, 64 to 32 in 1000 on a held-out set with other tool names; person and address recall unchanged on both. A person whose whole name is a listed word, mentioned alone, is no longer flagged (docs/TRADEOFFS.md).
- Added: `PII_IGNORE_NAMES` (comma-separated, case-insensitive) adds names to the built-in list.
- Added: unit tests for the filters (run in CI) and noise shapes in the end-to-end test.

## [0.2.7] - 2026-10-20

### guards-unified

- Changed: the structured PII kinds no longer come from Presidio. `CREDIT_CARD`, `IBAN_CODE`, `US_SSN`, `US_PASSPORT`, `PHONE_NUMBER`, `IP_ADDRESS` and `EMAIL_ADDRESS` are found by deterministic checks in the new `app/pii_guard/validators.py` (Luhn, IBAN country length and mod 97, SSN issued ranges, a visible phone structure, a parseable IPv4, an email pattern); Presidio keeps `PERSON` and `LOCATION`. Bare 10-digit ids, epoch timestamps and run ids are no longer read as phone numbers or passports. The entity names, the `/v1/scan` response shape and the `<ENTITY_TYPE>` placeholders in `redacted_text` are unchanged. Measured on the fabricated bake-off corpus (gramatr/guards-coordination#46) inside the published image: 43 ordinary engineering lines in 1000 flagged (was 109), overall recall 0.96, phone precision 0.69 to 1.00 and recall 0.93 to 1.00.
- Changed: a `PERSON` span containing `=`, `@` or `:` is now dropped as an identifier, in addition to a digit, underscore or slash.
- Changed: loopback and unspecified IPv4 addresses (`127.0.0.0/8`, `0.0.0.0`), the broadcast address and netmasks are not reported; `noreply@` / `no-reply@` / `donotreply@` senders and the `git` user of an ssh remote (`git@github.com:org/repo.git`) are not reported as email. Private-range IPv4 addresses and other role mailboxes (`security@`, `support@`) are still reported.
- Added: `PII_ENGINE=presidio` restores the previous all-Presidio behavior for one release; it is removed after that.
- Added: unit tests for the validators and the merge/redaction logic (Presidio stubbed, run in CI), and noise and true-positive cases in the end-to-end test.

## [0.2.6] - 2026-10-20

### guards-unified

- Fixed: the PII axis no longer raises a notice on run ids, epoch timestamps, PR numbers, 32-character hex ids, GUIDs or pod names. `US_DRIVER_LICENSE` and `US_BANK_NUMBER` are off by default (`PII_ENTITIES`), a match needs a score of 0.4 (`PII_MIN_SCORE`), and a `PERSON` span with a digit, underscore or slash is treated as an identifier. Names, emails, phone numbers, IP addresses and card numbers are still found, and hyphenated real names are kept. Tested in the real engine; the end-to-end test gains a noise case and a true-positive case.

## [0.2.5] - 2026-10-20

### guards-unified

- Fixed: prose that wraps a key word and its colon in quotes (`the "password:"
  field, then "some text"`) no longer redacts the text up to the next quote on
  the same line; this closes the known residual noted under 0.2.4. Real quoted
  values are unchanged: `password="x"`, `"password": "x"`, `"password":"x"`,
  `password: 'x y'`, `--password="x"` and nested shell quoting
  (`bash -c "PASSWORD="x" ./run"`) are still redacted.
- Known limit: a malformed `"pw:"value"` (the key's closing quote after the
  colon, the value glued on) reads as that prose and is not redacted; see
  [docs/TRADEOFFS.md](docs/TRADEOFFS.md).
- Fixed: the name of a setting about a credential is no longer read as a
  credential. A key that ends in a unit, limit, switch or mode word
  (`..._BYTES`, `..._SIZE`, `..._LENGTH`, `..._LIMIT`, `..._MAX`, `..._MIN`,
  `..._TIMEOUT`, `..._SECS`, `..._SECONDS`, `..._MS`, `..._PORT`, `..._DEPTH`,
  `..._MODE`, `..._ASK`, `..._ENABLED`, `..._DISABLED`) is treated like the
  descriptor names already skipped (`secretName`, `token_type`). Documentation
  and commit messages that show such settings were blocked by the publish guard.
  A key whose credential word is last (`MAX_BYTES_PASSWORD`, `AUTH_TOKEN`) is
  still redacted.
- Fixed: a tokenizer is not a token. Variables named `tokenizer` (the usual
  result of the Hugging Face `AutoTokenizer` loader) and similar names
  (`tokenization`, `tokenised`) are no longer redacted; a key that also has
  another credential word (`tokenizer_secret`) still is.
- Changed: build inputs are pinned. `uv` is copied by tag and digest, the
  injection model is downloaded at the revision this project evaluated
  (`INJECTION_GUARD_MODEL_REVISION`, reported by `GET /about` as
  `model_revision`), and `tests/dockerfile_pins_test.sh` fails on a floating tag.
  Python packages are still installed by version floor.
- Added: a scheduled and tag-triggered end-to-end workflow runs the real PII and injection models through `/v1/scan` (advisory, not a publish gate; needs the `HF_TOKEN` repository secret). `SECURITY.md` (private vulnerability reporting) and `docs/THREAT-MODEL.md`.
- Self-test: 116 cases (eleven required, nine harmless-lookalike added since 0.2.4).

### claude-plugin-guards

- Changed: the credential-file guard asks (for `.env`, kubeconfig and similar) only where a person can answer, and denies in `auto`, `bypassPermissions`, `dontAsk` and unknown modes, the same rule as the publish guard.
- Fixed: every hook now enforces its own deadline below its Claude Code timeout and decides deliberately when it expires (hard guards deny, output hooks withhold, advisory hooks stay silent). Claude Code fails open when a hook outlives its timeout, which this closes.
- Fixed: the credential-file guard no longer allows every call when `jq` is missing; it reads the payload with awk, and denies if even that fails.
- Fixed: the prompt hook scans the whole prompt (up to 900000 bytes) on the secret-only route, so a credential anywhere in a long prompt gets the note.
- Fixed: the `scan` MCP tool reports the real HTTP status (a 413 names the limit and the setting) instead of "unreachable".
- Added: tests for the SendMessage, prompt and self-heal hooks and the MCP tool, a CI check that the vendored `scan.sh` matches the server's, and `SECURITY.md`.
- Documented: the verified Claude Code behaviors (a hook timeout fails open; an ask with no person is a deny; deny beats ask beats allow), a configuration reference, a hook failure-mode matrix, limits and trade-offs pages.
- Synced the vendored `scan.sh` with the server changes above.

## [0.2.4] - 2026-10-19

### guards-unified

- Added: request size caps in UTF-8 bytes of `text`, `SCAN_FULL_MAX_BYTES`
  (default 65,536) on `/v1/scan` and `SCAN_SECRET_MAX_BYTES` (default
  1,048,576) on `/v1/scan/secret`. Over the cap is HTTP 413. A request could
  previously keep the service busy long after its client gave up.
- Fixed: an error in the second PII pass of `/v1/scan` returned HTTP 500 and
  dropped every finding. It now falls back to the secret-redacted text.
- Changed: `/v1/scan` now redacts PII in `redacted_text` when the secret scan
  errored (it used to return the untouched original). Secrets stay unredacted
  on a scan error, as before.
- Tests: `tests/api_contract_test.py`, both models stubbed, run in CI.
- Fixed: a quoted value in the key-name rules could cross newlines, so prose
  that quoted a key word with a colon (a quote-wrapped key word, then a second
  quote lines later) lost every line between the two quotes. A quoted value now
  stays on its line. Known residual: the same two quotes on one line still
  redact the text between them. Self-test: 98 cases (one required, one
  harmless-lookalike added).

### claude-plugin-guards

- Synced the vendored `scan.sh` with the quoted-value fix above.

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
