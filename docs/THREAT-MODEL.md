# Threat model

A short model of what the guard line (this server plus the
[Claude Code plugin](https://github.com/gramatr/claude-plugin-guards)) defends,
against whom, where the trust boundaries are, and what it does not defend. It is
written to be checked: every threat names the control, the documented limit and
where the evidence lives (code, or a test that pins it). It restates and
organises [LIMITS.md](LIMITS.md), [TRADEOFFS.md](TRADEOFFS.md) and
[CONFIGURATION.md](CONFIGURATION.md); where they disagree with this page,
they are the detail and this page should be corrected. Written against 0.2.4.

The posture in one paragraph: **secrets are the one hard rule** (deterministic,
fast, biased toward over-redaction, fails closed when it knows a secret
survived); personal data and prompt injection are best-effort notices; policy,
authentication and audit belong to a platform, not to this repository. This is a
filter, not a sandbox.

References to plugin files are to the
[claude-plugin-guards](https://github.com/gramatr/claude-plugin-guards)
repository, paths under `guards/`.

## Assets

| Asset | Why it matters | Where it exists |
|---|---|---|
| Credentials in tool output | A key, token or password printed by a command or returned by a tool reaches the model, its transcript and the API, and cannot be recalled. | Bash stdout and stderr, MCP tool results, files the agent reads. |
| Credentials in what the agent publishes | A commit, issue, pull request, comment or gist on a public repository is permanent once read. | Commands and tool inputs that publish. |
| Prompts and messages | The user's prompt and agent-to-agent messages can carry credentials or personal data. | The prompt as typed; `SendMessage` input. |
| Personal data | Names, emails and similar in tool output. | Tool output. |
| The agent's instructions | Text the model should not take orders from, if it came from data. | Tool output, web pages, files. |
| The scanned text itself, in transit | The service receives raw text that may contain the very secrets it exists to catch. | The hook-to-service request, the service process. |
| The host | The service is a container with a Docker-socket-holding updater next to it. | The machine running the plugin. |

## Actors

| Actor | Capability assumed |
|---|---|
| The model itself | Can emit commands and tool calls, including ones that read or publish credentials, by mistake or by manipulation. Not assumed malicious in design, but not trusted to self-police. |
| Hostile tool output (prompt injection) | Text controlled by a third party (web page, file, issue, tool result) that tries to steer the model, or that is crafted so a credential in it evades detection. |
| A local process or user | Can reach loopback ports, read files the user can read, write to shared directories. Not assumed to be root. |
| A network peer | Can reach the service only if it was exposed beyond loopback by mistake or by choice. |
| A compromised dependency, image or model download | Can run code in the build, the container, or the user's machine. |

Out of the model: an attacker who already runs as the user or as root, who
controls Claude Code or the container runtime, or who controls the machine.

## Trust boundaries

```
 Claude Code session (the user's environment)
 ┌────────────────────────────────────────────────────────────┐
 │  tool call ──► PreToolUse hooks (credfile, publish, message)│  B1
 │  tool output ◄─ PostToolUse hooks (Bash, MCP) ◄────────────┐│
 │  user prompt ──► UserPromptSubmit hook (note only)         ││
 │  plugin MCP server (one tool: scan) ───────────────────────┤│  B2
 └──────────────┬─────────────────────────────────────────────┘│
                │ HTTP, plaintext, no auth        B3           │
                ▼                                              │
        guards-unified on 127.0.0.1:8700  ── scan.sh, models   │
                ▲                                              │
                └─ or, if GUARDS_ENDPOINT is set: any host  B4 ┘
```

- **B1, hook to plugin scanner.** Hooks are shell scripts run by Claude Code
  with the user's privileges. They read the hook payload, scan it, and answer
  with allow, ask, deny or a rewritten output. The payload shapes are Claude
  Code's; the plugin only rewrites shapes it recognises. A hook that crashes or
  times out is assumed to leave the original text in place (Claude Code's
  behaviour, not verified here).
- **B2, plugin MCP server.** A local stdio process (`mcp/server.py`) exposing
  one tool, `scan`, that forwards text to the service. It is a client of B3, and
  its result is itself scanned by the MCP output hook.
- **B3, service on loopback.** The hooks call the HTTP service
  (`POST /v1/scan`, `POST /v1/scan/secret`). The service has no
  authentication, no TLS and no rate limit. Its only protection is that the
  compose file publishes it as `127.0.0.1:8700:8700`.
- **B4, optional platform endpoint.** `GUARDS_ENDPOINT` can point the hooks at
  another host that serves the same contract. Everything the hooks send then
  leaves the machine, in plaintext, to whoever runs that host. This is a
  deployment decision, not something this repository enables or secures.

## Threats

Each row: the control that exists, its documented limit, and the evidence.
"Pinned by" names a test; "code" names where the behaviour is implemented.
`app/` is this repository; `hooks/`, `bin/`, `docker/` and `tests/` under
`guards/` are the plugin.

### T1. A credential in tool output reaches the model

- **Control.** After every Bash call and every MCP tool call, the output is
  scanned and credential material is replaced with a placeholder before the model
  sees it. The scanner is gitleaks (default rules) plus context rules (key
  names, URL passwords, headers, command-line flags, a base64 pass, a
  private-key pass that does not need gitleaks).
- **Limit.** A bare value with no key name, vendor shape or context; short
  values; encodings other than base64; a secret split across calls; Read, Grep
  and WebFetch output (never rewritten); MCP shapes other than text blocks;
  Bash output past the first 256 KB; MCP blocks over 512 KB (skipped silently).
  See [LIMITS.md](LIMITS.md#secrets) and the plugin's `docs/LIMITS.md`.
- **Evidence.** Code: `app/scan.sh`, `_scan_secrets` in `app/main.py`;
  `hooks/combined-hook.sh`, `hooks/mcp-output-guard.sh`,
  `hooks/secret-scan-lib.sh`. Pinned by: `tests/redaction_selftest.py` and
  `tests/scan_options_test.sh` (required cases redacted, 23 lookalikes
  unchanged), plugin `tests/combined-hook.test.sh`,
  `tests/mcp-output-guard.test.sh`, `tests/scan-redaction.test.sh`.

### T2. The scanner finds a secret but does not remove it

- **Control.** After redaction the script re-checks the secrets gitleaks
  confirmed; if one survives, the whole output is replaced by a withheld
  placeholder. The server adds a backstop: a finding with unchanged text is
  withheld and reported with `redaction_failed`.
- **Limit.** The re-check covers only secrets gitleaks confirmed; values redacted
  by the context, base64 and environment passes are not re-verified.
- **Evidence.** Code: the verification step and `WITHHELD` in `app/scan.sh`;
  `REDACTION_WITHHELD` and the unchanged-text check in `_scan_secrets`. Pinned
  by: `tests/redaction_selftest.py` (a found verdict implies changed text with no
  fragment left).

### T3. An adversary or a huge input pushes text past the scanner

- **Control.** Linear-time matching, no per-rule match cap, a 15 s scan budget,
  size caps on the server (413 over 64 KiB on `/v1/scan`, 1 MiB on
  `/v1/scan/secret`), and a hook-side cap with a visible warning when a stream
  is truncated.
- **Limit.** **A scan that times out fails open**: the text is returned
  unscanned with verdict `error` and `SECRET_SCAN_TIMEOUT`. This was a deliberate
  decision (withholding was tried and dropped). Thousands of matches are slow.
  The body is read before its size is checked. If a hook is killed at its own
  timeout, the original text is assumed to stand.
- **Evidence.** Code: `subprocess.run(... timeout=15)` and the timeout branch of
  `_scan_secrets`; `_enforce_size`. Pinned by: `tests/api_contract_test.py` (413
  caps), the timing cases in `tests/scan_options_test.sh`, plugin
  `tests/combined-hook.test.sh` (a slow model stub cannot delay secret
  redaction).

### T4. The model reads a credential file

- **Control.** A `PreToolUse` hook on Read, Grep and Bash denies known
  credential files (SSH keys, cloud credential files, `.netrc`, `.pgpass`,
  keystores, any file whose content starts like a private key) and asks for
  files that are usually benign (`.env`, kubeconfig, registry token files,
  Terraform state). The hook never prints content.
- **Limit.** Indirect reads (a script, a path held in a variable, `eval`) are
  not caught; a Grep over a directory is checked by name only; the content sniff
  reads the first 10 MiB; it also denies documents that merely quote a key
  header (false positives). An ask is answered by Claude Code itself in `auto`
  mode, with no person. Override: `GUARDS_ALLOW_CRED_READ=1`.
- **Evidence.** Code: `hooks/credfile-guard.sh`. Pinned by:
  `tests/credfile-guard.test.sh` (deny and ask cases, `ssh -i` and
  `.env.example` allowed, deny beats ask, override).

### T5. The model publishes a credential

- **Control.** A `PreToolUse` hook scans what a publishing command or GitHub MCP
  write tool would send (command text, named body files, the staged diff for
  `git commit`). A match from a vendor or private-key rule is a hard deny. A match
  from a context rule asks when a person is present and denies when the
  permission mode has none. If no scanner can run, it denies.
- **Limit.** **`git push` is not covered**, only `git commit`; nor `curl` or other
  posters, scripts that publish indirectly, non-GitHub tools, or the GitHub web
  UI. Files named in a command and the staged diff are read up to 512 KB. The
  override `GUARDS_ALLOW_PUBLISH_SECRETS=1` disables it. A line marked
  `guards:synthetic` is excused in a staged diff.
- **Evidence.** Code: `hooks/publish-guard.sh` (publish detection, the ambiguous
  rule list, the permission-mode decision). Pinned by:
  `tests/publish-guard.test.sh` (ask versus deny by mode, hard deny for keys,
  scanner missing fails closed, no value in the message).

### T6. A credential in the user's own prompt or in an outgoing message

- **Control.** `SendMessage` input is scanned per field and rewritten before it
  is sent. For the prompt, a `UserPromptSubmit` hook adds a note when a secret is
  found, saying it was submitted as typed and to rotate it if real.
- **Limit.** **A secret typed in the user's prompt cannot be removed by a hook**;
  it reaches the model and the API unchanged, and the note is advisory (and is
  silently skipped if the service is slow or down). Tool inputs other than
  `SendMessage` and the publish verbs (`Write`, `Edit`, `curl`) are not scanned.
  `SendMessage` and the prompt hook have no automated tests.
- **Evidence.** Code: `hooks/sendmessage-guard.sh`,
  `hooks/userpromptsubmit-guard.sh`. Pinned by: nothing automated; both were
  verified by hand against a live session (see the plugin's `docs/LIMITS.md`,
  "Maintenance gaps").

### T7. Hostile tool output tries to steer the model (prompt injection)

- **Control.** The first 2 KB of a Bash output goes to the injection model (Llama
  Prompt Guard 2, 86M); a malicious verdict at or above a 0.95 score prepends a
  warning. Flag only: text is never altered.
- **Limit.** This is jailbreak and override detection. **Indirect injection (an
  instruction inside data with no override language) was caught 6% of the time**
  (InjecAgent, n=200). Only the first 2 KB is classified. Any window flags the
  whole input. The warning is advisory; nothing blocks the model from acting on
  the text. A clean verdict is not a safety guarantee.
- **Evidence.** Code: `app/injection_guard/model.py` (512-token windows),
  `INJECTION_MIN_SCORE` and `FLAG_MAX_BYTES` handling in
  `hooks/combined-hook.sh`. The 6% figure is recorded in `app/main.py` and the
  README; the evaluation itself is not in this repository.

### T8. Hostile output crafted to evade detection

- **Control.** Matching ignores ANSI colour codes and zero-width characters and
  maps fullwidth `=` and `:` to ASCII; base64 tokens are decoded and re-scanned.
- **Limit.** Anything else an adversary can encode, split, pad or reorder:
  hex, URL-encoding, compression, double base64, a secret across two outputs, a
  quoted value containing its own closing quote, text beyond the size caps.
  Redaction is by pattern, so a determined adversary who controls the text can
  evade it. After any redaction, ANSI codes, zero-width characters and fullwidth
  delimiters are normalised across the whole output.
- **Evidence.** Code: the normalised matching copy and base64 pass in
  `app/scan.sh`. Pinned by: `tests/scan_options_test.sh`.

### T9. Personal data in tool output

- **Control.** Presidio finds 9 English entity types by default and the plugin flags them
  in the first 2 KB of Bash output; values are left intact by default.
- **Limit.** English only; statistical misses and false positives; most real-world
  PII falls outside the entity set (a 63% figure from the predecessor project's
  benchmark, not reproduced here); flag only unless `PII_GUARD_MODE=redact`.
- **Evidence.** Code: `app/pii_guard/engine.py`. No automated test exercises the
  real PII engine; the API contract is tested with it stubbed
  (`tests/api_contract_test.py`).

### T10. A network peer reaches the service

- **Control.** The compose file publishes the port only on loopback
  (`127.0.0.1:8700:8700`), a prefix documented as load-bearing; the container runs
  as a non-root user; request sizes are capped.
- **Limit.** **The service has no authentication, no TLS and no rate limit.**
  Anyone who can reach the port can submit text for scanning and burn CPU. It returns nothing but that
  text's scan result. The container itself listens on `0.0.0.0`, so a
  `docker run -p 8700:8700` without the loopback prefix exposes it to the
  network. `/docs`, `/redoc` and `/openapi.json` are FastAPI defaults and were not
  disabled. The setting `INJECTION_GUARD_AUTH_TOKEN` exists in the vendored
  configuration but no code reads it.
- **Evidence.** Code: `guards/docker/docker-compose.yml`, `Dockerfile` (`USER`,
  the uvicorn command), `app/main.py` (no auth). The posture is written in
  [CONFIGURATION.md](CONFIGURATION.md#network-and-security-posture) and the
  plugin's `docker/SERVER-SIDE.md`. Pinned by: nothing automated.

### T11. A local process uses the service or its files

- **Control.** Metrics hold verdicts only (`ts`, `type`, `verdict`,
  `reason_code`), never scanned text; a failed metrics write never fails a scan.
  The scanner writes its temporary files with a cleanup trap.
- **Limit.** Any local process can call the loopback service. The metrics
  directory is created world-writable (mode 777) by the self-heal script so the
  container user can write to it, and the file is never rotated. The hooks and
  the container run with the user's privileges. The environment-value pass reads
  the process environment, so it protects only what that process holds.
- **Evidence.** Code: `_log_metric` and `METRICS_PATH` in `app/main.py`;
  `bin/guards-selfheal.sh` (the metrics directory); `trap` in `app/scan.sh`.

### T12. The service or a hook endpoint is not the one intended

- **Control.** Default endpoint is loopback. Secret scanning falls back to the
  vendored local `scan.sh` when the service is down, slow or malformed; the
  plugin's MCP `scan` tool returns an explicit error, never a clean result, when
  the backend fails.
- **Limit.** If `GUARDS_ENDPOINT` points elsewhere, raw tool output is sent
  there in plaintext and the answer is trusted: a malicious endpoint could read
  the text, or reply `clean` or return altered text. Nothing authenticates the
  endpoint. The local fallback runs the vendored `scan.sh`, which is kept in sync
  with this repository's by hand, with no check.
- **Evidence.** Code: `hooks/secret-scan-lib.sh` (service first, local fallback),
  `mcp/server.py`. Pinned by: plugin `tests/fast-secret-scan.test.sh` (service
  down, slow, 404, garbage).

### T13. A compromised dependency, image or model download

- **Control.** Gitleaks is pinned to a release and its download is checksum
  verified by the self-heal script; Trivy scans the filesystem and every built
  image in CI and on a schedule; dependency version floors for known CVEs; the
  image is rebuilt with OS upgrades; the container runs non-root; the updater is
  pinned to a version and scoped by label to this image.
- **Limit.** Known CVEs in the Go runtime inside the upstream gitleaks binary are
  accepted in `.trivyignore` until a fixed release exists. Python packages are
  installed by version floor, not by hash. The build copies the `uv` tool by tag
  and digest, and the injection model is downloaded at the revision this project
  evaluated, reported by `GET /about`; `INJECTION_GUARD_MODEL_ID` can still
  point anywhere, with only a warning, and then follows that repository's default
  branch unless a revision is set. The plugin's Watchtower container holds the
  Docker socket and pulls the floating `:cpu` tag every five minutes, so a bad
  published image would reach users within minutes (pin the tag and remove
  Watchtower if that is not acceptable). The plugin itself tracks `main`. Model
  weights are not signed or hash-checked by this project.
- **Evidence.** Code: `Dockerfile` and `Dockerfile.cpu`;
  `.github/workflows/ci.yml` and `publish.yml` (Trivy); `app/injection_guard/model.py`
  (model load, override warning); `bin/guards-selfheal.sh` (checksum),
  `docker/docker-compose.yml` (Watchtower). See also
  [security/dependency-cve-and-license-audit-2026-10-18.md](security/dependency-cve-and-license-audit-2026-10-18.md).

### T14. Self-heal and install actions on the user's machine

- **Control.** The SessionStart script always exits 0, serialises with a lock,
  verifies the gitleaks checksum, touches only a container whose image and compose
  file match the plugin's, and publishes the port on loopback only.
- **Limit.** It downloads and installs a binary into `~/.local/bin`, pulls and
  starts containers, and checks for plugin updates over the network, all
  automatically at session start. The trust is in GitHub releases, the GHCR image
  and the checksum file served from the same release.
- **Evidence.** Code: `bin/guards-selfheal.sh`. Pinned by: nothing automated (the
  script has no tests).

## Out of scope and not defended

Stated plainly, so nobody relies on a guarantee that does not exist.

- **No authentication, TLS or rate limit on the service.** Loopback is the whole
  defence. Do not expose the port, and treat `GUARDS_ENDPOINT` as a place where
  raw tool output is sent.
- **Secrets typed in the user's own prompt cannot be removed.** A hook can only
  note them. They reach the model and the API as typed.
- **Indirect prompt injection is mostly not detected** (6% recall). The injection
  verdict is a notice on a prefix, not a control. Nothing stops the model acting
  on hostile data.
- **`git push` is not covered by the publish guard**, nor `curl`, scripts, other
  hosts' tools or the web UI.
- **Read, Grep and WebFetch output is not scanned**; only credential-file reads
  are denied up front, by name and by content sniff, and indirect reads escape it.
- **Tool inputs other than `SendMessage` and the publish verbs are not scanned.**
  A secret written with `Write` or sent by a tool the guards do not name is not
  looked at.
- **Bare, short, or context-free secrets, and encodings beyond base64.**
- **Anything outside Claude Code sessions with the plugin installed**, and any
  harness whose hooks differ.
- **A scan that times out, a hook that is killed, a service that is down for the
  non-secret axes**: fail open by design. Secrets still get a local scan when the
  service is down; PII and injection notices simply disappear.
- **An attacker who controls the machine, the container runtime, the user's
  account or the hook environment**, including anyone who can set the override
  variables (`GUARDS_ALLOW_CRED_READ`, `GUARDS_ALLOW_PUBLISH_SECRETS`,
  `GUARDS_MCP_SCAN`, `GUARDS_MCP_SKIP`).
- **Personal data beyond the 9 default English entity types**, and any non-English text.
- **Policy, audit, async delivery, and org-wide rules.** These belong to a
  platform that serves the same endpoint contract behind `GUARDS_ENDPOINT`, not
  to this repository.
- **Windows** is not tested.

## Reporting and keeping this current

Vulnerabilities go through private reporting as described in
[SECURITY.md](../SECURITY.md). When a control or a limit changes, change the
row here in the same pull request that changes [LIMITS.md](LIMITS.md); the
"Evidence" lines are the part most likely to rot, so keep them to a file or a
test name rather than a line number.
