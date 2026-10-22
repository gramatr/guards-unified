# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's private
vulnerability reporting: open the **Security** tab of this repository and choose
**Report a vulnerability**. Issues are disabled on this repository, and please
do not describe a vulnerability in any public place (a pull request, a
discussion, a social post): a public report discloses it to everyone at once.

This is a small open-source project. Replies are best effort and no response
time is promised. A report that is clear, reproducible and about something in
scope is the most likely to be acted on quickly.

## Supported versions

Only the latest release is supported. This repository and
[claude-plugin-guards](https://github.com/gramatr/claude-plugin-guards) move in
lockstep (the same version number and tag, see [`docs/RELEASING.md`](docs/RELEASING.md)),
and the current number is in the [`VERSION`](VERSION) file. Fixes are made on `main` and shipped in a new release; older releases
are not patched.

## Past advisories

- [GHSA-5g92-g3j3-2g22](https://github.com/gramatr/guards-unified/security/advisories/GHSA-5g92-g3j3-2g22) (published 2026-10-22): in v0.2.9 and every earlier release, about 1 scan in 125 could return a vendor-shaped token unredacted, with no error. Fixed in v0.2.10. The same flaw in the plugin's copy of the scanner is [GHSA-h5rq-hrxc-f3vm](https://github.com/gramatr/claude-plugin-guards/security/advisories/GHSA-h5rq-hrxc-f3vm).

## What to send

Describe the **shape** of the finding and the steps to reproduce it. **Never
include a real credential, token, key or personal data**, not even a rotated or
expired one. Use a fabricated value that has the same shape (for example a
made-up string with the right prefix and length), and say which rule or
behaviour it exercises. Useful details:

- the version (`GET /about` reports it) and how you run it (image tag, CPU or
  GPU, plugin or direct HTTP);
- the exact request or input shape, with fabricated values;
- what you expected and what happened (for example "the value came back
  unchanged with verdict `clean`");
- the impact you see, and whether it needs a particular setting.

This repository's own scanner redacts credential-shaped text in tool output, so
describing a shape in words is also the safest way to get it past your own
tooling.

## What is in scope

- A secret that survives redaction when the input is of a kind the documentation
  says is covered: the scanner returns it unchanged, or reports `found` without
  removing it.
- A bypass of a guard that the documentation says holds, for example a way to
  make the scanner skip text it should scan, or to make a hook stay silent for a
  case it claims to block.
- Problems in the service itself: remote code execution, reading or writing
  files, leaking scanned text into logs, metrics or error responses, a way to
  disable the scanner for other callers, or a flaw in the container image or the
  build and release pipeline.
- A vulnerable dependency or a supply-chain weakness that is reachable here.

## What is not in scope

These are documented limits, not vulnerabilities. They are listed in
[`docs/LIMITS.md`](docs/LIMITS.md) and in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md#out-of-scope-and-not-defended):

- Anything the documentation already says is not detected (short values, a bare
  high-entropy value with no context, encodings other than base64, text split
  across calls, and similar).
- Prompt-injection recall: indirect injection is mostly missed by design (6%
  measured), and a `clean` verdict is never a safety guarantee.
- The service has no authentication, no TLS and no rate limit; it is meant to
  be reachable on loopback only. Exposing it to a network and then reporting
  that anyone can reach it is a deployment mistake, not a flaw.
- A scan that times out returns the text unscanned, deliberately.
- Findings that need an attacker who already controls the machine, the
  container runtime or the user's account.

If you are unsure whether something is in scope, report it privately and say so.
