# Reproducing the scanner miss fixed in v0.2.10

Evidence for the two published advisories ([GHSA-5g92-g3j3-2g22](https://github.com/gramatr/guards-unified/security/advisories/GHSA-5g92-g3j3-2g22) here, [GHSA-h5rq-hrxc-f3vm](https://github.com/gramatr/claude-plugin-guards/security/advisories/GHSA-h5rq-hrxc-f3vm) in the plugin), so anyone can check the claims without trusting us. Run on 2026-10-22.

## What the flaw is

In v0.2.9 and every earlier release, `app/scan.sh` gave gitleaks its input in a temporary file named by `mktemp` (`tmp.` and ten random letters and digits). gitleaks decides that a file is an archive from its **name** and then scans nothing. When the random name began like an archive extension, a vendor-shaped value standing alone in a sentence came back **unredacted**, with no error. v0.2.10 uses a private directory and a fixed plain name, and retries when gitleaks scans zero bytes.

## How to reproduce it

You need `bash`, `jq`, `git`, and `docker` (or any gitleaks v8.30.1 binary).

1. Get the old and new scripts: `git show v0.2.9:app/scan.sh > /tmp/scan-v0.2.9.sh` and the same for `v0.2.10`.
2. Get each release's own gitleaks from its image: `docker create ghcr.io/gramatr/guards-unified:cpu-v0.2.9`, then `docker cp <id>:/usr/bin/gitleaks <dir>/gitleaks`, and `docker rm <id>`.
3. Force the file name and run: `bash tests/repro_archive_name_miss.sh names /tmp/scan-v0.2.9.sh <dir>`. For the natural rate: `bash tests/repro_archive_name_miss.sh rate /tmp/scan-v0.2.9.sh <dir> 1600`.

The value used is fabricated and assembled at run time. It stands alone in a sentence on purpose: written as a key and a value, a different rule redacts it and hides the miss.

## What we saw

| Check | v0.2.9 (script and its own gitleaks) | v0.2.10 |
|---|---|---|
| Forced name starting `7z br bz2 gz lz4 rar s2 sz tar xz zip zst zz` | **leaked**, 13 of 13 | redacted, 13 of 13 |
| Ordinary forced names (`tmp.AbCdEfGhIj`, `tmp.zAbCdEfGhI`) | redacted | redacted |
| 1,600 scans with the real `mktemp` | **10 leaked** (0.63%) | 0 leaked |
| 1,500 scans against the running v0.2.10 service | n/a | 0 leaked |

The upstream gitleaks v8.30.1 binary (the one releases v0.1.5 to v0.2.8 shipped) leaked the same way for `7z`, `gz` and `zip` names, and so did the binary on the machine that ran the tests.

**The rate.** A sweep ran the v0.2.9 gitleaks on a file for every two- and three-character name prefix over letters and digits. 13 prefixes made it skip the file, and 23 of 23 upper-case and mixed-case variants skipped too. If the ten random characters are uniform over 62 letters and digits, that is a probability of **0.64%, 1 in 156**, which agrees with the measured 10 in 1,600.

**Other passes were not affected.** With an archive-like name forced on v0.2.9, a `password:` line and a private-key block were still redacted, because those passes do not use gitleaks.

## What this does not show

- It was run with the v0.2.9 script on the server side, not the plugin's vendored copy, which is the same script kept equal by CI.
- Releases v0.1.5 to v0.2.8 were not each run; they used the same gitleaks version and the same `mktemp` naming, which is the basis for "every earlier release". `v0.1.0` to `v0.1.4` no longer exist.
- Name prefixes of four or more characters were not swept, and the environment-values pass was not run under a forced name.
- The rate assumes uniform random characters. The measurement agrees with it, which supports the assumption but does not prove it for every platform's `mktemp`.
