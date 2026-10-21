"""Redaction self-test for guards-unified's secret axis.

Three modes, same checks:
  --image IMG      run /app/scan.sh inside a built docker image (what CI
                   does: tests the shipped artifact without starting the
                   service, whose injection model is a gated HF download).
  --endpoint URL   POST each case to a running guards-unified /v1/scan.
  --scan-sh        run app/scan.sh directly (needs gitleaks + jq on PATH).

Invariants asserted for EVERY case, regardless of rule:
  * if the secret axis says "found", the redacted text differs from the
    input and none of the secret material survives in it.
A "found but unchanged" result is the bug class this exists for: a detection with no redaction is worse than a
miss because the verdict claims success.

REQUIRED cases must additionally be found AND redacted. KNOWN_GAPS are
shapes still undetected today; they are reported, not failed, and carry
the issue that will turn them into REQUIRED cases.

Everything is synthetic: keys come from ssh-keygen / openssl at run time
in a temp dir and have never been used for anything. No real credential,
rotated or not, belongs in this file.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"
KEY_BODY_MIN = 16  # a body line shorter than this is not treated as secret material


def make_keys(tmp: Path) -> dict[str, str]:
    def run(*cmd: str) -> None:
        subprocess.run(cmd, check=True, capture_output=True)

    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp / "k_ed"), "-C", "throwaway")
    run("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "", "-f", str(tmp / "k_rsa"), "-C", "throwaway")
    run("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(tmp / "k_ec"))
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(tmp / "k_p8"))
    return {
        "openssh-ed25519": (tmp / "k_ed").read_text(),
        "rsa-pkcs1": (tmp / "k_rsa").read_text(),
        "ec-sec1": (tmp / "k_ec").read_text(),
        "pkcs8": (tmp / "k_p8").read_text(),
    }


def key_forms(pem: str) -> dict[str, str]:
    lines = pem.splitlines()
    return {
        "plain": pem,
        "prompt-wrapped": "$ cat key\n" + pem + "$ \n",
        "indented": "\n".join("    " + line for line in lines),
        "crlf": pem.replace("\n", "\r\n"),
        "json-escaped": json.dumps({"private_key": pem}),
        "yaml-block": "key: |\n" + "\n".join("  " + line for line in lines) + "\n",
        # No END marker: `head`, clipped or truncated output.
        "truncated-no-end": "\n".join(lines[:-1]) + "\n",
        "clipped-200-bytes": pem[:200],
    }


def key_material(pem: str) -> list[str]:
    return [line for line in pem.splitlines() if line and not line.startswith("-----") and len(line) >= KEY_BODY_MIN]


IMAGE_MARKER = "\n@@FINDINGS@@\n"


class Scanner:
    def __init__(self, endpoint: str | None, image: str | None = None):
        self.endpoint = endpoint
        self.image = image

    def scan(self, text: str) -> tuple[bool, str]:
        """Returns (secret_found, redacted_text)."""
        if self.endpoint:
            req = urllib.request.Request(
                self.endpoint.rstrip("/") + "/v1/scan",
                data=json.dumps({"text": text}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = json.load(resp)
            secret = next(f for f in body["findings"] if f["type"] == "secret")
            # The secret axis's own redacted_text, so PII redaction can
            # never mask a secret-axis failure.
            return secret["verdict"] == "found", secret["detail"].get("redacted_text", "")
        if self.image:
            script = (
                "SECRET_GUARD_FINDINGS_JSON=/tmp/f.json /app/scan.sh; "
                f"printf '{IMAGE_MARKER}'; cat /tmp/f.json 2>/dev/null"
            )
            proc = subprocess.run(
                ["docker", "run", "--rm", "-i", "--entrypoint", "bash", self.image, "-c", script],
                input=text,
                capture_output=True,
                text=True,
                check=False,
            )
            out, _, raw = proc.stdout.rpartition(IMAGE_MARKER)
            raw = raw.strip()
            return bool(raw) and raw != "null" and bool(json.loads(raw)), out
        with tempfile.NamedTemporaryFile(suffix=".json") as findings:
            proc = subprocess.run(
                ["bash", str(APP_DIR / "scan.sh")],
                input=text,
                capture_output=True,
                text=True,
                env={"PATH": os.environ["PATH"], "SECRET_GUARD_FINDINGS_JSON": findings.name},
                check=False,
            )
            raw = Path(findings.name).read_text().strip()
        found = bool(raw) and raw != "null" and bool(json.loads(raw))
        return found, proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--image")
    mode.add_argument("--endpoint")
    mode.add_argument("--scan-sh", action="store_true")
    args = ap.parse_args()
    scanner = Scanner(args.endpoint, args.image)

    failures: list[str] = []
    gaps: list[str] = []
    checked = 0

    def check(name: str, text: str, material: list[str], required: bool, gap_ref: str = "") -> None:
        nonlocal checked
        checked += 1
        found, out = scanner.scan(text)
        if found:
            if out == text:
                failures.append(f"{name}: found but redacted text is IDENTICAL to input")
            leaked = [m for m in material if m in out]
            if leaked:
                failures.append(f"{name}: found, but {len(leaked)}/{len(material)} secret fragments survive redaction")
        elif required:
            failures.append(f"{name}: not detected")
            dump = os.environ.get("SELFTEST_DUMP_DIR")
            if dump:
                Path(dump, name.replace("/", "_") + ".txt").write_text(text)
        else:
            gaps.append(f"{name}: still undetected ({gap_ref})")

    with tempfile.TemporaryDirectory() as d:
        keys = make_keys(Path(d))

    for kname, pem in keys.items():
        material = key_material(pem)
        for fname, text in key_forms(pem).items():
            check(f"{kname}/{fname}", text, material, required=True)

    # Context rules. Every value is fabricated.
    pw = "Tq7vN2xLm9Kd4RzP8wYb"
    punct = "Qm4*Xw9%tL2!pR7=zN3^vB8"
    cases = {
        "dsn/postgres": f"postgresql://svc:{pw}@db.internal:5432/app?sslmode=require",
        "dsn/redis-empty-user": f"redis://:{pw}@cache.internal:6379/0",
        "dsn/amqp": f"amqps://u:{pw}@mq.internal:5671/vh",
        "dsn/mongodb-srv": f"mongodb+srv://u:{pw}@c0.example.net/db",
        "dsn/clickhouse": f"clickhouse://u:{pw}@ch.internal:8123/db",
        "dsn/https-userinfo": f"https://u:{pw}@host.example.net/path",
        "env/special-chars": "DB_PASSWORD=Xk9mQ4vT2p@Lw8RzN5bJc7Hd3",
        "env/low-entropy": "DB_PASSWORD=hunter2",
        "json/punctuation-secret-key": '{"secretKey": "' + punct + '", "user": "bob"}',
        "yaml/quoted-with-spaces": 'password: "correct horse battery"',
        "yaml/next-line-scalar": "password:\n  " + pw,
        "yaml/quoted-then-more-lines": 'password: "correct horse battery"\nthe next line stays\n',
        "env/suffix-not-at-end": "MAX_BYTES_PASSWORD=Qm4xZ9vLpR2tK7wB",  # guards:synthetic
        "env/token-with-real-value": "AUTH_TOKEN=Zq8mLw3pXr7vKd2n",  # guards:synthetic
        "env/tokenizer-secret-key": "tokenizer_secret=Kd2nZq8mLw3pXr7v",  # guards:synthetic
        "yaml/single-quoted": "client_secret: 'Tq7vN2xLm9Kd4RzP8wYb'",
        "header/bearer": f"Authorization: Bearer {pw}",
        "header/basic": "authorization: Basic YWRtaW46c2VjcmV0cGFzcw==",
        "query/access-token": f"GET /x?access_token={pw}&page=2",
        "aws/secret-access-key": "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzzzzzzzzz",
    }
    materials = {
        "dsn/postgres": [pw], "dsn/redis-empty-user": [pw], "dsn/amqp": [pw], "dsn/mongodb-srv": [pw],
        "dsn/clickhouse": [pw], "dsn/https-userinfo": [pw],
        "env/special-chars": ["Xk9mQ4vT2p@Lw8RzN5bJc7Hd3"], "env/low-entropy": ["hunter2"],
        "json/punctuation-secret-key": [punct], "yaml/quoted-with-spaces": ["correct horse battery"],
        "yaml/next-line-scalar": [pw], "yaml/quoted-then-more-lines": ["correct horse battery"], "env/suffix-not-at-end": ["Qm4xZ9vLpR2tK7wB"], "env/token-with-real-value": ["Zq8mLw3pXr7vKd2n"], "env/tokenizer-secret-key": ["Kd2nZq8mLw3pXr7v"],"yaml/single-quoted": [pw], "header/bearer": [pw], "header/basic": ["YWRtaW46c2VjcmV0cGFzcw=="],  # guards:synthetic
        "query/access-token": [pw], "aws/secret-access-key": ["wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzzzzzzzzz"],
    }
    # Command-line flags and vendor shapes.
    b = "Xk9mQ4vT2pLw8RzN5bJc7Hd3"
    azure = "abc8Q~" + "Zx3mN7pQ2rT5vW8yB1cD4fG6hJ9kL0nM2o"
    esc = "\033"
    cases_b = {
        "alias/pw": f"GRAFANA_ADMIN_PW={b}",
        "alias/pass-quoted": f'ADMIN_PASS: "{b}"',
        "alias/cred": f"DB_CRED={b}",
        "flag/password-space": f"clickhouse-client --host h --password {b} --query x",
        "flag/mysql-glued": f"mysql -u root -p{b} appdb",
        "flag/redis-cli": f"redis-cli -h cache -a {b} ping",
        "flag/sshpass": f"sshpass -p {b} ssh host",
        "flag/docker-login": f"docker login -u bob -p {b} registry.example.invalid",
        "flag/mc-alias-set": f"mc alias set mine https://s3.example.invalid ACCESSIDEXAMPLE0001 {b}",
        "header/cookie": f"Cookie: session={b}; theme=dark",
        "file/netrc": f"machine h.example.invalid login bob password {b}",
        "file/pgpass": f"db.internal:5432:app:svc:{b}",
        "multiline/k8s-env": f'- name: DB_PASSWORD\n    value: "{b}"',
        "multiline/bitwarden-json": f'{{"key": "DB_PASSWORD", "value": "{b}"}}',
        "ansi/coloured-key": f"{esc}[32mDB_PASSWORD{esc}[0m={b}",
        "unicode/zero-width-in-key": "DB_PASS\u200bWORD=" + b,
        "unicode/fullwidth-equals": "DB_PASSWORD\uff1d" + b,
        "unicode/fullwidth-colon": "password\uff1a " + b,
        "kube/client-key-data": f"client-key-data: {b}{b}",
        "vendor/azure-client-secret": f"appId: x\npassword-ish: {azure}",
        "vendor/gcloud-access-token": "Authorization-less ya29." + "a0Af" + "B_byT3kZq8wXr5tNm2PvKd9sL1",
        "vendor/bcrypt-hash": "admin:$2y$10$" + "N9qo8uLOickgx2ZMRZoMye" + "IjZAgcfl7p92ldGxad68LJZdL17lhWy",
    }
    materials_b = {
        "alias/pw": [b], "alias/pass-quoted": [b], "alias/cred": [b], "flag/password-space": [b],
        "flag/mysql-glued": [b], "flag/redis-cli": [b], "flag/sshpass": [b], "flag/docker-login": [b],
        "flag/mc-alias-set": [b], "header/cookie": [b], "file/netrc": [b], "file/pgpass": [b],
        "multiline/k8s-env": [b], "multiline/bitwarden-json": [b], "ansi/coloured-key": [b],
        "unicode/zero-width-in-key": [b], "unicode/fullwidth-equals": [b], "unicode/fullwidth-colon": [b],
        "kube/client-key-data": [b], "vendor/azure-client-secret": [azure],
        "vendor/gcloud-access-token": ["ya29.a0AfB_byT3kZq8wXr5tNm2PvKd9sL1"],
        "vendor/bcrypt-hash": ["N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"[:20]],
    }
    # Secrets hiding in base64 under an innocent key name.
    import base64
    pem_b64 = base64.b64encode(keys["ec-sec1"].encode()).decode()
    dsn_b64 = base64.b64encode(f"postgresql://svc:{pw}@db.internal:5432/app".encode()).decode()
    env_b64 = base64.b64encode(f"DB_PASSWORD={b}\nOTHER=1".encode()).decode()
    cases_b.update({
        "base64/dsn-in-json": '{"conn": "' + dsn_b64 + '"}',
        "base64/env-file": "data:\n  cfg: " + env_b64 + "\n",
        "base64/private-key": '{"blob": "' + pem_b64 + '"}',
    })
    materials_b.update({"base64/dsn-in-json": [dsn_b64], "base64/env-file": [env_b64], "base64/private-key": [pem_b64]})
    cases.update(cases_b)
    materials.update(materials_b)
    for cname, text in cases.items():
        check(cname, text, materials[cname], required=True)

    # A quote-wrapped key word with its colon in prose ("token:") ends its own
    # quote where a quoted value would open; real quoted values stay redacted
    # in every style, including next to such prose.
    qv = "Kq7wXn4tMz2Pb8Lc"
    quoted_values = {
        "quoted/equals": (f'password="{qv}"', [qv]),
        "quoted/json-spaced": (f'{{"password": "{qv}"}}', [qv]),
        "quoted/json-compact": (f'{{"password":"{qv}"}}', [qv]),
        "quoted/single-with-spaces": ("password: 'correct horse battery'", ["correct horse battery"]),
        "quoted/cli-flag": (f'--password="{qv}"', [qv]),
        "quoted/nested-shell": (f'bash -c "PASSWORD="{qv}" ./run"', [qv]),
        "quoted/after-wrapped-key-prose": (f'the "token:" field, then {{"password": "{qv}"}}', [qv]),
    }
    for cname, (text, material) in quoted_values.items():
        check(cname, text, material, required=True)

    # A key whose LAST segment is the credential or a value word is a real
    # secret even when it has the same leading words as the reference keys above.
    sv = "Zq8xK2mNp4Lw9vTd"
    last_segment_secrets = {
        "last-segment/auth-token": f"AUTH_TOKEN={sv}",  # guards:synthetic
        "last-segment/db-password": f'db_password: "{sv}"',  # guards:synthetic
        "last-segment/api-secret": f'api_secret: "{sv}"',  # guards:synthetic
        "last-segment/client-secret-value": f'client_secret_value: "{sv}"',  # guards:synthetic
        "last-segment/client-secret-value-camel": f'clientSecretValue: "{sv}"',  # guards:synthetic
        "last-segment/secret-key": f'secret_key: "{sv}"',  # guards:synthetic
        "last-segment/secret-valid-not-id": f'secretValid: "{sv}"',  # guards:synthetic
    }
    for cname, text in last_segment_secrets.items():
        check(cname, text, [sv], required=True)

    # A credential inside a very long line is still found. Long unbroken runs are
    # masked for the context rules (they used to make the scan quadratic), so these
    # pin that the mask never hides a credential, whether it sits after a run, before one, between two,
    # and a long run as the value itself.
    run = "a" * 20000
    long_line_secrets = {
        "long-line/after-run": (f"{run} password: {sv}", [sv]),  # guards:synthetic
        "long-line/before-run": (f"password: {sv} {run}", [sv]),  # guards:synthetic
        "long-line/between-runs": (f"{run} DB_PASSWORD={sv} {run}", [sv]),  # guards:synthetic
        "long-line/in-json": ("{" + f'"blob":"{run}","password":"{sv}"' + "}", [sv]),  # guards:synthetic
        "long-line/run-as-value": (f"api_secret={run}", [run]),
    }
    for cname, (text, material) in long_line_secrets.items():
        check(cname, text, material, required=True)

    # Unquoted values in env, INI, YAML and shell contexts, and string literals
    # assigned to a token-named constant, stay secrets even though the code-shape
    # rule exists. Short, lowercase and digit-bearing words are included on purpose.
    config_secrets = {
        "config/env-word-digit": ("DB_PASSWORD=hunter2x", ["hunter2x"]),  # guards:synthetic
        "config/yaml-word-digit": ("password: hunter2x", ["hunter2x"]),  # guards:synthetic
        "config/yaml-word": ("password: correcthorse", ["correcthorse"]),  # guards:synthetic
        "config/ini-spaced": ("password = swordfish9", ["swordfish9"]),  # guards:synthetic
        "config/dotenv-spaced": ("token = abc123xyz", ["abc123xyz"]),  # guards:synthetic
        "config/shell-export": ("export API_TOKEN=abc123xyz", ["abc123xyz"]),  # guards:synthetic
        "config/shell-readonly": ("readonly API_TOKEN=abc123xyz", ["abc123xyz"]),  # guards:synthetic
        "config/shell-then-command": ("API_TOKEN=abc123xyz; curl -H x https://example.invalid", ["abc123xyz"]),  # guards:synthetic
        "config/yaml-trailing-comma": ("  password: hunter2x,", ["hunter2x"]),  # guards:synthetic
        "config/yaml-mixed-case": ("secret: Hunter2Pass", ["Hunter2Pass"]),  # guards:synthetic
        "config/code-string-literal-const": (f'  const SUBJECT_TOKEN = "{sv}";', [sv]),  # guards:synthetic
        "config/code-string-literal-prop": (f"  const subjectToken = '{sv}';", [sv]),  # guards:synthetic
        # Near-misses of the dependency rule must still redact: a 4-part version is not a 3-part one, an
        # underscore makes the key a config name, an unscoped key needs an operator or a protocol, and a
        # scoped package holding a non-version value is a value.
        "config/dep-lookalike-4part-password": ('    "password": "1.2.3.4",', ["1.2.3.4"]),  # guards:synthetic
        "config/dep-lookalike-underscore-key": ("client_secret: ^0.2.0", ["^0.2.0"]),  # guards:synthetic
        "config/dep-lookalike-unscoped-bare": ('    "api-key-rotator": "2.0.0",', ["2.0.0"]),  # guards:synthetic
        "config/dep-lookalike-scoped-nonversion": ('    "@scope/api-key": "Xk9mQ4vT2pLw8RzN5bJc",', ["Xk9mQ4vT2pLw8RzN5bJc"]),  # guards:synthetic
        "config/dep-lookalike-token-long": ('    "access-token": "Tq7vN2xLm9Kd4RzP8wYbQ3sF",', ["Tq7vN2xLm9Kd4RzP8wYbQ3sF"]),  # guards:synthetic
        "config/code-quoted-in-object": (f'body: JSON.stringify({{ subject_token: "{sv}", provider: P }}),', [sv]),  # guards:synthetic
    }
    for cname, (text, material) in config_secrets.items():
        check(cname, text, material, required=True)

    # Harmless lookalikes must come back byte-identical and not be flagged.
    benign = {
        "benign/placeholder": "password: ${DB_PASSWORD}",
        "benign/k8s-secret-name": "secretName: db-credentials",
        "benign/token-type": '{"token_type": "Bearer"}',
        "benign/prose": "The secret to good tests is isolation.",
        "benign/url-without-password": "https://github.com/gramatr/guards-unified",
        "benign/token-count": "token_count: 1234",
        # Keys naming an identifier or reference of a secret, with extra segments
        # before the descriptor. Values are fixture ids, not credentials.
        "benign/ref-key-snake-id": 'client_secret_bws_id: "bws-secret-id-123"',  # guards:synthetic
        "benign/ref-key-camel-id": 'clientSecretBwsId: "bws-secret-id-123"',  # guards:synthetic
        "benign/ref-key-caps-id": "CLIENT_SECRET_BWS_ID=bws-secret-id-123",  # guards:synthetic
        "benign/ref-key-vault-id": 'secret_vault_id = "vault-ref-9a1"',  # guards:synthetic
        "benign/ref-key-store-ref": 'token_store_ref: "store-ref-77"',  # guards:synthetic
        "benign/ref-key-provider-arn": 'credential_provider_arn: "arn:aws:iam::123456789012:role/example"',  # guards:synthetic
        # Ordinary source code: an unquoted value that is a call, an identifier,
        # a member chain or a type is not a credential. Fabricated lookalikes.
        "benign/code-property-identifier": "    accessToken: accessToken,",  # guards:synthetic
        "benign/code-property-member": "    refresh_token: tokens.refreshToken,",  # guards:synthetic
        "benign/code-property-in-object": "  const body = { subject_token: subjectToken, grant: 'x' };",  # guards:synthetic
        "benign/code-argument-member": "  await exchange({ token: this.cfg.apiToken });",  # guards:synthetic
        "benign/code-const-call": "  const callbackToken = createSignedToken(userId, 300);",  # guards:synthetic
        "benign/code-const-await-call": "  const bearerToken = await getToken(ctx);",  # guards:synthetic
        "benign/code-private-readonly-call": "  private readonly authToken = loadToken();",  # guards:synthetic
        "benign/code-kotlin-val-call": "  val apiToken = tokenProvider.fetch()",  # guards:synthetic
        "benign/code-type-annotation": "  readonly subject_token: string",  # guards:synthetic
        "benign/code-type-annotation-semicolon": "  access_token: string;",  # guards:synthetic
        "benign/code-generic-type": "  token: Promise<TokenSet>;",  # guards:synthetic
        "benign/code-return-object": "  return { idToken: idToken };",  # guards:synthetic
        # A dependency whose package NAME contains a credential word, with a version specifier as the
        # value (a package.json or a lockfile/YAML line): not a credential (coordination: the platform's
        # own @gramatr/credentials-lifecycle tripped the publish guard on every commit).
        "benign/dep-scoped-caret": '    "@gramatr/credentials-lifecycle": "^0.2.0",',
        "benign/dep-scoped-caret-token": '    "@gramatr/token-authority": "^0.2.0",',
        "benign/dep-diff-line": '+    "@gramatr/credentials-lifecycle": "^0.2.0",',
        "benign/dep-workspace": '    "@gramatr/credentials-lifecycle": "workspace:*",',
        "benign/dep-scoped-bare-version": '    "@gramatr/credentials-lifecycle": "0.2.0",',
        "benign/dep-range": '    "@gramatr/token-authority": ">=0.2.0 <1.0.0",',
        "benign/dep-tilde-unscoped": '    "secret-manager-client": "~1.4.2",',
        "benign/dep-api-key-package": '    "api-key-rotator": "^2.0.0",',
        "benign/dep-yaml": "credentials-lifecycle: ^0.2.0",
        "benign/ref-key-secretkeyref": 'secretKeyRef: {name: db-creds, key: password}',
        "benign/plural-heading-code-span": "Query-string tokens: `access_token=`, presigned URLs",
        "benign/base64-sentence": '{"note": "' + base64.b64encode(b"The quick brown fox jumps over the lazy dog and keeps running far away").decode() + '"}',
        "benign/base64-binary": '{"img": "' + base64.b64encode(bytes(range(256)) * 2).decode() + '"}',
        "benign/git-hash": "commit 3f2a9c1e5b7d4a6082f1c3e5a7b9d1f3e5a7c9b1 Author: x",
        "benign/sha256-hex": "sha256:" + "ab12" * 16,
        "benign/heading-then-command": "Rotate the secret:\n  kubectl delete secret old",
        "benign/heading-then-nested-key": "secret:\n  name: db-creds",
        "benign/setting-ask-switch": "set the switch to force: GUARDS_CRED_ASK=force",  # guards:synthetic
        "benign/setting-max-bytes": "SCAN_SECRET_MAX_BYTES=2000000",  # guards:synthetic
        "benign/setting-timeout": "API_TOKEN_TIMEOUT=30000",  # guards:synthetic
        "benign/setting-mode": "CRED_MODE=strict",  # guards:synthetic
        "benign/tokenizer-assignment": "self._tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)",  # guards:synthetic
        "benign/quoted-keywords-across-lines": 'A heading that ended in "token:" then text\nline two\nline three\nand later "secret:" follows here\nlast line\n',
        "benign/pwd-env-line": "PWD=/usr/bin",
        "benign/pwd-label": "pwd: /tmp",
        "benign/word-containing-pass": "compass: northwest heading",
        "benign/pass-true": "pass: true",
        "benign/tests-pass-prose": "all the tests pass: 12 of 12 ran",
        "benign/ssh-port-flag": "ssh -p 2222 host.example.invalid",
        "benign/docker-publish-flag": "docker run -p 8080:80 nginx",
        "benign/mysql-prompt": "mysql -u root -p appdb",
        "benign/access-key-id-default": "AccessKey : 48388a15798489a302330828b2388025",
        "benign/begin-prose": "hello -----BEGIN of a story\nline2\n",
    }
    benign.update({
        "benign/wrapped-key-prose": 'the "password:" field, then "some text here"',
        "benign/wrapped-key-prose-single": "a 'token:' label and 'another thing' after it",
        "benign/wrapped-key-prose-start": '"secret:" and "hello world" follow',
    })
    for bname, text in benign.items():
        checked += 1
        found, out = scanner.scan(text)
        if found or out != text:
            failures.append(f"{bname}: harmless text was flagged or altered")

    print(f"redaction self-test: {checked} cases, {len(failures)} failures, {len(gaps)} known gaps")
    for line in gaps:
        print("  KNOWN-GAP", line)
    for line in failures:
        print("  FAIL", line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
