#!/usr/bin/env python3
"""Unit tests for app/pii_guard/validators.py. Pure standard library: needs neither
Presidio nor the models. Every value is fabricated; numbers that must pass a
checksum are built at run time. Includes near-misses that must NOT be reported.

    python3 tests/validators_test.py
"""

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from pii_guard import validators as v

failures = []


def check(name, cond, detail=""):
    if not cond:
        failures.append(name)
        print(f"  FAIL  {name} {detail}")


def kinds(text, which=v.KINDS):
    return [(s.entity_type, text[s.start : s.end]) for s in v.find_pii(text, which)]


def hit(name, text, kind, expect=None):
    got = kinds(text, [kind])
    check(
        name,
        bool(got) and (expect is None or got[0][1] == expect),
        f"{text!r} -> {got}",
    )


def miss(name, text, kind=None):
    got = kinds(text, [kind] if kind else v.KINDS)
    check(name, not got, f"{text!r} -> {got}")


def luhn_complete(prefix, length):
    body = prefix + "".join(
        str(random.Random(prefix).randint(0, 9))
        for _ in range(length - 1 - len(prefix))
    )
    for c in range(10):
        if v.luhn_ok(body + str(c)):
            return body + str(c)


def luhn_broken(good):
    return good[:-1] + str((int(good[-1]) + 1) % 10)


def iban_for(country, body):
    rearr = "".join(str(int(c, 36)) for c in body + country + "00")
    return f"{country}{98 - int(rearr) % 97:02d}{body}"


# ---------------------------------------------------------------- credit card
visa = luhn_complete("4", 16)
amex = luhn_complete("37", 15)
grouped = " ".join(visa[i : i + 4] for i in range(0, 16, 4))
dashed = "-".join(visa[i : i + 4] for i in range(0, 16, 4))
amex_grp = f"{amex[:4]} {amex[4:10]} {amex[10:]}"
hit("card unseparated", f"card {visa} declined", "CREDIT_CARD", visa)
hit("card spaced", f"card {grouped} declined", "CREDIT_CARD", grouped)
hit("card dashed", f"card={dashed}", "CREDIT_CARD", dashed)
hit("card amex 4-6-5", f"amex {amex_grp}", "CREDIT_CARD", amex_grp)
hit("card amex unseparated", f"amex {amex}", "CREDIT_CARD", amex)
miss("card failing Luhn (16 digits)", f"id {luhn_broken(visa)}", "CREDIT_CARD")
miss("card spaced failing Luhn", luhn_broken(grouped.replace(" ", "")), "CREDIT_CARD")
# a Luhn-valid 16-digit run with no issuer prefix is an id
nonissuer = luhn_complete("9", 16)
miss("card Luhn-valid but no issuer prefix", f"run {nonissuer}", "CREDIT_CARD")
miss("card with wrong length for issuer", luhn_complete("37", 16), "CREDIT_CARD")
miss("epoch milliseconds", "ts 1760972400123", "CREDIT_CARD")
miss("GitHub run id", "gh run view 39442632382", "CREDIT_CARD")
miss("card inside a longer word/id", f"abc-{visa}", "CREDIT_CARD")
miss("card digits as a decimal fraction", f"{visa}.50", "CREDIT_CARD")
miss("card digits after a decimal point", f"1.{visa}", "CREDIT_CARD")
miss("UUID", "4f2a9c1e-7b3d-4e58-9a61-0c8d2b5e7f13", "CREDIT_CARD")

# ----------------------------------------------------------------------- IBAN
gb = iban_for("GB", "WEST12345698765432")
de = iban_for("DE", "370400440532013000")
gb_spaced = " ".join(gb[i : i + 4] for i in range(0, len(gb), 4))
hit("iban compact", f"iban {gb} on file", "IBAN_CODE", gb)
hit("iban grouped", f"IBAN {gb_spaced} on file", "IBAN_CODE", gb_spaced)
hit("iban german", f"to {de}", "IBAN_CODE", de)
hit(
    "iban followed by an upper-case word",
    f"IBAN {gb_spaced} DECLINED",
    "IBAN_CODE",
    gb_spaced,
)
bad_check = gb[:2] + ("00" if gb[2:4] != "00" else "01") + gb[4:]
miss("iban with wrong check digits", f"iban {bad_check}", "IBAN_CODE")
b32 = "AB12" + "".join(
    random.Random(7).choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(18)
)
miss("22-char base32-looking id (unknown country)", f"id {b32}", "IBAN_CODE")
b32_gb = (
    "GB"
    + "12"
    + "ZXCV"
    + "".join(random.Random(8).choice("234567ABCDEFG") for _ in range(14))
)
if v.iban_ok(b32_gb):
    b32_gb = b32_gb[:-1] + ("A" if b32_gb[-1] != "A" else "B")
miss(
    "22-char base32-looking id with a valid country and length, failing mod 97",
    f"id {b32_gb}",
    "IBAN_CODE",
)
miss("iban with the wrong length for its country", f"iban {gb[:-1]}", "IBAN_CODE")
miss("sha1 hex", "commit 3f786850e387550fdab836ed7e6dc881de23001b", "IBAN_CODE")
miss("UUID", "4F2A9C1E-7B3D-4E58-9A61-0C8D2B5E7F13", "IBAN_CODE")
miss("lower-case id", "gb82west12345698765432", "IBAN_CODE")

# ------------------------------------------------------------------------ SSN
ssn = "078-05-1120"  # guards:synthetic
ssn_bare = ssn.replace("-", "")
hit("ssn", f"ssn {ssn}", "US_SSN", ssn)
hit(
    "ssn 9xx area is kept (ITIN / fabricated)", "tin 912-70-1234", "US_SSN"
)  # guards:synthetic
for label, parts in (
    ("area 000", ["000", "12", "3456"]),
    ("area 666", ["666", "12", "3456"]),
    ("group 00", ["123", "00", "3456"]),
    ("serial 0000", ["123", "45", "0000"]),
):
    miss(f"ssn rejected: {label}", "-".join(parts), "US_SSN")
miss("date", "2026-10-20", "US_SSN")
miss("phone-shaped 3-3-4", "415-555-0132", "US_SSN")
miss("ssn glued to a longer id", "x" + ssn, "US_SSN")
miss("ssn inside a longer dashed id", ssn + "-77", "US_SSN")
hit("bare 9 digits after the word ssn", "ssn: " + ssn_bare, "US_SSN", ssn_bare)
hit(
    "bare 9 digits after social security number",
    "Social Security Number " + ssn_bare,
    "US_SSN",
)
miss("bare 9 digits, no context", "pid " + ssn_bare, "US_SSN")

# ------------------------------------------------------------------- passport
hit("passport with keyword", "passport number: 912345678", "US_PASSPORT", "912345678")
hit("passport letter plus 8", "Passport A12345678", "US_PASSPORT", "A12345678")
hit("passport_no=", "passport_no=912345678", "US_PASSPORT", "912345678")
miss("nine digits, no keyword", "id 912345678", "US_PASSPORT")
miss("passport word without a number", "passport control is open", "US_PASSPORT")

# ---------------------------------------------------------------------- phone
for name, t, exp in (
    ("nanp dashed", "call 415-555-0132 tomorrow", "415-555-0132"),
    ("nanp parens", "call (415) 555-0132 now", "(415) 555-0132"),
    ("nanp +1", "call +1 415 555 0132 now", "+1 415 555 0132"),
    ("nanp dotted", "tel 415.555.0132", "415.555.0132"),
    ("uk with plus", "phone +44 7700 900123 ok", "+44 7700 900123"),
    ("compact e164 mid-line", "phone +14155550132 ok", "+14155550132"),
    ("compact e164 non-US", "phone +447700900123 ok", "+447700900123"),
):
    hit(name, t, "PHONE_NUMBER", exp)
for name, t in (
    ("bare 10-digit id", '{"id": 4155550132, "ok": true}'),
    ("epoch seconds", "ts=1760972400"),
    ("epoch milliseconds", "ts 1760972400123"),
    ("offset=", "offset=4155550132 limit=50"),
    ("run id", "run 39437619279"),
    ("diff line adding an epoch", "+1760972400\n-1760972399"),
    ("compact +1 with an invalid area code", "x +10155550132"),
    ("area code starting 0/1", "call 115-555-0132"),
    ("exchange starting 1", "call 415-155-0132"),
    ("version-like", "v1.760.972.4001"),
    ("5 digits", "port 12345"),
    ("decimal", "mem 4155.550.0132"),
    ("sha", "3f786850e387550fdab836ed7e6dc881de23001b"),
):
    miss(f"phone: {name}", t, "PHONE_NUMBER")

# ----------------------------------------------------------------------- IPv4
for name, t, exp in (
    ("public (documentation range)", "from 203.0.113.9 ok", "203.0.113.9"),
    ("private 10/8", "server at 10.11.0.230 answered", "10.11.0.230"),
    ("private 192.168", "ssh deploy@192.168.132.45 uptime", "192.168.132.45"),
    ("private 172.16/12", "gw 172.16.4.1:8080", "172.16.4.1"),
    ("cidr keeps the address only", "allow 192.168.185.192/32", "192.168.185.192"),
):
    hit(f"ip {name}", t, "IP_ADDRESS", exp)
for name, t in (
    ("loopback", "listening on 127.0.0.1:9120"),
    ("loopback range", "bind 127.1.2.3"),
    ("unspecified", "bind 0.0.0.0:8161"),
    ("broadcast", "bcast 255.255.255.255"),
    ("netmask", "mask 255.255.255.0"),
    ("octet over 255", "ver 300.1.1.1"),
    ("leading zero octet", "ver 01.2.3.4"),
    ("five-part version", "v1.2.3.4.5"),
    ("prefixed by a word char", "build10.1.2.3"),
    ("three octets", "1.2.3"),
):
    miss(f"ip: {name}", t, "IP_ADDRESS")

# ---------------------------------------------------------------------- email
for name, t, exp in (
    ("plain", "mail ada.lovelace@example.com now", "ada.lovelace@example.com"),
    (
        ".invalid tld",
        "Author: <pat_doe@sample.example.invalid>",
        "pat_doe@sample.example.invalid",
    ),
    ("example.org", "to a@example.org", "a@example.org"),
    ("plus tag", "to a+tag@mail.example.net.", "a+tag@mail.example.net"),
    (
        "role mailbox is kept",
        "contact: security@example.invalid",
        "security@example.invalid",
    ),
    (
        "github noreply with a handle is kept",
        "12345+alice@users.noreply.github.com",
        "12345+alice@users.noreply.github.com",
    ),
):
    hit(f"email {name}", t, "EMAIL_ADDRESS", exp)
for name, t in (
    ("noreply", "From: noreply@example.invalid"),
    ("no-reply", "From: <No-Reply@example.com>"),
    ("donotreply", "From: donotreply@example.com"),
    ("git ssh remote (scp form)", "origin git@github.com:org/repo.git (fetch)"),
    ("git ssh remote (ssh://)", "url = ssh://git@example.com/org/repo.git"),
    ("retina asset", "background: url(logo@2x.png)"),
    ("npm package at version", "lodash@4.17.21"),
    ("docker digest", "image@sha256:3f786850e387550fdab836ed7e6dc881de23001b"),
    ("scoped package", "import x from '@types/node'"),
    ("no domain dot", "user@localhost"),
):
    miss(f"email: {name}", t, "EMAIL_ADDRESS")

# ----------------------------------------------------------- shape and safety
spans = v.find_pii(f"{gb} and {visa} at 10.0.0.1 or a@example.org")
check(
    "find_pii sorted by start",
    [s.start for s in spans] == sorted(s.start for s in spans),
    str(spans),
)
check(
    "spans are Span tuples with offsets and a score, no text",
    all(len(s) == 4 and 0 < s.score <= 1 for s in spans),
)
check(
    "kinds filter",
    {s.entity_type for s in v.find_pii(f"{visa} a@example.org", ["EMAIL_ADDRESS"])}
    == {"EMAIL_ADDRESS"},
)
check("unknown kind ignored", v.find_pii("a@example.org", ["NOPE"]) == [])
big = ("1" * 40 + " 12 34 " + "9" * 30 + "\n") * 800

t0 = time.perf_counter()
v.find_pii(big)
check("no pathological backtracking on 64 KB of digits", time.perf_counter() - t0 < 2.0)

print(
    f"\n{'FAILED: ' + str(len(failures)) if failures else 'all validator tests passed'}"
)
sys.exit(1 if failures else 0)
