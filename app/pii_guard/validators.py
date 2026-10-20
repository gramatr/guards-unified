"""
Deterministic PII validators: pure standard library, no model, no state.

These replace Presidio's own recognizers for the structured kinds. Presidio
scores a pattern match, so a bare 10-digit id or an epoch timestamp reads as a
phone number and a 9-digit run as a passport. Here a match has to pass the
check the format actually defines (Luhn for cards, mod 97 for IBANs, the issued
ranges for SSNs, a visible phone structure, a parseable IPv4), so engineering
output full of ids and numbers stays silent. Measured on a fabricated corpus in
gramatr/guards-coordination#46.

Every finder returns a list of Span(entity_type, start, end, score) using
Presidio's entity names, so results merge with Presidio's PERSON and LOCATION.
Spans carry offsets and a score, never the matched text.

Decisions on the cases people disagree about (see docs/LIMITS.md):
  * IPv4: loopback (127.0.0.0/8), 0.0.0.0, broadcast and netmasks are skipped;
    private ranges (10/8, 172.16/12, 192.168/16) are still reported, because a
    host address on an internal network is what a leak looks like.
  * Email: no-reply senders (noreply@, no-reply@, donotreply@) and the `git`
    user of an ssh remote (git@github.com:org/repo.git) are skipped, since
    neither names a person. Other role mailboxes (security@, support@) are
    still reported.
"""

import ipaddress
import re
from typing import NamedTuple


class Span(NamedTuple):
    entity_type: str
    start: int
    end: int
    score: float


# Entity types this module produces. engine.py hands everything else to Presidio.
KINDS = (
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "US_PASSPORT",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "EMAIL_ADDRESS",
)

# ---------------------------------------------------------------- credit card


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# (prefix regex, allowed lengths) for an unseparated number. A grouped number
# (4-4-4-4, 4-6-5) is trusted on its shape plus Luhn; a bare run of digits must
# also look like an issuer, because one 16-digit id in ten passes Luhn by chance.
_ISSUERS = (
    (re.compile(r"4"), (13, 16, 19)),  # Visa
    (re.compile(r"5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)"), (16,)),  # Mastercard
    (re.compile(r"3[47]"), (15,)),  # American Express
    (re.compile(r"6011|65|64[4-9]"), (16, 17, 18, 19)),  # Discover
    (re.compile(r"35(?:2[89]|[3-8]\d)"), (16, 17, 18, 19)),  # JCB
)
_CARD_GROUPED = re.compile(r"\d{4}([ -]\d{4}){2,3}(\d{0,3})|\d{4}[ -]\d{6}[ -]\d{5}")
_CARD = re.compile(r"(?<![\w-])(?<!\d\.)(?:\d[ -]?){12,18}\d(?![\w-]|\.\d)")


def cards(text: str) -> list[Span]:
    out = []
    for m in _CARD.finditer(text):
        s = m.group(0)
        d = re.sub(r"[ -]", "", s)
        if not 13 <= len(d) <= 19 or not luhn_ok(d):
            continue
        if re.search(r"[ -]", s):
            if not _CARD_GROUPED.fullmatch(s):
                continue
        elif not any(p.match(d) and len(d) in lens for p, lens in _ISSUERS):
            continue
        out.append(Span("CREDIT_CARD", m.start(), m.end(), 1.0))
    return out


# ----------------------------------------------------------------------- IBAN

IBAN_LEN = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}  # fmt: skip
_IBAN = re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,4}){2,8}(?![\w-])")


def iban_ok(compact: str) -> bool:
    """Country length plus ISO 7064 mod 97-10 on the rearranged number."""
    if IBAN_LEN.get(compact[:2]) != len(compact):
        return False
    return int("".join(str(int(c, 36)) for c in compact[4:] + compact[:4])) % 97 == 1


def ibans(text: str) -> list[Span]:
    out = []
    for m in _IBAN.finditer(text):
        # The pattern is greedy: "IBAN ... 32 DECLINED" also swallows an
        # upper-case word. Try the full match, then drop trailing groups.
        s = m.group(0)
        cuts = [m.end()] + [m.start() + i for i, ch in enumerate(s) if ch == " "][::-1]
        for end in cuts:
            if iban_ok(text[m.start() : end].replace(" ", "")):
                out.append(Span("IBAN_CODE", m.start(), end, 1.0))
                break
    return out


# ------------------------------------------------------------------------ SSN

_SSN = re.compile(r"(?<![\w.-])(\d{3})-(\d{2})-(\d{4})(?![\w-]|\.\d)")
# Nine bare digits only count when the word SSN or "social security" sits right
# before them; nine digits alone are an id.
_SSN_CONTEXT = re.compile(
    r"(?i)(?:\bssn|social[ -]security(?: number| no\.?| #)?)\W{0,4}(\d{9})(?![\w-])"
)


def _ssn_ok(area: str, group: str, serial: str) -> bool:
    # 000, 666, group 00 and serial 0000 are never issued. 9xx areas are kept:
    # they are not SSNs but ITINs (also a taxpayer number worth hiding), and
    # fabricated test data uses them.
    return area not in ("000", "666") and group != "00" and serial != "0000"


def ssns(text: str) -> list[Span]:
    out = []
    for m in _SSN.finditer(text):
        if _ssn_ok(*m.groups()):
            out.append(Span("US_SSN", m.start(), m.end(), 0.85))
    for m in _SSN_CONTEXT.finditer(text):
        d = m.group(1)
        if _ssn_ok(d[:3], d[3:5], d[5:]):
            out.append(Span("US_SSN", m.start(1), m.end(1), 0.85))
    return out


# ------------------------------------------------------------------- passport

# A US passport number is nine digits (or a letter and eight): without a keyword
# it is any id, so it is reported only straight after the word "passport".
_PASSPORT = re.compile(
    r"(?i)\bpassport(?:[ _-]?(?:no\.?|num(?:ber)?|#|id))?\W{0,4}([A-Z]?\d{8,9})(?![\w-])"
)


def passports(text: str) -> list[Span]:
    return [Span("US_PASSPORT", m.start(1), m.end(1), 0.85) for m in _PASSPORT.finditer(text)]


# ---------------------------------------------------------------------- phone

# North America: area code and exchange start 2-9, and the number must show
# structure (parentheses, or separators between the groups). Ten bare digits are
# a JSON id or an epoch, not a phone number.
_NANP = re.compile(
    r"(?<![\w.+-])(?<!\d\.)(?:\+1[ .-]?)?"
    r"(?:\(([2-9]\d\d)\)[ .-]?|([2-9]\d\d)[ .-])([2-9]\d\d)[ .-](\d{4})(?![\w-]|\.\d)"
)
# International with separators: +CC then 2-4 groups of 2-6 digits.
_INTL = re.compile(r"(?<![\w.+-])\+(?!1[ .-]?\d)([1-9]\d{0,2})(?:[ .-]\d{2,6}){2,4}(?![\w-]|\.\d)")
# Compact E.164 (+14155550132). Not at the start of a line, where "+" is a diff
# marker and the digits an epoch or an id.
_E164 = re.compile(r"(?<=[^\n\w.+-])\+([1-9]\d{7,14})(?![\w-]|\.\d)")


def phones(text: str) -> list[Span]:
    out = []
    for m in _NANP.finditer(text):
        out.append(Span("PHONE_NUMBER", m.start(), m.end(), 0.85))
    for m in _INTL.finditer(text):
        if 8 <= len(re.sub(r"\D", "", m.group(0))) <= 15:
            out.append(Span("PHONE_NUMBER", m.start(), m.end(), 0.85))
    for m in _E164.finditer(text):
        d = m.group(1)
        # +1 numbers are NANP: 10 digits after the 1, area and exchange 2-9.
        if d[0] == "1" and not re.fullmatch(r"1[2-9]\d\d[2-9]\d{6}", d):
            continue
        out.append(Span("PHONE_NUMBER", m.start(), m.end(), 0.8))
    return out


# ----------------------------------------------------------------------- IPv4

_IP = re.compile(r"(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}(?![\w-]|\.\d)")


def _is_netmask(a: ipaddress.IPv4Address) -> bool:
    n = int(a)
    inv = (~n) & 0xFFFFFFFF
    return n != 0 and (inv & (inv + 1)) == 0  # ones followed by zeros


def ips(text: str) -> list[Span]:
    out = []
    for m in _IP.finditer(text):
        try:
            a = ipaddress.IPv4Address(m.group(0))
        except ValueError:  # octet over 255, leading zero
            continue
        if a.is_loopback or a.is_unspecified or a == ipaddress.IPv4Address("255.255.255.255"):
            continue
        if _is_netmask(a):
            continue
        out.append(Span("IP_ADDRESS", m.start(), m.end(), 0.85))
    return out


# ---------------------------------------------------------------------- email

_EMAIL = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![\w-])"
)
_NO_REPLY = re.compile(r"(?i)(?:no[-_.]?reply|do[-_.]?not[-_.]?reply)")
_RETINA_FILE = re.compile(r"(?i)\d+x\.(?:png|jpe?g|gif|webp|svg|avif)")


def emails(text: str) -> list[Span]:
    out = []
    for m in _EMAIL.finditer(text):
        local, domain = m.group(1), m.group(2)
        if _NO_REPLY.fullmatch(local):
            continue  # an automated sender, not a person
        if local.lower() == "git":
            continue  # the user of an ssh remote: git@host:org/repo.git
        if _RETINA_FILE.fullmatch(domain):
            continue  # logo@2x.png
        out.append(Span("EMAIL_ADDRESS", m.start(), m.end(), 0.9))
    return out


# --------------------------------------------------------------------- driver

_FINDERS = {
    "CREDIT_CARD": cards,
    "IBAN_CODE": ibans,
    "US_SSN": ssns,
    "US_PASSPORT": passports,
    "PHONE_NUMBER": phones,
    "IP_ADDRESS": ips,
    "EMAIL_ADDRESS": emails,
}


def find_pii(text: str, kinds=KINDS) -> list[Span]:
    """All validator findings for the requested entity types, sorted by start.
    Overlaps between kinds are possible here; engine.merge_spans resolves them."""
    out: list[Span] = []
    for k in kinds:
        finder = _FINDERS.get(k)
        if finder:
            out.extend(finder(text))
    return sorted(out, key=lambda s: (s.start, s.end))
