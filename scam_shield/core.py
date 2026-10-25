"""Explainable scam detection for messages and call transcripts, plus family safe words."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

__all__ = ["Signal", "Verdict", "analyze", "lookalike", "hash_safeword", "verify_safeword", "BRANDS"]

BRANDS = [
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "irs",
    "ssa",
    "fedex",
    "ups",
    "usps",
    "dhl",
    "coinbase",
    "venmo",
    "zelle",
    "facebook",
    "instagram",
]
TWO_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "co.nz",
    "co.jp",
    "com.br",
    "co.in",
    "com.mx",
    "co.za",
}
ZERO_WIDTH = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"))
QUOTES = str.maketrans({"\u2018": "'", "\u2019": "'", "\u02bc": "'", "\u201c": '"', "\u201d": '"'})


def _normalise(text: str) -> str:
    """Undo the cheap evasions: fullwidth/compat letters, zero-width splits, curly quotes (phones type them)."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).translate(QUOTES).casefold()


SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}

RULES = [
    ("urgency", 15, r"\b(act now|immediately|urgent|within 24 hours|right away|final notice|expires today|asap)\b"),
    ("secrecy", 20, r"\b(don'?t tell|keep this between us|do not tell|don'?t call (mom|dad|anyone)|keep it secret)\b"),
    ("gift_cards", 30, r"\b(gift ?cards?|itunes card|google play card|steam card)\b"),
    (
        "untraceable_payment",
        25,
        r"\b(wire (the )?money|western union|moneygram|bitcoin|crypto|usdt|zelle|cash app|courier will pick up)\b",
    ),
    (
        "family_emergency",
        25,
        r"\b(it'?s me,? (grandma|grandpa|mom|dad)|grandma,? it'?s me|i'?m in jail|bail money|i had an accident|i'?m in trouble|this is my new number)\b",
    ),
    (
        "authority",
        20,
        r"\b(irs|social security|warrant for your arrest|police department|fraud department|tax debt|medicare)\b",
    ),
    (
        "credential_request",
        25,
        r"\b(verify your (account|identity)|confirm your password|read me the code|one[- ]time code|send me the code|login details|ssn)\b",
    ),
    ("prize", 15, r"\b(you('ve| have)? won|lottery|claim your prize|inheritance|beneficiary)\b"),
    ("refund_lure", 10, r"\b(refund|overpaid|unauthorized charge|suspicious activity on your account)\b"),
]
ADVICE = {
    "family_emergency": "Hang up and call the family member back on the number you already have. Ask for the family safe word.",
    "gift_cards": "No real company, government agency or relative in trouble asks to be paid in gift cards.",
    "untraceable_payment": "Don't send wire transfers, crypto or cash to someone you only know from this message.",
    "authority": "Government agencies don't threaten arrest by phone or text. Call the agency using its official website number.",
    "credential_request": "Never share passwords or one-time codes. Your bank will never ask for them.",
    "lookalike_domain": "The sender's address imitates a real brand. Don't click links; go to the official site directly.",
    "link_mismatch": "The link goes somewhere other than what it says. Don't click it.",
}


@dataclass
class Signal:
    name: str
    weight: int
    evidence: str


@dataclass
class Verdict:
    score: int
    label: str
    signals: list = field(default_factory=list)
    advice: list = field(default_factory=list)


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})


def lookalike(domain: str) -> str | None:
    """Return the brand a domain imitates, or None if it is the brand itself / unrelated."""
    domain = domain.lower().strip(".")
    if domain.startswith("xn--") or ".xn--" in domain or not domain.isascii():
        return "punycode"  # unicode homoglyphs (Cyrillic a in apple) whether or not they were encoded
    parts = domain.split(".")
    reg = 3 if ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES else 2  # amazon.co.uk -> label "amazon"
    label = parts[-reg] if len(parts) >= reg else parts[0]
    subdomains = parts[:-reg] if len(parts) > reg else []
    if label not in BRANDS:
        for sub in subdomains:  # paypal.com.secure-login.ru
            if sub.replace("-", "") in BRANDS:
                return sub.replace("-", "")
    normalised = label.translate(HOMOGLYPHS).replace("rn", "m").replace("-", "")
    for brand in BRANDS:
        if label == brand:
            return None
        if normalised == brand or (len(brand) >= 5 and _lev(normalised, brand) == 1):
            return brand
        if brand in label and label != brand:  # paypal-security, amazon-refunds
            return brand
    return None


LINK_RE = re.compile(
    r"\[([^\]]+)\]\((https?://[^)\s]+)\)|<a [^>]*href=[\"'](https?://[^\"']+)[\"'][^>]*>([^<]+)</a>|(https?://[^\s)>\"']+)",
    re.I,
)


def _links(text):
    for m in LINK_RE.finditer(text):
        if m.group(2):
            yield m.group(1), m.group(2)
        elif m.group(3):
            yield m.group(4), m.group(3)
        else:
            yield None, m.group(5)


def analyze(text: str, sender: str | None = None) -> Verdict:
    signals = []
    low = _normalise(text)
    for name, w, pattern in RULES:
        m = re.search(pattern, low)
        if m:
            signals.append(Signal(name, w, m.group(0)))
    if sender and "@" in sender:
        brand = lookalike(sender.split("@", 1)[1])
        if brand:
            signals.append(Signal("lookalike_domain", 35, f"{sender} imitates {brand}"))
    for shown, url in _links(text):
        host = (urlparse(url).hostname or "").lower()
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or ":" in host:  # IPv4, or IPv6 (only literals have a colon)
            signals.append(Signal("raw_ip_link", 20, url))
        if host in SHORTENERS:
            signals.append(Signal("shortened_link", 10, url))
        brand = lookalike(host)
        if brand:
            signals.append(Signal("lookalike_domain", 35, f"{host} imitates {brand}"))
        if shown and re.search(r"[\w-]+\.[a-z]{2,}", shown.lower()):
            shown_host = re.search(r"[\w.-]+\.[a-z]{2,}", shown.lower()).group(0)
            shown_host = shown_host.removeprefix("www.")
            if host != shown_host and not host.endswith("." + shown_host):  # evilpaypal.com is not paypal.com
                signals.append(Signal("link_mismatch", 30, f"shows {shown_host}, goes to {host}"))
    # dedupe by name, keep strongest
    best = {}
    for s in signals:
        if s.name not in best or s.weight > best[s.name].weight:
            best[s.name] = s
    signals = sorted(best.values(), key=lambda s: -s.weight)
    score = min(100, sum(s.weight for s in signals))
    if len(signals) >= 3:
        score = min(100, score + 10)  # combos of tactics are a strong tell
    label = "likely scam" if score >= 50 else "suspicious" if score >= 20 else "safe"
    advice = [ADVICE[s.name] for s in signals if s.name in ADVICE]
    if label != "safe" and not advice:
        advice.append("Don't reply or click. Contact the company or person through a channel you already trust.")
    return Verdict(score, label, signals, advice)


def hash_safeword(word: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", word.strip().lower().encode(), salt, 200_000)
    return salt.hex() + ":" + digest.hex()


def verify_safeword(word: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split(":")
    candidate = hash_safeword(word, bytes.fromhex(salt_hex)).split(":")[1]
    return hmac.compare_digest(candidate, digest_hex)
