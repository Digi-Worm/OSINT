"""Selector auto-detection and safe normalisation."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

try:  # phonenumbers is an optional import for lightweight tooling use.
    import phonenumbers
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    phonenumbers = None

from .models import SELECTOR_TYPES, Detection

EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")
HASH_RE = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9_\u0080-\uffff](?:[A-Za-z0-9_\-.\u0080-\uffff]*[A-Za-z0-9_\u0080-\uffff])?)$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
BTC_RE = re.compile(r"^(?:bc1[a-z0-9]{20,87}|[13][1-9A-HJ-NP-Za-km-z]{24,39})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _candidate(kind: str, confidence: float, reason: str) -> Dict[str, Any]:
    return {"type": kind, "confidence": round(confidence, 2), "reason": reason}


def _normalise_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def _phone_like(value: str) -> bool:
    if len(value) > 32 or not re.fullmatch(r"[+()\-\.\s\d]+", value):
        return False
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15


def normalize_selector(value: str, selector_type: str = "auto") -> str:
    """Return a stable representation suitable for task de-duplication."""

    text = value.strip()
    if selector_type == "email" or (selector_type == "auto" and "@" in text):
        return text.lower()
    if selector_type in {"domain", "url"}:
        if selector_type == "url" or "://" in text:
            parts = urlsplit(text if "://" in text else f"https://{text}")
            if parts.hostname:
                return text if selector_type == "url" else _normalise_domain(parts.hostname)
        return _normalise_domain(text)
    if selector_type == "crypto":
        return text.lower() if text.startswith(("0x", "bc1")) else text
    if selector_type == "hash":
        return text.lower()
    return re.sub(r"\s+", " ", text)


def detect_selector(value: str, default_region: Optional[str] = None) -> Detection:
    """Detect one of DigiScope's supported selector types.

    Detection is deliberately deterministic and explainable.  The UI shows
    the top result and the candidate list can be used by an API client to
    offer a manual override when an input is ambiguous (for example a short
    numeric username versus a phone number).
    """

    raw = value.strip()
    candidates: List[Dict[str, Any]] = []
    if not raw:
        return Detection("person", 0.0, "", "Enter a selector to begin", [])

    # URL must precede hostname detection.  Only web URLs are accepted by the
    # active URL module; mailto and javascript strings are not treated as URLs.
    parts = urlsplit(raw)
    if parts.scheme.lower() in {"http", "https"} and parts.netloc and parts.hostname:
        candidates.append(_candidate("url", 0.99, "HTTP(S) scheme and host detected"))
        return Detection("url", 0.99, raw, "HTTP(S) URL", candidates)

    if EMAIL_RE.fullmatch(raw):
        candidates.append(_candidate("email", 0.99, "Single RFC-style address with a domain"))
        return Detection("email", 0.99, raw.lower(), "Email address", candidates)

    try:
        ipaddress.ip_address(raw.strip("[]"))
    except ValueError:
        pass
    else:
        candidates.append(_candidate("ip", 1.0, "Valid IPv4/IPv6 literal"))
        return Detection("ip", 1.0, raw.strip("[]"), "IP address", candidates)

    if ETH_RE.fullmatch(raw) or BTC_RE.fullmatch(raw):
        candidates.append(_candidate("crypto", 0.98, "Recognised Ethereum or Bitcoin address shape"))
        return Detection("crypto", 0.98, raw.lower() if raw.startswith(("0x", "bc1")) else raw, "Cryptocurrency address", candidates)

    if len(raw) in {32, 40, 64, 128} and HASH_RE.fullmatch(raw):
        algorithm = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}[len(raw)]
        candidates.append(_candidate("hash", 0.99, f"{algorithm} hexadecimal digest length"))
        return Detection("hash", 0.99, raw.lower(), f"{algorithm} hash", candidates)

    # A phone library check improves confidence for international numbers but
    # never makes the detector depend on a region being configured.
    if _phone_like(raw):
        phone_confidence = 0.72
        reason = "Phone-shaped digit string"
        if phonenumbers is not None:
            try:
                parsed = phonenumbers.parse(raw, default_region or None)
                if phonenumbers.is_possible_number(parsed):
                    phone_confidence = 0.9 if phonenumbers.is_valid_number(parsed) else 0.78
                    reason = "Recognised by the offline libphonenumber metadata"
            except phonenumbers.NumberParseException:
                pass
        candidates.append(_candidate("phone", phone_confidence, reason))
        return Detection("phone", phone_confidence, raw, "Phone number", candidates)

    # Domain/hostname.  A dot is required for auto-detection to avoid turning
    # ordinary names into network lookups.  The manual override still permits
    # a local hostname for authorised lab environments.
    domain_value = raw.rstrip(".")
    labels = domain_value.split(".")
    if len(labels) >= 2 and DOMAIN_RE.fullmatch(domain_value):
        candidates.append(_candidate("domain", 0.94, "Hostname-shaped value with a DNS suffix"))
        return Detection("domain", 0.94, _normalise_domain(domain_value), "Domain or hostname", candidates)

    if USERNAME_RE.fullmatch(raw) and not raw.isdigit():
        candidates.append(_candidate("username", 0.68, "Handle-shaped value without whitespace"))
        return Detection("username", 0.68, raw, "Username or handle", candidates)

    words = [word for word in re.split(r"\s+", raw) if word]
    if len(words) >= 2 and all(re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ'’-]+", word) for word in words):
        candidates.append(_candidate("person", 0.76, "Multiple name-like words"))
        return Detection("person", 0.76, " ".join(words), "Person name / investigation plan", candidates)

    candidates.append(_candidate("person", 0.3, "Fallback for free text; use a manual type for unusual selectors"))
    return Detection("person", 0.3, raw, "Free text", candidates)


def detect_type(value: str, default_region: Optional[str] = None) -> str:
    """Compatibility helper used by small integrations and tests."""

    return detect_selector(value, default_region).type


def validate_selector_type(selector_type: str) -> bool:
    return selector_type == "auto" or selector_type in SELECTOR_TYPES


__all__ = [
    "detect_selector",
    "detect_type",
    "normalize_selector",
    "validate_selector_type",
]
