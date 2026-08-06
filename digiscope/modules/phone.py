"""Offline phone intelligence with optional Numverify enrichment."""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import quote

from ..models import Section
from .base import ScanContext, add_entity, add_failure, add_finding, add_link, new_result, register

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    phonenumbers = None


def _phone_type(number: Any) -> str:
    if phonenumbers is None:
        return "unknown"
    try:
        return phonenumbers.PhoneNumberType.to_string(phonenumbers.number_type(number)).replace("_", " ").title()
    except (AttributeError, TypeError, ValueError):
        return "unknown"


async def _numverify(ctx: ScanContext, raw: str) -> Dict[str, Any]:
    key = ctx.api_key("numverify_api_key")
    if not key:
        return {"skipped": True, "error": "optional Numverify API key not configured"}
    response = await ctx.fetcher.get_json(
        "https://apilayer.net/api/validate",
        params={"access_key": key, "number": raw, "format": "1"},
        source="Numverify",
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    return {"ok": True, **response.data}


@register(
    "phone",
    "Phone intelligence",
    "Offline libphonenumber validation, canonical formats, carrier/region/timezone metadata and optional Numverify.",
    category="identity",
    sources=["libphonenumber offline metadata", "Numverify (key)", "analyst search links"],
)
async def run_phone(ctx: ScanContext, target: str) -> Any:
    result = new_result("phone", target)
    if phonenumbers is None:
        result.status = "error"
        result.error = "phonenumbers dependency is not installed"
        return result
    region = str(ctx.key("phone_region", "US") or "US").upper()
    if region == "AUTO":
        region = None
    try:
        number = phonenumbers.parse(target, region)
    except phonenumbers.NumberParseException as exc:
        result.status = "error"
        result.error = f"Could not parse phone number: {exc}"
        return result

    valid = phonenumbers.is_valid_number(number)
    possible = phonenumbers.is_possible_number(number)
    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    international = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)
    rfc3966 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.RFC3966)
    region_code = phonenumbers.region_code_for_number(number) or "Unknown"
    timezones = list(timezone.time_zones_for_number(number))
    network = carrier.name_for_number(number, "") or "Unknown / unavailable"
    location = geocoder.description_for_number(number, "en") or "Unknown / unavailable"
    values = {
        "input": target,
        "possible": possible,
        "valid": valid,
        "number_type": _phone_type(number),
        "country_code": f"+{number.country_code}",
        "region": region_code,
        "location_hint": location,
        "carrier_hint": network,
        "timezones": timezones,
        "E.164": e164,
        "International": international,
        "National": national,
        "RFC 3966": rfc3966,
    }
    result.sections.append(Section("Offline parse", "kv", values, "libphonenumber metadata is offline and does not prove subscriber identity."))
    add_entity(result, "phone", e164, "libphonenumber", pivot=False, label="Canonical E.164 number")
    if not possible:
        add_finding(result, "Number is not possible", "medium", 8, "The digit pattern is not possible for the selected region metadata.", "libphonenumber")
    elif not valid:
        add_finding(result, "Number is possible but not currently valid", "low", 3, "The number shape is possible but failed validity metadata checks.", "libphonenumber")

    numverify = await _numverify(ctx, target)
    if numverify.get("skipped"):
        result.notes.append("Numverify skipped: supply a per-scan API key for optional carrier validation.")
    elif numverify.get("ok"):
        result.sections.append(Section("Numverify", "kv", {key: value for key, value in numverify.items() if key != "ok"}, "Optional keyed source; key is not persisted."))
    else:
        add_failure(result, "Numverify", numverify.get("error", "unavailable"))

    encoded = quote(e164, safe="+")
    exact_query = quote('"' + e164 + '"', safe="")
    add_link(result, "Google exact-number search", "https://www.google.com/search?q=" + exact_query, "search", "Google")
    add_link(result, "Bing exact-number search", "https://www.bing.com/search?q=" + exact_query, "search", "Bing")
    add_link(result, "Truecaller lookup", f"https://www.truecaller.com/search/{encoded}", "lookup", "Truecaller")
    add_link(result, "Tellows lookup", f"https://www.tellows.com/num/{encoded}", "reputation", "Tellows")
    result.coverage.update({"offline": True, "optional_numverify": not numverify.get("skipped", False)})
    return result


__all__ = ["run_phone"]
