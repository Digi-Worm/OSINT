"""DNS lookups with UDP-first and DNS-over-HTTPS fallback."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

try:
    import dns.asyncresolver
    import dns.exception
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    dns = None  # type: ignore[assignment]

from .network import AsyncFetcher

DOH_URL = "https://dns.google/resolve"
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "DS")
TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
    "DS": 43,
}


@dataclass
class DNSAnswer:
    name: str
    record_type: str
    values: List[str] = field(default_factory=list)
    ok: bool = False
    source: str = ""
    dnssec: bool = False
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.record_type,
            "values": self.values,
            "ok": self.ok,
            "source": self.source,
            "dnssec": self.dnssec,
            "error": self.error,
        }


class DNSClient:
    def __init__(self, fetcher: AsyncFetcher, timeout: float = 4.0) -> None:
        self.fetcher = fetcher
        self.timeout = max(1.0, min(float(timeout), 10.0))
        self._resolver = None
        if dns is not None:
            try:
                self._resolver = dns.asyncresolver.Resolver(configure=True)
                self._resolver.timeout = self.timeout
                self._resolver.lifetime = self.timeout
            except Exception:  # pragma: no cover
                self._resolver = None

    @staticmethod
    def _clean_rdata(record_type: str, value: str) -> str:
        text = value.strip()
        if record_type == "MX":
            parts = text.split()
            return parts[-1].rstrip(".") if parts else text
        if record_type == "TXT":
            # dnspython emits one or more quoted chunks.  Keeping the text
            # readable is more useful in the dashboard than the wire syntax.
            text = re.sub(r'"\s+"', "", text)
            return text.replace('"', "")
        if record_type in {"NS", "CNAME"}:
            return text.rstrip(".")
        return text

    async def _udp_query(self, name: str, record_type: str) -> DNSAnswer:
        answer = DNSAnswer(name, record_type, source="DNS/UDP")
        if self._resolver is None:
            answer.error = "dnspython unavailable"
            return answer
        try:
            response = await self._resolver.resolve(name, record_type, raise_on_no_answer=False)
            answer.values = [self._clean_rdata(record_type, rdata.to_text()) for rdata in response]
            answer.ok = True
            return answer
        except Exception as exc:
            answer.error = f"{type(exc).__name__}: {str(exc)[:180]}"
            return answer

    async def _doh_query(self, name: str, record_type: str) -> DNSAnswer:
        answer = DNSAnswer(name, record_type, source="Google Public DNS DoH")
        response = await self.fetcher.get_json(
            DOH_URL,
            params={"name": name, "type": record_type, "do": "1"},
            source="dns.google",
        )
        if not response.ok or not isinstance(response.data, dict):
            answer.error = response.error or f"HTTP {response.status}"
            return answer
        answer.dnssec = bool(response.data.get("AD"))
        status = response.data.get("Status", 0)
        if status not in (0, None):
            answer.error = f"DNS response status {status}"
            answer.ok = status == 3  # NXDOMAIN is a valid negative answer.
            return answer
        wanted = TYPE_CODES.get(record_type)
        for item in response.data.get("Answer", []) or []:
            if not isinstance(item, dict):
                continue
            if wanted is not None and item.get("type") != wanted:
                continue
            value = item.get("data")
            if isinstance(value, str):
                answer.values.append(self._clean_rdata(record_type, value))
        answer.ok = True
        return answer

    async def query(self, name: str, record_type: str) -> DNSAnswer:
        record_type = record_type.upper()
        if record_type not in DNS_TYPES:
            return DNSAnswer(name, record_type, error="unsupported record type")
        udp = await self._udp_query(name, record_type)
        if udp.ok:
            return udp
        doh = await self._doh_query(name, record_type)
        if doh.ok:
            return doh
        # Preserve both failure clues without exposing a large exception.
        doh.error = "; ".join(part for part in (udp.error, doh.error) if part)[:300]
        return doh

    async def query_many(self, name: str, record_types: List[str]) -> List[DNSAnswer]:
        return list(await asyncio.gather(*(self.query(name, record_type) for record_type in record_types)))


__all__ = ["DNSAnswer", "DNSClient", "DNS_TYPES"]
