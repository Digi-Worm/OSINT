import pytest

from digiscope.dns import DNSAnswer
from digiscope.modules.base import ScanContext
from digiscope.modules.domain import _dns_wordlist_enumeration


class FakeDNS:
    async def query_many(self, name, record_types):
        values = ["192.0.2.10"] if name == "api.example.org" else []
        return [DNSAnswer(name, record_type, values=values if record_type == "A" else [], ok=True, source="fake") for record_type in record_types]


@pytest.mark.asyncio
async def test_dns_wordlist_enumeration_is_bounded_and_opt_in():
    context = ScanContext(
        fetcher=None,
        dns=FakeDNS(),
        options={"authorized_dns_enum": True, "dns_wordlist": "api\ndev\nnot-valid!", "dns_enum_max": 100, "dns_enum_delay_ms": 50, "concurrency": 2},
        selector_type="domain",
    )
    result = await _dns_wordlist_enumeration(context, "example.org", {"addresses": []})
    assert result["enabled"] is True
    assert result["checked"] == 2
    assert result["found"][0]["hostname"] == "api.example.org"
