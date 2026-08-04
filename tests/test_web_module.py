import pytest

from digiscope.modules.base import ScanContext
from digiscope.modules.web import run_web


@pytest.mark.asyncio
async def test_authorized_web_mapper_is_opt_in():
    context = ScanContext(fetcher=None, dns=None, options={"authorized_asset_crawl": False}, selector_type="web")
    result = await run_web(context, "example.org")
    assert result.status == "partial"
    assert "disabled" in result.notes[0].lower()
