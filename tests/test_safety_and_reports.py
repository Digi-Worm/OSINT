from digiscope.engine import make_job
from digiscope.network import AsyncFetcher
from digiscope.reports import as_csv, as_html, as_json, as_markdown


def test_safe_fetcher_rejects_private_and_credential_urls():
    fetcher = AsyncFetcher(safe_mode=True)
    assert fetcher._validate_url("http://127.0.0.1:8000")
    assert fetcher._validate_url("http://localhost/admin")
    assert fetcher._validate_url("https://user:pass@example.org")
    assert fetcher._validate_url("ftp://example.org")
    assert fetcher._validate_url("https://example.org") is None


def test_report_renderers_are_nonempty_and_redact_keys():
    job = make_job("example.org", options={"modules": [], "hibp_api_key": "secret-value"})
    payload = as_json(job)
    assert "secret-value" not in payload
    assert "••••••••" in payload
    assert "record_type" in as_csv(job)
    assert "DigiScope investigation report" in as_markdown(job)
    assert "DigiScope investigation report" in as_html(job)
