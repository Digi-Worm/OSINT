# DigiScope

DigiScope is a standalone, browser-first OSINT dashboard for **passive, public-source research**. Paste one selector — email, domain, IP, URL, phone number, username, person name, file hash or Bitcoin/Ethereum address — and it detects the input, runs the matching module, follows bounded typed pivots, de-duplicates the result into an entity graph, and makes the evidence exportable.

> **Responsible use:** DigiScope is for authorised security testing, own-footprint review, threat intelligence, journalism and research. Do not use it for stalking, harassment, doxxing, credential discovery, unlawful surveillance or targeting people without a lawful basis. Person-name mode is a lead-generation plan and does not claim to resolve identity.

## What is included

| Module | Key capabilities | Free/public sources |
|---|---|---|
| Domain | A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/DS, SPF/DMARC/DKIM selector checks, MTA-STS, DNSSEC signal, HTTP headers/title/technology hints, RDAP, CT names/issuers, Wayback and an explicit authorized same-host web-surface map | Google Public DNS DoH, rdap.org, crt.sh, Internet Archive, target HTTP(S), target robots/sitemaps |
| IP | Reverse DNS, approximate geolocation/network, RIR allocation and abuse contacts, ASN/routing context, historical services/CVEs/CPEs | system DNS, ip-api.com, rdap.org, BGPView, Shodan InternetDB; full Shodan host data with an optional key |
| Email | Syntax/role/disposable heuristics, MX, Gravatar hash/profile, public GitHub commit-email metadata, optional breach lookup | offline parser, DNS, Gravatar, GitHub; HIBP with a user-supplied key |
| Username | Concurrent heuristic presence checks using a validated Sherlock-compatible public catalogue with bundled fallback, coverage counts, GitHub profile/repos/blog/social enrichment | public profile URLs, public catalogue JSON, GitHub API |
| Phone | Offline validity/possibility, carrier/region/timezone hints, E.164/international/national/RFC3966 formats, curated lookup links | libphonenumber metadata; Numverify optional |
| Person | Dork/search plan for general, social, professional, image, documents and public-sector queries; bounded public-index discovery; probable handle permutations | Google/Bing/DuckDuckGo links, Wikipedia, Wikidata, OpenAlex, Crossref, GitHub API, LinkedIn and image search |
| Company | Public organization indexes, GitHub organizations/public members, structured website metadata, map/professional/registry links and ownership-verification plan | Wikipedia, Wikidata, OpenAlex, GitHub API, Google Maps, Bing Maps, LinkedIn, OpenCorporates links |
| URL | Scheme/host/path/query-key breakdown, bounded five-hop redirect chain, status/title/headers, host pivot | target HTTP(S) |
| Hash | MD5/SHA-1/SHA-256/SHA-512 identification, optional VirusTotal, MalwareBazaar and analyst pivots | offline checks, MalwareBazaar, VirusTotal optional key |
| Crypto | Bitcoin balance/transaction context, optional Ethereum dashboard, explorer links | Blockchain.com, Blockchair, Etherscan |

All modules return the same structured contract: renderable sections, entities, links, findings, notes, coverage and timeline events. A failed provider becomes a `partial` note; it never aborts the investigation.

## Quick start

### From source

Python 3.9+ is supported; Python 3.11 is recommended.

```bash
python -m venv .venv
. .venv/bin/activate             # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:8000>. The server binds to `0.0.0.0:8000` by default so it also works in a container or preview environment. Set `DIGISCOPE_HOST`, `DIGISCOPE_PORT` and `DIGISCOPE_LOG_LEVEL` in `.env` or the environment.

The equivalent entry points are:

```bash
python -m digiscope
# after pip install -e .
digiscope
```

### Docker

```bash
cp .env.example .env
docker compose up --build
```

The image runs as a non-root user, is read-only at runtime, has a healthcheck, and stores no database.

## Dashboard controls

* Auto-detection shows a confidence score and reason; the selector type can be overridden.
* Module chips let the analyst enable/disable each source family. Username scans can refresh a public Sherlock-compatible rule catalogue (GET-only, NSFW/non-GET rules excluded) or use DigiScope's bundled fallback, with a per-scan site budget.
* Auto-pivot, BFS pivot depth (`0–3`), bounded concurrency, per-source timeout and CT-name cap are per-scan controls.
* Safe/passive mode is on by default. It blocks literal/private/local destinations and DigiScope never performs active port scans, internet-wide scanning or hidden-service crawling. An explicit **Authorized same-host crawl** opt-in is available for assets you own: it obeys robots when available, uses GET only, stays on one host, skips forms/binaries/query strings, enforces a page/depth/delay budget, and stores metadata rather than page bodies. This mapper is self-hosted and keyless.
* Phone region and person context are local scan options. Person mode can query bounded public knowledge indexes (Wikipedia, Wikidata, OpenAlex, Crossref and GitHub) as candidate-only leads; it never automatically merges or resolves a person identity.
* HIBP, Shodan, AbuseIPDB, VirusTotal, GitHub, Numverify, Google Programmable Search and Bing Web Search keys are accepted per scan, kept in memory only, redacted from API responses/reports, and never written to disk. Google/Bing use official APIs rather than scraping search-result pages.
* Results are available as Overview, Modules, a drag/zoom/click entity graph, Timeline, analyst Links and Raw JSON.
* JSON, CSV, Markdown and self-contained HTML exports are generated server-side.

## REST API

FastAPI's interactive documentation is at `/docs` and `/redoc`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/meta` | Module catalogue, supported types and safe defaults |
| `GET` | `/api/detect?q=...` | Detect selector type, confidence, normalised value and reason |
| `POST` | `/api/scan` | Start a scan; body is `{ "input": "...", "type": "auto", "options": {...} }` |
| `GET` | `/api/scan/{id}` | Poll status/progress or read the full correlated result |
| `GET` | `/api/scan/{id}/export?format=json\|csv\|md\|html` | Download a report |
| `GET` | `/api/history` | In-memory scan history summaries |
| `GET` | `/api/health` | Liveness and loaded module count |

Example:

```bash
curl 'http://127.0.0.1:8000/api/detect?q=8.8.8.8'
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'content-type: application/json' \
  -d '{"input":"example.org","type":"auto","options":{"safe_mode":true,"pivot_depth":1}}'
curl http://127.0.0.1:8000/api/scan/<id>
curl -OJ 'http://127.0.0.1:8000/api/scan/<id>/export?format=html'
```

Options are clamped server-side. `modules: null` means all modules are available to matching root/pivot tasks; an explicit list restricts execution. The API is asynchronous because public providers have different latency and rate limits.

## Architecture

```text
FastAPI / static dashboard
        │
        ├── detector → normalised selector + confidence
        ├── ScanEngine → bounded BFS waves / task de-duplication
        │       ├── module registry (one self-registering file per type)
        │       ├── shared AsyncFetcher (HTTP/1.1 TLS ALPN, timeout, SSRF guard)
        │       └── DNSClient (dnspython UDP → Google DoH fallback)
        ├── correlation → entities, graph edges, findings, timeline, coverage
        └── report renderers → JSON / CSV / Markdown / HTML
```

The application has no database. A bounded in-memory job/history store is suitable for a local analyst console. The registry and result contract make it straightforward to add a provider without changing the UI. Source keys are never part of the result model except as redacted presence markers.

### Network and safety design

* `httpx.AsyncClient` is shared per scan with TLS verification, `http2=False`, explicit `http/1.1` ALPN and a browser-like user agent.
* Every source call returns a structured response; exceptions are converted into source notes.
* Safe mode rejects private, loopback, link-local, multicast, reserved, unspecified, `.local`, `.internal` and embedded-credential URLs. Literal IP validation is strict.
* DNS uses dnspython first and `https://dns.google/resolve` JSON DoH as a fallback when UDP/53 is unavailable. Discovered passive names can be bounded-resolved to A/AAAA records, and a random-label wildcard-DNS probe is shown separately so wildcard answers are not mistaken for unique hosts.
* Shodan InternetDB is an existing public snapshot. DigiScope does not probe ports, brute-force credentials, evade access controls, scrape search engines, or crawl sites.
* Username presence is heuristic. HTTP 200 is reported as a lead and is not evidence of identity; rate-limited/blocked checks are shown as inconclusive.

## Research references

The public interfaces and data semantics used during implementation are based on the providers' public documentation and standards:

* [SpiderFoot](https://github.com/smicallef/spiderfoot), [OWASP Amass](https://github.com/owasp-amass/amass) and [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) informed the registry/event, passive-source, provenance, wildcard-elimination and bounded asset-mapping design. DigiScope reimplements selected passive ideas rather than shelling out to those projects.
* [Sherlock](https://github.com/sherlock-project/sherlock) and [Maigret](https://github.com/soxoj/maigret) informed the maintained username catalogue, site-specific missing-page rules, format validation, coverage counts and false-positive warnings. DigiScope excludes NSFW/non-GET rules and uses a bundled fallback.
* [RDAP.org](https://about.rdap.org/) and [RFC 9082/9083](https://datatracker.ietf.org/doc/rfc9083/) for machine-readable registration data.
* [Google Public DNS JSON DoH](https://developers.google.com/speed/public-dns/docs/doh/json) for record and DNSSEC-aware fallback queries.
* [Shodan InternetDB](https://internetdb.shodan.io/) for a keyless, passive IP snapshot of ports, CPEs, hostnames, tags and CVE identifiers.
* [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962), the public [crt.sh](https://crt.sh/) search endpoint and [Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1) for logged certificate names; DigiScope unions observations and keeps source provenance.
* Passive hostname/history datasets including [Wayback CDX](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md), [HackerTarget hostsearch](https://api.hackertarget.com/), [BufferOver](https://dns.bufferover.run/) and the public [urlscan search API](https://urlscan.io/docs/search/). Providers are optional and may be unavailable or rate-limited.
* [GitHub REST API](https://docs.github.com/en/rest), [Gravatar](https://gravatar.com/site/implement/profiles/), [Have I Been Pwned API](https://haveibeenpwned.com/API/v3) and [libphonenumber](https://github.com/google/libphonenumber) for the identity modules.
* [Wikipedia REST API](https://en.wikipedia.org/api/rest_v1/), [Wikidata API](https://www.wikidata.org/w/api.php), [OpenAlex](https://docs.openalex.org/), [Crossref REST API](https://api.crossref.org/) and GitHub user search for candidate-only person-name discovery. Search pages are not scraped and candidates are never auto-merged into an identity.
* [Internet Archive Availability API](https://archive.org/developers/wayback-cdx-server.html), [BGPView](https://bgpview.io/), [ip-api](https://ip-api.com/docs/), [Blockchain.com](https://www.blockchain.com/api) and [Blockchair](https://blockchair.com/api/docs) for public enrichment.

Providers can rate-limit, change formats or be unavailable from a particular network. DigiScope reports the observed state and does not treat a missing result as proof of absence.

## Development

```bash
make install
make test
make lint
make run
```

The tests are network-free and cover all detector types, API metadata/detection, a no-module asynchronous scan, export formats and the safe HTTP guard. CI runs Ruff, pytest on Python 3.9/3.11/3.12 and a Docker build.

## Security

See [SECURITY.md](SECURITY.md) for threat model, disclosure guidance and responsible-use boundaries. See [CONTRIBUTING.md](CONTRIBUTING.md) before adding a source module.
