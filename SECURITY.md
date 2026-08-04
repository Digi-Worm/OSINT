# Security and responsible use

## Scope

DigiScope is a local/authorised, passive public-source research tool. It is intended for:

* reviewing infrastructure that you own or are authorised to assess;
* threat intelligence and defensive exposure management;
* journalism, academic research and public-interest investigations with a lawful basis; and
* reviewing an individual's or organisation's own public footprint.

Do not use DigiScope to stalk, harass, doxx, deanonymise, profile or surveil people without a lawful basis. Do not use the output to make high-impact decisions about a person. A public match is a lead, not proof of identity or ownership.

## Technical boundaries

* Safe/passive mode is the default. It rejects literal private/local destinations and embedded URL credentials.
* DigiScope does not perform active port scans, credential attacks, brute force, exploit delivery, CAPTCHA bypass, search-engine scraping or access-control evasion.
* Shodan InternetDB and other provider results are historical/public snapshots; they are not active observations by DigiScope.
* Person mode creates search links and candidate handles only. Automatic identity resolution is intentionally not implemented.
* Username checks are bounded public URL probes with a catalogue, status/missing-page heuristics and explicit inconclusive states. Respect provider terms, robots/rate limits and applicable law.
* Optional API keys are supplied per scan, held in process memory and redacted from result responses and exports. Do not put secrets in issues, screenshots or committed files.
* Public sources may include personal data. Minimise collection, verify independently, retain only what is necessary and honour removal or legal requests.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability, credential or private data in a public issue. If GitHub private vulnerability reporting is enabled, use it. Otherwise contact the repository maintainers through the repository's current security contact, including:

1. a concise description and impact;
2. affected commit/version and deployment mode;
3. safe reproduction steps or a minimal proof of concept; and
4. any mitigations you know.

Allow reasonable time for a fix. DigiScope is provided without warranty; operators are responsible for configuring network egress, authentication, access and retention policies appropriate to their environment.
