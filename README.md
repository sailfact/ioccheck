# ioccheck

`ioccheck` is a Rust-based command-line tool for enriching indicators of compromise with public threat intelligence.

It supports five indicator types — IP, domain, URL, SHA256 hash, and CVE — querying public threat-intelligence feeds, combining the results into a single risk score, and printing either a human-readable report or stable JSON for automation.

## Install

```bash
git clone https://github.com/sailfact/ioccheck.git
cd ioccheck
cargo build --release   # binary at target/release/ioccheck
```

Or run directly from source with `cargo run -- <args>` (examples below).

## Usage

```bash
cargo run -- ip 8.8.8.8
cargo run -- domain example.com
cargo run -- url https://example.com/login
cargo run -- hash <sha256>
cargo run -- cve CVE-2024-3094
cargo run -- file indicators.txt
cargo run -- file indicators.txt --json
cargo run -- file indicators.txt --fail-on high
```

## Flags

* `--json` - output machine-readable JSON
* `--no-color` - disable colored output
* `--timeout <seconds>` - request timeout for API lookups
* `--cache` - cache normalized source findings on disk and reuse fresh entries (off by default)
* `--cache-ttl <seconds>` - max age for a cached entry to be reused, default `3600` (requires `--cache`)
* `--fail-on <low|medium|high|critical>` - return exit code `1` when the highest finding meets or exceeds this threshold

## Environment

Optional API keys may be provided in a `.env` file or environment variables:

```bash
ABUSEIPDB_API_KEY=
THREATFOX_API_KEY=
OTX_API_KEY=
NVD_API_KEY=
```

## Implemented sources

* CISA Known Exploited Vulnerabilities (CVE lookup)
* NVD API (CVE lookup; works without a key, `NVD_API_KEY` only raises the rate limit)
* URLhaus (URL lookup)
* MalwareBazaar (SHA256 lookup)
* ThreatFox (IP/domain lookup, requires `THREATFOX_API_KEY`)
* AbuseIPDB (IP lookup, requires `ABUSEIPDB_API_KEY`)
* AlienVault OTX (all indicator types, requires `OTX_API_KEY`)

## Scoring

Each source that returns a hit contributes points to an additive score, which is
capped at 100 and then bucketed into a risk level:

| Source contribution                     | Points |
| --------------------------------------- | ------ |
| CISA KEV                                | +40    |
| URLhaus                                 | +30    |
| MalwareBazaar                           | +30    |
| ThreatFox                               | +30    |
| AbuseIPDB (high / medium / low)         | +30 / +15 / +5 |
| AlienVault OTX (medium / low)           | +15 / +5 |
| Other sources, e.g. NVD (by severity)   | critical +30 / high +20 / medium +10 / low +5 |

| Score    | Risk     |
| -------- | -------- |
| 0–19     | low      |
| 20–49    | medium   |
| 50–79    | high     |
| 80–100   | critical |

Findings are advisory: a single feed hit is not proof of compromise. The report
lists every contributing source so a score can be reviewed by hand.

## JSON output

With `--json`, a single-indicator lookup writes a stable object to stdout. All
casing is lowercase (`risk`, `severity`, and `indicator_type`):

```json
{
  "indicator": "185.220.101.42",
  "indicator_type": "ip",
  "risk": "high",
  "score": 75,
  "findings": [
    {
      "source": "AbuseIPDB",
      "severity": "high",
      "summary": "AbuseIPDB confidence 92% from 83 reports",
      "details": null
    }
  ],
  "summary": null
}
```

Bulk `file` mode wraps the per-indicator results in `{ "results": [...], "summary": {...} }`,
where `summary` carries the scanned/severity/error counts. When `--json` is set,
only valid JSON goes to stdout; errors are written to stderr.

## Exit codes

* `0` - completed successfully and no fail threshold matched
* `1` - completed successfully but fail threshold matched
* `2` - invalid input or configuration error
* `3` - API/source failure. Single-indicator lookups return this only when
  every attempted source for that indicator fails; partial source failures are
  warned on stderr and successful sibling findings are still reported.

## Source query behavior

For each indicator, applicable sources are queried concurrently to keep lookups
responsive. Source failures are isolated: if one source fails but another source
for the same indicator succeeds, `ioccheck` keeps the successful findings and
writes a warning to stderr. A lookup is treated as an API/source failure only
when every attempted source for that indicator fails.

## Caching

`--cache` enables an on-disk cache of normalized source findings, keyed by
`(source, indicator)`. On a lookup, each source is consulted from the cache
first; a fresh entry skips the network call, and a miss queries the source and
stores its result. Entries older than `--cache-ttl` seconds (default `3600`) are
treated as a miss.

* Cache files live under `$XDG_CACHE_HOME/ioccheck` (or `~/.cache/ioccheck`),
  one JSON file per `(source, indicator)` pair.
* Only successful lookups with at least one finding are cached; errors and
  empty results are never stored. (A key-gated source skipped for a missing key
  returns an empty result, so caching empties could let a keyless first run
  suppress real findings until the TTL expired.)
* Caching is off unless `--cache` is passed, so default behavior is unchanged.
* API keys are never part of a finding and are never written to the cache.
* To clear the cache, delete the directory above.

## Limitations

* Most sources are key-gated (AbuseIPDB, ThreatFox, OTX); without their API keys
  those lookups are silently skipped, so IP and domain lookups may return no
  findings out of the box. The two CVE sources (CISA KEV, NVD) work without a key.
* Domain validation is regex-only and does not resolve DNS.
* Threat-intelligence results are advisory, not authoritative.

## Security notes

* API keys are read only from the environment (or a local `.env`); never commit real keys.
* `.env` should stay out of version control.
* All source APIs are queried over HTTPS, and keys are never printed in output or errors.
* `ioccheck` only reports — it never blocks indicators or executes any fetched content.
