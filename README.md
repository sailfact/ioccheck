# ioccheck

`ioccheck` is a Rust-based command-line tool for enriching indicators of compromise with public threat intelligence.

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
* `--cache` - reserved for v2; currently ignored
* `--cache-ttl <seconds>` - reserved for v2; currently ignored
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

## Exit codes

* `0` - completed successfully and no fail threshold matched
* `1` - completed successfully but fail threshold matched
* `2` - invalid input or configuration error
* `3` - API/source failure
