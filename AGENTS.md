# AGENTS.md

## Project

`ioccheck` is a Rust-based security CLI for enriching indicators of compromise using public APIs and open-source threat intelligence sources.

The tool should support:

* IP address enrichment
* Domain enrichment
* URL enrichment
* SHA256 hash enrichment
* CVE enrichment
* Bulk indicator scanning from files
* Human-readable terminal output
* JSON output for automation and CI/CD use

The project should be useful for security analysts, systems administrators, homelab users, and open-source security tooling workflows.

---

## Core principles

When working on this repository:

1. Prefer simple, maintainable Rust over clever abstractions.
2. Keep the CLI fast, predictable, and scriptable.
3. Do not hardcode API keys, secrets, tokens, or private endpoints.
4. Treat public threat intelligence as advisory, not absolute truth.
5. Handle API failures gracefully.
6. Avoid panics in normal user-facing paths.
7. Keep output stable enough for automation.
8. Prefer explicit error messages over silent failures.
9. Add tests for parsing, scoring, and source response handling.
10. Keep dependencies minimal and security-conscious.

---

## Recommended stack

Use stable Rust.

Recommended crates:

```toml
[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
colored = "2"
dotenvy = "0.15"
regex = "1"
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["full"] }
url = "2"
```

Optional later:

```toml
ratatui = "0.29"
crossterm = "0.29"
rusqlite = { version = "0.32", features = ["bundled"] }
```

Use `rustls-tls` instead of native OpenSSL where practical.

---

## Repository structure

Preferred structure:

```text
ioccheck/
  AGENTS.md
  Cargo.toml
  README.md
  .env.example
  src/
    main.rs
    cli.rs
    indicator.rs
    scoring.rs
    output.rs
    sources/
      mod.rs
      abuseipdb.rs
      urlhaus.rs
      malwarebazaar.rs
      threatfox.rs
      otx.rs
      cisa_kev.rs
      nvd.rs
  tests/
    indicator_tests.rs
    scoring_tests.rs
```

---

## CLI design

The CLI should be predictable and automation-friendly.

Target commands:

```bash
ioccheck ip 8.8.8.8
ioccheck domain example.com
ioccheck url https://example.com/login
ioccheck hash <sha256>
ioccheck cve CVE-2024-3094
ioccheck file indicators.txt
ioccheck file indicators.txt --json
ioccheck file indicators.txt --fail-on high
```

Preferred global flags:

```bash
--json
--no-color
--timeout <seconds>
--cache
--cache-ttl <seconds>
--fail-on <low|medium|high|critical>
```

Exit codes:

```text
0 = completed successfully and no fail threshold matched
1 = completed successfully but fail threshold matched
2 = invalid input or configuration error
3 = API/source failure
```

---

## Indicator types

The application should classify indicators into these types:

```rust
pub enum IndicatorType {
    Ip,
    Domain,
    Url,
    Sha256,
    Cve,
    Unknown,
}
```

Validation rules:

* IPv4 and IPv6 should be supported.
* CVEs should match the format `CVE-YYYY-NNNN` or longer numeric suffixes.
* SHA256 hashes should be 64 hexadecimal characters.
* URLs should parse using the `url` crate.
* Domains should be validated conservatively and should not require DNS resolution.

---

## Threat intelligence sources

Prioritise open-source and public-friendly sources first.

### No-key or easy public sources

* CISA Known Exploited Vulnerabilities catalog
* URLhaus
* MalwareBazaar
* ThreatFox

### Optional API-key sources

* AbuseIPDB
* AlienVault OTX
* NVD API

API keys must be read from environment variables:

```bash
ABUSEIPDB_API_KEY=
OTX_API_KEY=
NVD_API_KEY=
```

Never commit real API keys.

---

## Source module pattern

Each source should live under `src/sources/`.

Each source module should expose a clear lookup function.

Example shape:

```rust
pub async fn lookup(indicator: &Indicator) -> anyhow::Result<Vec<SourceFinding>> {
    // source-specific implementation
}
```

Common result structure:

```rust
pub struct SourceFinding {
    pub source: String,
    pub severity: Severity,
    pub summary: String,
    pub details: Option<serde_json::Value>,
}
```

Do not let source-specific response formats leak throughout the app.

Normalize source responses into internal structs.

---

## Severity model

Use this enum:

```rust
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
```

Recommended score mapping:

```text
0-19    Low
20-49   Medium
50-79   High
80+     Critical
```

Recommended scoring signals:

```text
Listed in CISA KEV                       +40
Listed by URLhaus                        +30
Listed by MalwareBazaar                  +30
Listed by ThreatFox                      +30
AbuseIPDB confidence > 75                +30
AbuseIPDB confidence between 40 and 75   +15
OTX pulses > 3                           +15
Recent sighting within 30 days           +10
No source hits                             0
```

Scoring should be transparent. Users should be able to see which sources contributed to a score.

---

## Output requirements

Human output should be readable and compact.

Example:

```text
Indicator: 185.220.101.42
Type:      IP
Risk:      High

Findings:
[HIGH] AbuseIPDB: 83 reports, confidence 92%
[MED]  ThreatFox: Listed as C2 infrastructure
[LOW]  OTX: Seen in 4 pulses

Recommendation:
Block at firewall/proxy. Investigate recent logs for connections to this IP.
```

JSON output should be stable and machine-readable.

Example:

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
      "summary": "83 reports, confidence 92%"
    }
  ]
}
```

When `--json` is used:

* Do not print banners.
* Do not print progress bars.
* Do not use terminal colours.
* Write valid JSON to stdout.
* Write errors to stderr.

---

## Error handling

Use `anyhow` for application-level errors.

Use `thiserror` where custom error types improve clarity.

Do not use `unwrap()` or `expect()` in production paths.

Acceptable:

```rust
let value = response.json::<ApiResponse>().await?;
```

Avoid:

```rust
let value = response.json::<ApiResponse>().await.unwrap();
```

Errors should include context:

```rust
.context("failed to query URLhaus")
```

---

## API behaviour

HTTP clients should:

* Use sensible timeouts.
* Set a clear user agent.
* Handle rate limits.
* Handle non-200 responses.
* Handle malformed JSON.
* Avoid retry storms.
* Avoid leaking API keys in logs or error messages.

Recommended user agent:

```text
ioccheck/<version>
```

---

## Caching

Caching is optional for MVP but preferred for v2.

If implemented:

* Use SQLite or simple local JSON cache.
* Cache by source and indicator.
* Respect a configurable TTL.
* Do not cache API keys.
* Provide a way to disable cache.

Suggested default cache location:

```text
~/.cache/ioccheck/
```

---

## Bulk file mode

The `file` command should accept one indicator per line.

Example:

```text
8.8.8.8
example.com
https://example.com/login
CVE-2024-3094
```

Ignore:

* Empty lines
* Lines beginning with `#`

Bulk mode should continue scanning even if one indicator fails.

At the end, print a summary:

```text
Scanned: 25
Low: 18
Medium: 4
High: 2
Critical: 1
Errors: 0
```

---

## Testing requirements

Add tests for:

* Indicator type detection
* CVE parsing
* SHA256 parsing
* URL parsing
* Domain parsing
* Score calculation
* Severity mapping
* JSON output shape
* Source response normalization

Use fixture files for sample API responses.

Do not make live API calls in unit tests.

Live API tests should be ignored by default.

Example:

```rust
#[ignore]
#[tokio::test]
async fn live_urlhaus_lookup_works() {
    // live test
}
```

---

## Security requirements

This is a security tool. Maintain secure defaults.

Do:

* Validate input.
* Avoid shelling out.
* Avoid logging secrets.
* Use HTTPS APIs.
* Use least-privilege API keys where possible.
* Pin only necessary dependencies.
* Run `cargo audit` where available.
* Keep `.env` out of git.

Do not:

* Store API keys in code.
* Print full environment variables.
* Execute downloaded content.
* Treat a single feed hit as definitive proof of compromise.
* Automatically block indicators without explicit user action.

---

## Development commands

Common commands:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
cargo run -- ip 8.8.8.8
cargo run -- cve CVE-2024-3094
```

Before committing:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

---

## Documentation requirements

Update `README.md` when changing:

* CLI commands
* Flags
* Output formats
* Environment variables
* Supported sources
* Scoring behaviour
* Exit codes

The README should include:

* Project overview
* Install instructions
* Example usage
* API key setup
* JSON output example
* Supported sources
* Limitations
* Security notes

---

## MVP scope

The first usable version should include:

* CLI argument parsing
* Indicator type detection
* CISA KEV lookup for CVEs
* URLhaus lookup for URLs
* MalwareBazaar lookup for SHA256 hashes
* Human-readable output
* JSON output
* Basic scoring
* Unit tests for parsing and scoring

Do not overbuild the first version.

---

## Out of scope for MVP

Avoid these until the core CLI works:

* Web dashboard
* TUI interface
* Authentication system
* Multi-user support
* Automatic firewall blocking
* OpenCTI integration
* MISP integration
* STIX/TAXII export
* Long-running daemon mode

---

## Post-MVP roadmap

The MVP is complete: all five indicator types parse and validate, seven sources
are wired in (CISA KEV, NVD, URLhaus, MalwareBazaar, ThreatFox, AbuseIPDB, OTX),
scoring → severity → output (human + JSON) works, bulk file mode exists, and the
test suite covers parsing, scoring, output shape, and per-source normalization.

The following backlog is ordered by value/effort. Each item is independently
shippable — pick items rather than treating this as one large change.

### Tier 1 — highest value, already-promised or low-risk

1. **Caching layer (the one explicit v2 feature).** The `--cache` /
   `--cache-ttl` flags already exist but are ignored. Implement a cache keyed by
   `(source, indicator)` storing normalized `Vec<SourceFinding>` with a
   timestamp, honoring the configured TTL. Use a simple local JSON cache under
   `~/.cache/ioccheck/`. Wrap each source call (do not make source modules
   cache-aware). Never cache API keys. Add unit tests against a temp dir; no
   network. Update `README.md` and `CLAUDE.md` (drop "currently ignored").
2. **Scoring-contract guard.** *(Done.)* Source names live in the shared
   `sources::names` module and are referenced by both the source modules and
   `scoring.rs`, so a rename is a compile error rather than a silently dropped
   score. The `every_known_source_scores_non_zero` test (driven by `names::ALL`)
   asserts each known source string yields a non-zero score.
3. **De-duplicate the single-lookup command arms.** *(Done.)* `main.rs::run`
   parses each `Command` variant into an `Indicator`, then runs the shared
   `analyze_and_print` helper for the common
   lookup → score → severity → print → threshold pipeline; `File` mode routes to
   `run_file`.

### Tier 2 — robustness & correctness

4. **Concurrent source queries.** Sources run sequentially today; fire a type's
   sources concurrently with `tokio::join!` / `join_all` and flatten.
5. **Per-source error isolation.** `lookup_indicator` joins sources behind a
   single `?`, so one source's `Err` discards every sibling's findings and trips
   exit 3. Collect per-source results, keep the `Ok` findings, warn on the
   `Err`s, and only return exit 3 if every source failed (or behind `--strict`).
6. **Retry / backoff on transient errors.** Bounded retry (e.g. 2 attempts) for
   transient HTTP errors, ideally centralized in the cache/query wrapper.
7. **API-key visibility.** Optionally (e.g. `--verbose` / stderr) note which
   key-gated sources were skipped for a missing key, keeping default output
   clean and machine-readable.

### Tier 3 — new capabilities / coverage

8. **Additional sources** following the existing two-function split + fixture
   test pattern: GreyNoise (IP), Shodan (IP/domain), VirusTotal (all types),
   Spamhaus/DNSBL (IP). Each needs a dispatch entry, a scoring arm (via the
   Tier 1 constants), and fixtures.
9. **Indicator normalization:** URL canonicalization, hostname extraction from
   URLs, and defang/refang support (`hxxp://`, `1.1.1.1[.]evil`) on input.
10. **Output enhancements:** `--output <file>`, CSV output for bulk mode, and
    populating the currently-null `AnalysisResult.summary` recommendation.

### Tier 4 — larger / later

These remain out of scope unless explicitly requested: TUI interface,
daemon/watch mode, MISP/OpenCTI integration, STIX/TAXII export.

---

## Coding style

Prefer explicit, readable code.

Good:

```rust
if findings.is_empty() {
    return RiskLevel::Low;
}
```

Avoid overly compressed logic that makes security decisions hard to review.

Use clear names:

```rust
indicator_type
source_findings
risk_score
api_response
```

Avoid vague names:

```rust
data
thing
stuff
res
```

---

## Agent instructions

When an AI coding agent works on this repository:

1. Read this file first.
2. Preserve the project scope unless explicitly told otherwise.
3. Make small, reviewable changes.
4. Do not introduce unnecessary frameworks.
5. Do not add paid-only APIs as required dependencies.
6. Keep public/open-source sources usable without paid accounts.
7. Do not break JSON output compatibility without updating docs.
8. Do not make live network calls in unit tests.
9. Add or update tests when changing logic.
10. Run formatting and tests before presenting changes.
11. Explain any limitations or assumptions in the final response.
12. Never invent API response fields. Use fixtures or official API documentation.
13. Prefer source-specific modules over one large enrichment file.
14. Keep secrets in environment variables only.
15. Keep recommendations defensive and operationally safe.

---

## Recommended first tasks for an agent

Implement in this order:

1. Create base Rust CLI using `clap`.
2. Add indicator detection.
3. Add internal finding, severity, and score structs.
4. Add CISA KEV CVE lookup.
5. Add URLhaus URL lookup.
6. Add MalwareBazaar SHA256 lookup.
7. Add human-readable output.
8. Add JSON output.
9. Add bulk file mode.
10. Add tests and fixtures.

---

## Final quality bar

A change is acceptable when:

* It compiles.
* `cargo fmt` passes.
* `cargo clippy -- -D warnings` passes.
* `cargo test` passes.
* CLI output is understandable.
* JSON output remains valid.
* Secrets are not exposed.
* Error messages are useful.
* README changes match the implemented behaviour.
