# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`ioccheck` is a Rust CLI that enriches indicators of compromise (IP, domain, URL, SHA256, CVE) using public threat-intelligence sources. `AGENTS.md` holds the full project charter (scope, security rules, conventions, MVP roadmap) — read it for intent; this file documents what is actually wired up today.

## Commands

```bash
cargo run -- ip 8.8.8.8           # single-indicator lookups: ip|domain|url|hash|cve
cargo run -- file indicators.txt  # bulk mode, one indicator per line (# comments and blanks skipped)
cargo run -- cve CVE-2024-3094 --json --fail-on high

cargo test                        # all tests
cargo test --test scoring_tests   # one integration test file (tests live in tests/, not unit modules)
cargo test parse_ip               # single test by name
cargo fmt
cargo clippy -- -D warnings       # required to pass; clippy is part of the quality bar
```

Live-network tests must be marked `#[ignore]`; unit/integration tests never hit the network.

## Architecture

Flow per indicator (`src/main.rs::run`): parse/validate → `lookup_indicator` (dispatches to source modules by `IndicatorType`) → `score_findings` → `severity_from_score` → `OutputFormatter`. `main` returns an exit code via `Result<i32, i32>`; the `Err` arm carries the failure code. Exit codes: `0` ok, `1` fail-threshold met, `2` invalid input/config, `3` source/API failure.

- **`indicator.rs`** — `Indicator { value, kind }` and per-type `parse_*` validators. `from_guess` (used by bulk file mode) tries parsers in a fixed order — **ip → cve → sha256 → url → domain** — and order is significant because URL/domain patterns overlap. Domain validation is regex-only, no DNS.
- **`sources/*.rs`** — one module per feed, each exposing `async fn lookup(client, indicator) -> Result<Vec<SourceFinding>>`. Source-specific JSON is deserialized into private structs and normalized to `SourceFinding`; never let a feed's raw shape leak outward. Implemented: `cisa_kev` (CVE), `urlhaus` (URL), `malwarebazaar` (SHA256), `threatfox` (IP/domain), `abuseipdb` (IP). IPs query both threatfox and abuseipdb.
- **`scoring.rs`** — additive score capped at 100, then bucketed (`<20` low, `<50` medium, `<80` high, else critical). **Scoring matches on the `SourceFinding.source` string literal** (`"CISA KEV"`, `"URLhaus"`, `"ThreatFox"`, etc.). These strings are the contract between a source module and scoring — renaming one in a source file without updating `scoring.rs` silently drops its contribution. AbuseIPDB scores by severity tier rather than a flat value.
- **`output.rs`** — `Severity` enum, the `SourceFinding`/`AnalysisResult`/`BatchReport` data model, and `OutputFormatter` (human vs `--json`). JSON is the stable machine contract.

## Conventions specific to this repo

- **API keys are optional and gate their source.** Each source reads its key from env (`ABUSEIPDB_API_KEY`, `THREATFOX_API_KEY`, …); a missing/empty key or a `401` makes `lookup` return `Ok(vec![])` (silently skipped), not an error. So with no `.env` the IP/domain paths produce no findings — expected, not a bug. `.env` is loaded via `dotenvy` at startup; copy `.env.example`.
- **JSON casing is mixed by construction:** `AnalysisResult.risk` is lowercased (`"high"`), but `SourceFinding.severity` serializes via serde derive as PascalCase (`"High"`), and `indicator_type` comes from `format!("{:?}", kind)` (`"Ip"`, `"Cve"`). Preserve existing casing — downstream automation depends on it — and update `README.md` if you change any output shape.
- Application errors use `anyhow` with `.context(...)`; custom errors use `thiserror`. Avoid `unwrap()`/`expect()` in request/parse paths.
- `src/main.rs` repeats nearly identical per-command blocks; if you touch the single-lookup pipeline, change every command arm or refactor them together.
