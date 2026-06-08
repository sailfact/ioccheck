# CLAUDE.md

@AGENTS.md

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
- **`sources/*.rs`** — one module per feed. Each is a **two-function split**: `async fn lookup(client, indicator)` owns network/status/key concerns, then delegates to a pure `findings_from_response(parsed)` (or `findings_from_feed(indicator, feed)` where client-side filtering is needed, e.g. `cisa_kev`) that normalizes into `SourceFinding`. The pure half is unit-tested inline against JSON fixtures in `tests/fixtures/sources/`; never let a feed's raw shape leak outward. Implemented: `cisa_kev` + `nvd` (CVE), `urlhaus` (URL), `malwarebazaar` (SHA256), `threatfox` (IP/domain), `abuseipdb` (IP), `otx` (all types). Dispatch in `lookup_indicator`: IP → threatfox + abuseipdb + otx; domain → threatfox + otx; URL → urlhaus + otx; SHA256 → malwarebazaar + otx; CVE → cisa_kev + nvd + otx.
- **`scoring.rs`** — additive score capped at 100, then bucketed (`<20` low, `<50` medium, `<80` high, else critical). **Scoring matches on the `SourceFinding.source` name via the shared `sources::names` constants** (`names::CISA_KEV`, `names::URLHAUS`, `names::THREATFOX`, `names::OTX`, etc.). Both the source modules (when building a `SourceFinding`) and the scoring arms reference the same constant, so renaming a source is a compile error rather than a silently dropped contribution; the `every_known_source_scores_non_zero` test (`tests/scoring_tests.rs`, driven by `names::ALL`) guards the same contract. `AbuseIPDB` and `AlienVault OTX` score by severity tier; everything else without an explicit arm (e.g. `NVD`) falls through the default severity-based arm.
- **`output.rs`** — `Severity` enum, the `SourceFinding`/`AnalysisResult`/`BatchReport` data model, and `OutputFormatter` (human vs `--json`). JSON is the stable machine contract.

## Conventions specific to this repo

- **Most sources are key-gated; two CVE sources are keyless.** Key-gated sources (`abuseipdb`, `threatfox`, `otx`) read their env key and return `Ok(vec![])` on a missing/empty key or `401` (silently skipped), not an error — so with no `.env` the IP and domain paths produce no findings, which is expected. `cisa_kev` and `nvd` need no key (NVD sends `NVD_API_KEY` only to raise its rate limit), so CVE lookups still work out of the box. `.env` is loaded via `dotenvy` at startup; copy `.env.example`.
- **A source must never hard-fail the aggregate.** `lookup_indicator` joins sources behind a single `?`, so any `Err` drops *every* sibling source's findings for that indicator and trips exit code 3. New sources should map "no data / rate limited" statuses to `Ok(vec![])` rather than erroring (see `nvd::lookup` treating `403/404/429` as empty).
- **JSON casing is uniformly lowercase:** `AnalysisResult.risk`, `SourceFinding.severity` (`Severity` derives `#[serde(rename_all = "lowercase")]`), and `indicator_type` (explicit lowercase match in `AnalysisResult::new`) all serialize lowercase (`"high"`, `"cve"`). Downstream automation depends on this — update `README.md` if you change any output shape.
- Application errors use `anyhow` with `.context(...)`; custom errors use `thiserror`. Avoid `unwrap()`/`expect()` in request/parse paths.
- `src/main.rs::run` parses each single-indicator `Command` into an `Indicator`, then runs the shared `analyze_and_print` pipeline (lookup → score → severity → print → threshold); `File` mode routes to `run_file`. Add new single-indicator commands by extending the parse match — the pipeline is shared, not duplicated per arm.

## Roadmap (post-MVP)

The MVP is complete. The prioritized backlog lives in `AGENTS.md` ("Post-MVP roadmap") — read it before starting new feature work. Highest-value next steps:

- **Caching layer** — `--cache`/`--cache-ttl` are parsed but ignored; implement a `(source, indicator)` cache with TTL under `~/.cache/ioccheck/`, wrapping each source call (keep sources cache-unaware). Never cache API keys.
- ~~**Scoring-contract guard**~~ — done: source names live in `sources::names` and are referenced by both the source modules and `scoring.rs`; `every_known_source_scores_non_zero` guards the contract.
- ~~**Refactor the repeated `main.rs` command arms**~~ — done: collapsed into the shared `analyze_and_print` helper (file mode in `run_file`).
- **Per-source error isolation + concurrency** — stop letting one source's `Err` drop its siblings (see the aggregate-failure convention above); run a type's sources concurrently.

Each item is independently shippable; see `AGENTS.md` for the full tiered list (additional sources, indicator defang/normalization, output formats).
