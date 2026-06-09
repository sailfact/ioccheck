use clap::Parser;
use dotenvy::dotenv;
use reqwest::Client;
use std::time::Duration;

use ioccheck::cache::{cached_lookup, Cache};
use ioccheck::cli::{Cli, Command, FailThreshold};
use ioccheck::indicator::{Indicator, IndicatorType};
use ioccheck::output::{
    AnalysisResult, BatchReport, BatchSummary, OutputFormatter, Severity, SourceFinding,
};
use ioccheck::scoring::{score_findings, severity_from_score};
use ioccheck::sources::{abuseipdb, cisa_kev, malwarebazaar, names, nvd, otx, threatfox, urlhaus};

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cli = Cli::parse();
    let client = Client::builder()
        .user_agent("ioccheck/0.1")
        .timeout(Duration::from_secs(cli.timeout))
        .build()
        .expect("failed to build HTTP client");

    let result = match run(cli, client).await {
        Ok(code) => code,
        Err(code) => {
            std::process::exit(code);
        }
    };

    std::process::exit(result);
}

async fn run(cli: Cli, client: Client) -> Result<i32, i32> {
    let output = OutputFormatter::new(cli.no_color, cli.json);
    let fail_threshold = cli.fail_on.map(FailThreshold::into);
    // The cache wraps each source call when `--cache` is set; sources stay
    // cache-unaware. `None` means caching is disabled (the default).
    let cache = if cli.cache {
        Some(Cache::new(cli.cache_ttl))
    } else {
        None
    };

    // Each single-indicator command differs only in how its argument is parsed;
    // everything after parsing is the shared `analyze_and_print` pipeline. File
    // mode has its own batch pipeline.
    let indicator = match cli.command {
        Command::Ip { value } => Indicator::parse_ip(&value).map_err(|_| 2)?,
        Command::Domain { value } => Indicator::parse_domain(&value).map_err(|_| 2)?,
        Command::Url { value } => Indicator::parse_url(&value).map_err(|_| 2)?,
        Command::Hash { value } => Indicator::parse_sha256(&value).map_err(|_| 2)?,
        Command::Cve { value } => Indicator::parse_cve(&value).map_err(|_| 2)?,
        Command::File { path } => {
            return run_file(&client, &output, fail_threshold, cache.as_ref(), &path).await
        }
    };

    analyze_and_print(&client, &output, fail_threshold, cache.as_ref(), &indicator).await
}

/// Shared single-indicator pipeline: lookup → score → severity → print →
/// threshold. Returns the process exit code.
async fn analyze_and_print(
    client: &Client,
    output: &OutputFormatter,
    fail_threshold: Option<Severity>,
    cache: Option<&Cache>,
    indicator: &Indicator,
) -> Result<i32, i32> {
    let findings = lookup_indicator(client, cache, indicator)
        .await
        .map_err(|_| 3)?;
    let score = score_findings(&findings);
    let risk = severity_from_score(score);
    let analysis = AnalysisResult::new(indicator, risk.clone(), score, findings);
    output.print_single(&analysis).map_err(|_| 3)?;
    Ok(if threshold_reached(&risk, fail_threshold) {
        1
    } else {
        0
    })
}

/// Bulk file pipeline: one indicator per line, skipping blanks and `#`
/// comments, continuing past per-line failures and reporting a batch summary.
async fn run_file(
    client: &Client,
    output: &OutputFormatter,
    fail_threshold: Option<Severity>,
    cache: Option<&Cache>,
    path: &std::path::Path,
) -> Result<i32, i32> {
    let text = std::fs::read_to_string(path).map_err(|_| 2)?;
    let mut results = Vec::new();
    let mut input_errors = 0;
    let mut source_errors = 0;

    for (line_number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match Indicator::from_guess(line) {
            Ok(indicator) => match lookup_indicator(client, cache, &indicator).await {
                Ok(findings) => {
                    let score = score_findings(&findings);
                    let risk = severity_from_score(score);
                    results.push(AnalysisResult::new(&indicator, risk, score, findings));
                }
                Err(error) => {
                    source_errors += 1;
                    eprintln!("failed to scan line {} ({line}): {error}", line_number + 1);
                }
            },
            Err(_) => {
                input_errors += 1;
                eprintln!("invalid indicator on line {}: {line}", line_number + 1);
            }
        }
    }

    let errors = input_errors + source_errors;
    output
        .print_batch(&BatchReport {
            results: results.clone(),
            summary: BatchSummary::from_results(&results, errors),
        })
        .map_err(|_| 3)?;

    let max_severity = results
        .iter()
        .map(|result| result.risk.clone())
        .filter_map(|risk| Severity::from_str(&risk).ok())
        .max_by_key(|severity| severity.as_rank());

    let exit_code = if let Some(risk) = max_severity {
        if threshold_reached(&risk, fail_threshold) {
            1
        } else if source_errors > 0 {
            3
        } else {
            0
        }
    } else if source_errors > 0 {
        3
    } else if input_errors > 0 {
        2
    } else {
        0
    };
    Ok(exit_code)
}

async fn lookup_indicator(
    client: &Client,
    cache: Option<&Cache>,
    indicator: &Indicator,
) -> anyhow::Result<Vec<SourceFinding>> {
    // Each source call is wrapped in `cached_lookup` so a fresh `(source,
    // indicator)` cache entry short-circuits the network call. Sources stay
    // cache-unaware; the source-name constant doubles as the cache key.
    //
    // Sources for a given indicator type are queried concurrently. Their errors
    // are isolated: successful source findings are kept, failed source names are
    // warned on stderr, and the lookup fails only when every source attempted
    // for that indicator type failed.
    match indicator.kind {
        IndicatorType::Ip => {
            let (threatfox_result, abuseipdb_result, otx_result) = tokio::join!(
                cached_lookup(cache, names::THREATFOX, indicator, || {
                    threatfox::lookup(client, indicator)
                }),
                cached_lookup(cache, names::ABUSEIPDB, indicator, || {
                    abuseipdb::lookup(client, indicator)
                }),
                cached_lookup(cache, names::OTX, indicator, || {
                    otx::lookup(client, indicator)
                })
            );
            collect_source_findings(vec![
                (names::THREATFOX, threatfox_result),
                (names::ABUSEIPDB, abuseipdb_result),
                (names::OTX, otx_result),
            ])
        }
        IndicatorType::Domain => {
            let (threatfox_result, otx_result) = tokio::join!(
                cached_lookup(cache, names::THREATFOX, indicator, || {
                    threatfox::lookup(client, indicator)
                }),
                cached_lookup(cache, names::OTX, indicator, || {
                    otx::lookup(client, indicator)
                })
            );
            collect_source_findings(vec![
                (names::THREATFOX, threatfox_result),
                (names::OTX, otx_result),
            ])
        }
        IndicatorType::Url => {
            let (urlhaus_result, otx_result) = tokio::join!(
                cached_lookup(cache, names::URLHAUS, indicator, || {
                    urlhaus::lookup(client, indicator)
                }),
                cached_lookup(cache, names::OTX, indicator, || {
                    otx::lookup(client, indicator)
                })
            );
            collect_source_findings(vec![
                (names::URLHAUS, urlhaus_result),
                (names::OTX, otx_result),
            ])
        }
        IndicatorType::Sha256 => {
            let (malwarebazaar_result, otx_result) = tokio::join!(
                cached_lookup(cache, names::MALWAREBAZAAR, indicator, || {
                    malwarebazaar::lookup(client, indicator)
                }),
                cached_lookup(cache, names::OTX, indicator, || {
                    otx::lookup(client, indicator)
                })
            );
            collect_source_findings(vec![
                (names::MALWAREBAZAAR, malwarebazaar_result),
                (names::OTX, otx_result),
            ])
        }
        IndicatorType::Cve => {
            let (cisa_kev_result, nvd_result, otx_result) = tokio::join!(
                cached_lookup(cache, names::CISA_KEV, indicator, || {
                    cisa_kev::lookup(client, indicator)
                }),
                cached_lookup(cache, names::NVD, indicator, || {
                    nvd::lookup(client, indicator)
                }),
                cached_lookup(cache, names::OTX, indicator, || {
                    otx::lookup(client, indicator)
                })
            );
            collect_source_findings(vec![
                (names::CISA_KEV, cisa_kev_result),
                (names::NVD, nvd_result),
                (names::OTX, otx_result),
            ])
        }
        _ => Ok(Vec::new()),
    }
}

fn collect_source_findings(
    results: Vec<(&'static str, anyhow::Result<Vec<SourceFinding>>)>,
) -> anyhow::Result<Vec<SourceFinding>> {
    let mut findings = Vec::new();
    let mut successful_sources = 0;
    let mut errors = Vec::new();

    for (source, result) in results {
        match result {
            Ok(mut source_findings) => {
                successful_sources += 1;
                findings.append(&mut source_findings);
            }
            Err(error) => errors.push(format!("{source}: {error:#}")),
        }
    }

    if successful_sources == 0 && !errors.is_empty() {
        anyhow::bail!("all sources failed: {}", errors.join("; "));
    }

    for error in errors {
        eprintln!("warning: source lookup failed: {error}");
    }

    Ok(findings)
}

fn threshold_reached(risk: &Severity, threshold: Option<Severity>) -> bool {
    if let Some(threshold) = threshold {
        risk.as_rank() >= threshold.as_rank()
    } else {
        false
    }
}

trait FromStrSeverity {
    fn from_str(value: &str) -> Result<Severity, ()>;
}

impl FromStrSeverity for Severity {
    fn from_str(value: &str) -> Result<Severity, ()> {
        match value.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(source: &str) -> SourceFinding {
        SourceFinding {
            source: source.to_string(),
            severity: Severity::High,
            summary: "test finding".to_string(),
            details: None,
        }
    }

    #[test]
    fn collect_source_findings_keeps_successes_when_a_sibling_fails() {
        let findings = collect_source_findings(vec![
            (names::URLHAUS, Ok(vec![finding(names::URLHAUS)])),
            (names::OTX, Err(anyhow::anyhow!("temporary failure"))),
        ])
        .expect("one successful source should keep the lookup successful");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, names::URLHAUS);
    }

    #[test]
    fn collect_source_findings_fails_when_every_source_fails() {
        let error = collect_source_findings(vec![
            (names::URLHAUS, Err(anyhow::anyhow!("urlhaus failed"))),
            (names::OTX, Err(anyhow::anyhow!("otx failed"))),
        ])
        .expect_err("all failed sources should fail the lookup");

        let message = error.to_string();
        assert!(message.contains("all sources failed"));
        assert!(message.contains(names::URLHAUS));
        assert!(message.contains(names::OTX));
    }
}
