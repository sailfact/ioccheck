use clap::Parser;
use dotenvy::dotenv;
use reqwest::Client;
use std::time::Duration;

use ioccheck::cli::{Cli, Command, FailThreshold};
use ioccheck::indicator::{Indicator, IndicatorType};
use ioccheck::output::{
    AnalysisResult, BatchReport, BatchSummary, OutputFormatter, Severity, SourceFinding,
};
use ioccheck::scoring::{score_findings, severity_from_score};
use ioccheck::sources::{abuseipdb, cisa_kev, malwarebazaar, nvd, otx, threatfox, urlhaus};

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

    match cli.command {
        Command::Ip { value } => {
            let indicator = Indicator::parse_ip(&value).map_err(|_| 2)?;
            let findings = lookup_indicator(&client, &indicator).await.map_err(|_| 3)?;
            let score = score_findings(&findings);
            let risk = severity_from_score(score);
            let analysis = AnalysisResult::new(&indicator, risk.clone(), score, findings);
            output.print_single(&analysis).map_err(|_| 3)?;
            Ok(if threshold_reached(&risk, fail_threshold) {
                1
            } else {
                0
            })
        }
        Command::Domain { value } => {
            let indicator = Indicator::parse_domain(&value).map_err(|_| 2)?;
            let findings = lookup_indicator(&client, &indicator).await.map_err(|_| 3)?;
            let score = score_findings(&findings);
            let risk = severity_from_score(score);
            let analysis = AnalysisResult::new(&indicator, risk.clone(), score, findings);
            output.print_single(&analysis).map_err(|_| 3)?;
            Ok(if threshold_reached(&risk, fail_threshold) {
                1
            } else {
                0
            })
        }
        Command::Url { value } => {
            let indicator = Indicator::parse_url(&value).map_err(|_| 2)?;
            let findings = lookup_indicator(&client, &indicator).await.map_err(|_| 3)?;
            let score = score_findings(&findings);
            let risk = severity_from_score(score);
            let analysis = AnalysisResult::new(&indicator, risk.clone(), score, findings);
            output.print_single(&analysis).map_err(|_| 3)?;
            Ok(if threshold_reached(&risk, fail_threshold) {
                1
            } else {
                0
            })
        }
        Command::Hash { value } => {
            let indicator = Indicator::parse_sha256(&value).map_err(|_| 2)?;
            let findings = lookup_indicator(&client, &indicator).await.map_err(|_| 3)?;
            let score = score_findings(&findings);
            let risk = severity_from_score(score);
            let analysis = AnalysisResult::new(&indicator, risk.clone(), score, findings);
            output.print_single(&analysis).map_err(|_| 3)?;
            Ok(if threshold_reached(&risk, fail_threshold) {
                1
            } else {
                0
            })
        }
        Command::Cve { value } => {
            let indicator = Indicator::parse_cve(&value).map_err(|_| 2)?;
            let findings = lookup_indicator(&client, &indicator).await.map_err(|_| 3)?;
            let score = score_findings(&findings);
            let risk = severity_from_score(score);
            let analysis = AnalysisResult::new(&indicator, risk.clone(), score, findings);
            output.print_single(&analysis).map_err(|_| 3)?;
            Ok(if threshold_reached(&risk, fail_threshold) {
                1
            } else {
                0
            })
        }
        Command::File { path } => {
            let text = std::fs::read_to_string(&path).map_err(|_| 2)?;
            let mut results = Vec::new();
            let mut input_errors = 0;
            let mut source_errors = 0;

            for (line_number, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                match Indicator::from_guess(line) {
                    Ok(indicator) => match lookup_indicator(&client, &indicator).await {
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
                } else {
                    if source_errors > 0 {
                        3
                    } else {
                        0
                    }
                }
            } else {
                if source_errors > 0 {
                    3
                } else if input_errors > 0 {
                    2
                } else {
                    0
                }
            };
            Ok(exit_code)
        }
    }
}

async fn lookup_indicator(
    client: &Client,
    indicator: &Indicator,
) -> anyhow::Result<Vec<SourceFinding>> {
    match indicator.kind {
        IndicatorType::Ip => {
            let mut findings = Vec::new();
            findings.extend(threatfox::lookup(client, indicator).await?);
            findings.extend(abuseipdb::lookup(client, indicator).await?);
            findings.extend(otx::lookup(client, indicator).await?);
            Ok(findings)
        }
        IndicatorType::Domain => {
            let mut findings = Vec::new();
            findings.extend(threatfox::lookup(client, indicator).await?);
            findings.extend(otx::lookup(client, indicator).await?);
            Ok(findings)
        }
        IndicatorType::Url => {
            let mut findings = Vec::new();
            findings.extend(urlhaus::lookup(client, indicator).await?);
            findings.extend(otx::lookup(client, indicator).await?);
            Ok(findings)
        }
        IndicatorType::Sha256 => {
            let mut findings = Vec::new();
            findings.extend(malwarebazaar::lookup(client, indicator).await?);
            findings.extend(otx::lookup(client, indicator).await?);
            Ok(findings)
        }
        IndicatorType::Cve => {
            let mut findings = Vec::new();
            findings.extend(cisa_kev::lookup(client, indicator).await?);
            findings.extend(nvd::lookup(client, indicator).await?);
            findings.extend(otx::lookup(client, indicator).await?);
            Ok(findings)
        }
        _ => Ok(Vec::new()),
    }
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
