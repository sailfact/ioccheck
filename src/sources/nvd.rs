use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::env;

static NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
}

#[derive(Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Default, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    cvss_v31: Vec<NvdCvssV3>,
    #[serde(rename = "cvssMetricV30", default)]
    cvss_v30: Vec<NvdCvssV3>,
    #[serde(rename = "cvssMetricV2", default)]
    cvss_v2: Vec<NvdCvssV2>,
}

#[derive(Deserialize)]
struct NvdCvssV3 {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssV3Data,
}

#[derive(Deserialize)]
struct NvdCvssV3Data {
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Deserialize)]
struct NvdCvssV2 {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssV2Data,
    // In CVSS v2 the severity is a sibling of `cvssData`, not nested inside it.
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Deserialize)]
struct NvdCvssV2Data {
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let mut request = client
        .get(NVD_API)
        .query(&[("cveId", indicator.value.as_str())]);

    // NVD works without a key; the key only raises the rate limit.
    if let Ok(key) = env::var("NVD_API_KEY") {
        if !key.trim().is_empty() {
            request = request.header("apiKey", key);
        }
    }

    let response = request.send().await.context("failed to query NVD")?;

    // Treat rate-limit / not-found as "no finding" so a single source does not
    // poison the aggregated CVE lookup (which shares one `?` in main.rs).
    if matches!(response.status().as_u16(), 403 | 404 | 429) {
        return Ok(Vec::new());
    }

    let response = response
        .error_for_status()
        .context("NVD returned an error status")?;

    let result: NvdResponse = response
        .json()
        .await
        .context("failed to parse NVD response")?;

    Ok(findings_from_response(result))
}

fn findings_from_response(result: NvdResponse) -> Vec<SourceFinding> {
    let Some(vulnerability) = result.vulnerabilities.into_iter().next() else {
        return Vec::new();
    };
    let cve = vulnerability.cve;

    let (base_score, base_severity) = extract_cvss(&cve.metrics);
    let severity = base_severity
        .as_deref()
        .map(severity_from_cvss_label)
        .unwrap_or(Severity::Info);

    let description = cve
        .descriptions
        .iter()
        .find(|description| description.lang == "en")
        .map(|description| description.value.as_str())
        .unwrap_or("no description available");
    let description = truncate(description, 160);

    let summary = match (base_score, &base_severity) {
        (Some(score), Some(label)) => {
            format!(
                "NVD: CVSS {score:.1} ({}) — {description}",
                label.to_lowercase()
            )
        }
        _ => format!("NVD: no CVSS score yet — {description}"),
    };

    vec![SourceFinding {
        source: "NVD".to_string(),
        severity,
        summary,
        details: Some(serde_json::json!({
            "cve_id": cve.id,
            "base_score": base_score,
            "base_severity": base_severity,
        })),
    }]
}

/// Prefer CVSS v3.1, then v3.0, then v2. Returns the base score and severity
/// label from the first metric available.
fn extract_cvss(metrics: &NvdMetrics) -> (Option<f64>, Option<String>) {
    if let Some(metric) = metrics.cvss_v31.first() {
        return (
            metric.cvss_data.base_score,
            metric.cvss_data.base_severity.clone(),
        );
    }
    if let Some(metric) = metrics.cvss_v30.first() {
        return (
            metric.cvss_data.base_score,
            metric.cvss_data.base_severity.clone(),
        );
    }
    if let Some(metric) = metrics.cvss_v2.first() {
        return (metric.cvss_data.base_score, metric.base_severity.clone());
    }
    (None, None)
}

fn severity_from_cvss_label(label: &str) -> Severity {
    match label.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        let truncated: String = value.chars().take(max_chars).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_nvd_cvss_v31_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/nvd_cvss_v31.json");
        let response: NvdResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "NVD");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].summary.contains("10.0"));
        assert_eq!(
            findings[0].details.as_ref().unwrap()["base_severity"],
            "CRITICAL"
        );
    }

    #[test]
    fn info_severity_when_no_cvss() {
        let fixture = include_str!("../../tests/fixtures/sources/nvd_no_cvss.json");
        let response: NvdResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("no CVSS"));
    }

    #[test]
    fn no_finding_when_cve_not_found() {
        let fixture = include_str!("../../tests/fixtures/sources/nvd_not_found.json");
        let response: NvdResponse = serde_json::from_str(fixture).unwrap();

        assert!(findings_from_response(response).is_empty());
    }

    #[test]
    fn maps_cvss_labels() {
        assert_eq!(severity_from_cvss_label("CRITICAL"), Severity::Critical);
        assert_eq!(severity_from_cvss_label("high"), Severity::High);
        assert_eq!(severity_from_cvss_label("Medium"), Severity::Medium);
        assert_eq!(severity_from_cvss_label("LOW"), Severity::Low);
        assert_eq!(severity_from_cvss_label("unknown"), Severity::Info);
    }
}
