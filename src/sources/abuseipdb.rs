use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::env;

static ABUSEIPDB_API: &str = "https://api.abuseipdb.com/api/v2/check";

#[derive(Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Deserialize)]
struct AbuseIpDbData {
    #[serde(rename = "ipAddress")]
    ip_address: String,
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,
    #[serde(rename = "totalReports")]
    total_reports: Option<u32>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "isPublic")]
    is_public: Option<bool>,
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let api_key = match env::var("ABUSEIPDB_API_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(Vec::new()),
    };

    let response = client
        .get(ABUSEIPDB_API)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .query(&[
            ("ipAddress", indicator.value.as_str()),
            ("maxAgeInDays", "90"),
        ])
        .send()
        .await
        .context("failed to query AbuseIPDB")?;

    if response.status().as_u16() == 401 {
        return Ok(Vec::new());
    }

    let response = response
        .error_for_status()
        .context("AbuseIPDB returned an error status")?;

    let result: AbuseIpDbResponse = response
        .json()
        .await
        .context("failed to parse AbuseIPDB response")?;

    Ok(findings_from_response(result))
}

fn findings_from_response(result: AbuseIpDbResponse) -> Vec<SourceFinding> {
    let confidence = result.data.abuse_confidence_score;
    let severity = if confidence > 75 {
        Severity::High
    } else if confidence >= 40 {
        Severity::Medium
    } else {
        Severity::Low
    };

    let summary = format!(
        "AbuseIPDB confidence {}% from {} reports",
        confidence,
        result.data.total_reports.unwrap_or(0)
    );

    let details = serde_json::json!({
        "ip_address": result.data.ip_address,
        "abuse_confidence_score": confidence,
        "total_reports": result.data.total_reports,
        "country_code": result.data.country_code,
        "is_public": result.data.is_public,
    });

    vec![SourceFinding {
        source: "AbuseIPDB".to_string(),
        severity,
        summary,
        details: Some(details),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_abuseipdb_high_confidence_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/abuseipdb_high.json");
        let response: AbuseIpDbResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "AbuseIPDB");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].summary.contains("92%"));
        assert_eq!(findings[0].details.as_ref().unwrap()["total_reports"], 83);
    }

    #[test]
    fn normalizes_abuseipdb_medium_confidence_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/abuseipdb_medium.json");
        let response: AbuseIpDbResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
