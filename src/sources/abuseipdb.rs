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
    ip_address: String,
    abuse_confidence_score: u8,
    total_reports: Option<u32>,
    country_code: Option<String>,
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

    Ok(vec![SourceFinding {
        source: "AbuseIPDB".to_string(),
        severity,
        summary,
        details: Some(details),
    }])
}
