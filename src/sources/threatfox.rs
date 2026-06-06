use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::env;

static THREATFOX_API: &str = "https://threatfox-api.abuse.ch/api/v1/";

#[derive(Deserialize)]
struct ThreatFoxResponse {
    query_status: String,
    data: Option<Vec<ThreatFoxEntry>>,
}

#[derive(Deserialize)]
struct ThreatFoxEntry {
    ioc: Option<String>,
    ioc_type: Option<String>,
    tags: Option<String>,
    first_seen: Option<String>,
    confidence_level: Option<String>,
    reporter: Option<String>,
}

impl ThreatFoxEntry {
    fn confidence_value(&self) -> Option<u8> {
        self.confidence_level
            .as_ref()
            .and_then(|value| value.trim_end_matches('%').parse::<u8>().ok())
    }
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let api_key = match env::var("THREATFOX_API_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(Vec::new()),
    };

    let body = serde_json::json!({
        "query": "search_ioc",
        "ioc": indicator.value,
    });

    let mut request = client.post(THREATFOX_API).json(&body);
    request = request
        .header("API-KEY", api_key.clone())
        .header("X-API-KEY", api_key);

    let response = request.send().await.context("failed to query ThreatFox")?;
    if response.status().as_u16() == 401 {
        return Ok(Vec::new());
    }

    let response = response
        .error_for_status()
        .context("ThreatFox returned an error status")?;

    let result: ThreatFoxResponse = response
        .json()
        .await
        .context("failed to parse ThreatFox response")?;

    if result.query_status.to_lowercase() != "ok" {
        return Ok(Vec::new());
    }

    let entries = result.data.unwrap_or_default();
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let findings = entries
        .into_iter()
        .map(|entry| {
            let confidence = entry.confidence_value();
            let severity = match confidence {
                Some(value) if value > 70 => Severity::High,
                Some(value) if value >= 40 => Severity::Medium,
                Some(_) => Severity::Low,
                None => Severity::Medium,
            };

            let summary = format!(
                "ThreatFox reported {} {}",
                entry.ioc_type.clone().unwrap_or_else(|| "IOC".to_string()),
                entry
                    .tags
                    .clone()
                    .unwrap_or_else(|| "threat intelligence".to_string())
            );

            SourceFinding {
                source: "ThreatFox".to_string(),
                severity,
                summary,
                details: Some(serde_json::json!({
                    "ioc": entry.ioc,
                    "ioc_type": entry.ioc_type,
                    "tags": entry.tags,
                    "first_seen": entry.first_seen,
                    "confidence_level": entry.confidence_level,
                    "reporter": entry.reporter,
                })),
            }
        })
        .collect();

    Ok(findings)
}
