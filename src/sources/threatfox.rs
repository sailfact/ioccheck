use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use crate::sources::{deserialize_optional_string_list, deserialize_optional_u8};
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
    #[serde(default, deserialize_with = "deserialize_optional_string_list")]
    tags: Option<Vec<String>>,
    first_seen: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u8")]
    confidence_level: Option<u8>,
    reporter: Option<String>,
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let api_key = match env::var("THREATFOX_API_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(Vec::new()),
    };

    let body = serde_json::json!({
        "query": "search_ioc",
        "search_term": indicator.value,
        "exact_match": true,
    });

    let request = client
        .post(THREATFOX_API)
        .header("Auth-Key", api_key)
        .json(&body);

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

    Ok(findings_from_response(result))
}

fn findings_from_response(result: ThreatFoxResponse) -> Vec<SourceFinding> {
    if result.query_status.to_lowercase() != "ok" {
        return Vec::new();
    }

    let entries = result.data.unwrap_or_default();
    if entries.is_empty() {
        return Vec::new();
    }

    entries
        .into_iter()
        .map(|entry| {
            let confidence = entry.confidence_level;
            let severity = match confidence {
                Some(value) if value > 70 => Severity::High,
                Some(value) if value >= 40 => Severity::Medium,
                Some(_) => Severity::Low,
                None => Severity::Medium,
            };
            let tags = entry
                .tags
                .as_ref()
                .filter(|tags| !tags.is_empty())
                .map(|tags| tags.join(", "))
                .unwrap_or_else(|| "threat intelligence".to_string());

            let summary = format!(
                "ThreatFox reported {} {}",
                entry.ioc_type.clone().unwrap_or_else(|| "IOC".to_string()),
                tags
            );

            SourceFinding {
                source: crate::sources::names::THREATFOX.to_string(),
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
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_threatfox_hit_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/threatfox_hit.json");
        let response: ThreatFoxResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "ThreatFox");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].summary.contains("ip:port"));
        assert_eq!(
            findings[0].details.as_ref().unwrap()["confidence_level"],
            75
        );
    }

    #[test]
    fn normalizes_threatfox_no_result_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/threatfox_no_result.json");
        let response: ThreatFoxResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert!(findings.is_empty());
    }
}
