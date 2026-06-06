use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

static URLHAUS_API: &str = "https://urlhaus-api.abuse.ch/v1/url/";

#[derive(Deserialize)]
struct UrlhausResponse {
    query_status: String,
    url: Option<UrlhausEntry>,
}

#[derive(Deserialize)]
struct UrlhausEntry {
    url: String,
    threat: Option<String>,
    tags: Option<String>,
    urlhaus_reference: Option<String>,
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let response = client
        .post(URLHAUS_API)
        .form(&[("url", &indicator.value)])
        .send()
        .await
        .context("failed to query URLhaus")?
        .error_for_status()?;

    let result: UrlhausResponse = response
        .json()
        .await
        .context("failed to parse URLhaus response")?;

    if result.query_status.to_lowercase() != "ok" {
        return Ok(Vec::new());
    }

    let entry = if let Some(entry) = result.url {
        entry
    } else {
        return Ok(Vec::new());
    };

    let summary = format!(
        "URLhaus matched{}",
        entry
            .threat
            .as_deref()
            .unwrap_or(" with a known suspicious URL")
    );

    Ok(vec![SourceFinding {
        source: "URLhaus".to_string(),
        severity: Severity::High,
        summary,
        details: Some(serde_json::json!({
            "url": entry.url,
            "tags": entry.tags,
            "reference": entry.urlhaus_reference,
        })),
    }])
}
