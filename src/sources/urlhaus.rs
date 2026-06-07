use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use crate::sources::deserialize_optional_string_list;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

static URLHAUS_API: &str = "https://urlhaus-api.abuse.ch/v1/url/";

#[derive(Deserialize)]
struct UrlhausResponse {
    query_status: String,
    url: Option<String>,
    threat: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_list")]
    tags: Option<Vec<String>>,
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

    Ok(findings_from_response(result))
}

fn findings_from_response(result: UrlhausResponse) -> Vec<SourceFinding> {
    if result.query_status.to_lowercase() != "ok" {
        return Vec::new();
    }

    let url = if let Some(url) = result.url {
        url
    } else {
        return Vec::new();
    };

    let summary = if let Some(threat) = result.threat.as_deref() {
        format!("URLhaus matched {threat}")
    } else {
        "URLhaus matched a known suspicious URL".to_string()
    };

    vec![SourceFinding {
        source: crate::sources::names::URLHAUS.to_string(),
        severity: Severity::High,
        summary,
        details: Some(serde_json::json!({
            "url": url,
            "tags": result.tags,
            "reference": result.urlhaus_reference,
        })),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_urlhaus_hit_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/urlhaus_hit.json");
        let response: UrlhausResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "URLhaus");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].summary.contains("malware_download"));
        assert_eq!(findings[0].details.as_ref().unwrap()["tags"][0], "elf");
    }

    #[test]
    fn normalizes_urlhaus_no_results_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/urlhaus_no_results.json");
        let response: UrlhausResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert!(findings.is_empty());
    }
}
