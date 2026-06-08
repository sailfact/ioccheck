use crate::indicator::{Indicator, IndicatorType};
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::env;
use std::net::IpAddr;

static OTX_BASE: &str = "https://otx.alienvault.com";

#[derive(Deserialize)]
struct OtxResponse {
    pulse_info: Option<OtxPulseInfo>,
}

#[derive(Deserialize)]
struct OtxPulseInfo {
    count: Option<u32>,
    #[serde(default)]
    pulses: Option<Vec<OtxPulse>>,
}

#[derive(Deserialize)]
struct OtxPulse {
    name: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

/// Maps an indicator to its OTX `indicators/{section}` path segment.
fn otx_section(indicator: &Indicator) -> Option<&'static str> {
    match indicator.kind {
        IndicatorType::Ip => match indicator.value.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => Some("IPv4"),
            Ok(IpAddr::V6(_)) => Some("IPv6"),
            Err(_) => None,
        },
        IndicatorType::Domain => Some("domain"),
        IndicatorType::Url => Some("url"),
        IndicatorType::Sha256 => Some("file"),
        IndicatorType::Cve => Some("cve"),
        IndicatorType::Unknown => None,
    }
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let api_key = match env::var("OTX_API_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(Vec::new()),
    };

    let Some(section) = otx_section(indicator) else {
        return Ok(Vec::new());
    };

    let mut url = Url::parse(OTX_BASE).expect("valid OTX base URL");
    {
        let mut segments = url
            .path_segments_mut()
            .expect("OTX base URL supports path segments");
        segments.push("api");
        segments.push("v1");
        segments.push("indicators");
        segments.push(section);
        segments.push(indicator.value.as_str());
        segments.push("general");
    }

    let response = client
        .get(url)
        .header("X-OTX-API-KEY", api_key)
        .send()
        .await
        .context("failed to query AlienVault OTX")?;

    if response.status().as_u16() == 404 {
        return Ok(Vec::new());
    }

    let response = response
        .error_for_status()
        .context("AlienVault OTX returned an error status")?;

    let result: OtxResponse = response
        .json()
        .await
        .context("failed to parse AlienVault OTX response")?;

    Ok(findings_from_response(result))
}

fn findings_from_response(result: OtxResponse) -> Vec<SourceFinding> {
    let pulse_info = match result.pulse_info {
        Some(info) => info,
        None => return Vec::new(),
    };

    let count = pulse_info.count.unwrap_or(0);
    let severity = match count {
        0 => return Vec::new(),
        1..=3 => Severity::Low,
        _ => Severity::Medium,
    };

    let pulses = pulse_info.pulses.unwrap_or_default();
    let names: Vec<String> = pulses
        .iter()
        .filter_map(|pulse| pulse.name.clone())
        .take(3)
        .collect();
    let tags: Vec<String> = pulses
        .iter()
        .filter_map(|pulse| pulse.tags.clone())
        .flatten()
        .collect();

    let summary = if names.is_empty() {
        format!("AlienVault OTX: seen in {count} pulses")
    } else {
        format!(
            "AlienVault OTX: seen in {count} pulses ({})",
            names.join(", ")
        )
    };

    vec![SourceFinding {
        source: crate::sources::names::OTX.to_string(),
        severity,
        summary,
        details: Some(serde_json::json!({
            "pulse_count": count,
            "pulses": names,
            "tags": tags,
        })),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_otx_pulses_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/otx_pulses.json");
        let response: OtxResponse = serde_json::from_str(fixture).unwrap();

        let findings = findings_from_response(response);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "AlienVault OTX");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].summary.contains("7 pulses"));
        assert_eq!(findings[0].details.as_ref().unwrap()["pulse_count"], 7);
    }

    #[test]
    fn no_finding_when_no_pulses() {
        let fixture = include_str!("../../tests/fixtures/sources/otx_no_pulses.json");
        let response: OtxResponse = serde_json::from_str(fixture).unwrap();

        assert!(findings_from_response(response).is_empty());
    }

    #[test]
    fn low_severity_for_few_pulses() {
        let response = OtxResponse {
            pulse_info: Some(OtxPulseInfo {
                count: Some(2),
                pulses: None,
            }),
        };

        let findings = findings_from_response(response);

        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].summary.contains("2 pulses"));
    }
}
