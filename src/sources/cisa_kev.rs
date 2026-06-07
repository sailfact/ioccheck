use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

static CISA_KEV_FEED: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct CisaFeed {
    // The live feed names this array `vulnerabilities`.
    vulnerabilities: Vec<CisaEntry>,
}

#[derive(Deserialize)]
struct CisaEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: Option<String>,
    product: Option<String>,
    #[serde(rename = "dateAdded")]
    date_added: Option<String>,
}

pub async fn lookup(client: &Client, indicator: &Indicator) -> Result<Vec<SourceFinding>> {
    let response = client
        .get(CISA_KEV_FEED)
        .send()
        .await
        .context("failed to fetch CISA KEV feed")?;

    let response = response
        .error_for_status()
        .context("CISA KEV feed returned an error status")?;

    let feed: CisaFeed = response
        .json()
        .await
        .context("failed to parse CISA KEV feed")?;

    Ok(findings_from_feed(indicator, feed))
}

fn findings_from_feed(indicator: &Indicator, feed: CisaFeed) -> Vec<SourceFinding> {
    let found = feed
        .vulnerabilities
        .into_iter()
        .find(|entry| entry.cve_id.eq_ignore_ascii_case(&indicator.value));

    if let Some(entry) = found {
        let vendor_project = entry.vendor_project.clone().unwrap_or_default();
        let product = entry.product.clone().unwrap_or_default();
        let summary = format!("Listed in CISA KEV feed: {} {}", vendor_project, product);

        vec![SourceFinding {
            source: "CISA KEV".to_string(),
            severity: Severity::High,
            summary,
            details: Some(serde_json::json!({
                "cve_id": entry.cve_id,
                "date_added": entry.date_added,
                "vendor_project": entry.vendor_project,
                "product": entry.product,
            })),
        }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorType;

    #[test]
    fn normalizes_cisa_kev_hit_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/cisa_kev_hit.json");
        let feed: CisaFeed = serde_json::from_str(fixture).unwrap();
        let indicator = Indicator::new("CVE-2024-3094", IndicatorType::Cve);

        let findings = findings_from_feed(&indicator, feed);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "CISA KEV");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].summary.contains("XZ Utils"));
        assert_eq!(
            findings[0].details.as_ref().unwrap()["date_added"],
            "2024-04-01"
        );
    }

    #[test]
    fn normalizes_cisa_kev_miss_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/sources/cisa_kev_hit.json");
        let feed: CisaFeed = serde_json::from_str(fixture).unwrap();
        let indicator = Indicator::new("CVE-2099-0001", IndicatorType::Cve);

        let findings = findings_from_feed(&indicator, feed);

        assert!(findings.is_empty());
    }
}
