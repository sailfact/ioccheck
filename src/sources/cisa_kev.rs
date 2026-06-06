use crate::indicator::Indicator;
use crate::output::{Severity, SourceFinding};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

static CISA_KEV_FEED: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct CisaFeed {
    known_exploited_vulnerabilities: Vec<CisaEntry>,
}

#[derive(Deserialize)]
struct CisaEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: Option<String>,
    product: Option<String>,
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

    let found = feed
        .known_exploited_vulnerabilities
        .into_iter()
        .find(|entry| entry.cve_id.eq_ignore_ascii_case(&indicator.value));

    if let Some(entry) = found {
        let vendor_project = entry.vendor_project.clone().unwrap_or_default();
        let product = entry.product.clone().unwrap_or_default();
        let summary = format!("Listed in CISA KEV feed: {} {}", vendor_project, product);

        Ok(vec![SourceFinding {
            source: "CISA KEV".to_string(),
            severity: Severity::High,
            summary,
            details: Some(serde_json::json!({
                "cve_id": entry.cve_id,
                "date_added": entry.date_added,
                "vendor_project": entry.vendor_project,
                "product": entry.product,
            })),
        }])
    } else {
        Ok(Vec::new())
    }
}
