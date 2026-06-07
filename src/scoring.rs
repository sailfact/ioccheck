use crate::output::{Severity, SourceFinding};
use crate::sources::names;

pub fn score_findings(findings: &[SourceFinding]) -> u8 {
    let mut score = 0u8;

    for finding in findings {
        match finding.source.as_str() {
            names::CISA_KEV => score = score.saturating_add(40),
            names::URLHAUS => score = score.saturating_add(30),
            names::MALWAREBAZAAR => score = score.saturating_add(30),
            names::THREATFOX => score = score.saturating_add(30),
            names::ABUSEIPDB => match finding.severity {
                Severity::High => score = score.saturating_add(30),
                Severity::Medium => score = score.saturating_add(15),
                Severity::Low => score = score.saturating_add(5),
                Severity::Info => {}
                Severity::Critical => score = score.saturating_add(30),
            },
            names::OTX => match finding.severity {
                Severity::Medium => score = score.saturating_add(15),
                Severity::Low => score = score.saturating_add(5),
                _ => {}
            },
            // NVD (and any other source) scores by its normalized severity.
            _ => match finding.severity {
                Severity::Critical => score = score.saturating_add(30),
                Severity::High => score = score.saturating_add(20),
                Severity::Medium => score = score.saturating_add(10),
                Severity::Low => score = score.saturating_add(5),
                Severity::Info => {}
            },
        }
    }

    score.min(100)
}

pub fn severity_from_score(score: u8) -> Severity {
    match score {
        0..=19 => Severity::Low,
        20..=49 => Severity::Medium,
        50..=79 => Severity::High,
        _ => Severity::Critical,
    }
}
