use crate::output::{Severity, SourceFinding};

pub fn score_findings(findings: &[SourceFinding]) -> u8 {
    let mut score = 0u8;

    for finding in findings {
        match finding.source.as_str() {
            "CISA KEV" => score = score.saturating_add(40),
            "URLhaus" => score = score.saturating_add(30),
            "MalwareBazaar" => score = score.saturating_add(30),
            "ThreatFox" => score = score.saturating_add(30),
            "AbuseIPDB" => match finding.severity {
                Severity::High => score = score.saturating_add(30),
                Severity::Medium => score = score.saturating_add(15),
                Severity::Low => score = score.saturating_add(5),
                Severity::Info => {}
                Severity::Critical => score = score.saturating_add(30),
            },
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
