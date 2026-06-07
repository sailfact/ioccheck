use ioccheck::output::{Severity, SourceFinding};
use ioccheck::scoring::{score_findings, severity_from_score};
use ioccheck::sources::names;

#[test]
fn score_no_findings_is_zero() {
    let result = score_findings(&[]);
    assert_eq!(result, 0);
}

#[test]
fn score_cisa_kev_is_high() {
    let findings = vec![SourceFinding {
        source: "CISA KEV".to_string(),
        severity: Severity::High,
        summary: "Listed in CISA KEV".to_string(),
        details: None,
    }];

    assert_eq!(score_findings(&findings), 40);
}

#[test]
fn score_otx_medium_is_fifteen() {
    let findings = vec![SourceFinding {
        source: "AlienVault OTX".to_string(),
        severity: Severity::Medium,
        summary: "AlienVault OTX: seen in 7 pulses".to_string(),
        details: None,
    }];

    assert_eq!(score_findings(&findings), 15);
}

#[test]
fn score_nvd_uses_severity_default() {
    let findings = vec![SourceFinding {
        source: "NVD".to_string(),
        severity: Severity::Critical,
        summary: "NVD: CVSS 10.0 (critical)".to_string(),
        details: None,
    }];

    assert_eq!(score_findings(&findings), 30);
}

/// Scoring-contract guard: every known source name must score non-zero, so a
/// renamed source (whose findings would fall through to a default arm or be
/// dropped) is caught here rather than silently contributing nothing. A
/// `Medium` finding yields a positive score under every source's arm.
#[test]
fn every_known_source_scores_non_zero() {
    for source in names::ALL {
        let findings = vec![SourceFinding {
            source: source.to_string(),
            severity: Severity::Medium,
            summary: format!("{source}: contract guard"),
            details: None,
        }];

        assert!(
            score_findings(&findings) > 0,
            "source {source:?} scored zero — check its arm in scoring.rs"
        );
    }
}

#[test]
fn severity_from_score_map() {
    assert_eq!(severity_from_score(0), Severity::Low);
    assert_eq!(severity_from_score(25), Severity::Medium);
    assert_eq!(severity_from_score(55), Severity::High);
    assert_eq!(severity_from_score(90), Severity::Critical);
}
