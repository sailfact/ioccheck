use ioccheck::output::{Severity, SourceFinding};
use ioccheck::scoring::{score_findings, severity_from_score};

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
fn severity_from_score_map() {
    assert_eq!(severity_from_score(0), Severity::Low);
    assert_eq!(severity_from_score(25), Severity::Medium);
    assert_eq!(severity_from_score(55), Severity::High);
    assert_eq!(severity_from_score(90), Severity::Critical);
}
