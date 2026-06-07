use ioccheck::indicator::{Indicator, IndicatorType};
use ioccheck::output::{AnalysisResult, BatchReport, BatchSummary, Severity, SourceFinding};

#[test]
fn json_single_result_shape_is_stable() {
    let indicator = Indicator::new("185.220.101.42", IndicatorType::Ip);
    let analysis = AnalysisResult::new(
        &indicator,
        Severity::High,
        75,
        vec![SourceFinding {
            source: "AbuseIPDB".to_string(),
            severity: Severity::High,
            summary: "83 reports, confidence 92%".to_string(),
            details: None,
        }],
    );

    let value = serde_json::to_value(&analysis).unwrap();

    assert_eq!(value["indicator"], "185.220.101.42");
    assert_eq!(value["indicator_type"], "ip");
    assert_eq!(value["risk"], "high");
    assert_eq!(value["score"], 75);
    assert_eq!(value["findings"][0]["source"], "AbuseIPDB");
    assert_eq!(value["findings"][0]["severity"], "high");
    assert_eq!(
        value["findings"][0]["summary"],
        "83 reports, confidence 92%"
    );
}

#[test]
fn json_batch_result_shape_is_stable() {
    let indicator = Indicator::new("CVE-2024-3094", IndicatorType::Cve);
    let result = AnalysisResult::new(&indicator, Severity::High, 40, Vec::new());
    let report = BatchReport {
        results: vec![result],
        summary: BatchSummary {
            scanned: 2,
            info: 0,
            low: 0,
            medium: 0,
            high: 1,
            critical: 0,
            errors: 1,
        },
    };

    let value = serde_json::to_value(&report).unwrap();

    assert_eq!(value["results"][0]["indicator"], "CVE-2024-3094");
    assert_eq!(value["results"][0]["indicator_type"], "cve");
    assert_eq!(value["summary"]["scanned"], 2);
    assert_eq!(value["summary"]["errors"], 1);
}
