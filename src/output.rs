use colored::Colorize;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn as_rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceFinding {
    pub source: String,
    pub severity: Severity,
    pub summary: String,
    pub details: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalysisResult {
    pub indicator: String,
    pub indicator_type: String,
    pub risk: String,
    pub score: u8,
    pub findings: Vec<SourceFinding>,
    pub summary: Option<String>,
}

impl AnalysisResult {
    pub fn new(
        indicator: &crate::indicator::Indicator,
        risk: Severity,
        score: u8,
        findings: Vec<SourceFinding>,
    ) -> Self {
        let summary = if findings.is_empty() {
            Some("No findings were identified for this indicator.".to_string())
        } else {
            None
        };

        Self {
            indicator: indicator.value.clone(),
            indicator_type: format!("{:?}", indicator.kind),
            risk: risk.as_str().to_string(),
            score,
            findings,
            summary,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BatchSummary {
    pub scanned: usize,
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
    pub errors: usize,
}

impl BatchSummary {
    pub fn from_results(results: &[AnalysisResult], errors: usize) -> Self {
        let mut info = 0;
        let mut low = 0;
        let mut medium = 0;
        let mut high = 0;
        let mut critical = 0;

        for result in results {
            match result.risk.as_str() {
                "info" => info += 1,
                "low" => low += 1,
                "medium" => medium += 1,
                "high" => high += 1,
                "critical" => critical += 1,
                _ => {}
            }
        }

        Self {
            scanned: results.len() + errors,
            info,
            low,
            medium,
            high,
            critical,
            errors,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BatchReport {
    pub results: Vec<AnalysisResult>,
    pub summary: BatchSummary,
}

pub struct OutputFormatter {
    no_color: bool,
    json: bool,
}

impl OutputFormatter {
    pub fn new(no_color: bool, json: bool) -> Self {
        Self { no_color, json }
    }

    pub fn print_single(&self, analysis: &AnalysisResult) -> Result<(), std::io::Error> {
        if self.json {
            let output = serde_json::to_string_pretty(&analysis).unwrap();
            println!("{}", output);
            return Ok(());
        }

        println!("Indicator: {}", analysis.indicator);
        println!("Type:      {}", analysis.indicator_type);
        println!("Risk:      {}", self.color_risk(&analysis.risk));
        println!("");
        println!("Findings:");

        if analysis.findings.is_empty() {
            println!("  None");
        } else {
            for finding in &analysis.findings {
                println!(
                    "  [{}] {}: {}",
                    finding.severity.as_str().to_uppercase(),
                    finding.source,
                    finding.summary
                );
            }
        }

        if let Some(summary) = &analysis.summary {
            println!("");
            println!("Recommendation:");
            println!("  {}", summary);
        }

        Ok(())
    }

    pub fn print_batch(&self, report: &BatchReport) -> Result<(), std::io::Error> {
        if self.json {
            let output = serde_json::to_string_pretty(&report).unwrap();
            println!("{}", output);
            return Ok(());
        }

        for result in &report.results {
            self.print_single(result)?;
            println!("---");
        }

        println!("Summary:");
        println!("  Scanned: {}", report.summary.scanned);
        println!("  Info:    {}", report.summary.info);
        println!("  Low:     {}", report.summary.low);
        println!("  Medium:  {}", report.summary.medium);
        println!("  High:    {}", report.summary.high);
        println!("  Critical:{}", report.summary.critical);
        println!("  Errors:  {}", report.summary.errors);
        Ok(())
    }

    fn color_risk(&self, value: &str) -> String {
        if self.no_color {
            return value.to_string();
        }

        match value {
            "critical" => value.red().to_string(),
            "high" => value.yellow().to_string(),
            "medium" => value.cyan().to_string(),
            "low" => value.green().to_string(),
            _ => value.normal().to_string(),
        }
    }
}
