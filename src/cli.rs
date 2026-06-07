use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "ioccheck",
    version,
    about = "Enrich indicators of compromise with public threat intelligence."
)]
pub struct Cli {
    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub no_color: bool,

    #[arg(long, default_value_t = 15)]
    pub timeout: u64,

    #[arg(long, help = "Reserved for v2; currently ignored")]
    pub cache: bool,

    #[arg(
        long,
        default_value_t = 3600,
        help = "Reserved for v2; currently ignored"
    )]
    pub cache_ttl: u64,

    #[arg(long, value_enum)]
    pub fail_on: Option<FailThreshold>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Ip { value: String },
    Domain { value: String },
    Url { value: String },
    Hash { value: String },
    Cve { value: String },
    File { path: std::path::PathBuf },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum FailThreshold {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailThreshold> for crate::output::Severity {
    fn from(value: FailThreshold) -> crate::output::Severity {
        match value {
            FailThreshold::Low => crate::output::Severity::Low,
            FailThreshold::Medium => crate::output::Severity::Medium,
            FailThreshold::High => crate::output::Severity::High,
            FailThreshold::Critical => crate::output::Severity::Critical,
        }
    }
}
