use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "ioccheck",
    version,
    about = "Enrich indicators of compromise with public threat intelligence."
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,

    #[arg(long, global = true)]
    pub no_color: bool,

    #[arg(long, global = true, default_value_t = 15)]
    pub timeout: u64,

    #[arg(
        long,
        global = true,
        help = "Cache normalized source findings under ~/.cache/ioccheck and reuse fresh entries"
    )]
    pub cache: bool,

    #[arg(
        long,
        global = true,
        default_value_t = 3600,
        help = "Max age in seconds for a cached entry to be reused (requires --cache)"
    )]
    pub cache_ttl: u64,

    #[arg(long, global = true, value_enum)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_flags_are_accepted_after_file_subcommand() {
        let cli = Cli::try_parse_from([
            "ioccheck",
            "file",
            "indicators.txt",
            "--json",
            "--fail-on",
            "high",
            "--cache",
            "--cache-ttl",
            "120",
        ])
        .expect("global flags should work after subcommands");

        assert!(cli.json);
        assert!(cli.cache);
        assert_eq!(cli.cache_ttl, 120);
        assert!(matches!(cli.fail_on, Some(FailThreshold::High)));
        assert!(matches!(cli.command, Command::File { .. }));
    }

    #[test]
    fn global_flags_are_accepted_after_single_lookup_subcommand() {
        let cli = Cli::try_parse_from(["ioccheck", "cve", "CVE-2024-3094", "--json"])
            .expect("global flags should work after subcommands");

        assert!(cli.json);
        assert!(matches!(cli.command, Command::Cve { .. }));
    }
}
