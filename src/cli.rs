use clap::Parser;

#[derive(Parser)]
#[command(
    name = "depblast",
    version,
    about = "Dependency vulnerability scanner: lockfile -> OSV CVEs -> source blast radius"
)]
pub struct Cli {
    /// Directory to scan (default: current directory)
    #[arg(value_name = "SOURCE_DIR")]
    pub source_dir: Option<std::path::PathBuf>,

    /// Only check a specific package
    #[arg(short, long)]
    pub package: Option<String>,

    /// Output machine-readable JSON
    #[arg(short, long)]
    pub json: bool,

    /// Refresh the local CVE cache
    #[arg(short, long)]
    pub update: bool,

    /// Include dev-only dependencies
    #[arg(long)]
    pub dev: bool,

    /// Exit code 1 if any vulnerability of this severity or higher is found
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,

    /// Run the AI slop & vibe-coding security audit alongside dependency scanning
    #[arg(long)]
    pub slop: bool,

    /// Run only the AI slop & security audit (skip dependency scanning)
    #[arg(long)]
    pub slop_only: bool,

    /// Run everything: dependency scan + AI slop audit
    #[arg(long)]
    pub all: bool,
}
