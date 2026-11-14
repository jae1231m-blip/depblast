//! Output rendering (v4): rich text with trace trees, JSON, and SARIF v2.1.0.

pub mod sarif;
pub mod text;

use crate::cli::Cli;
use crate::model::Report;

pub fn render(report: &Report, cli: &Cli) -> String {
    if cli.json {
        return serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());
    }
    if cli.format == "sarif" {
        return sarif::render(report);
    }
    text::render(report)
}
