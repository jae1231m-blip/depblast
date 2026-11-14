//! Rich text rendering: attack surface summary, findings with trace trees.

use crate::model::{Report, SlopCategory, SlopFinding};
use colored::{ColoredString, Colorize};

fn paint_severity(s: &str) -> ColoredString {
    match s {
        "CRITICAL" => "CRITICAL".red().bold(),
        "HIGH" => "HIGH".red(),
        "MEDIUM" => "MEDIUM".yellow(),
        "LOW" => "LOW".green(),
        "INFO" => "INFO".cyan(),
        _ => "UNKNOWN".white(),
    }
}

fn paint_slop_finding(f: &SlopFinding) -> String {
    let cat = match f.category {
        SlopCategory::Secret => "SECRET".red().bold(),
        SlopCategory::LazyConfig => "LAZY_CONFIG".yellow(),
        SlopCategory::DangerousSink => "DANGEROUS_SINK".red(),
        SlopCategory::AccessControl => "ACCESS_CONTROL".magenta(),
        SlopCategory::AiSlop => "AI_SLOP".cyan(),
    };
    let mut out = format!(
        "  {} {} {}:{} — {}\n    fix: {}\n",
        cat,
        paint_severity(&f.severity),
        f.file,
        f.line,
        f.detail,
        f.fix_tip
    );
    if !f.trace.is_empty() {
        out.push_str("    trace:\n");
        for step in &f.trace {
            out.push_str(&format!(
                "      {} {}:{} — {}\n",
                step.kind, step.file, step.line, step.label
            ));
        }
    }
    out
}

fn attack_surface_section(report: &Report) -> String {
    let Some(surface) = &report.attack_surface else { return String::new() };
    let mut out = String::from("\nAttack surface:\n");
    out.push_str(&format!(
        "  HTTP endpoints: {} (unauthenticated state-changing: {})\n",
        surface.endpoints, surface.unauthenticated_endpoints
    ));
    out.push_str(&format!("  external network sinks: {}\n", surface.network_sinks));
    out.push_str(&format!("  OS command/code sinks: {}\n", surface.command_sinks));
    out
}

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "depblast v{} — scanning {} ({} files)\n",
        env!("CARGO_PKG_VERSION"),
        report.source_dir.display(),
        report.scanned_files
    ));

    if report.hits.is_empty() {
        if !report.slop_only {
            out.push_str("✓ No known vulnerabilities found.\n");
        }
    } else {
        out.push_str("Vulnerabilities found:\n");
        for h in &report.hits {
            let sev = paint_severity(&h.severity);
            let indent = "  ";
            out.push_str(&format!(
                "{}{}\n  {} — {}\n  chain: {}\n",
                indent,
                sev,
                h.package,
                h.version,
                h.chain.join(" → ")
            ));
            out.push_str(&format!(
                "  file: {} {}\n",
                h.file,
                h.line.map_or_else(String::new, |l| format!(":{l}"))
            ));
        }
    }

    out.push_str(&attack_surface_section(report));

    let (production, test): (Vec<&SlopFinding>, Vec<&SlopFinding>) = report
        .slop
        .iter()
        .partition(|f| !f.in_test_context);

    if !production.is_empty() {
        out.push_str(&format!(
            "\nAI slop & security audit — {} findings:\n",
            production.len()
        ));
        for f in &production {
            out.push_str(&paint_slop_finding(f));
        }
    }

    if !test.is_empty() {
        out.push_str(&format!(
            "\nTest/mock findings (INFO — isolated, do not gate CI) — {} findings:\n",
            test.len()
        ));
        for f in &test {
            out.push_str(&paint_slop_finding(f));
        }
    }

    if report.cache_status.used_cached > 0 || report.cache_status.fetched > 0 {
        out.push_str(&format!(
            "cache: {} used / {} fetched\n",
            report.cache_status.used_cached, report.cache_status.fetched
        ));
    }

    out
}
