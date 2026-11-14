use crate::model::{Report, SlopCategory};
use colored::{ColoredString, Colorize};

fn paint_severity(s: &str) -> ColoredString {
    match s {
        "CRITICAL" => "CRITICAL".red().bold(),
        "HIGH" => "HIGH".red(),
        "MEDIUM" => "MEDIUM".yellow(),
        "LOW" => "LOW".green(),
        _ => "UNKNOWN".white(),
    }
}

pub fn render(report: &Report, json: bool) -> String {
    if json {
        return serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());
    }

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
            out.push_str(&format!("  file: {} {}\n", h.file, h.line.map_or_else(String::new, |l| format!(":{}", l))));
        }
    }

    if !report.slop.is_empty() {
        out.push_str(&format!(
            "\nAI slop & security audit — {} findings:\n",
            report.slop.len()
        ));
        for f in &report.slop {
            let cat = match f.category {
                SlopCategory::Secret => "SECRET".red().bold(),
                SlopCategory::LazyConfig => "LAZY_CONFIG".yellow(),
                SlopCategory::DangerousSink => "DANGEROUS_SINK".red(),
                SlopCategory::AiSlop => "AI_SLOP".cyan(),
            };
            out.push_str(&format!(
                "  {} {} {}:{} — {}\n    fix: {}\n",
                cat,
                paint_severity(&f.severity),
                f.file,
                f.line,
                f.detail,
                f.fix_tip
            ));
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
