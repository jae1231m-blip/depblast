//! SARIF v2.1.0 export (v4) — compatible with GitHub Code Scanning.
//!
//! Every slop finding becomes a `result` with `ruleId`, `level`,
//! `locations`, a stable `partialFingerprints` hash, and a `codeFlow` with
//! the cross-file taint trace when one exists.

use std::collections::BTreeMap;

use crate::model::{Report, SlopFinding};

/// SARIF `level` from depblast severity.
fn level(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

/// Stable fingerprint: sha1-ish short hash of (file, line, rule).
fn fingerprint(f: &SlopFinding) -> String {
    let input = format!("{}:{}/{}:{}", f.file, f.line, f.rule, f.severity);
    // FNV-1a 64-bit — stable, dependency-free.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in input.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016X}")
}

/// Trace path as a single readable string for the message.
fn trace_text(f: &SlopFinding) -> String {
    if f.trace.is_empty() {
        return String::new();
    }
    let hops: Vec<String> = f
        .trace
        .iter()
        .map(|s| format!("{} ({}:{}) [{}]", s.kind.to_uppercase(), s.file, s.line, s.label))
        .collect();
    format!(" — trace: {}", hops.join(" -> "))
}

/// Rules referenced by the findings (deduplicated, sorted).
fn rules_for(findings: &[&SlopFinding]) -> Vec<serde_json::Value> {
    let mut by_id: BTreeMap<&str, &SlopFinding> = BTreeMap::new();
    for f in findings {
        by_id.entry(f.rule.as_str()).or_insert(f);
    }
    by_id
        .into_iter()
        .map(|(id, f)| {
            serde_json::json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": f.detail },
                "fullDescription": { "text": f.detail },
                "help": {
                    "text": f.fix_tip,
                    "markdown": f.fix_tip
                },
                "properties": {
                    "category": format!("{:?}", f.category),
                    "security-severity": match f.severity.as_str() {
                        "CRITICAL" => "9.5",
                        "HIGH" => "8.0",
                        "MEDIUM" => "5.5",
                        "LOW" | "INFO" => "2.0",
                        _ => "2.0",
                    }
                }
            })
        })
        .collect()
}

fn result_for(f: &SlopFinding) -> serde_json::Value {
    let mut result = serde_json::json!({
        "ruleId": f.rule,
        "level": level(&f.severity),
        "message": { "text": format!("{}{}", f.detail, trace_text(f)) },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": f.file },
                "region": { "startLine": f.line }
            }
        }],
        "partialFingerprints": { "depblastFinding/v1": fingerprint(f) }
    });
    if !f.trace.is_empty() {
        let steps: Vec<serde_json::Value> = f
            .trace
            .iter()
            .map(|s| {
                serde_json::json!({
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": { "uri": s.file },
                            "region": { "startLine": s.line }
                        },
                        "message": { "text": format!("{}: {}", s.kind, s.label) }
                    }
                })
            })
            .collect();
        result["codeFlows"] = serde_json::json!([{
            "threadFlows": [{ "locations": steps }]
        }]);
    }
    result
}

pub fn render(report: &Report) -> String {
    let all: Vec<&SlopFinding> = report.slop.iter().collect();
    let rules = rules_for(&all);
    let results: Vec<serde_json::Value> = all.iter().map(|f| result_for(f)).collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "depblast",
                    "informationUri": "https://github.com/jae1231m-blip/depblast",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}
