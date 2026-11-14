//! The v3 SAST engine: AST-based analysis with taint tracking, entropy
//! verification, path-context awareness and inline suppression.

pub mod context;
pub mod parser;
pub mod suppression;
pub mod walk;

use std::collections::HashSet;

use crate::model::{SlopCategory, SlopFinding};
use crate::rules::{python, secrets};
use crate::taint;

/// Analyze one Python source file with the full engine pipeline:
///
/// 1. Intra-procedural taint analysis (drives `CRITICAL` sink findings).
/// 2. AST security rules (calls, assignments, keyword arguments).
/// 3. AST-based unused-import detection (`__future__` whitelisted).
/// 4. High-confidence line-level rules (token-shaped secrets, TODO markers).
/// 5. Inline suppression via `# sast-ignore` comment nodes.
pub fn analyze_python(rel: &str, src: &str) -> Vec<SlopFinding> {
    let Some(tree) = parser::parse_python(src) else {
        return Vec::new();
    };

    let mut out = Vec::new();

    // 1) Taint first: its findings upgrade sinks to CRITICAL and suppress the
    //    generic AST eval/exec finding on the same line.
    let taint_hits = taint::analyze(src, &tree);
    let tainted_sinks: HashSet<usize> = taint_hits.iter().map(|h| h.line).collect();
    for hit in &taint_hits {
        out.push(SlopFinding::new(
            rel,
            hit.line,
            SlopCategory::DangerousSink,
            "CRITICAL",
            "tainted-input-to-sink",
            format!("tainted input from `{}` reaches `{}`", hit.origin, hit.sink),
            "Validate and sanitize the value at the trust boundary; never feed request data straight into execution sinks.",
        ));
    }

    // 2) AST security rules.
    python::run_rules(&tree, src, &tainted_sinks, rel, &mut out);

    // 3) Unused imports (AST-derived, `__future__` whitelisted).
    python::unused_imports(&tree, src, rel, &mut out);

    // 4) High-confidence line rules (entropy-verified secrets, TODO markers).
    secrets::line_checks(rel, src, &mut out);

    // 5) Inline suppression.
    let comments = suppression::python_comments(tree.root_node(), src);
    let rows = suppression::suppressed_rows(&comments.iter().map(|(r, t)| (*r, t.as_str())).collect::<Vec<_>>());
    out.retain(|f| !rows.contains(&(f.line - 1)));

    out
}
