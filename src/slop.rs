//! Slop/sast audit dispatcher (v4): two-pass cross-file engine.
//!
//! Pass 1 indexes every file into a global `SymbolTable` (modules, imports,
//! function IR, endpoints). Pass 2 runs the cross-file taint engine per rule
//! in parallel, alongside the v3 per-file AST engine (secrets, insecure
//! defaults, unused imports) and the legacy JS/TS line rules.

use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use rayon::prelude::*;

use crate::engine;
use crate::framework;
use crate::indexer;
use crate::model::{AttackSurface, SlopCategory, SlopFinding};
use crate::rules::secrets;
use crate::rules::taint_rules::RuleRegistry;
use crate::taint::xfile;

const PY_EXTS: &[&str] = &["py", "pyw"];
const JS_EXTS: &[&str] = &["js", "ts", "jsx", "tsx", "mjs", "cjs", "vue", "svelte"];

/// Attack surface computed during the audit, returned alongside findings.
pub struct AuditResult {
    pub findings: Vec<SlopFinding>,
    pub attack_surface: Option<AttackSurface>,
}

/// Run the audit over an already-collected list of source files.
///
/// Two passes, both parallel:
/// 1. Index every file into the global `SymbolTable`.
/// 2. Cross-file taint per YAML rule + per-file v3 AST engine + framework
///    access-control analysis.
pub fn audit(
    root: &Path,
    files: &[std::path::PathBuf],
    max_depth: usize,
    rules_path: Option<&Path>,
) -> AuditResult {
    // ---- Pass 1: global symbol table ----
    let table = indexer::SymbolTable::build(files, root);

    // Framework analysis: access-control findings + attack surface stats.
    let (ac_findings, surface) = framework::analyze(&table);

    // ---- Pass 2a: cross-file taint per rule ----
    let mut registry = RuleRegistry::builtin();
    if let Some(path) = rules_path {
        match registry.load_extra(path) {
            Ok(n) => eprintln!("loaded {n} extra ruleset rule(s) from {}", path.display()),
            Err(e) => eprintln!("warning: failed to load extra rules: {e:?}"),
        }
    }
    let budget = Arc::new(AtomicUsize::new(200_000));
    let py_files: Vec<&std::path::PathBuf> = files
        .iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| PY_EXTS.contains(&e.to_lowercase().as_str()))
                .unwrap_or(false)
        })
        .collect();

    let taint_findings: Vec<SlopFinding> = py_files
        .par_iter()
        .flat_map_iter(|path| {
            let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().to_string();
            let mut per_rule = Vec::new();
            for rule in &registry.rules {
                // Language gating: rules may restrict themselves to a language.
                if !rule.languages.is_empty()
                    && !rule.languages.iter().any(|l| l == "python")
                {
                    continue;
                }
                let engine = xfile::Engine::new(&table, rule, max_depth, budget.clone());
                per_rule.extend(engine.analyze_file(&rel));
            }
            per_rule
        })
        .collect();

    // ---- Pass 2b: per-file v3 engine (AST rules, secrets, unused imports) ----
    let mut findings: Vec<SlopFinding> = files
        .par_iter()
        .filter_map(|path| audit_one(root, path))
        .flatten()
        .collect();
    // v3's intra-procedural taint findings are superseded by v4's cross-file
    // engine (same class of issue, richer trace paths).
    findings.retain(|f| f.rule != "tainted-input-to-sink");
    findings.extend(taint_findings);
    findings.extend(ac_findings);

    // Context-aware path filtering: downgrade test/mock findings to INFO.
    for f in &mut findings {
        let in_test = engine::context::is_test_path(&f.file);
        if in_test {
            f.in_test_context = true;
            f.severity = "INFO".into();
        }
    }

    findings.sort_by(|a, b| {
        a.file.cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then_with(|| {
                crate::model::severity_to_rank(Some(&b.severity))
                    .cmp(&crate::model::severity_to_rank(Some(&a.severity)))
            })
    });
    findings.dedup_by(|a, b| {
        a.file == b.file && a.line == b.line && a.rule == b.rule && a.category == b.category
    });
    AuditResult {
        findings,
        attack_surface: Some(surface),
    }
}

fn audit_one(root: &Path, path: &std::path::PathBuf) -> Option<Vec<SlopFinding>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())?;
    let is_py = PY_EXTS.contains(&ext.as_str());
    let is_js = JS_EXTS.contains(&ext.as_str());
    if !is_py && !is_js {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().to_string();

    let findings = if is_py {
        // v3: AST + intra taint + entropy + suppression engine.
        engine::analyze_python(&rel, &content)
    } else {
        check_js(&rel, &content, &ext)
    };
    Some(findings)
}

// ---------------------------------------------------------------------------
// JS/TS checks (line-based)
// ---------------------------------------------------------------------------

static JS_REJECT_UNAUTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)rejectUnauthorized\s*:\s*false\b").unwrap());
static JS_CORS_WILDCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\borigin\s*:\s*["']\*["']"#).unwrap());

static JS_EVAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\beval\s*\(").unwrap());
static JS_NEW_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+Function\s*\(").unwrap());
static JS_EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bexec(?:Sync)?\s*\(").unwrap());
static JS_SHELL_TRUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bshell\s*:\s*true\b").unwrap());
static JS_THROW_NI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)throw\s+new\s+Error\(\s*["'][^"']*(not implemented|unimplemented|not supported|todo)"#)
        .unwrap()
});

static JS_IMPORT_FROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*import\s+([^'";]+?)\s+from\s+['"][^'"]+['"]"#).unwrap());
static JS_REQUIRE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*const\s+([A-Za-z_$][\w$]*|\{[^}]*\})\s*=\s*require\s*\("#).unwrap());
static JS_SAST_IGNORE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*//.*sast-ignore").unwrap());

use std::sync::LazyLock;
use regex::Regex;

fn check_js(rel: &str, content: &str, ext: &str) -> Vec<SlopFinding> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();

    // Shared high-confidence rules (entropy-verified secrets, TODO markers).
    secrets::line_checks(rel, content, &mut out);

    // Inline suppression for JS: `// sast-ignore` on a line silences that line
    // and the one below it.
    let mut suppressed = std::collections::HashSet::new();
    for (idx, line) in lines.iter().enumerate() {
        if JS_SAST_IGNORE.is_match(line) {
            suppressed.insert(idx);
            suppressed.insert(idx + 1);
        }
    }

    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("*") {
            continue;
        }

        // 2) Lazy AI security defaults.
        if JS_REJECT_UNAUTH.is_match(line) {
            push(&mut out, rel, line_no, "tls-reject-disabled", SlopCategory::LazyConfig, "HIGH",
                "TLS certificate validation disabled (`rejectUnauthorized: false`)",
                "Remove rejectUnauthorized:false and trust a proper CA bundle — this setting enables MITM attacks.");
        }
        if JS_CORS_WILDCARD.is_match(line) {
            push(&mut out, rel, line_no, "cors-wildcard", SlopCategory::LazyConfig, "MEDIUM",
                "CORS `origin: \"*\"` allows any site to call this endpoint",
                "Echo an explicit allow-list of origins instead of the wildcard.");
        }

        // 3) Dangerous execution sinks.
        if JS_EVAL.is_match(line) {
            push(&mut out, rel, line_no, "eval-use", SlopCategory::DangerousSink, "HIGH",
                "use of `eval()` on dynamic input",
                "Replace eval() with JSON.parse or an explicit parser; eval on untrusted input is remote code execution.");
        }
        if JS_NEW_FUNCTION.is_match(line) {
            push(&mut out, rel, line_no, "new-function", SlopCategory::DangerousSink, "HIGH",
                "dynamic code generation via `new Function()`",
                "Avoid new Function() — it is eval in disguise; use explicit logic or a vetted DSL.");
        }
        if (JS_EXEC.is_match(line) && line.contains('`') && exec_is_process_call(line))
            || (JS_EXEC.is_match(line) && line.contains("child_process"))
        {
            push(&mut out, rel, line_no, "exec-shell-injection", SlopCategory::DangerousSink, "HIGH",
                "`child_process.exec` with a template literal (shell injection risk)",
                "Use execFile/spawn with an argv array instead of building a shell string via interpolation.");
        }
        if JS_SHELL_TRUE.is_match(line) {
            push(&mut out, rel, line_no, "shell-true", SlopCategory::DangerousSink, "HIGH",
                "spawn/exec with shell:true",
                "Use spawn with an argv array and no shell option; interpolate nothing into shell strings.");
        }

        // 4b) Unfinished placeholders.
        if JS_THROW_NI.is_match(line) {
            push(&mut out, rel, line_no, "not-implemented", SlopCategory::AiSlop, "MEDIUM",
                "`throw new Error(\"Not implemented\")` — unfinished implementation",
                "Complete the implementation before merging, or make the unimplemented path unreachable.");
        }
    }

    // 4a) Unused imports.
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        for name in js_import_names(raw) {
            // The classic-runtime JSX import (`import React from 'react'`) may
            // be required even without a `React.` reference — don't flag it.
            if name.eq_ignore_ascii_case("react") && matches!(ext, "jsx" | "tsx") {
                continue;
            }
            if crate::rules::python::name_is_referenced(&name, &lines, idx) {
                continue;
            }
            push(&mut out, rel, line_no, "unused-import", SlopCategory::AiSlop, "LOW",
                format!("unused import: `{name}`"),
                "Remove the unused import — dead code is a typical AI-slop artifact.");
        }
    }

    out.retain(|f| !suppressed.contains(&(f.line - 1)));
    out
}

fn push(
    out: &mut Vec<SlopFinding>,
    rel: &str,
    line: usize,
    rule: &str,
    category: SlopCategory,
    severity: &str,
    detail: impl Into<String>,
    tip: &str,
) {
    out.push(SlopFinding::new(rel, line, category, severity, rule, detail, tip));
}

/// Heuristic: does an `exec(` match refer to process execution (child_process)
/// rather than, say, `regex.exec()`? Checks that the call is not a plain
/// method call on another object (preceding char is not `.`), or that the
/// line mentions child_process explicitly.
fn exec_is_process_call(line: &str) -> bool {
    if line.contains("child_process") || line.contains("childProcess") {
        return true;
    }
    if let Some(m) = JS_EXEC.find(line) {
        let before = m.start();
        if before == 0 {
            return true;
        }
        let prev = line[..before].chars().last().unwrap_or(' ');
        return prev != '.';
    }
    false
}

/// Local names introduced by a JS/TS import line.
fn js_import_names(line: &str) -> Vec<String> {
    let mut names = Vec::new();

    if let Some(m) = JS_IMPORT_FROM.captures(line) {
        names.extend(js_binding_names(&m[1]));
    } else if let Some(m) = JS_REQUIRE.captures(line) {
        names.extend(js_binding_names(&m[1]));
    }
    names
}

/// Parse an ES import binding (`React`, `{ a, b as c }`, `* as ns`,
/// `React, { useState }`, `type Foo`) into local names.
fn js_binding_names(binding: &str) -> Vec<String> {
    let mut names = Vec::new();
    let binding = binding.trim();
    let binding = binding.strip_prefix("type ").unwrap_or(binding).trim();

    if let Some(open) = binding.find('{') {
        let close = binding.find('}').unwrap_or(binding.len());
        let default_part = &binding[..open];
        let default_part = default_part.trim_matches(',').trim();
        if !default_part.is_empty() {
            names.push(last_identifier(default_part));
        }
        for item in binding[open + 1..close].split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let item = item.strip_prefix("type ").unwrap_or(item).trim();
            let local = item.split(" as ").last().unwrap_or(item).trim();
            // `b: c` (renamed) -> c; also handles object-destructure in require.
            let local = local.split(':').last().unwrap_or(local).trim();
            let local = local.trim_end_matches('?').trim();
            if !local.is_empty() && local != "*" {
                names.push(local.to_string());
            }
        }
    } else if let Some(idx) = binding.find("* as ") {
        let ns = binding[idx + 5..].trim();
        if !ns.is_empty() {
            names.push(ns.to_string());
        }
    } else {
        let n = last_identifier(binding);
        if !n.is_empty() {
            names.push(n);
        }
    }
    names
}

/// Last identifier-ish token of a fragment (`"React"` -> React).
fn last_identifier(fragment: &str) -> String {
    fragment
        .split_whitespace()
        .last()
        .unwrap_or("")
        .trim_matches(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .to_string()
}
