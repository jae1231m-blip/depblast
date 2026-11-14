//! Fast, low-false-positive "AI slop & vibe-coding" security auditor.
//!
//! Runs a set of targeted regex heuristics over Python and JS/TS source files
//! to surface:
//!
//! 1. Hardcoded secrets & tokens (API keys, tokens, PEM blocks, ...)
//! 2. Lazy AI security defaults (SSL bypass, debug mode, 0.0.0.0 binds, CORS `*`)
//! 3. Dangerous execution sinks (`eval`, `exec`, `pickle.loads`, unsafe
//!    `yaml.load`, `shell=True`, `child_process.exec` with template literals)
//! 4. AI slop code smells (unused imports, unfinished placeholders)
//!
//! The checks are deliberately conservative: matches that look like obvious
//! placeholders (`YOUR_API_KEY`, `${...}`, `process.env`, ...) are skipped so
//! the signal stays high.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{SlopCategory, SlopFinding};

const PY_EXTS: &[&str] = &["py", "pyw"];
const JS_EXTS: &[&str] = &["js", "ts", "jsx", "tsx", "mjs", "cjs", "vue", "svelte"];

/// Substrings that make an assigned "secret" value an obvious placeholder
/// rather than a real credential. Matched case-insensitively.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "your", "xxx", "<", "${", "%s", "example", "placeholder", "changeme",
    "change_me", "dummy", "fake", "todo", "insert_", "****", "...",
];

type Seen = HashSet<(String, usize, String)>;

/// Run the audit over an already-collected list of source files.
/// Returns findings sorted by file, line, then severity (worst first).
pub fn audit(root: &Path, files: &[std::path::PathBuf]) -> Vec<SlopFinding> {
    let mut findings: Vec<SlopFinding> = Vec::new();
    let mut seen: Seen = HashSet::new();

    for path in files {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        let is_py = PY_EXTS.contains(&ext.as_str());
        let is_js = JS_EXTS.contains(&ext.as_str());
        if !is_py && !is_js {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().to_string();
        let lines: Vec<&str> = content.lines().collect();
        if is_py {
            check_python(&rel, &lines, &mut findings, &mut seen);
        } else {
            check_js(&rel, &lines, &ext, &mut findings, &mut seen);
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
    findings
}

fn push(
    out: &mut Vec<SlopFinding>,
    seen: &mut Seen,
    file: &str,
    line: usize,
    rule: &str,
    category: SlopCategory,
    severity: &str,
    detail: impl Into<String>,
    tip: &str,
) {
    if seen.insert((file.to_string(), line, rule.to_string())) {
        out.push(SlopFinding {
            file: file.to_string(),
            line,
            category,
            severity: severity.to_string(),
            rule: rule.to_string(),
            detail: detail.into(),
            fix_tip: tip.to_string(),
        });
    }
}

fn is_placeholder(value: &str) -> bool {
    let v = value.to_lowercase();
    PLACEHOLDER_MARKERS.iter().any(|m| v.contains(m))
}

// ---------------------------------------------------------------------------
// Shared secret/token rules (applied to Python and JS/TS alike).
// ---------------------------------------------------------------------------

struct TokenRule {
    re: Regex,
    rule: &'static str,
    severity: &'static str,
    detail: &'static str,
    tip: &'static str,
}

static TOKEN_RULES: LazyLock<Vec<TokenRule>> = LazyLock::new(|| {
    vec![
        TokenRule {
            re: Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").unwrap(),
            rule: "embedded-private-key",
            severity: "CRITICAL",
            detail: "Private key material embedded in source code",
            tip: "Keep private keys in a secrets manager or a protected key file; rotate any key that was committed.",
        },
        TokenRule {
            re: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b").unwrap(),
            rule: "github-token",
            severity: "HIGH",
            detail: "GitHub token (ghp_/gho_/ghs_/...) hardcoded",
            tip: "Use `gh auth` / an environment variable instead; revoke the leaked token immediately.",
        },
        TokenRule {
            re: Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b").unwrap(),
            rule: "github-pat",
            severity: "HIGH",
            detail: "GitHub fine-grained personal access token hardcoded",
            tip: "Move the PAT to an environment variable and revoke the exposed one.",
        },
        TokenRule {
            re: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            rule: "aws-access-key",
            severity: "HIGH",
            detail: "AWS access key id (AKIA…) hardcoded",
            tip: "Rotate the key pair, then use short-lived roles or env vars instead of static keys.",
        },
        TokenRule {
            re: Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap(),
            rule: "bearer-style-api-key",
            severity: "HIGH",
            detail: "API key literal (sk-…, e.g. OpenAI/Anthropic style) hardcoded",
            tip: "Load the key from an environment variable or secret manager and rotate the exposed key.",
        },
        TokenRule {
            re: Regex::new(r"\bsk_live_[A-Za-z0-9]{20,}\b").unwrap(),
            rule: "stripe-live-key",
            severity: "CRITICAL",
            detail: "Stripe live secret key (sk_live_…) hardcoded",
            tip: "Roll the key in the Stripe dashboard and read it from the environment at runtime.",
        },
        TokenRule {
            re: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
            rule: "slack-token",
            severity: "HIGH",
            detail: "Slack token (xoxb-/xoxp-/…) hardcoded",
            tip: "Store Slack tokens in env vars and regenerate the leaked one.",
        },
        TokenRule {
            re: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(),
            rule: "google-api-key",
            severity: "HIGH",
            detail: "Google API key (AIza…) hardcoded",
            tip: "Restrict and rotate the key, then inject it via the environment.",
        },
    ]
});

static SECRET_ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    // `api_key = "..."`, `password: "..."`, `const authToken = "..."` etc.
    Regex::new(
        r#"(?i)\b(api[_-]?key|api[_-]?secret|secret|client[_-]?secret|secret[_-]?key|password|passwd|pwd|token|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[=:]\s*["']([^"']{8,})["']"#,
    )
    .unwrap()
});

static TODO_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(TODO|FIXME|XXX)\b").unwrap());

fn check_todo(
    file: &str,
    line_no: usize,
    line: &str,
    out: &mut Vec<SlopFinding>,
    seen: &mut Seen,
) {
    // 4b) Unfinished AI placeholders: TODO / FIXME markers (incl. comment-only
    // lines, which most TODOs live on).
    if TODO_MARKER.is_match(line) {
        push(
            out, seen, file, line_no, "todo-marker", SlopCategory::AiSlop, "LOW",
            "leftover TODO/FIXME marker (possibly an unfinished AI-generated stub)",
            "Finish the work or convert it to a tracked ticket before merging.",
        );
    }
}

fn check_common(
    file: &str,
    line_no: usize,
    line: &str,
    out: &mut Vec<SlopFinding>,
    seen: &mut Seen,
) {
    // 1) Known token formats (high confidence).
    for rule in TOKEN_RULES.iter() {
        if rule.re.is_match(line) {
            push(
                out, seen, file, line_no, rule.rule, SlopCategory::Secret, rule.severity,
                rule.detail.to_string(), rule.tip,
            );
        }
    }

    // 1b) Generic credential assignment with a non-placeholder value.
    if let Some(m) = SECRET_ASSIGN.captures(line) {
        let value = &m[2];
        if !is_placeholder(value) {
            push(
                out, seen, file, line_no, "hardcoded-secret", SlopCategory::Secret, "HIGH",
                format!("hardcoded credential literal for `{}`", &m[1]),
                "Load credentials from the environment or a secrets manager — never commit literals.",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Python checks
// ---------------------------------------------------------------------------

static PY_VERIFY_FALSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bverify\s*=\s*False\b").unwrap());
static PY_DEBUG_TRUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bdebug\s*=\s*True\b").unwrap());
static PY_BIND_ALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhost\s*=\s*["']0\.0\.0\.0["']"#).unwrap());
static PY_CORS_WILDCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)allow_origins?\s*=\s*\[?\s*["']\*["']"#).unwrap());

static PY_EVAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\beval\s*\(").unwrap());
static PY_EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bexec\s*\(").unwrap());
static PY_PICKLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bpickle\.loads?\s*\(").unwrap());
static PY_YAML_LOAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\byaml\.load\s*\(").unwrap());
static PY_YAML_UNSAFE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\byaml\.unsafe_load\s*\(").unwrap());
static PY_SHELL_TRUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bshell\s*=\s*True\b").unwrap());
static PY_RAISE_NIE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\braise\s+NotImplementedError\b").unwrap());
static PY_PASS_STUB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*pass\b[^:\n]*#\s*.*\b(implement|todo|later|placeholder|for now|future)\b")
        .unwrap()
});

static PY_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*import\s+([^\s#].*)$").unwrap());
static PY_FROM_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*from\s+([.\w]+)\s+import\s+(.+)$").unwrap());

fn check_python(file: &str, lines: &[&str], out: &mut Vec<SlopFinding>, seen: &mut Seen) {
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end();

        // TODO/FIXME markers can live on comment-only lines.
        check_todo(file, line_no, line, out, seen);

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // 2) Lazy AI security defaults.
        if PY_VERIFY_FALSE.is_match(line) {
            push(
                out, seen, file, line_no, "ssl-verify-disabled", SlopCategory::LazyConfig, "HIGH",
                "SSL certificate verification disabled (`verify=False`)",
                "Remove verify=False; pass a CA bundle (e.g. certifi) instead — disabled checks enable MITM attacks.",
            );
        }
        if PY_DEBUG_TRUE.is_match(line) {
            push(
                out, seen, file, line_no, "debug-enabled", SlopCategory::LazyConfig, "MEDIUM",
                "debug mode enabled (`debug=True`) leaks stack traces and config",
                "Drive debug mode from an env var (e.g. app.run(debug=DEBUG)) and keep it off in production.",
            );
        }
        if PY_BIND_ALL.is_match(line) {
            push(
                out, seen, file, line_no, "bind-0.0.0.0", SlopCategory::LazyConfig, "MEDIUM",
                "service bound to 0.0.0.0 (all interfaces)",
                "Bind to 127.0.0.1 for local dev, or front the service with a firewall/proxy if external access is required.",
            );
        }
        if PY_CORS_WILDCARD.is_match(line) {
            push(
                out, seen, file, line_no, "cors-wildcard", SlopCategory::LazyConfig, "MEDIUM",
                "CORS wildcard origin (`allow_origins=[\"*\"]`)",
                "List the exact origins that need access instead of reflecting any origin.",
            );
        }

        // 3) Dangerous execution sinks.
        if PY_EVAL.is_match(line) {
            push(
                out, seen, file, line_no, "eval-use", SlopCategory::DangerousSink, "HIGH",
                "use of `eval()` on dynamic input",
                "Replace eval() with ast.literal_eval() or explicit parsing; eval on untrusted input is remote code execution.",
            );
        }
        if PY_EXEC.is_match(line) {
            push(
                out, seen, file, line_no, "exec-use", SlopCategory::DangerousSink, "HIGH",
                "use of `exec()` on dynamic code",
                "Refactor away exec(); running dynamically built code is unsafe and untestable.",
            );
        }
        if PY_PICKLE.is_match(line) {
            push(
                out, seen, file, line_no, "pickle-load", SlopCategory::DangerousSink, "HIGH",
                "deserializing untrusted data with pickle",
                "Use JSON or another safe format for untrusted data; pickle.load on attacker-controlled bytes is RCE.",
            );
        }
        if PY_YAML_UNSAFE.is_match(line)
            || (PY_YAML_LOAD.is_match(line) && !line.contains("SafeLoader") && !line.contains("BaseLoader"))
        {
            push(
                out, seen, file, line_no, "unsafe-yaml-load", SlopCategory::DangerousSink, "HIGH",
                "yaml.load without SafeLoader can execute arbitrary constructors",
                "Use yaml.safe_load(...) or pass Loader=yaml.SafeLoader.",
            );
        }
        if PY_SHELL_TRUE.is_match(line) {
            push(
                out, seen, file, line_no, "shell-true", SlopCategory::DangerousSink, "HIGH",
                "subprocess call with shell=True",
                "Pass the command as an argv list without shell=True, and never interpolate untrusted input into it.",
            );
        }

        // 4b) Unfinished placeholders.
        if PY_RAISE_NIE.is_match(line) {
            push(
                out, seen, file, line_no, "not-implemented", SlopCategory::AiSlop, "MEDIUM",
                "raises NotImplementedError — unfinished implementation",
                "Complete the implementation or guard the call site before shipping.",
            );
        }
        if PY_PASS_STUB.is_match(line) {
            push(
                out, seen, file, line_no, "pass-stub", SlopCategory::AiSlop, "LOW",
                "`pass` stub with a deferred-work comment",
                "Replace the empty stub with a real implementation.",
            );
        }

        check_common(file, line_no, line, out, seen);
    }

    // 4a) Unused imports (needs whole-file context).
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        for name in py_import_names(raw) {
            if name_is_referenced(&name, lines, idx) {
                continue;
            }
            push(
                out, seen, file, line_no, "unused-import", SlopCategory::AiSlop, "LOW",
                format!("unused import: `{name}`"),
                "Remove the unused import — dead code is a typical AI-slop artifact.",
            );
        }
    }
}

/// Local names introduced by a Python import line (`import os, sys as system`,
/// `from typing import List, Dict as D`).
fn py_import_names(line: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(m) = PY_IMPORT.captures(line) {
        for part in m[1].split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // `foo.bar as fb` -> fb, `foo.bar` -> foo
            let local = part.split(" as ").last().unwrap_or(part).trim();
            let top = local.split('.').next().unwrap_or("").trim();
            if !top.is_empty() {
                names.push(top.to_string());
            }
        }
    } else if let Some(m) = PY_FROM_IMPORT.captures(line) {
        for part in m[2].split(',') {
            let part = part.trim();
            if part.is_empty() || part == "*" {
                continue;
            }
            let local = part.split(" as ").last().unwrap_or(part).trim();
            let local = local.split('(').next().unwrap_or(local).trim();
            if !local.is_empty() && local.chars().all(|c| c.is_alphanumeric() || c == '_') {
                names.push(local.to_string());
            }
        }
    }
    names
}

/// True when `name` appears as a whole word on any line other than line `skip`.
fn name_is_referenced(name: &str, lines: &[&str], skip: usize) -> bool {
    let re = match Regex::new(&format!(r"\b{}\b", regex::escape(name))) {
        Ok(r) => r,
        Err(_) => return true, // be conservative on regex failure
    };
    for (i, l) in lines.iter().enumerate() {
        if i == skip {
            continue;
        }
        if re.is_match(l) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// JS/TS checks
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

fn check_js(file: &str, lines: &[&str], ext: &str, out: &mut Vec<SlopFinding>, seen: &mut Seen) {
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end();

        // TODO/FIXME markers can live on comment-only lines.
        check_todo(file, line_no, line, out, seen);

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        // 2) Lazy AI security defaults.
        if JS_REJECT_UNAUTH.is_match(line) {
            push(
                out, seen, file, line_no, "tls-reject-disabled", SlopCategory::LazyConfig, "HIGH",
                "TLS certificate validation disabled (`rejectUnauthorized: false`)",
                "Remove rejectUnauthorized:false and trust a proper CA bundle — this setting enables MITM attacks.",
            );
        }
        if JS_CORS_WILDCARD.is_match(line) {
            push(
                out, seen, file, line_no, "cors-wildcard", SlopCategory::LazyConfig, "MEDIUM",
                "CORS `origin: \"*\"` allows any site to call this endpoint",
                "Echo an explicit allow-list of origins instead of the wildcard.",
            );
        }

        // 3) Dangerous execution sinks.
        if JS_EVAL.is_match(line) {
            push(
                out, seen, file, line_no, "eval-use", SlopCategory::DangerousSink, "HIGH",
                "use of `eval()` on dynamic input",
                "Replace eval() with JSON.parse or an explicit parser; eval on untrusted input is remote code execution.",
            );
        }
        if JS_NEW_FUNCTION.is_match(line) {
            push(
                out, seen, file, line_no, "new-function", SlopCategory::DangerousSink, "HIGH",
                "dynamic code generation via `new Function()`",
                "Avoid new Function() — it is eval in disguise; use explicit logic or a vetted DSL.",
            );
        }
        if (JS_EXEC.is_match(line) && line.contains('`') && exec_is_process_call(line))
            || (JS_EXEC.is_match(line) && line.contains("child_process"))
        {
            push(
                out, seen, file, line_no, "exec-shell-injection", SlopCategory::DangerousSink, "HIGH",
                "`child_process.exec` with a template literal (shell injection risk)",
                "Use execFile/spawn with an argv array instead of building a shell string via interpolation.",
            );
        }
        if JS_SHELL_TRUE.is_match(line) {
            push(
                out, seen, file, line_no, "shell-true", SlopCategory::DangerousSink, "HIGH",
                "spawn/exec with shell:true",
                "Use spawn with an argv array and no shell option; interpolate nothing into shell strings.",
            );
        }

        // 4b) Unfinished placeholders.
        if JS_THROW_NI.is_match(line) {
            push(
                out, seen, file, line_no, "not-implemented", SlopCategory::AiSlop, "MEDIUM",
                "`throw new Error(\"Not implemented\")` — unfinished implementation",
                "Complete the implementation before merging, or make the unimplemented path unreachable.",
            );
        }

        check_common(file, line_no, line, out, seen);
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
            if name_is_referenced(&name, lines, idx) {
                continue;
            }
            push(
                out, seen, file, line_no, "unused-import", SlopCategory::AiSlop, "LOW",
                format!("unused import: `{name}`"),
                "Remove the unused import — dead code is a typical AI-slop artifact.",
            );
        }
    }
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
