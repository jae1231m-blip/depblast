//! AST-based Python security rules (tree-sitter).
//!
//! These replace v2's regex heuristics: standalone builtin calls (`exec(...)`)
//! are distinguished from object-method calls (`session.exec(...)`), insecure
//! defaults are matched as real keyword arguments / assignments, and eval/exec
//! severity is driven by taint analysis (CRITICAL) or literal arguments (LOW).

use std::collections::HashSet;

use tree_sitter::{Node, Tree};

use crate::model::{SlopCategory, SlopFinding};

pub fn run_rules(
    tree: &Tree,
    src: &str,
    tainted_sinks: &HashSet<usize>,
    rel: &str,
    out: &mut Vec<SlopFinding>,
) {
    visit(tree.root_node(), src, tainted_sinks, rel, out);
}

fn visit(node: Node, src: &str, tainted: &HashSet<usize>, rel: &str, out: &mut Vec<SlopFinding>) {
    match node.kind() {
        "call" => check_call(node, src, tainted, rel, out),
        "assignment" | "augmented_assignment" => check_assignment(node, src, rel, out),
        "keyword_argument" => check_kwarg(node, src, rel, out),
        _ => {}
    }
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        visit(child, src, tainted, rel, out);
        i += 1;
    }
}

fn line_of(node: Node) -> usize {
    node.start_position().row + 1
}

fn text<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    node.utf8_text(src.as_bytes()).ok()
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

fn check_call(node: Node, src: &str, tainted: &HashSet<usize>, rel: &str, out: &mut Vec<SlopFinding>) {
    let Some(func) = node.child_by_field_name("function") else { return };
    let Some(ftext) = text(func, src) else { return };
    let line = line_of(node);

    if func.kind() == "identifier" {
        // Standalone builtin: `exec(...)`, `eval(...)`.
        if matches!(ftext, "eval" | "exec") {
            if tainted.contains(&line) {
                return; // CRITICAL taint finding already covers this call
            }
            let literal = node
                .child_by_field_name("arguments")
                .map(|args| all_literals(args, 0))
                .unwrap_or(false);
            if literal {
                out.push(SlopFinding::new(
                    rel, line, SlopCategory::DangerousSink, "LOW", "eval-literal",
                    format!("`{ftext}()` on a hardcoded literal — verify it never becomes dynamic"),
                    "Replace with explicit parsing; if the literal is intentional, suppress with `# sast-ignore`.",
                ));
            } else {
                out.push(SlopFinding::new(
                    rel,
                    line,
                    SlopCategory::DangerousSink,
                    "HIGH",
                    "eval-use",
                    format!("use of standalone `{ftext}()` on dynamic input"),
                    "Replace with ast.literal_eval() or explicit parsing; eval/exec on untrusted input is remote code execution.",
                ));
            }
        }
    } else if func.kind() == "attribute" {
        // Only module-level functions are sinks here; `obj.load(...)`,
        // `session.exec(...)` etc. are deliberately ignored.
        if matches!(
            ftext,
            "pickle.loads" | "os.system" | "os.popen" | "yaml.load" | "yaml.unsafe_load"
        ) {
            let args_text = node
                .child_by_field_name("arguments")
                .and_then(|args| text(args, src))
                .unwrap_or("");
            if ftext.starts_with("yaml.") {
                let safe = args_text.contains("SafeLoader")
                    || args_text.contains("BaseLoader")
                    || args_text.contains("CSafeLoader");
                if !safe {
                    out.push(SlopFinding::new(
                        rel,
                        line,
                        SlopCategory::DangerousSink,
                        "HIGH",
                        "unsafe-yaml-load",
                        "yaml.load without SafeLoader can execute arbitrary constructors",
                        "Use yaml.safe_load(...) or pass Loader=yaml.SafeLoader.",
                    ));
                }
                return;
            }
            if tainted.contains(&line) {
                return; // CRITICAL taint finding already covers this call
            }
            let literal = node
                .child_by_field_name("arguments")
                .map(|args| all_literals(args, 0))
                .unwrap_or(false);
            if literal {
                out.push(SlopFinding::new(
                    rel, line, SlopCategory::DangerousSink, "LOW", "sink-literal",
                    format!("`{ftext}()` on a hardcoded literal — verify it stays trusted"),
                    "Prefer safer APIs (subprocess argv lists, JSON); suppress with `# sast-ignore` if intentional.",
                ));
            } else {
                out.push(SlopFinding::new(
                    rel,
                    line,
                    SlopCategory::DangerousSink,
                    "HIGH",
                    "dangerous-call",
                    format!("use of `{ftext}()` on non-literal input"),
                    "Validate the input or use a safer API; untrusted data here is remote code execution.",
                ));
            }
        }
    }
}

/// True when every value in the argument subtree is a hardcoded literal
/// (strings, numbers, booleans, containers of literals).
fn all_literals(node: Node, depth: usize) -> bool {
    match node.kind() {
        "string" | "integer" | "float" | "true" | "false" | "none" => true,
        "list" | "tuple" | "set" | "dictionary" => {
            if depth > 2 {
                return false;
            }
            all_children_literals(node, depth)
        }
        "call" | "identifier" | "attribute" | "subscript" | "binary_operator"
        | "string_interpolation" | "list_splat" | "generator_expression" => false,
        _ => {
            if depth > 3 {
                return false;
            }
            all_children_literals(node, depth)
        }
    }
}

fn all_children_literals(node: Node, depth: usize) -> bool {
    let mut i = 0;
    let mut any = false;
    while let Some(child) = node.named_child(i) {
        if !all_literals(child, depth + 1) {
            return false;
        }
        any = true;
        i += 1;
    }
    any
}

// ---------------------------------------------------------------------------
// Insecure defaults: keyword arguments & assignments
// ---------------------------------------------------------------------------

fn check_kwarg(node: Node, src: &str, rel: &str, out: &mut Vec<SlopFinding>) {
    let Some(name) = node.child_by_field_name("name") else { return };
    let Some(value) = node.child_by_field_name("value") else { return };
    let Some(name) = text(name, src) else { return };
    let line = line_of(node);

    match (name, value.kind()) {
        ("verify", "false") => push_ssl_bypass(rel, line, out),
        ("shell", "true") => push_shell_true(rel, line, out),
        ("debug", "true") => push_debug(rel, line, out),
        ("host", _) => {
            if string_value(value, src).as_deref() == Some("0.0.0.0") {
                push_bind_all(rel, line, out);
            }
        }
        ("allow_origins", _) | ("allow_origin", _) | ("origin", _) => {
            if is_wildcard_value(value, src) {
                push_cors(rel, line, out);
            }
        }
        _ => {}
    }
}

fn check_assignment(node: Node, src: &str, rel: &str, out: &mut Vec<SlopFinding>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    let Some(right) = node.child_by_field_name("right") else { return };
    let Some(ltext) = text(left, src) else { return };
    let line = line_of(node);

    if (ltext == "verify" || ltext.ends_with(".verify")) && right.kind() == "false" {
        push_ssl_bypass(rel, line, out);
        return;
    }
    if (ltext == "debug" || ltext == "DEBUG" || ltext.ends_with(".debug")) && right.kind() == "true" {
        push_debug(rel, line, out);
        return;
    }
    if (ltext == "host" || ltext.ends_with(".host"))
        && string_value(right, src).as_deref() == Some("0.0.0.0")
    {
        push_bind_all(rel, line, out);
        return;
    }
    if (ltext == "allow_origins"
        || ltext.ends_with(".allow_origins")
        || ltext == "origin"
        || ltext.ends_with(".origin")
        || ltext == "ALLOWED_ORIGINS")
        && is_wildcard_value(right, src)
    {
        push_cors(rel, line, out);
    }
}

fn string_value(node: Node, src: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        if child.kind() == "string_content" {
            return text(child, src).map(str::to_string);
        }
        i += 1;
    }
    None
}

/// `["*"]`, `("*",)`, `"*"` — any literal wildcard in the value.
fn is_wildcard_value(node: Node, src: &str) -> bool {
    match node.kind() {
        "string" => string_value(node, src).as_deref() == Some("*"),
        "list" | "tuple" | "set" => {
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                if string_value(child, src).as_deref() == Some("*") {
                    return true;
                }
                i += 1;
            }
            false
        }
        _ => false,
    }
}

fn push_ssl_bypass(rel: &str, line: usize, out: &mut Vec<SlopFinding>) {
    out.push(SlopFinding::new(
        rel, line, SlopCategory::LazyConfig, "HIGH", "ssl-verify-disabled",
        "SSL certificate verification disabled (`verify=False`)",
        "Remove verify=False; pass a CA bundle (e.g. certifi) instead — disabled checks enable MITM attacks.",
    ));
}

fn push_shell_true(rel: &str, line: usize, out: &mut Vec<SlopFinding>) {
    out.push(SlopFinding::new(
        rel, line, SlopCategory::DangerousSink, "HIGH", "shell-true",
        "subprocess call with shell=True",
        "Pass the command as an argv list without shell=True, and never interpolate untrusted input into it.",
    ));
}

fn push_debug(rel: &str, line: usize, out: &mut Vec<SlopFinding>) {
    out.push(SlopFinding::new(
        rel, line, SlopCategory::LazyConfig, "MEDIUM", "debug-enabled",
        "debug mode enabled (`debug=True`) leaks stack traces and config",
        "Drive debug mode from an env var (e.g. app.run(debug=DEBUG)) and keep it off in production.",
    ));
}

fn push_bind_all(rel: &str, line: usize, out: &mut Vec<SlopFinding>) {
    out.push(SlopFinding::new(
        rel, line, SlopCategory::LazyConfig, "MEDIUM", "bind-0.0.0.0",
        "service bound to 0.0.0.0 (all interfaces)",
        "Bind to 127.0.0.1 for local dev, or front the service with a firewall/proxy if external access is required.",
    ));
}

fn push_cors(rel: &str, line: usize, out: &mut Vec<SlopFinding>) {
    out.push(SlopFinding::new(
        rel, line, SlopCategory::LazyConfig, "MEDIUM", "cors-wildcard",
        "CORS wildcard origin (`[\"*\"]`) allows any origin",
        "List the exact origins that need access instead of reflecting any origin.",
    ));
}

// ---------------------------------------------------------------------------
// Unused imports (AST-derived, `__future__` whitelisted)
// ---------------------------------------------------------------------------

struct ImportSite {
    row: usize,
    names: Vec<String>,
    future: bool,
}

pub fn unused_imports(tree: &Tree, src: &str, rel: &str, out: &mut Vec<SlopFinding>) {
    let mut sites = Vec::new();
    collect_imports(tree.root_node(), src, &mut sites);

    let lines: Vec<&str> = src.lines().collect();
    for site in &sites {
        if site.future {
            continue; // `from __future__ import annotations` is never slop
        }
        for name in &site.names {
            if name_is_referenced(name, &lines, site.row) {
                continue;
            }
            out.push(SlopFinding::new(
                rel,
                site.row + 1,
                SlopCategory::AiSlop,
                "LOW",
                "unused-import",
                format!("unused import: `{name}`"),
                "Remove the unused import — dead code is a typical AI-slop artifact.",
            ));
        }
    }
}

fn collect_imports(node: Node, src: &str, sites: &mut Vec<ImportSite>) {
    match node.kind() {
        "import_statement" | "import_from_statement" => {
            let row = node.start_position().row;
            let future = node
                .child_by_field_name("module_name")
                .and_then(|m| text(m, src))
                .map(|t| t == "__future__" || t.ends_with(".__future__"))
                .unwrap_or(false);
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.children_by_field_name("name", &mut cursor) {
                match child.kind() {
                    "dotted_name" => {
                        if let Some(t) = text(child, src) {
                            names.push(top_segment(t));
                        }
                    }
                    "aliased_import" => {
                        if let Some(alias) = child.child_by_field_name("alias") {
                            if let Some(t) = text(alias, src) {
                                names.push(t.to_string());
                            }
                        }
                    }
                    _ => {} // wildcard_import can't be tracked reliably
                }
            }
            if !names.is_empty() {
                sites.push(ImportSite { row, names, future });
            }
        }
        _ => {}
    }
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        collect_imports(child, src, sites);
        i += 1;
    }
}

fn top_segment(dotted: &str) -> String {
    dotted.split('.').next().unwrap_or(dotted).to_string()
}

/// True when `name` appears as a whole word on any line other than `skip`
/// (0-based row of the import statement itself).
pub(crate) fn name_is_referenced(name: &str, lines: &[&str], skip: usize) -> bool {
    let re = match regex::Regex::new(&format!(r"\b{}\b", regex::escape(name))) {
        Ok(r) => r,
        Err(_) => return true, // be conservative on regex failure
    };
    for (i, line) in lines.iter().enumerate() {
        if i == skip {
            continue;
        }
        if re.is_match(line) {
            return true;
        }
    }
    false
}
