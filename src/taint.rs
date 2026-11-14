//! Lightweight intra-procedural taint analysis for Python sources (v3).
//!
//! Tracks simple variable assignments within a single scope (function body or
//! module top level) from untrusted **sources** (`request.*`, `input()`,
//! `sys.argv`, `os.environ`) to dangerous **sinks** (`eval`, `exec`,
//! `subprocess.*` with `shell=True`, `pickle.loads`, `os.system`).
//!
//! Sanitizers (`shlex.quote`, `html.escape`, `int()`, ...) clear taint.
//! The result drives severity: a tainted value reaching a sink is `CRITICAL`,
//! while a hardcoded literal argument is downgraded to `LOW` by the AST rules.
//!
//! v4 adds the cross-file engine in the `xfile` submodule.

pub mod xfile;

use std::collections::HashMap;

use tree_sitter::Node;

/// One tainted source-to-sink flow.
pub struct TaintHit {
    /// 1-based line of the sink call.
    pub line: usize,
    /// Text of the sink function, e.g. `eval` or `subprocess.run(shell=True)`.
    pub sink: String,
    /// Where the tainted value came from, e.g. `request.*` or `input()`.
    pub origin: String,
}

/// var name (or dotted attribute path) -> origin description.
type TaintMap = HashMap<String, String>;

/// Sanitizer functions that make a value safe for sinks. Matched on the last
/// path segment of the callee.
const SANITIZERS: &[&str] = &[
    "quote", "quote_plus", "escape", "clean", "int", "float", "bool",
    "len", "secure_filename", "shlex_join", "sanitize",
];

pub fn analyze(src: &str, tree: &tree_sitter::Tree) -> Vec<TaintHit> {
    let mut hits = Vec::new();
    scan_scope(tree.root_node(), src, &mut hits);
    hits
}

// ---------------------------------------------------------------------------
// Scope walking
// ---------------------------------------------------------------------------

fn scan_scope(scope: Node, src: &str, hits: &mut Vec<TaintHit>) {
    let mut tainted: TaintMap = HashMap::new();
    let mut i = 0;
    while let Some(stmt) = scope.named_child(i) {
        process_statement(stmt, src, &mut tainted, hits);
        i += 1;
    }
}

fn process_statement(node: Node, src: &str, tainted: &mut TaintMap, hits: &mut Vec<TaintHit>) {
    match node.kind() {
        // Each function definition is its own scope with a fresh taint map.
        "function_definition" => {
            if let Some(body) = node.child_by_field_name("body") {
                scan_scope(body, src, hits);
            }
        }
        "assignment" | "augmented_assignment" => handle_assign(node, src, tainted, hits),
        "for_statement" => handle_for(node, src, tainted, hits),
        "call" => {
            check_sink(node, src, tainted, hits);
            recurse_children(node, src, tainted, hits);
        }
        _ => recurse_children(node, src, tainted, hits),
    }
}

fn recurse_children(node: Node, src: &str, tainted: &mut TaintMap, hits: &mut Vec<TaintHit>) {
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        process_statement(child, src, tainted, hits);
        i += 1;
    }
}

fn handle_for(node: Node, src: &str, tainted: &mut TaintMap, hits: &mut Vec<TaintHit>) {
    if let (Some(left), Some(right)) =
        (node.child_by_field_name("left"), node.child_by_field_name("right"))
    {
        // `for x in request.args.getall(...)` — the loop variable is tainted.
        if let Some(origin) =
            expr_origin(right, src).or_else(|| references_tainted(right, tainted, src))
        {
            for name in target_names(left, src) {
                tainted.insert(name, origin.clone());
            }
        }
    }
    if let Some(right) = node.child_by_field_name("right") {
        process_statement(right, src, tainted, hits);
    }
    if let Some(body) = node.child_by_field_name("body") {
        process_statement(body, src, tainted, hits);
    }
}

fn handle_assign(node: Node, src: &str, tainted: &mut TaintMap, hits: &mut Vec<TaintHit>) {
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    let (Some(left), Some(right)) = (left, right) else { return };

    // Sinks inside the RHS are evaluated with the taint state as of now,
    // *before* the new binding is recorded.
    process_statement(right, src, tainted, hits);

    let names = target_names(left, src);
    if let Some(origin) = expr_origin(right, src) {
        for name in &names {
            tainted.insert(name.clone(), origin.clone());
        }
    } else if expr_is_sanitized(right, src) {
        for name in &names {
            tainted.remove(name.as_str());
        }
    } else if let Some(origin) = references_tainted(right, tainted, src) {
        for name in &names {
            tainted.insert(name.clone(), origin.clone());
        }
    } else {
        // Literal / unrelated assignment clears any previous taint.
        for name in &names {
            tainted.remove(name.as_str());
        }
    }
}

// ---------------------------------------------------------------------------
// Sink detection
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum SinkMode {
    /// Value flows straight into code execution: eval/exec/pickle/os.system.
    Direct,
    /// Command string into a subprocess call guarded by `shell=True`.
    Subprocess,
}

fn check_sink(call: Node, src: &str, tainted: &TaintMap, hits: &mut Vec<TaintHit>) {
    let Some(func) = call.child_by_field_name("function") else { return };
    let Ok(ftext) = func.utf8_text(src.as_bytes()) else { return };
    let line = call.start_position().row + 1;

    // Object-method calls (`session.exec(...)`) are deliberately NOT sinks —
    // this is the v2 false positive this module eliminates.
    let (sink, mode) = if func.kind() == "identifier" {
        match ftext {
            "eval" | "exec" | "compile" => (ftext, SinkMode::Direct),
            _ => return,
        }
    } else if func.kind() == "attribute" {
        match ftext {
            "pickle.loads" | "os.system" | "os.popen" => (ftext, SinkMode::Direct),
            "subprocess.run" | "subprocess.call" | "subprocess.check_call"
            | "subprocess.check_output" | "subprocess.Popen" => (ftext, SinkMode::Subprocess),
            _ => return,
        }
    } else {
        return;
    };

    let Some(args) = call.child_by_field_name("arguments") else { return };
    match mode {
        SinkMode::Direct => {
            if let Some(origin) = args_taint_origin(args, src, tainted) {
                hits.push(TaintHit { line, sink: sink.to_string(), origin });
            }
        }
        SinkMode::Subprocess => {
            if !has_shell_true(args, src) {
                return; // argv-list calls without a shell are not string sinks
            }
            if let Some(first) = args.named_child(0) {
                if let Some(origin) = arg_taint_origin(first, src, tainted) {
                    hits.push(TaintHit {
                        line,
                        sink: format!("{sink}(shell=True)"),
                        origin,
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Source / sanitizer / propagation predicates
// ---------------------------------------------------------------------------

/// If `node` is itself an untrusted source expression, return its origin.
fn expr_origin(node: Node, src: &str) -> Option<String> {
    match node.kind() {
        "call" => {
            let func = node.child_by_field_name("function")?;
            let ftext = func.utf8_text(src.as_bytes()).ok()?;
            if func.kind() == "identifier" && ftext == "input" {
                return Some("input()".into());
            }
            // `request.args.get(...)`, `os.environ.get(...)`, `sys.argv[1](...)`
            expr_origin(func, src)
        }
        "attribute" | "subscript" => {
            let text = node.utf8_text(src.as_bytes()).ok()?;
            if text.starts_with("request") {
                return Some("request.*".into());
            }
            if text.starts_with("os.environ") {
                return Some("os.environ".into());
            }
            if text.starts_with("sys.argv") {
                return Some("sys.argv".into());
            }
            let obj = if node.kind() == "attribute" {
                node.child_by_field_name("object")
            } else {
                node.child_by_field_name("value")
            }?;
            expr_origin(obj, src)
        }
        _ => None,
    }
}

/// If any identifier inside `node` carries taint, return its origin.
fn references_tainted(node: Node, tainted: &TaintMap, src: &str) -> Option<String> {
    match node.kind() {
        "identifier" => tainted.get(node.utf8_text(src.as_bytes()).ok()?).cloned(),
        "attribute" => {
            // Check the dotted path itself (`self.query`) then recurse into
            // the object only — the attribute name is not a variable.
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                if let Some(origin) = tainted.get(text) {
                    return Some(origin.clone());
                }
            }
            references_tainted(node.child_by_field_name("object")?, tainted, src)
        }
        _ => {
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                if let Some(origin) = references_tainted(child, tainted, src) {
                    return Some(origin);
                }
                i += 1;
            }
            None
        }
    }
}

/// Origin of a sink argument: direct source expression or tainted variable.
fn arg_taint_origin(arg: Node, src: &str, tainted: &TaintMap) -> Option<String> {
    expr_origin(arg, src).or_else(|| references_tainted(arg, tainted, src))
}

fn args_taint_origin(args: Node, src: &str, tainted: &TaintMap) -> Option<String> {
    let mut i = 0;
    while let Some(arg) = args.named_child(i) {
        // Keyword arguments (`eval(expr=...)` is unusual but legal): check the
        // value child, not the keyword name.
        let value = if arg.kind() == "keyword_argument" {
            arg.child_by_field_name("value")
        } else {
            Some(arg)
        };
        if let Some(value) = value {
            if let Some(origin) = arg_taint_origin(value, src, tainted) {
                return Some(origin);
            }
        }
        i += 1;
    }
    None
}

/// True when the expression is a call to a known sanitizer.
fn expr_is_sanitized(node: Node, src: &str) -> bool {
    if node.kind() != "call" {
        return false;
    }
    let Some(func) = node.child_by_field_name("function") else { return false };
    let Ok(ftext) = func.utf8_text(src.as_bytes()) else { return false };
    let last = ftext.rsplit('.').next().unwrap_or("");
    SANITIZERS.contains(&last)
}

/// Assignment targets introduced by the left-hand side: simple names and
/// dotted attribute paths (`a`, `a.b`, tuples/pattern lists).
fn target_names(left: Node, src: &str) -> Vec<String> {
    match left.kind() {
        "identifier" => vec![left.utf8_text(src.as_bytes()).unwrap_or_default().to_string()],
        "attribute" => vec![left.utf8_text(src.as_bytes()).unwrap_or_default().to_string()],
        _ => {
            let mut names = Vec::new();
            let mut i = 0;
            while let Some(child) = left.named_child(i) {
                names.extend(target_names(child, src));
                i += 1;
            }
            names
        }
    }
}

fn has_shell_true(args: Node, src: &str) -> bool {
    let mut i = 0;
    while let Some(arg) = args.named_child(i) {
        if arg.kind() == "keyword_argument" {
            if let (Some(name), Some(value)) =
                (arg.child_by_field_name("name"), arg.child_by_field_name("value"))
            {
                if name.utf8_text(src.as_bytes()) == Ok("shell") && value.kind() == "true" {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}
