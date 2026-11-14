//! Pass 1 AST extraction (v4): imports, functions, endpoints, and the per
//! function IR (`Step`s with `Rhs` provenance) that Pass 2 simulates.
//!
//! Python is first-class; JS/TS gets light indexing (imports, functions,
//! arrow functions) so the symbol table is complete across the repo.

use std::collections::HashMap;

use tree_sitter::Node;

use super::parse::{self, Lang};
use super::symbols::{CallArg, Endpoint, FnSummary, ImportBinding, ParamInfo, Rhs, Step};

/// Everything extracted from one file during Pass 1.
#[derive(Debug, Clone, Default)]
pub struct FileIndex {
    pub path: String,
    /// Dotted module path derived from the file path (`services.fetcher`).
    pub module_path: String,
    pub imports: Vec<ImportBinding>,
    pub functions: Vec<FnSummary>,
    pub endpoints: Vec<Endpoint>,
    pub classes: Vec<String>,
}

/// Derive the dotted module path from a relative file path.
pub fn module_path(rel: &str) -> String {
    let stem = match rel.rsplit_once('.') {
        Some((base, ext)) if matches!(ext, "py" | "pyw" | "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx") => base,
        _ => rel,
    };
    let stem = stem.strip_suffix("/__init__").unwrap_or(stem);
    stem.replace('/', ".")
}

pub fn extract(path_rel: &str, src: &str, lang: Lang) -> FileIndex {
    let mut index = FileIndex {
        path: path_rel.to_string(),
        module_path: module_path(path_rel),
        ..Default::default()
    };
    let Some(tree) = parse::parse(lang, src) else { return index };
    let mut ctx = ExtractCtx { src, index: &mut index };

    match lang {
        Lang::Python => walk_py(tree.root_node(), &mut ctx),
        Lang::JavaScript => walk_js(tree.root_node(), &mut ctx),
    }

    // Module top-level IR: a `__module__` pseudo-function so that top-level
    // flows (`cmd = sys.argv[1]; os.system(cmd)`) are analyzed in Pass 2.
    let mut steps = Vec::new();
    let mut vars = HashMap::new();
    visit_stmt_py(tree.root_node(), ctx.src, &[], &mut vars, &mut steps);
    if !steps.is_empty() {
        ctx.index.functions.push(FnSummary {
            qualified: format!("{}.__module__", ctx.index.module_path),
            file: ctx.index.path.clone(),
            line: 0,
            params: Vec::new(),
            steps,
        });
    }
    index
}

struct ExtractCtx<'a> {
    src: &'a str,
    index: &'a mut FileIndex,
}

fn text<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    node.utf8_text(src.as_bytes()).ok()
}

// ---------------------------------------------------------------------------
// Python walk
// ---------------------------------------------------------------------------

fn walk_py(node: Node, ctx: &mut ExtractCtx) {
    match node.kind() {
        "import_statement" | "import_from_statement" => extract_import_py(node, ctx),
        "decorated_definition" => {
            extract_decorated_py(node, ctx);
            return; // the inner definition is handled here — don't re-extract
        }
        "function_definition" => {
            extract_function_py(node, None, ctx);
        }
        "class_definition" => {
            if let Some(name) = node.child_by_field_name("name").and_then(|n| text(n, ctx.src)) {
                ctx.index.classes.push(name.to_string());
            }
            if let Some(body) = node.child_by_field_name("body") {
                let class_name = node
                    .child_by_field_name("name")
                    .and_then(|n| text(n, ctx.src))
                    .unwrap_or("")
                    .to_string();
                let mut i = 0;
                while let Some(child) = body.named_child(i) {
                    if child.kind() == "decorated_definition" {
                        extract_decorated_py(child, ctx);
                    } else if child.kind() == "function_definition" {
                        extract_function_py(child, Some(&class_name), ctx);
                    }
                    i += 1;
                }
            }
            return; // methods handled above — don't re-extract
        }
        _ => {}
    }
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        walk_py(child, ctx);
        i += 1;
    }
}

fn extract_import_py(node: Node, ctx: &mut ExtractCtx) {
    let line = node.start_position().row + 1;
    let from_module = node
        .child_by_field_name("module_name")
        .and_then(|m| text(m, ctx.src))
        .map(str::to_string);
    let mut cursor = node.walk();
    for child in node.children_by_field_name("name", &mut cursor) {
        match child.kind() {
            "aliased_import" => {
                let name = child
                    .child_by_field_name("name")
                    .and_then(|n| text(n, ctx.src))
                    .unwrap_or("")
                    .to_string();
                let alias = child
                    .child_by_field_name("alias")
                    .and_then(|n| text(n, ctx.src))
                    .unwrap_or(&name)
                    .to_string();
                push_import_py(ctx, line, from_module.as_deref(), &name, &alias);
            }
            "dotted_name" => {
                let name = text(child, ctx.src).unwrap_or("").to_string();
                push_import_py(ctx, line, from_module.as_deref(), &name, &name);
            }
            _ => {} // wildcard_import can't be resolved statically
        }
    }
}

/// Record one resolved import binding.
///
/// - `from utils.net import fetch as get_url` -> local `get_url` resolves to
///   `utils.net.fetch`.
/// - `import a.b` binds the top segment `a` to module `a`.
/// - `import a.b as c` binds `c` to module `a.b`.
fn push_import_py(ctx: &mut ExtractCtx, line: usize, from_module: Option<&str>, name: &str, alias: &str) {
    if name.is_empty() || name == "*" {
        return;
    }
    match from_module {
        Some(module) => {
            let module = module.trim_start_matches('.').to_string();
            ctx.index.imports.push(ImportBinding {
                alias: if module.is_empty() {
                    name.to_string()
                } else {
                    format!("{module}.{name}")
                },
                module,
                symbol: name.to_string(),
                local: alias.to_string(),
                line,
            });
        }
        None => {
            let top = name.split('.').next().unwrap_or(name).to_string();
            let (module, local) = if alias == name {
                (top.clone(), top)
            } else {
                (name.to_string(), alias.to_string())
            };
            ctx.index.imports.push(ImportBinding {
                alias: module.clone(),
                module,
                symbol: String::new(),
                local,
                line,
            });
        }
    }
}

fn extract_decorated_py(node: Node, ctx: &mut ExtractCtx) {
    // decorated_definition: children = decorators..., definition
    let mut decorators: Vec<Node> = Vec::new();
    let mut func: Option<Node> = None;
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        if child.kind() == "decorator" {
            decorators.push(child);
        } else if child.kind() == "function_definition" {
            func = Some(child);
        }
        i += 1;
    }
    let Some(f) = func else { return };

    // HTTP endpoint registration?
    if let Some(deco) = decorators
        .iter()
        .find(|d| http_decorator_method(**d, ctx.src).is_some())
    {
        let deco: Node = *deco;
        let method = http_decorator_method(deco, ctx.src).unwrap_or_default();
        let path = decorator_route_path(deco, ctx.src);
        let authenticated = decorators.iter().any(|d| decorator_has_auth(*d, ctx.src))
            || func_has_auth_hint(f, ctx.src);
        let func_name = f
            .child_by_field_name("name")
            .and_then(|n| text(n, ctx.src))
            .unwrap_or("")
            .to_string();
        ctx.index.endpoints.push(Endpoint {
            file: ctx.index.path.clone(),
            line: f.start_position().row + 1,
            method,
            path,
            func: func_name,
            authenticated,
        });
    }
    extract_function_py(f, None, ctx);
}

/// HTTP method when the decorator is a route registration (`@app.post`,
/// `@router.delete`, `@app.route(..., methods=["POST"])`).
fn http_decorator_method(deco: Node, src: &str) -> Option<String> {
    let call = deco.named_child(0)?; // decorator -> call/attribute/identifier
    if call.kind() != "call" {
        return None;
    }
    let func = call.child_by_field_name("function")?;
    let ftext = text(func, src)?;
    let last = ftext.rsplit('.').next()?;
    if last == "route" {
        // @app.route("/x", methods=["POST"])
        let args = call.child_by_field_name("arguments")?;
        let arg_text = args.utf8_text(src.as_bytes()).ok()?;
        let upper = arg_text.to_uppercase();
        for m in ["POST", "PUT", "DELETE", "PATCH", "GET"] {
            if upper.contains(&format!("\"{m}\"")) || upper.contains(&format!("'{m}'")) {
                return Some(m.to_string());
            }
        }
        return Some("GET".into());
    }
    for m in ["GET", "POST", "PUT", "DELETE", "PATCH"] {
        if last.eq_ignore_ascii_case(&m.to_lowercase()) {
            return Some(m.to_string());
        }
    }
    None
}

fn decorator_route_path(deco: Node, src: &str) -> String {
    let Some(call) = deco.named_child(0) else { return String::new() };
    if call.kind() != "call" {
        return String::new();
    }
    let Some(args) = call.child_by_field_name("arguments") else { return String::new() };
    let mut i = 0;
    while let Some(arg) = args.named_child(i) {
        if arg.kind() == "string" {
            let mut j = 0;
            while let Some(part) = arg.named_child(j) {
                if part.kind() == "string_content" {
                    return text(part, src).unwrap_or("").to_string();
                }
                j += 1;
            }
        }
        i += 1;
    }
    String::new()
}

/// Auth detection inside the decorator: `Depends(...)`, `login_required`,
/// `auth_required`, `permission_required`, `requires_auth`.
fn decorator_has_auth(deco: Node, src: &str) -> bool {
    let Some(t) = text(deco, src) else { return false };
    t.contains("Depends(")
        || t.contains("login_required")
        || t.contains("auth_required")
        || t.contains("permission_required")
        || t.contains("requires_auth")
        || t.contains("permission_classes")
        || t.contains("get_current_user")
}

/// Auth hint in the function signature: `Depends(...)` annotations or a
/// `current_user` / `token` parameter.
fn func_has_auth_hint(f: Node, src: &str) -> bool {
    let Some(params) = f.child_by_field_name("parameters") else { return false };
    let Some(t) = text(params, src) else { return false };
    t.contains("Depends(")
        || t.contains("current_user")
        || t.contains("get_current_user")
        || t.contains("token")
}

fn extract_function_py(node: Node, class: Option<&str>, ctx: &mut ExtractCtx) {
    let Some(name) = node.child_by_field_name("name").and_then(|n| text(n, ctx.src)) else { return };
    let qualified = match class {
        // module.ClassName.method
        Some(c) => format!("{}.{}.{}", ctx.index.module_path, c, name),
        None => format!("{}.{}", ctx.index.module_path, name),
    };

    let params = node
        .child_by_field_name("parameters")
        .map(|p| param_names(p, ctx.src))
        .unwrap_or_default();

    let mut steps = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        let mut vars = HashMap::new();
        visit_stmt_py(body, ctx.src, &params, &mut vars, &mut steps);
    }
    ctx.index.functions.push(FnSummary {
        qualified,
        file: ctx.index.path.clone(),
        line: node.start_position().row + 1,
        params,
        steps,
    });
}

fn param_names(params: Node, src: &str) -> Vec<ParamInfo> {
    let mut names = Vec::new();
    let mut i = 0;
    while let Some(child) = params.named_child(i) {
        let name = match child.kind() {
            "identifier" => text(child, src).map(str::to_string),
            "default_parameter" | "typed_parameter" | "typed_default_parameter" => {
                child.child_by_field_name("name").and_then(|n| text(n, src)).map(str::to_string)
            }
            "list_splat_pattern" | "dictionary_splat_pattern" => {
                child.named_child(0).and_then(|n| text(n, src)).map(str::to_string)
            }
            _ => None,
        };
        if let Some(name) = name {
            // `x: int = 5` / `x: Request` — annotation text after the colon.
            let annotation = if matches!(
                child.kind(),
                "typed_parameter" | "typed_default_parameter"
            ) {
                text(child, src)
                    .unwrap_or("")
                    .split_once(':')
                    .map(|(_, ann)| ann.split('=').next().unwrap_or(ann).trim().to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            names.push(ParamInfo { name, annotation });
        }
        i += 1;
    }
    names
}

// ---------------------------------------------------------------------------
// Python IR construction (ordered steps with provenance)
// ---------------------------------------------------------------------------

/// Walk statements in source order, building the IR. Skips nested function /
/// class definitions (they get their own summaries).
fn visit_stmt_py(
    node: Node,
    src: &str,
    params: &[ParamInfo],
    vars: &mut HashMap<String, Rhs>,
    steps: &mut Vec<Step>,
) {
    match node.kind() {
        "function_definition" | "class_definition" | "decorated_definition" | "lambda" => return,
        "assignment" => {
            let Some(left) = node.child_by_field_name("left") else { return };
            let rhs = node
                .child_by_field_name("right")
                .map(|r| expr_rhs(r, src, params, vars))
                .unwrap_or(Rhs::Unknown);
            let line = node.start_position().row + 1;
            for name in target_names(left, src) {
                steps.push(Step::Assign { var: name.clone(), rhs: rhs.clone(), line });
                vars.insert(name, rhs.clone());
            }
        }
        "augmented_assignment" => {
            let Some(left) = node.child_by_field_name("left") else { return };
            let rhs = node
                .child_by_field_name("right")
                .map(|r| expr_rhs(r, src, params, vars))
                .unwrap_or(Rhs::Unknown);
            let line = node.start_position().row + 1;
            // `cmd += suffix` — taint-capable RHS taints the target; a plain
            // literal keeps whatever taint the variable already had.
            let taint_capable = matches!(
                rhs,
                Rhs::Param(_) | Rhs::Source(_) | Rhs::Call { .. } | Rhs::Container(_)
            );
            for name in target_names(left, src) {
                let merged = if taint_capable {
                    rhs.clone()
                } else {
                    vars.get(&name).cloned().unwrap_or(Rhs::Unknown)
                };
                steps.push(Step::Assign { var: name.clone(), rhs: merged.clone(), line });
                vars.insert(name, merged);
            }
        }
        "expression_statement" => {
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                if child.kind() == "call" {
                    record_call_step(child, None, src, params, vars, steps);
                } else {
                    visit_stmt_py(child, src, params, vars, steps);
                }
                i += 1;
            }
        }
        "return_statement" => {
            let rhs = node
                .named_child(0)
                .map(|r| expr_rhs(r, src, params, vars))
                .unwrap_or(Rhs::Literal("None".into()));
            steps.push(Step::Return { rhs, line: node.start_position().row + 1 });
        }
        "for_statement" => {
            if let (Some(left), Some(right)) =
                (node.child_by_field_name("left"), node.child_by_field_name("right"))
            {
                let rhs = expr_rhs(right, src, params, vars);
                let line = node.start_position().row + 1;
                for name in target_names(left, src) {
                    steps.push(Step::Assign { var: name.clone(), rhs: rhs.clone(), line });
                    vars.insert(name, rhs.clone());
                }
            }
            visit_children_py(node, src, params, vars, steps);
        }
        "with_statement" => {
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                if child.kind() == "with_item" {
                    // `with open(user_path) as f:` — the call itself is a step.
                    let mut j = 0;
                    while let Some(inner) = child.named_child(j) {
                        if inner.kind() == "call" {
                            record_call_step(inner, None, src, params, vars, steps);
                        }
                        j += 1;
                    }
                } else {
                    visit_stmt_py(child, src, params, vars, steps);
                }
                i += 1;
            }
        }
        _ => visit_children_py(node, src, params, vars, steps),
    }
}

fn visit_children_py(
    node: Node,
    src: &str,
    params: &[ParamInfo],
    vars: &mut HashMap<String, Rhs>,
    steps: &mut Vec<Step>,
) {
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        visit_stmt_py(child, src, params, vars, steps);
        i += 1;
    }
}

fn record_call_step(
    call: Node,
    recv: Option<Rhs>,
    src: &str,
    params: &[ParamInfo],
    vars: &mut HashMap<String, Rhs>,
    steps: &mut Vec<Step>,
) {
    let Some(func) = call.child_by_field_name("function") else { return };
    let Some(callee) = text(func, src) else { return };
    let mut args = Vec::new();
    if let Some(arglist) = call.child_by_field_name("arguments") {
        let mut i = 0;
        while let Some(arg) = arglist.named_child(i) {
            args.push(call_arg(arg, src, params, vars));
            i += 1;
        }
    }
    steps.push(Step::Call {
        callee: callee.to_string(),
        recv,
        args,
        line: call.start_position().row + 1,
    });
}

fn call_arg(arg: Node, src: &str, params: &[ParamInfo], vars: &HashMap<String, Rhs>) -> CallArg {
    if arg.kind() == "keyword_argument" {
        let kw = arg
            .child_by_field_name("name")
            .and_then(|n| text(n, src))
            .map(str::to_string);
        let rhs = arg
            .child_by_field_name("value")
            .map(|v| expr_rhs(v, src, params, vars))
            .unwrap_or(Rhs::Unknown);
        CallArg { kw, rhs }
    } else {
        CallArg { kw: None, rhs: expr_rhs(arg, src, params, vars) }
    }
}

/// Build the `Rhs` provenance of an expression.
fn expr_rhs(node: Node, src: &str, params: &[ParamInfo], vars: &HashMap<String, Rhs>) -> Rhs {
    match node.kind() {
        "identifier" => {
            let Some(t) = text(node, src) else { return Rhs::Unknown };
            if let Some(rhs) = vars.get(t) {
                return rhs.clone();
            }
            if params.iter().any(|p| p.name == t) {
                return Rhs::Param(t.to_string());
            }
            Rhs::Unknown
        }
        "string" | "integer" | "float" | "true" | "false" | "none" => {
            Rhs::Literal(text(node, src).unwrap_or("").to_string())
        }
        "call" => {
            // `input()` — the call node itself is the source.
            if let Some(origin) = source_origin(node, src) {
                return Rhs::Source(origin);
            }
            // Calls on untrusted receivers (`request.args.get`).
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(origin) = source_origin(func, src) {
                    return Rhs::Source(origin);
                }
            }
            let func = node.child_by_field_name("function");
            let callee = func.and_then(|f| text(f, src)).unwrap_or("").to_string();
            let recv = func
                .filter(|f| f.kind() == "attribute")
                .and_then(|f| f.child_by_field_name("object"))
                .map(|o| Box::new(expr_rhs(o, src, params, vars)));
            let mut args = Vec::new();
            if let Some(arglist) = node.child_by_field_name("arguments") {
                let mut i = 0;
                while let Some(arg) = arglist.named_child(i) {
                    args.push(call_arg(arg, src, params, vars));
                    i += 1;
                }
            }
            Rhs::Call { callee, recv, args }
        }
        "attribute" | "subscript" => {
            if let Some(origin) = source_origin(node, src) {
                return Rhs::Source(origin);
            }
            let obj = if node.kind() == "attribute" {
                node.child_by_field_name("object")
            } else {
                node.child_by_field_name("value")
            };
            match obj {
                Some(o) => expr_rhs(o, src, params, vars),
                None => Rhs::Unknown,
            }
        }
        "binary_operator" => {
            let left = node.child_by_field_name("left").map(|n| expr_rhs(n, src, params, vars));
            let right = node.child_by_field_name("right").map(|n| expr_rhs(n, src, params, vars));
            match (left, right) {
                (Some(l), Some(r)) => pick_binary_rhs(l, r),
                (Some(l), None) => l,
                (None, Some(r)) => r,
                (None, None) => Rhs::Unknown,
            }
        }
        "list" | "tuple" => {
            let mut items = Vec::new();
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                items.push(expr_rhs(child, src, params, vars));
                i += 1;
            }
            Rhs::Container(items)
        }
        "dictionary" | "set" => Rhs::Raw(text(node, src).unwrap_or("").to_string()),
        _ => Rhs::Unknown,
    }
}

/// `"ls " + cmd` — prefer the non-literal side so taint propagates through
/// string concatenation.
fn pick_binary_rhs(l: Rhs, r: Rhs) -> Rhs {
    match (&l, &r) {
        (Rhs::Literal(_), Rhs::Literal(_)) => l,
        (Rhs::Literal(_), _) => r,
        (_, Rhs::Literal(_)) => l,
        (Rhs::Unknown, _) => r,
        (_, Rhs::Unknown) => l,
        _ => l,
    }
}

/// Global untrusted-source detection on an expression node. Rule-specific
/// filtering (which origins count for which rule) happens in Pass 2.
fn source_origin(node: Node, src: &str) -> Option<String> {
    match node.kind() {
        "call" => {
            let func = node.child_by_field_name("function")?;
            if func.kind() == "identifier" && text(func, src) == Some("input") {
                return Some("input()".into());
            }
            None
        }
        "attribute" | "subscript" => {
            let t = text(node, src)?;
            // Prefix with a boundary: `request.args` matches, `requests.get`
            // (the HTTP client!) must NOT.
            if prefixed(&t, "request") {
                return Some("request.*".into());
            }
            if prefixed(&t, "os.environ") {
                return Some("os.environ".into());
            }
            if prefixed(&t, "sys.argv") {
                return Some("sys.argv".into());
            }
            None
        }
        _ => None,
    }
}

/// `t` starts with `prefix` followed by an access boundary (`.` `[` `(`)
/// or is exactly `prefix`.
fn prefixed(t: &str, prefix: &str) -> bool {
    match t.strip_prefix(prefix) {
        Some(rest) => {
            rest.is_empty()
                || rest.starts_with('.')
                || rest.starts_with('[')
                || rest.starts_with('(')
        }
        None => false,
    }
}

/// Assignment target names: simple names, dotted attribute paths, tuples.
fn target_names(left: Node, src: &str) -> Vec<String> {
    match left.kind() {
        "identifier" => vec![text(left, src).unwrap_or_default().to_string()],
        "attribute" => vec![text(left, src).unwrap_or_default().to_string()],
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

// ---------------------------------------------------------------------------
// JavaScript / TypeScript (light: imports + functions + call IR)
// ---------------------------------------------------------------------------

fn walk_js(node: Node, ctx: &mut ExtractCtx) {
    match node.kind() {
        "import_statement" => extract_import_js(node, ctx),
        "function_declaration" | "generator_function_declaration" => {
            let Some(name) = node.child_by_field_name("name").and_then(|n| text(n, ctx.src)) else { return };
            let params = node
                .child_by_field_name("parameters")
                .map(|p| param_names_js(p, ctx.src))
                .unwrap_or_default();
            let mut steps = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let mut vars = HashMap::new();
                visit_stmt_js(body, ctx.src, &params, &mut vars, &mut steps);
            }
            ctx.index.functions.push(FnSummary {
                qualified: format!("{}.{}", ctx.index.module_path, name),
                file: ctx.index.path.clone(),
                line: node.start_position().row + 1,
                params,
                steps,
            });
            return;
        }
        "lexical_declaration" => {
            // const fetch = (...) => {...} / const fetch = function(...) {...}
            let mut i = 0;
            while let Some(decl) = node.named_child(i) {
                if decl.kind() != "variable_declarator" {
                    i += 1;
                    continue;
                }
                if let (Some(name), Some(value)) =
                    (decl.child_by_field_name("name"), decl.child_by_field_name("value"))
                {
                    if matches!(value.kind(), "arrow_function" | "function_expression") {
                        if let Some(fname) = text(name, ctx.src) {
                            let params = value
                                .child_by_field_name("parameters")
                                .map(|p| param_names_js(p, ctx.src))
                                .unwrap_or_default();
                            let mut steps = Vec::new();
                            if let Some(body) = value.child_by_field_name("body") {
                                let mut vars = HashMap::new();
                                visit_stmt_js(body, ctx.src, &params, &mut vars, &mut steps);
                            }
                            ctx.index.functions.push(FnSummary {
                                qualified: format!("{}.{}", ctx.index.module_path, fname),
                                file: ctx.index.path.clone(),
                                line: decl.start_position().row + 1,
                                params,
                                steps,
                            });
                            i += 1;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            return;
        }
        _ => {}
    }
    let mut i = 0;
    while let Some(child) = node.named_child(i) {
        walk_js(child, ctx);
        i += 1;
    }
}

fn extract_import_js(node: Node, ctx: &mut ExtractCtx) {
    let line = node.start_position().row + 1;
    let source = node
        .child_by_field_name("source")
        .and_then(|s| text(s, ctx.src))
        .unwrap_or("")
        .trim_matches(|c| c == '\'' || c == '"')
        .to_string();
    let mut cursor = node.walk();
    for child in node.children_by_field_name("name", &mut cursor) {
        if child.kind() == "import_specifier" {
            let name = child
                .child_by_field_name("name")
                .and_then(|n| text(n, ctx.src))
                .unwrap_or("")
                .to_string();
            let alias = child
                .child_by_field_name("alias")
                .and_then(|n| text(n, ctx.src))
                .unwrap_or(&name)
                .to_string();
            if !name.is_empty() {
                ctx.index.imports.push(ImportBinding {
                    alias: format!("{source}.{name}"),
                    module: source.clone(),
                    symbol: name,
                    local: alias,
                    line,
                });
            }
        } else if child.kind() == "identifier" {
            if let Some(name) = text(child, ctx.src) {
                ctx.index.imports.push(ImportBinding {
                    alias: format!("{source}.default"),
                    module: source.clone(),
                    symbol: "default".into(),
                    local: name.to_string(),
                    line,
                });
            }
        }
    }
}

fn param_names_js(params: Node, src: &str) -> Vec<ParamInfo> {
    let mut names = Vec::new();
    let mut i = 0;
    while let Some(child) = params.named_child(i) {
        let name = match child.kind() {
            "identifier" | "shorthand_property_identifier" => {
                text(child, src).map(str::to_string)
            }
            "assignment_pattern" => child
                .child_by_field_name("left")
                .and_then(|n| text(n, src))
                .map(str::to_string),
            _ => None,
        };
        if let Some(name) = name {
            names.push(ParamInfo { name, annotation: String::new() });
        }
        i += 1;
    }
    names
}

/// Light JS/TS IR: assignments, bare calls, returns.
fn visit_stmt_js(
    node: Node,
    src: &str,
    params: &[ParamInfo],
    vars: &mut HashMap<String, Rhs>,
    steps: &mut Vec<Step>,
) {
    match node.kind() {
        "function_declaration" | "function_expression" | "arrow_function"
        | "generator_function" | "generator_function_declaration" | "class_declaration" => return,
        "variable_declarator" => {
            if let (Some(name), Some(value)) =
                (node.child_by_field_name("name"), node.child_by_field_name("value"))
            {
                if let Some(name) = text(name, src) {
                    let rhs = expr_rhs_js(value, src, params, vars);
                    let line = node.start_position().row + 1;
                    steps.push(Step::Assign { var: name.to_string(), rhs: rhs.clone(), line });
                    vars.insert(name.to_string(), rhs);
                }
            }
        }
        "expression_statement" => {
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                if child.kind() == "call_expression" {
                    record_call_step_js(child, None, src, params, vars, steps);
                }
                i += 1;
            }
        }
        "return_statement" => {
            let rhs = node
                .named_child(0)
                .map(|r| expr_rhs_js(r, src, params, vars))
                .unwrap_or(Rhs::Literal("undefined".into()));
            steps.push(Step::Return { rhs, line: node.start_position().row + 1 });
        }
        _ => {
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                visit_stmt_js(child, src, params, vars, steps);
                i += 1;
            }
        }
    }
}

fn record_call_step_js(
    call: Node,
    recv: Option<Rhs>,
    src: &str,
    params: &[ParamInfo],
    vars: &mut HashMap<String, Rhs>,
    steps: &mut Vec<Step>,
) {
    let Some(func) = call.child_by_field_name("function") else { return };
    let Some(callee) = text(func, src) else { return };
    let mut args = Vec::new();
    if let Some(arglist) = call.child_by_field_name("arguments") {
        let mut i = 0;
        while let Some(arg) = arglist.named_child(i) {
            let kw = if arg.kind() == "pair" {
                arg.child_by_field_name("key")
                    .and_then(|k| text(k, src))
                    .map(str::to_string)
            } else {
                None
            };
            let value = if arg.kind() == "pair" {
                arg.child_by_field_name("value")
            } else {
                Some(arg)
            };
            let rhs = value
                .map(|v| expr_rhs_js(v, src, params, vars))
                .unwrap_or(Rhs::Unknown);
            args.push(CallArg { kw, rhs });
            i += 1;
        }
    }
    steps.push(Step::Call {
        callee: callee.to_string(),
        recv,
        args,
        line: call.start_position().row + 1,
    });
}

fn expr_rhs_js(node: Node, src: &str, params: &[ParamInfo], vars: &HashMap<String, Rhs>) -> Rhs {
    match node.kind() {
        "identifier" | "shorthand_property_identifier" => {
            let Some(t) = text(node, src) else { return Rhs::Unknown };
            if let Some(rhs) = vars.get(t) {
                return rhs.clone();
            }
            if params.iter().any(|p| p.name == t) {
                return Rhs::Param(t.to_string());
            }
            Rhs::Unknown
        }
        "string" | "number" | "true" | "false" | "null" | "undefined" => {
            Rhs::Literal(text(node, src).unwrap_or("").to_string())
        }
        "call_expression" => {
            let func = node.child_by_field_name("function");
            let callee = func.and_then(|f| text(f, src)).unwrap_or("").to_string();
            let recv = func
                .filter(|f| f.kind() == "member_expression")
                .and_then(|f| f.child_by_field_name("object"))
                .map(|o| Box::new(expr_rhs_js(o, src, params, vars)));
            let mut args = Vec::new();
            if let Some(arglist) = node.child_by_field_name("arguments") {
                let mut i = 0;
                while let Some(arg) = arglist.named_child(i) {
                    let rhs = expr_rhs_js(arg, src, params, vars);
                    args.push(CallArg { kw: None, rhs });
                    i += 1;
                }
            }
            Rhs::Call { callee, recv, args }
        }
        "member_expression" | "subscript_expression" => {
            let obj = node.child_by_field_name("object");
            match obj {
                Some(o) => expr_rhs_js(o, src, params, vars),
                None => Rhs::Unknown,
            }
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left").map(|n| expr_rhs_js(n, src, params, vars));
            let right = node.child_by_field_name("right").map(|n| expr_rhs_js(n, src, params, vars));
            match (left, right) {
                (Some(l), Some(r)) => pick_binary_rhs(l, r),
                (Some(l), None) => l,
                (None, Some(r)) => r,
                (None, None) => Rhs::Unknown,
            }
        }
        "array" => {
            let mut items = Vec::new();
            let mut i = 0;
            while let Some(child) = node.named_child(i) {
                items.push(expr_rhs_js(child, src, params, vars));
                i += 1;
            }
            Rhs::Container(items)
        }
        "template_string" => Rhs::Unknown,
        _ => Rhs::Unknown,
    }
}
