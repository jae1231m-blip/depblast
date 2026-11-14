//! Framework-aware analysis (v4): unauthenticated state-changing endpoints
//! (FastAPI / Flask) and the attack surface summary.

use crate::indexer::symbols::Step;
use crate::indexer::SymbolTable;
use crate::model::{AttackSurface, SlopCategory, SlopFinding};

/// External network sink prefixes (SSRF/outbound egress surface).
const NETWORK_SINKS: &[&str] = &[
    "requests.", "httpx.", "urllib.request.urlopen", "urllib.urlopen",
    "urllib2.urlopen", "aiohttp.", "http.client.HTTPConnection",
];

/// OS command / code execution sink prefixes.
const COMMAND_SINKS: &[&str] = &[
    "subprocess.", "os.system", "os.popen", "eval", "exec", "pickle.loads",
    "pickle.load",
];

/// Analyze the symbol table: endpoint auth posture + attack surface counts.
pub fn analyze(table: &SymbolTable) -> (Vec<SlopFinding>, AttackSurface) {
    let mut findings = Vec::new();
    let mut surface = AttackSurface::default();

    for entry in table.endpoints.iter() {
        for ep in entry.value() {
            surface.endpoints += 1;
            let state_changing = matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
            if state_changing && !ep.authenticated {
                surface.unauthenticated_endpoints += 1;
                let route = if ep.path.is_empty() { ep.func.clone() } else { ep.path.clone() };
                findings.push(SlopFinding::new(
                    &ep.file,
                    ep.line,
                    SlopCategory::AccessControl,
                    "MEDIUM",
                    "unauth-state-change",
                    format!(
                        "{} {} is a state-changing endpoint with no authentication dependency (`{}`)",
                        ep.method, route, ep.func
                    ),
                    "Require an auth dependency (FastAPI `Depends(get_current_user)` / Flask `@login_required`) on every endpoint that mutates state.",
                ));
            }
        }
    }

    // Sink counts: every call site across all indexed functions, including
    // calls nested in assignment/return RHS (`return requests.get(url)`).
    for entry in table.functions.iter() {
        for step in &entry.value().steps {
            match step {
                Step::Call { callee, .. } => {
                    count_callee(callee, &mut surface);
                }
                Step::Assign { rhs, .. } | Step::Return { rhs, .. } => {
                    count_rhs(rhs, &mut surface);
                }
            }
        }
    }

    findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    (findings, surface)
}

fn count_callee(callee: &str, surface: &mut AttackSurface) {
    if is_sink(callee, NETWORK_SINKS) {
        surface.network_sinks += 1;
    }
    if is_sink(callee, COMMAND_SINKS) {
        surface.command_sinks += 1;
    }
}

fn count_rhs(rhs: &crate::indexer::symbols::Rhs, surface: &mut AttackSurface) {
    use crate::indexer::symbols::Rhs;
    match rhs {
        Rhs::Call { callee, recv, args } => {
            count_callee(callee, surface);
            if let Some(recv) = recv {
                count_rhs(recv, surface);
            }
            for arg in args {
                count_rhs(&arg.rhs, surface);
            }
        }
        Rhs::Container(items) => {
            for item in items {
                count_rhs(item, surface);
            }
        }
        _ => {}
    }
}

fn is_sink(callee: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| {
        if p.ends_with('.') {
            callee.starts_with(p)
        } else {
            callee == *p || callee.starts_with(&format!("{p}("))
        }
    })
}
