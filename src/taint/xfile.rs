//! Cross-file taint engine (v4 pass 2).
//!
//! Simulates each function's Pass-1 IR with tainted argument bindings,
//! resolving callees through the global `SymbolTable`. Sink hits carry a full
//! structured trace: `Source (file:line) -> Call (file:line) -> Sink`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::indexer::symbols::{CallArg, FnSummary, ParamInfo, Rhs, Step};
use crate::indexer::SymbolTable;
use crate::model::{SlopFinding, TraceStep};
use crate::rules::taint_rules::CompiledRule;

/// A tainted value flowing through the simulation.
#[derive(Debug, Clone)]
pub struct TaintVal {
    /// Origin tag (`request.*`, `input()`, `http-param`, ...).
    pub origin: String,
    /// Trace path from the source to this point.
    pub trace: Vec<TraceStep>,
}

/// A sink reached by tainted data.
#[derive(Debug, Clone)]
pub struct SinkHit {
    pub file: String,
    pub line: usize,
    pub sink: String,
    /// `eval`/`exec` with restricted `{"__builtins__": ...}` globals —
    /// downgraded to LOW (RESTRICTED_EXECUTION) instead of full RCE.
    pub restricted: bool,
    pub trace: Vec<TraceStep>,
}

#[derive(Default)]
struct EvalOut {
    hits: Vec<SinkHit>,
    ret: Option<TaintVal>,
}

pub struct Engine<'a> {
    table: &'a SymbolTable,
    rule: &'a CompiledRule,
    max_depth: usize,
    /// Shared evaluation budget across all rules and files.
    budget: Arc<AtomicUsize>,
}

impl<'a> Engine<'a> {
    pub fn new(table: &'a SymbolTable, rule: &'a CompiledRule, max_depth: usize, budget: Arc<AtomicUsize>) -> Self {
        Engine { table, rule, max_depth, budget }
    }

    /// Analyze every function (and the module top level) of one file.
    pub fn analyze_file(&self, file: &str) -> Vec<SlopFinding> {
        let mut findings = Vec::new();
        let Some(keys) = self.table.functions_by_file.get(file).map(|k| k.clone()) else {
            return findings;
        };
        for qualified in keys {
            let Some(summary) = self.table.functions.get(&qualified).map(|s| s.value().clone()) else {
                continue;
            };
            let bindings = self.source_bindings(&summary);
            let mut out = EvalOut::default();
            self.simulate(&summary, &bindings, self.max_depth, &mut out);
            for hit in out.hits {
                findings.push(self.hit_to_finding(hit));
            }
        }
        // One finding per (file, line, rule).
        findings.sort_by(|a, b| a.line.cmp(&b.line));
        findings.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.rule == b.rule);
        findings
    }

    /// Order trace steps chronologically: Source -> Call -> Sink. Call steps
    /// are prepended as hits bubble up through callers, so a stable sort by
    /// kind restores the propagation order.
    fn order_trace(trace: Vec<TraceStep>) -> Vec<TraceStep> {
        fn rank(kind: &str) -> u8 {
            match kind {
                "source" => 0,
                "call" => 1,
                _ => 2,
            }
        }
        let mut trace = trace;
        trace.sort_by_key(|s| rank(&s.kind));
        trace
    }

    fn hit_to_finding(&self, hit: SinkHit) -> SlopFinding {
        if hit.restricted {
            return SlopFinding::new(
                &hit.file,
                hit.line,
                self.rule.category,
                "LOW",
                "restricted-execution",
                format!(
                    "`{}` executes with restricted `{{\"__builtins__\": ...}}` globals — sandboxed, downgraded from RCE",
                    hit.sink
                ),
                "Keep the restricted globals exactly as they are; an empty `__builtins__` is what makes this safe. Review any change that removes it.",
            )
            .with_trace(Self::order_trace(hit.trace));
        }
        SlopFinding::new(
            &hit.file,
            hit.line,
            self.rule.category,
            &self.rule.severity,
            &self.rule.id,
            self.rule.message.replace("{sink}", &hit.sink),
            &self.rule.remediation,
        )
        .with_trace(Self::order_trace(hit.trace))
    }

    /// Bind framework sources for endpoint handlers: FastAPI `Query()/Body()/
    /// Form()/Header()/File()/UploadFile` parameters and a `request` param.
    fn source_bindings(&self, summary: &FnSummary) -> HashMap<String, TaintVal> {
        let mut b = HashMap::new();
        let is_handler = self
            .table
            .endpoints
            .get(&summary.file)
            .map(|eps| {
                eps.iter().any(|e| {
                    e.func == summary.qualified.rsplit('.').next().unwrap_or("")
                })
            })
            .unwrap_or(false);
        for p in &summary.params {
            let tag = if p.name == "request" || p.annotation.contains("Request") {
                Some("request.*")
            } else if is_handler && (framework_param(&p.annotation) || p.annotation.is_empty()) {
                // FastAPI Query()/Body()/... params, and unannotated handler
                // params (Flask path params, FastAPI implicit query params).
                // Typed non-framework annotations (`user_id: int`) count as
                // validated at the framework boundary.
                Some("http-param")
            } else {
                None
            };
            if let Some(tag) = tag {
                b.insert(
                    p.name.clone(),
                    TaintVal {
                        origin: tag.to_string(),
                        trace: vec![TraceStep::source(
                            &summary.file,
                            summary.line.max(1),
                            format!("{} ({tag})", p.name),
                        )],
                    },
                );
            }
        }
        b
    }

    /// Simulate one function's IR with the given tainted bindings.
    fn simulate(&self, summary: &FnSummary, bindings: &HashMap<String, TaintVal>, depth: usize, out: &mut EvalOut) {
        let mut vars: HashMap<String, Option<TaintVal>> = HashMap::new();
        let mut ret: Option<TaintVal> = None;
        for step in &summary.steps {
            match step {
                Step::Assign { var, rhs, line } => {
                    let t = self.taint_of(rhs, bindings, &vars, depth, &summary.file, *line, out);
                    vars.insert(var.clone(), t);
                }
                Step::Call { callee, recv, args, line } => {
                    let rhs = Rhs::Call {
                        callee: callee.clone(),
                        recv: recv.clone().map(Box::new),
                        args: args.clone(),
                    };
                    let _ = self.taint_of(&rhs, bindings, &vars, depth, &summary.file, *line, out);
                }
                Step::Return { rhs, line } => {
                    if let Some(t) = self.taint_of(rhs, bindings, &vars, depth, &summary.file, *line, out) {
                        ret = Some(t);
                    }
                }
            }
        }
        out.ret = ret;
    }

    fn taint_of(
        &self,
        rhs: &Rhs,
        bindings: &HashMap<String, TaintVal>,
        vars: &HashMap<String, Option<TaintVal>>,
        depth: usize,
        file: &str,
        line: usize,
        out: &mut EvalOut,
    ) -> Option<TaintVal> {
        match rhs {
            Rhs::Param(p) => bindings.get(p).cloned(),
            Rhs::Source(tag) => {
                if self.rule.source_matches(tag) {
                    Some(TaintVal {
                        origin: tag.clone(),
                        trace: vec![TraceStep::source(file, line, tag)],
                    })
                } else {
                    None
                }
            }
            Rhs::Literal(_) | Rhs::Raw(_) | Rhs::Unknown => None,
            Rhs::Container(items) => items
                .iter()
                .find_map(|i| self.taint_of(i, bindings, vars, depth, file, line, out)),
            Rhs::Call { callee, recv, args } => {
                self.taint_of_call(callee, recv.as_deref(), args, bindings, vars, depth, file, line, out)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn taint_of_call(
        &self,
        callee: &str,
        recv: Option<&Rhs>,
        args: &[CallArg],
        bindings: &HashMap<String, TaintVal>,
        vars: &HashMap<String, Option<TaintVal>>,
        depth: usize,
        file: &str,
        line: usize,
        out: &mut EvalOut,
    ) -> Option<TaintVal> {
        // Nested arguments first: their sink checks record hits too.
        let arg_taints: Vec<Option<TaintVal>> = args
            .iter()
            .map(|a| self.taint_of(&a.rhs, bindings, vars, depth, file, line, out))
            .collect();
        let recv_taint = recv.and_then(|r| self.taint_of(r, bindings, vars, depth, file, line, out));

        // Sanitizers strip taint along this branch.
        if self.rule.is_sanitizer(callee) {
            return None;
        }

        // Sink?
        if self.rule.sink_match(callee, args) {
            let first_only = self.rule.sink_is_first_arg(callee);
            let tainted = if first_only {
                arg_taints.first().cloned().flatten().or(recv_taint.clone())
            } else {
                arg_taints.iter().flatten().next().cloned().or(recv_taint.clone())
            };
            if let Some(t) = tainted {
                let restricted = is_restricted_exec(callee, args);
                let mut trace = t.trace.clone();
                trace.push(TraceStep::sink(file, line, callee));
                out.hits.push(SinkHit {
                    file: file.to_string(),
                    line,
                    sink: callee.to_string(),
                    restricted,
                    trace,
                });
            }
            return None;
        }

        // Cross-file propagation through the symbol table.
        if depth > 0 && self.budget.load(Ordering::Relaxed) > 0 {
            if let Some(qualified) = self.table.resolve_callee(file, callee) {
                if let Some(summary) = self.table.functions.get(&qualified).map(|s| s.value().clone()) {
                    self.budget.fetch_sub(1, Ordering::Relaxed);
                    let callee_bindings = self.bind_callee(&summary, args, recv, &arg_taints, recv_taint.clone());
                    let mut sub = EvalOut::default();
                    self.simulate(&summary, &callee_bindings, depth - 1, &mut sub);
                    for mut hit in sub.hits {
                        hit.trace.insert(0, TraceStep::call(file, line, callee));
                        out.hits.push(hit);
                    }
                    if let Some(rt) = sub.ret {
                        let mut trace = rt.trace.clone();
                        trace.push(TraceStep::call(file, line, callee));
                        return Some(TaintVal { origin: rt.origin, trace });
                    }
                }
            }
        }

        // A method call on a tainted receiver propagates taint
        // (`tainted_data.strip()`, `tainted_list[0]`, ...).
        recv_taint
    }

    /// Build tainted bindings for a callee's parameters from this call.
    fn bind_callee(
        &self,
        summary: &FnSummary,
        args: &[CallArg],
        recv: Option<&Rhs>,
        arg_taints: &[Option<TaintVal>],
        recv_taint: Option<TaintVal>,
    ) -> HashMap<String, TaintVal> {
        let mut b: HashMap<String, TaintVal> = HashMap::new();
        let positional: Vec<&ParamInfo> = summary
            .params
            .iter()
            .filter(|p| recv.is_none() || (p.name != "self" && p.name != "cls"))
            .collect();
        for (i, p) in positional.iter().enumerate() {
            if let (Some(arg), Some(t)) = (args.get(i), arg_taints.get(i).and_then(|t| t.clone())) {
                if arg.kw.is_none() {
                    b.insert(p.name.clone(), t);
                }
            }
        }
        // Keyword arguments bind by name.
        for (arg, t) in args.iter().zip(arg_taints) {
            if let (Some(kw), Some(t)) = (&arg.kw, t) {
                b.insert(kw.clone(), t.clone());
            }
        }
        // Bound method: the receiver taints `self`.
        if let (Some(rt), Some(first)) = (recv_taint, summary.params.first()) {
            b.insert(first.name.clone(), rt);
        }
        b
    }
}

/// FastAPI-style framework parameter annotations that carry request data.
/// (`Depends(...)` is auth/infrastructure, not a data source.)
fn framework_param(annotation: &str) -> bool {
    ["Query(", "Body(", "Form(", "Header(", "Cookie(", "File(", "UploadFile"]
        .iter()
        .any(|m| annotation.contains(m))
}

/// `eval(expr, {"__builtins__": {}})` — restricted globals downgrade.
fn is_restricted_exec(callee: &str, args: &[CallArg]) -> bool {
    matches!(callee, "eval" | "exec")
        && args.iter().any(|a| {
            matches!(&a.rhs, Rhs::Raw(text) if text.contains("__builtins__"))
        })
}
