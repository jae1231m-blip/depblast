use std::collections::HashMap;
use std::path::PathBuf;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    pub package: String,
    pub version: String,
    pub severity: String,
    pub ids: Vec<String>,
    pub summary: String,
    pub cvss: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    pub name: String,
    pub original_name: String,
    pub version: String,
    pub is_dev: bool,
    pub ecosystem: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Imported {
    pub file: String,
    pub line: usize,
    pub package: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum HitKind {
    Direct,
    Transitive,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub file: String,
    pub line: Option<usize>,
    pub kind: HitKind,
    pub chain: Vec<String>,
    pub package: String,
    pub version: String,
    pub severity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SlopCategory {
    Secret,
    LazyConfig,
    DangerousSink,
    AccessControl,
    AiSlop,
}

/// One hop in a cross-file taint trace path.
#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    /// `source` | `call` | `sink`
    pub kind: String,
    pub file: String,
    /// 1-based line.
    pub line: usize,
    /// Human-readable hop description (`request.args.get`, `fetch(url)`).
    pub label: String,
}

impl TraceStep {
    pub fn source(file: &str, line: usize, label: impl Into<String>) -> Self {
        TraceStep { kind: "source".into(), file: file.into(), line, label: label.into() }
    }

    pub fn call(file: &str, line: usize, label: impl Into<String>) -> Self {
        TraceStep { kind: "call".into(), file: file.into(), line, label: label.into() }
    }

    pub fn sink(file: &str, line: usize, label: impl Into<String>) -> Self {
        TraceStep { kind: "sink".into(), file: file.into(), line, label: label.into() }
    }
}

/// Attack surface statistics for the summary section.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AttackSurface {
    /// Total HTTP endpoints discovered by route decorators.
    pub endpoints: usize,
    /// State-changing endpoints (POST/PUT/PATCH/DELETE) with no auth.
    pub unauthenticated_endpoints: usize,
    /// Call sites that reach external network sinks (requests/httpx/urllib).
    pub network_sinks: usize,
    /// Call sites that execute OS commands or code (subprocess/os.system/eval).
    pub command_sinks: usize,
}

/// One finding of the AI slop / security audit.
#[derive(Debug, Clone, Serialize)]
pub struct SlopFinding {
    pub file: String,
    pub line: usize,
    pub category: SlopCategory,
    pub severity: String,
    /// Short machine-readable rule id, e.g. `hardcoded-secret`.
    pub rule: String,
    /// One-line description of what was found (never echoes secret values).
    pub detail: String,
    /// Short actionable fix suggestion.
    pub fix_tip: String,
    /// True when the finding sits in a test/fixture/mock path (v3: severity
    /// is downgraded to INFO and it renders in a separate section).
    pub in_test_context: bool,
    /// Cross-file taint trace (`Source -> Call -> Sink`), when present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<TraceStep>,
}

impl SlopFinding {
    pub fn new(
        file: &str,
        line: usize,
        category: SlopCategory,
        severity: &str,
        rule: &str,
        detail: impl Into<String>,
        fix_tip: &str,
    ) -> Self {
        SlopFinding {
            file: file.to_string(),
            line,
            category,
            severity: severity.to_string(),
            rule: rule.to_string(),
            detail: detail.into(),
            fix_tip: fix_tip.to_string(),
            in_test_context: false,
            trace: Vec::new(),
        }
    }

    /// Attach a trace path and return the finding.
    pub fn with_trace(mut self, trace: Vec<TraceStep>) -> Self {
        self.trace = trace;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub source_dir: PathBuf,
    pub scanned_files: usize,
    pub dependencies: usize,
    pub vulnerabilities: usize,
    pub hits: Vec<Hit>,
    pub cache_status: CacheStatus,
    /// Findings from the AI slop / security audit (empty unless --slop/--all).
    pub slop: Vec<SlopFinding>,
    /// True when only the slop audit ran (--slop-only).
    pub slop_only: bool,
    /// Attack surface summary (v4, present when the audit ran).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_surface: Option<AttackSurface>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStatus {
    pub queried: usize,
    pub used_cached: usize,
    pub fetched: usize,
}

#[derive(Debug, Clone)]
pub struct DepGraph {
    pub adj: HashMap<String, Vec<String>>,
}

impl DepGraph {
    pub fn new() -> Self {
        DepGraph { adj: HashMap::new() }
    }
}

impl Report {
    /// Worst severity across dependency hits and production slop findings
    /// (test/mock findings are INFO and never gate the exit code).
    fn worst_severity(&self) -> u8 {
        self.hits
            .iter()
            .map(|h| severity_to_rank(Some(&h.severity)))
            .chain(
                self.slop
                    .iter()
                    .filter(|f| !f.in_test_context)
                    .map(|f| severity_to_rank(Some(&f.severity))),
            )
            .max()
            .unwrap_or(0)
    }

    pub fn exit_code(&self, fail_on: Option<&str>) -> u8 {
        let threshold = fail_on.map(|s| severity_to_rank(Some(s))).unwrap_or(0);
        if threshold == 0 {
            // Default: fail when anything was found (even UNKNOWN-severity hits).
            let production_slop = self.slop.iter().any(|f| !f.in_test_context);
            return if self.hits.is_empty() && !production_slop { 0 } else { 1 };
        }
        if self.worst_severity() >= threshold {
            1
        } else {
            0
        }
    }
}

pub fn severity_to_rank(s: Option<&str>) -> u8 {
    match s {
        Some(x) => match x.to_ascii_uppercase() {
            s if s == "CRITICAL" => 4,
            s if s == "HIGH" => 3,
            s if s == "MEDIUM" => 2,
            s if s == "LOW" => 1,
            _ => 0,
        },
        None => 0,
    }
}

/// Normalize a package name to lowercase and replace hyphens with underscores,
/// so `yargs-parser` and `YARGS-PARSER` both match as `yargs_parser`.
pub fn normalize_name(pkg: &str) -> String {
    pkg.to_lowercase().replace('-', "_")
}
