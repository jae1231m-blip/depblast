//! Dynamic YAML rule engine (v4).
//!
//! Taint rules are data, not code: each rule declares its `sources`,
//! `sanitizers` and `sinks` in YAML. Default rulesets are embedded with
//! `include_str!`; extra rulesets can be loaded from disk with `--rules`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::SlopCategory;

/// A rule as written in YAML.
#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub id: String,
    pub severity: String,
    /// `dangerous_sink` | `secret` | `lazy_config` | `ai_slop` | `access_control`
    pub category: String,
    #[serde(default)]
    pub languages: Vec<String>,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub sanitizers: Vec<String>,
    #[serde(default)]
    pub sinks: Vec<SinkSpec>,
}

/// One sink signature.
#[derive(Debug, Deserialize)]
pub struct SinkSpec {
    /// Dotted callee. `subprocess.*` matches every `subprocess.X`.
    pub call: String,
    /// Which argument must carry taint: `any` (default) or `first`.
    #[serde(default)]
    pub arg: Option<String>,
    /// Required keyword flag, e.g. `shell=True`:
    /// `requires: { name: shell, value: "True" }`.
    #[serde(default)]
    pub requires: Option<FlagReq>,
}

#[derive(Debug, Deserialize)]
pub struct FlagReq {
    pub name: String,
    pub value: String,
}

/// A rule compiled for matching.
#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub severity: String,
    pub category: SlopCategory,
    pub message: String,
    pub remediation: String,
    pub sources: Vec<String>,
    pub sanitizers: Vec<String>,
    pub sinks: Vec<SinkSpec>,
    pub languages: Vec<String>,
}

impl CompiledRule {
    /// Does the captured origin tag count as a source for this rule?
    pub fn source_matches(&self, origin: &str) -> bool {
        self.sources.iter().any(|spec| origin_spec_matches(spec, origin))
    }

    /// Does `callee` name a sanitizer for this rule? Sanitizers may be used
    /// bare after a from-import (`from shlex import quote; quote(x)`), so the
    /// last path segment matches too.
    pub fn is_sanitizer(&self, callee: &str) -> bool {
        self.sanitizers.iter().any(|spec| {
            spec == callee
                || last_segment(spec) == last_segment(callee)
        })
    }

    /// Does `callee` match one of this rule's sinks (with its constraints)?
    pub fn sink_match(&self, callee: &str, args: &[crate::indexer::symbols::CallArg]) -> bool {
        self.sinks.iter().any(|sink| {
            if !sink_call_matches(&sink.call, callee) {
                return false;
            }
            if let Some(req) = &sink.requires {
                let hit = args.iter().any(|a| {
                    a.kw.as_deref() == Some(req.name.as_str())
                        && matches!(&a.rhs,
                            crate::indexer::symbols::Rhs::Literal(v)
                            if v.eq_ignore_ascii_case(&req.value)
                        )
                });
                if !hit {
                    return false;
                }
            }
            true
        })
    }

    /// `true` when only the first argument must be tainted.
    pub fn sink_is_first_arg(&self, callee: &str) -> bool {
        self.sinks.iter().any(|sink| {
            sink_call_matches(&sink.call, callee) && sink.arg.as_deref() == Some("first")
        })
    }
}

pub fn category_from(s: &str) -> SlopCategory {
    match s {
        "secret" => SlopCategory::Secret,
        "lazy_config" => SlopCategory::LazyConfig,
        "ai_slop" => SlopCategory::AiSlop,
        "access_control" => SlopCategory::AccessControl,
        _ => SlopCategory::DangerousSink,
    }
}

/// `request.*` matches origin `request.*` (prefix); `input()` matches
/// `input()`; `http-param` matches the framework parameter tag.
fn origin_spec_matches(spec: &str, origin: &str) -> bool {
    if spec == origin {
        return true;
    }
    let prefix = spec
        .trim_end_matches(".*")
        .trim_end_matches("()")
        .trim_end_matches('.');
    !prefix.is_empty() && origin.starts_with(prefix)
}

fn last_segment(dotted: &str) -> &str {
    dotted.rsplit('.').next().unwrap_or(dotted)
}

/// Exact dotted match, or prefix wildcard (`subprocess.*`).
fn sink_call_matches(spec: &str, callee: &str) -> bool {
    if let Some(prefix) = spec.strip_suffix(".*") {
        return callee.starts_with(prefix);
    }
    spec == callee
}

/// All rules: embedded defaults + any loaded from `--rules`.
pub struct RuleRegistry {
    pub rules: Vec<Arc<CompiledRule>>,
}

impl RuleRegistry {
    /// Embedded default rulesets.
    pub fn builtin() -> RuleRegistry {
        let mut rules = Vec::new();
        for src in [
            include_str!("yaml/ssrf.yaml"),
            include_str!("yaml/path-traversal.yaml"),
            include_str!("yaml/code-injection.yaml"),
        ] {
            match load_yaml_str(src) {
                Ok(mut rs) => rules.append(&mut rs),
                Err(e) => eprintln!("warning: embedded rule parse failed: {e}"),
            }
        }
        RuleRegistry {
            rules: rules.into_iter().map(|r| Arc::new(compile(r))).collect(),
        }
    }

    /// Load additional YAML rulesets from a file or directory.
    pub fn load_extra(&mut self, path: &Path) -> Result<usize> {
        let mut loaded = 0;
        let paths: Vec<std::path::PathBuf> = if path.is_dir() {
            let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(path)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    matches!(p.extension().and_then(|e| e.to_str()), Some("yaml") | Some("yml"))
                })
                .collect();
            files.sort();
            files
        } else {
            vec![path.to_path_buf()]
        };
        for p in paths {
            let text = std::fs::read_to_string(&p)
                .with_context(|| format!("reading ruleset {}", p.display()))?;
            let rs = load_yaml_str(&text)
                .with_context(|| format!("parsing ruleset {}", p.display()))?;
            loaded += rs.len();
            let compiled: Vec<Arc<CompiledRule>> =
                rs.into_iter().map(|r| Arc::new(compile(r))).collect();
            self.rules.extend(compiled);
        }
        Ok(loaded)
    }
}

/// Compile a YAML rule into its matching form.
fn compile(raw: RawRule) -> CompiledRule {
    CompiledRule {
        id: raw.id,
        severity: raw.severity,
        category: category_from(&raw.category),
        message: raw.message,
        remediation: raw.remediation,
        sources: raw.sources,
        sanitizers: raw.sanitizers,
        sinks: raw.sinks,
        languages: raw.languages,
    }
}

/// Parse a YAML document containing one rule or a list of rules.
pub fn load_yaml_str(src: &str) -> Result<Vec<RawRule>> {
    let trimmed = src.trim_start();
    let raw_rules: Vec<RawRule> = if trimmed.starts_with('-') {
        serde_yaml::from_str(src).context("parsing rule list")?
    } else {
        vec![serde_yaml::from_str(src).context("parsing rule")?]
    };
    for r in &raw_rules {
        if r.id.is_empty() {
            anyhow::bail!("rule with empty id");
        }
    }
    Ok(raw_rules)
}
