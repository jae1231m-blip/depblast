use crate::api::OsvClient;
use crate::cache::Cache;
use crate::model::{DepGraph, Dependency, normalize_name, Imported, Vulnerability, HitKind};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
enum CacheOp {
    Cached,
    Fetched,
    Skipped,
}

fn find_vulns(
    cache: &Cache,
    api: &OsvClient,
    package: &str,
    version: &str,
    ecosystem: &str,
    update: bool,
) -> Result<(Vec<Vulnerability>, CacheOp), anyhow::Error> {
    // Unresolvable versions (e.g. unpinned requirements) can't be matched
    // against OSV; skip them instead of caching a useless empty result.
    if version.is_empty() || version == "(unpinned)" {
        return Ok((Vec::new(), CacheOp::Skipped));
    }
    if !update {
        if let Some(v) = cache.get(package, version)? {
            return Ok((parse_vulns(&v, package, version), CacheOp::Cached));
        }
    }
    let v = api.query(package, ecosystem, version)?;
    cache.set(package, version, v.clone())?;
    Ok((parse_vulns(&v, package, version), CacheOp::Fetched))
}

fn parse_vulns(v: &serde_json::Value, package: &str, version: &str) -> Vec<Vulnerability> {
    let mut out = Vec::new();
    for vuln in v
        .get("vulns")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        let severity = vuln
            .get("database_specific")
            .and_then(|s| s.get("severity"))
            .and_then(|s| s.as_str())
            .map(|s| {
                match s {
                    "CRITICAL" => "CRITICAL",
                    "HIGH" => "HIGH",
                    "LOW" => "LOW",
                    "MODERATE" | "MEDIUM" => "MEDIUM",
                    "P0" => "CRITICAL",
                    "P1" => "HIGH",
                    "P2" => "MEDIUM",
                    "P3" => "LOW",
                    "P4" => "LOW",
                    _ => "UNKNOWN",
                }
            })
            .unwrap_or_else(|| {
                vuln.get("severity")
                    .and_then(|x| x.as_array())
                    .and_then(|a| a.first())
                    .and_then(|x| x.get("score").and_then(|s| s.as_str()))
                    .map(|s| cvss_vector_to_severity(s))
                    .unwrap_or_else(|| "UNKNOWN")
            });
        let cvss = vuln
            .get("severity")
            .and_then(|s| s.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.get("score").and_then(|s| s.as_str()))
            .map(|s| s.to_string());
        let ids = vuln
            .get("identifiers")
            .and_then(|i| i.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("value").and_then(|s| s.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let summary = vuln
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("Unknown vulnerability")
            .to_string();
        out.push(Vulnerability {
            package: package.to_string(),
            version: version.to_string(),
            severity: severity.to_string(),
            cvss,
            ids,
            summary,
        });
    }
    out
}

fn cvss_vector_to_severity(vector: &str) -> &'static str {
    let mut av = 0.0f32;
    let mut ac = 0.0f32;
    let mut pr = 0.0f32;
    let mut ui = 0.0f32;
    let mut scope = 'U';
    let mut c = 0.0f32;
    let mut i = 0.0f32;
    let mut a = 0.0f32;
    for part in vector.split('/') {
        let part = part.trim();
        if part.len() < 3 {
            continue;
        }
        let k = &part[..2];
        let v = &part[2..];
        match k {
            "AV" => av = match v { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => 0.0 },
            "AC" => ac = match v { "L" => 0.77, "H" => 0.44, _ => 0.0 },
            "PR" => pr = match v { "N" => 0.85, "L" => 0.62, "H" => 0.27, _ => 0.0 },
            "UI" => ui = match v { "N" => 0.85, "R" => 0.62, _ => 0.0 },
            "S" => scope = v.chars().next().unwrap_or('U'),
            "C" => c = match v { "N" => 0.92, "L" => 0.22, "H" => 0.56, _ => 0.0 },
            "I" => i = match v { "N" => 0.92, "L" => 0.22, "H" => 0.56, _ => 0.0 },
            "A" => a = match v { "N" => 0.92, "L" => 0.22, "H" => 0.56, _ => 0.0 },
            _ => {}
        }
    }
    let pr = if scope == 'C' {
        match pr { 0.62 => 0.68, 0.27 => 0.5, _ => pr }
    } else {
        match pr { 0.68 => 0.62, 0.5 => 0.27, _ => pr }
    };
    let impact = if scope == 'U' {
        let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
        6.42 * iss
    } else {
        let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = impact + exploitability;
    let score = if scope == 'U' {
        if raw > 10.0 { 1.08 * (raw - 10.0) + 10.0 } else { raw }
    } else {
        raw.min(10.0)
    };
    let score = (score * 10.0).ceil() / 10.0;
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else {
        "LOW"
    }
}
pub async fn resolve(
    deps: &[Dependency],
    graph: &DepGraph,
    imported: &[Imported],
    update: bool,
    package_filter: Option<String>,
    scanned_files: usize,
    root: PathBuf,
) -> Result<crate::model::Report, anyhow::Error> {
    let cache = Cache::new()?;
    let api = OsvClient::new()?;

    // Index dependency names (lowercased) for O(1) membership tests.
    let mut deps_by_name: HashMap<String, Vec<&Dependency>> = HashMap::new();
    for d in deps {
        deps_by_name
            .entry(normalize_name(&d.name))
            .or_default()
            .push(d);
    }

    // Names we care about: everything (default) or a single package filter.
    let dep_names: HashSet<String> = if let Some(ref p) = package_filter {
        let target = normalize_name(p);
        deps
            .iter()
            .map(|d| normalize_name(&d.name))
            .filter(move |n| *n == target)
            .collect()
    } else {
        deps.iter().map(|d| normalize_name(&d.name)).collect()
    };

    // Reduce imported packages to those that actually map to a managed dependency.
    let mut filtered_imported: Vec<&Imported> = imported.iter().collect();
    filtered_imported.retain(|i| dep_names.contains(&i.package.to_lowercase()));

    // 1) Query vulnerabilities per dependency (cache-first, force-refresh with --update).
    let mut affected: HashMap<String, Vec<Vulnerability>> = HashMap::new();
    let mut cache_status = crate::model::CacheStatus {
        queried: 0,
        used_cached: 0,
        fetched: 0,
    };

    for d in deps {
        let name = normalize_name(&d.name);
        if !dep_names.contains(&name) {
            continue;
        }
        let (mut vulns, op) = find_vulns(&cache, &api, &d.original_name, &d.version, &d.ecosystem, update)?;
        if !vulns.is_empty() {
            // Key affected entries (and vuln.package) by the normalized name so
            // direct/transitive classification and path lookup stay consistent.
            for v in &mut vulns {
                v.package = name.clone();
            }
            affected.entry(name.clone()).or_default().extend(vulns);
        }
        match op {
            CacheOp::Cached => cache_status.used_cached += 1,
            CacheOp::Fetched => cache_status.fetched += 1,
            CacheOp::Skipped => {}
        }
    }
    cache_status.queried = cache_status.used_cached + cache_status.fetched;

    // Normalized dependency name -> concrete version, for reporting transitive hits.
    let version_by_name: HashMap<String, String> = deps
        .iter()
        .map(|d| (normalize_name(&d.name), d.version.clone()))
        .collect();

    // 2) Compute transitive reachability from every dependency.
    let reach = compute_reachability(graph);

    // 3) Build hits from imports x vulnerabilities.
    let mut hits = Vec::new();
    let mut seen = HashSet::new();

    for i in filtered_imported {
        let name = crate::model::normalize_name(&i.package);
        if package_filter
        .as_ref()
        .map_or(true, |p| name == normalize_name(p))
        {
            if !deps_by_name.contains_key(&name) {
                continue;
            }
            if let Some(vulns) = affected.get(&name) {
                for v in vulns {
                    let kind = if name == v.package {
                        HitKind::Direct
                    } else {
                        HitKind::Transitive
                    };
                    let chain = if kind == HitKind::Transitive {
                        path_to(graph, &name, v.package.as_str())
                    } else {
                        vec![name.clone()]
                    };                    let key = (
                        i.file.clone(),
                        i.line,
                        v.package.clone(),
                        v.version.clone(),
                        v.severity.clone(),
                        chain.join("|"),
                    );
                    if seen.insert(key) {
                        hits.push(crate::model::Hit {
                            file: i.file.clone(),
                            line: Some(i.line),
                            kind,
                            chain,
                            package: v.package.clone(),
                            version: v.version.clone(),
                            severity: v.severity.clone(),
                        });
                    }
                }
            }
            // Transitive hits for this import.
            if let Some(reachable) = reach.get(&name) {
                for r in reachable {
                    if r.as_str() == name || !affected.contains_key(r.as_str()) {
                        continue;
                    }
                    let chain = path_to(graph, &name, r.as_str());
                    let version = version_by_name.get(r.as_str()).cloned().unwrap_or_else(|| "unknown".into());
                    let key = (
                        i.file.clone(),
                        i.line,
                        r.clone(),
                        version.clone(),
                        affected.get(r.as_str()).unwrap()[0].severity.clone(),
                        chain.join("|"),
                    );
                    if seen.insert(key) {
                        hits.push(crate::model::Hit {
                            file: i.file.clone(),
                            line: Some(i.line),
                            kind: HitKind::Transitive,
                            chain,
                            package: r.clone(),
                            version,
                            severity: affected.get(r.as_str()).unwrap()[0].severity.clone(),
                        });
                    }
                }
            }
        }
    }

    // Sort: direct hits first, then by file/line.
    hits.sort_by(|a, b| {
        let ak = match a.kind {
            HitKind::Direct => 0,
            HitKind::Transitive => 1,
        };
        let bk = match b.kind {
            HitKind::Direct => 0,
            HitKind::Transitive => 1,
        };
        ak.cmp(&bk).then_with(|| a.file.cmp(&b.file)).then_with(|| a.line.cmp(&b.line))
    });

    Ok(crate::model::Report {
        source_dir: root,
        scanned_files,
        dependencies: deps.len(),
        vulnerabilities: affected.values().map(|v| v.len()).sum(),
        hits,
        cache_status,
        slop: Vec::new(),
        slop_only: false,
    })
}

fn compute_reachability(graph: &DepGraph) -> HashMap<String, Vec<String>> {
    let mut reach = HashMap::new();
    for name in graph.adj.keys() {
        let mut seen = HashSet::new();
        let mut stack = vec![name.clone()];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(deps) = graph.adj.get(&cur) {
                for d in deps {
                    if seen.insert(d.clone()) {
                        stack.push(d.clone());
                    }
                }
            }
        }
        reach.insert(name.clone(), seen.into_iter().collect());
    }
    reach
}

fn path_to(graph: &DepGraph, from: &str, to: &str) -> Vec<String> {
    if from == to {
        return vec![from.to_string()];
    }
    let mut prev: HashMap<String, String> = HashMap::new();
    let mut visited = HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(from.to_string());
    visited.insert(from.to_string());
    while let Some(cur) = queue.pop_front() {
        if let Some(deps) = graph.adj.get(&cur) {
            for d in deps {
                if visited.insert(d.clone()) {
                    prev.insert(d.clone(), cur.clone());
                    if d.as_str() == to {
                        let mut path = vec![d.clone()];
                        let mut cur = d.clone();
                        while let Some(p) = prev.get(&cur) {
                            path.push(p.clone());
                            cur = p.clone();
                        }
                        path.reverse();
                        return path;
                    }
                    queue.push_back(d.clone());
                }
            }
        }
    }
    vec![]
}

