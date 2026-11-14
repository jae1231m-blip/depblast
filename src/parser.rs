use crate::model::{DepGraph, Dependency, normalize_name};
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

pub struct ParsedProject {
    pub deps: Vec<Dependency>,
    pub dev_deps: Vec<Dependency>,
    pub graph: DepGraph,
}

impl ParsedProject {
    pub fn new() -> Self {
        ParsedProject {
            deps: Vec::new(),
            dev_deps: Vec::new(),
            graph: DepGraph::new(),
        }
    }
}

pub fn parse_project(root: &Path) -> Result<ParsedProject> {
    let mut proj = ParsedProject::new();

    // JavaScript / Node.js: package-lock.json
    let pkg_lock = root.join("package-lock.json");
    if pkg_lock.exists() {
        let mut p = parse_package_lock(&pkg_lock)?;
        proj.deps.append(&mut p.deps);
        proj.dev_deps.append(&mut p.dev_deps);
        proj.graph = p.graph;
        return Ok(proj);
    }

    // Python: requirements.txt
    let req = root.join("requirements.txt");
    if req.exists() {
        let mut p = parse_requirements(&req, false)?;
        proj.deps.append(&mut p.deps);
        proj.dev_deps.append(&mut p.dev_deps);
        proj.graph = p.graph;
        return Ok(proj);
    }

    // Python: pyproject.toml
    let pyproject = root.join("pyproject.toml");
    if pyproject.exists() {
        let mut p = parse_pyproject(&pyproject, false)?;
        proj.deps.append(&mut p.deps);
        proj.dev_deps.append(&mut p.dev_deps);
        proj.graph = p.graph;
        return Ok(proj);
    }

    Err(anyhow::anyhow!(
        "no supported dependency manifest found (package-lock.json, requirements.txt, or pyproject.toml)"
    ))
}

fn parse_package_lock(path: &Path) -> Result<ParsedProject> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&data)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    let mut proj = ParsedProject::new();

    // Resolve concrete version strings from the flattened `packages` tree,
    // falling back to the literal dependency value when a packages node is
    // absent or the dependency is only declared as a range.
    let mut version_by_name: HashMap<String, String> = HashMap::new();
    if let Some(pkg) = v.get("packages").and_then(|x| x.as_object()) {
        for (key, val) in pkg {
            if let Some(rest) = key.strip_prefix("node_modules/") {
                // Skip nested packages (node_modules/foo/node_modules/bar).
                if rest.contains("node_modules") {
                    continue;
                }
                let name = normalize_name(rest.split('/').next().unwrap_or(""));
                if let Some(obj) = val.as_object() {
                    if let Some(ver) = obj.get("version").and_then(|x| x.as_str()) {
                        if !ver.is_empty() {
                            version_by_name.insert(name, ver.to_string());
                        }
                    }
                }
            }
        }
    }

    // Dependencies live under the root package node (`packages[""]`).
    let mut read_deps = |deps_obj: Option<&serde_json::Value>, is_dev: bool| {
        if let Some(deps_obj) = deps_obj {
            for (name, val) in deps_obj.as_object().unwrap() {
                let original_name = name.to_string();
                let name = normalize_name(name);
                let version = if let Some(v) = version_by_name.get(&name) {
                    v.clone()
                } else if let Some(obj) = val.as_object() {
                    obj.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string()
                } else if let Some(s) = val.as_str() {
                    s.to_string()
                } else {
                    "(unpinned)".into()
                };
                if !version.is_empty() && version != "(unpinned)" {
                    if is_dev {
                        proj.dev_deps.push(Dependency {
                            name: name.clone(),
                            original_name: original_name.clone(),
                            version,
                            is_dev: true,
                            ecosystem: "npm".into(),
                            source: path.display().to_string(),
                        });
                    } else {
                        proj.deps.push(Dependency {
                            name: name.clone(),
                            original_name: original_name.clone(),
                            version,
                            is_dev: false,
                            ecosystem: "npm".into(),
                            source: path.display().to_string(),
                        });
                    }
                }
            }
        }
    };

    read_deps(
        v.get("packages")
            .and_then(|x| x.as_object())
            .and_then(|p| p.get(""))
            .and_then(|x| x.as_object())
            .and_then(|r| r.get("dependencies")),
        false,
    );
    read_deps(
        v.get("packages")
            .and_then(|x| x.as_object())
            .and_then(|p| p.get(""))
            .and_then(|x| x.as_object())
            .and_then(|r| r.get("devDependencies")),
        true,
    );

    if let Some(pkg) = v.get("packages").and_then(|x| x.as_object()) {
        proj.graph = build_js_graph(&serde_json::Value::Object(pkg.clone()))?;
    }

    Ok(proj)
}

fn parse_requirements(path: &Path, include_dev: bool) -> Result<ParsedProject> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut proj = ParsedProject::new();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip directives and URL/git references that carry no name.
        if line.starts_with("-") || line.starts_with("http") || line.starts_with("git+") {
            continue;
        }
        let name = extract_name(line)?;
        if name.is_empty() {
            continue;
        }
        // Strip environment markers: name==1.0; python_version>="3.8"
        let name_part = name.split(';').next().unwrap_or("").trim();
        // name may be "name==version", "name @ url", or just "name".
        let name = name_part.split_whitespace().next().unwrap_or("").to_string();
        // Capture the version token; strip environment markers and URL refs.
        let version = name_part
            .strip_prefix(name.as_str())
            .map(|rest| {
                rest.split([';', '@', ' '])
                    .next()
                    .unwrap_or("")
                    .trim()
            })
            .unwrap_or("")
            .trim_start_matches("==")
            .trim()
            .to_string();

        if !include_dev {
            proj.deps.push(Dependency {
                name: name.to_string(),
                original_name: name.to_string(),
                version: if version.is_empty() { "(unpinned)".into() } else { version },
                is_dev: false,
                ecosystem: "PyPI".into(),
                source: path.display().to_string(),
            });
        }
    }

    Ok(proj)
}

fn parse_pyproject(path: &Path, include_dev: bool) -> Result<ParsedProject> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let v: toml::Value = toml::from_str(&data)?;

    let mut proj = ParsedProject::new();

    // PEP 621: [project].dependencies = ["name>=1.0"]
    if let Some(arr) = v.get("project")
        .and_then(|x| x.get("dependencies"))
        .and_then(|x| x.as_array())
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                let name = extract_name(s)?;
                if !name.is_empty() && !include_dev {
                    add_pypi_dep(&mut proj, name, false, path);
                }
            } else if let Some(t) = item.as_table() {
                if let Some(name) = t.get("name").and_then(|x| x.as_str()) {
                    if !include_dev {
                        add_pypi_dep(&mut proj, name.to_string(), false, path);
                    }
                }
            }
        }
    }

    // Poetry: [tool.poetry.dependencies] (production), [tool.poetry.group.dev.dependencies] (dev)
    if let Some(poetry) = v.get("tool").and_then(|x| x.get("poetry")) {
        if let Some(d) = poetry.get("dependencies").and_then(|x| x.as_table()) {
            for (name, _) in d {
                add_pypi_dep(&mut proj, name.clone(), false, path);
            }
        }
        if let Some(g) = poetry.get("group").and_then(|x| x.get("dev")) {
            if let Some(d) = g.get("dependencies").and_then(|x| x.as_table()) {
                for (name, _) in d {
                    add_pypi_dep(&mut proj, name.clone(), true, path);
                }
            }
        }
    }

    // PEP 735: [dependency-groups] / [tool.poetry.dependency-groups]
    if let Some(table) = v.get("dependency-groups")
        .or_else(|| v.get("tool").and_then(|x| x.get("poetry")).and_then(|x| x.get("dependency-groups")))
        .and_then(|x| x.as_table())
    {
        for (name, _) in table {
            add_pypi_dep(&mut proj, name.clone(), true, path);
        }
    }

    Ok(proj)
}

fn add_pypi_dep(proj: &mut ParsedProject, name: String, is_dev: bool, path: &Path) {
    let dep = Dependency {
        name: name.clone(),
        original_name: name.clone(),
        version: "(unpinned)".into(),
        is_dev,
        ecosystem: "PyPI".into(),
        source: path.display().to_string(),
    };
    proj.deps.push(dep);
    if is_dev {
        proj.dev_deps.push(Dependency {
            name: name.clone(),
            original_name: name,
            version: "(unpinned)".into(),
            is_dev: true,
            ecosystem: "PyPI".into(),
            source: path.display().to_string(),
        });
    }
}

/// Extract the leading distribution name from a requirement line such as
/// `foo==1.2.3`, `foo>=1.0`, or `foo @ https://...`.
fn extract_name(line: &str) -> Result<String> {
    let re = Regex::new(r"^([A-Za-z0-9][A-Za-z0-9._-]*)").context("build name regex")?;
    let cap = re.captures(line).context("parse requirement line")?;
    Ok(cap[1].to_string())
}

// --- JavaScript dependency graph ---
fn build_js_graph(packages: &serde_json::Value) -> Result<DepGraph> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();

    if let Some(obj) = packages.as_object() {
        for (key, val) in obj {
            // Direct deps declared in this package's node.
            if let Some(d) = val.get("dependencies").and_then(|x| x.as_object()) {
                for dep_name in d.keys() {
                    add_edge(&mut adj, key, dep_name);
                }
            }
            // Nested packages: node_modules/X/node_modules/Y -> X -> Y.
            add_nested_edges(key, &mut adj);
        }
    }

    for v in adj.values_mut() {
        v.sort();
        v.dedup();
    }
    Ok(DepGraph { adj })
}

fn add_edge(adj: &mut HashMap<String, Vec<String>>, from: &str, to: &str) {
    let from = normalize_name(canonical_package(from));
    let to = normalize_name(canonical_package(to));
    if from.is_empty() || to.is_empty() {
        return;
    }
    adj.entry(from).or_default().push(to);
}

fn canonical_package(s: &str) -> &str {
    let s = s.strip_prefix("node_modules/").unwrap_or(s);
    s.split('@').next().unwrap_or(s)
}

fn add_nested_edges(key: &str, adj: &mut HashMap<String, Vec<String>>) {
    if let Some(rest) = key.strip_prefix("node_modules/") {
        if let Some(second) = rest.find("node_modules/") {
            let x = &rest[..second];
            let y = &rest[second + "node_modules/".len()..];
            add_edge(adj, x, y);
        }
    }
}
