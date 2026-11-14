use std::sync::LazyLock;
use anyhow::Context;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

use crate::model::{Imported};

/// Directories that never contain first-party source code worth scanning.
const SKIP_DIRS: &[&str] = &[
    "node_modules", "target", "dist", "build", "out", "vendor",
    ".next", ".nuxt", "venv", ".venv", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "site-packages", "coverage",
];

pub fn collect_source_files(root: &Path) -> Result<Vec<std::path::PathBuf>, anyhow::Error> {
    // Collect every source file under root (skipping dependency and build dirs).
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).with_context(|| format!("read dir {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                    stack.push(path);
                }
                continue;
            }
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if is_source_ext(ext) {
                        files.push(path);
                    }
                }
            }
        }
    }

    files.sort();
    Ok(files)
}

pub fn scan(root: &Path, package_filter: Vec<String>) -> Result<(Vec<Imported>, Vec<std::path::PathBuf>), anyhow::Error> {
    let files = collect_source_files(root)?;

    let filter_set: HashSet<String> = package_filter.iter().map(|s| s.to_lowercase()).collect();
    let mut imports = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(root)
            .with_context(|| format!("path strip {}", path.display()))?;
        let rel = rel.to_string_lossy().to_string();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (idx, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // --- Python ---
            if path.extension().and_then(|e| e.to_str()) == Some("py") {
                if let Some(cap) = PY_FROM_IMPORT.captures(line) {
                    let pkg = &cap[1];
                    if !pkg.starts_with('.') && in_filter(&top_level(pkg), &filter_set) {
                        add_import(&mut imports, &rel, idx + 1, top_level(pkg));
                    }
                } else if let Some(cap) = PY_IMPORT.captures(line) {
                    let pkg = &cap[1];
                    if in_filter(&top_level(pkg), &filter_set) {
                        add_import(&mut imports, &rel, idx + 1, top_level(pkg));
                    }
                }
                continue;
            }

            // --- JavaScript / TypeScript ---
            if let Some(cap) = JS_REQUIRE.captures(line) {
                let pkg = &cap[1];
                if in_filter(&normalize_js(pkg), &filter_set) {
                    add_import(&mut imports, &rel, idx + 1, normalize_js(pkg));
                }
            } else if let Some(cap) = JS_IMPORT_FROM.captures(line) {
                let pkg = &cap[1];
                if in_filter(&normalize_js(pkg), &filter_set) {
                    add_import(&mut imports, &rel, idx + 1, normalize_js(pkg));
                }
            } else if let Some(cap) = JS_IMPORT_SIDE.captures(line) {
                let pkg = &cap[1];
                if in_filter(&normalize_js(pkg), &filter_set) {
                    add_import(&mut imports, &rel, idx + 1, normalize_js(pkg));
                }
            } else if let Some(cap) = JS_EXPORT_FROM.captures(line) {
                let pkg = &cap[1];
                if in_filter(&normalize_js(pkg), &filter_set) {
                    add_import(&mut imports, &rel, idx + 1, normalize_js(pkg));
                }
            } else if let Some(cap) = JS_DYNAMIC.captures(line) {
                let pkg = &cap[1];
                if in_filter(&normalize_js(pkg), &filter_set) {
                    add_import(&mut imports, &rel, idx + 1, normalize_js(pkg));
                }
            }
        }
    }

    imports.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));

    Ok((imports, files))
}

fn is_source_ext(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "rs" | "py" | "js" | "ts" | "jsx" | "tsx" | "go" | "java" | "c" | "cpp" | "h" | "hpp"
            | "cc" | "cxx" | "rb" | "php" | "cs" | "swift" | "kt" | "kts" | "scala" | "vue"
            | "svelte" | "m" | "mm" | "pl" | "pm" | "tcl" | "sh" | "bash" | "zsh" | "fish"
            | "html" | "css" | "scss" | "less" | "sql" | "yaml" | "yml" | "toml" | "ini" | "md"
    )
}

fn add_import(imports: &mut Vec<Imported>, file: &str, line: usize, package: String) {
    imports.push(Imported { file: file.to_string(), line, package });
}

fn top_level(pkg: &str) -> String {
    pkg.split('.').next().unwrap_or("").to_string()
}

fn normalize_js(pkg: &str) -> String {
    let mut s = pkg.to_lowercase();
    s = s.replace('-', "_");
    s
}

fn in_filter(name: &str, set: &HashSet<String>) -> bool {
    if set.is_empty() {
        return true;
    }
    set.contains(&name.to_lowercase())
}

// --- Python imports ---
static PY_FROM_IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^from\s+([A-Za-z0-9_\.]+)\s+import").unwrap());
static PY_IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^import\s+([A-Za-z0-9_\.]+)").unwrap());

// --- JavaScript / TypeScript imports ---
static JS_REQUIRE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"require\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap());
static JS_IMPORT_FROM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"import\s+[^'"]*\bfrom\s*['"]([^'"]+)['"]"#).unwrap());
static JS_IMPORT_SIDE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"import\s*['"]([^'"]+)['"]"#).unwrap());
static JS_EXPORT_FROM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"export\s+[^'%]*\bfrom\s*['"]([^'"]+)['"]"#).unwrap());
static JS_DYNAMIC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"import\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap());
