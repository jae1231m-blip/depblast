//! The v4 global symbol table and two-pass orchestration.
//!
//! **Pass 1** (parallel): parse every Python/JS/TS file and populate the
//! concurrent maps (modules, imports, function IR, endpoints, classes).
//! **Resolution**: rewrite each file's import bindings against the now
//! complete module map (handles relative imports via prefix candidates).
//! **Pass 2** (parallel, in `crate::taint`): simulate each function's IR with
//! tainted bindings, resolving callees through this table.

pub mod extract;
pub mod parse;
pub mod symbols;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use rayon::prelude::*;

use crate::indexer::extract::FileIndex;
use crate::indexer::symbols::{Endpoint, FnSummary, ImportBinding, ImportMap};

pub struct SymbolTable {
    /// Dotted module path -> relative file path (`services.fetcher` ->
    /// `services/fetcher.py`).
    pub modules: DashMap<String, String>,
    /// Relative file path -> import bindings.
    pub imports: DashMap<String, Vec<ImportBinding>>,
    /// Qualified key -> function IR summary.
    pub functions: DashMap<String, FnSummary>,
    /// Relative file path -> qualified keys of its functions.
    pub functions_by_file: DashMap<String, Vec<String>>,
    /// Relative file path -> local name -> resolved dotted symbol.
    pub resolved: DashMap<String, ImportMap>,
    /// Relative file path -> endpoints.
    pub endpoints: DashMap<String, Vec<Endpoint>>,
    /// Relative file path -> class names (for `self.method` resolution).
    pub classes: DashMap<String, Vec<String>>,
    /// Callee resolution cache: (file, callee text) -> qualified function.
    pub callee_cache: DashMap<(String, String), Option<String>>,
}

impl SymbolTable {
    fn new() -> Self {
        SymbolTable {
            modules: DashMap::new(),
            imports: DashMap::new(),
            functions: DashMap::new(),
            functions_by_file: DashMap::new(),
            resolved: DashMap::new(),
            endpoints: DashMap::new(),
            classes: DashMap::new(),
            callee_cache: DashMap::new(),
        }
    }

    /// Pass 1: index every file in parallel, then resolve imports.
    pub fn build(files: &[PathBuf], root: &Path) -> Arc<SymbolTable> {
        let table = SymbolTable::new();
        let root = root.to_path_buf();

        let indexes: Vec<FileIndex> = files
            .par_iter()
            .filter_map(|path| {
                let ext = path.extension()?.to_str()?.to_lowercase();
                let lang = parse::lang_for_ext(&ext)?;
                let src = std::fs::read_to_string(path).ok()?;
                let rel = path.strip_prefix(&root).unwrap_or(path).to_string_lossy().to_string();
                Some(extract::extract(&rel, &src, lang))
            })
            .collect();

        for index in indexes {
            let file = index.path.clone();
            table.modules.insert(index.module_path.clone(), file.clone());
            table.imports.insert(file.clone(), index.imports);
            table.endpoints.insert(file.clone(), index.endpoints);
            table.classes.insert(file.clone(), index.classes);
            let mut keys = Vec::new();
            for summary in index.functions {
                let q = summary.qualified.clone();
                keys.push(q.clone());
                table.functions.insert(q, summary);
            }
            table.functions_by_file.insert(file, keys);
        }

        table.resolve_imports();
        Arc::new(table)
    }

    /// Resolve every file's import bindings to dotted symbols, relative to
    /// that file's own module path (handles relative imports).
    fn resolve_imports(&self) {
        let files: Vec<String> = self.imports.iter().map(|e| e.key().clone()).collect();
        for file in files {
            let Some(bindings) = self.imports.get(&file).map(|b| b.clone()) else { continue };
            let module_path = self
                .modules
                .iter()
                .find(|e| e.value() == &file)
                .map(|e| e.key().clone())
                .unwrap_or_default();
            let mut map = ImportMap::new();
            for binding in &bindings {
                if let Some(target) = self.resolve_binding(&binding.alias, &module_path) {
                    map.entry(binding.local.clone()).or_insert(target);
                }
            }
            self.resolved.insert(file, map);
        }
    }

    /// Candidate resolution for a fully qualified target: exact, then with
    /// progressively shorter prefixes of the importing module's path
    /// (`from .fetcher import x` in `services/api.py` tries
    /// `services.api.fetcher.x`, `services.fetcher.x`, `fetcher.x`).
    fn resolve_binding(&self, target: &str, importer_module: &str) -> Option<String> {
        if self.functions.contains_key(target) || self.modules.contains_key(target) {
            return Some(target.to_string());
        }
        let segs: Vec<&str> = importer_module.split('.').filter(|s| !s.is_empty()).collect();
        for take in (0..=segs.len()).rev() {
            let candidate = if take == 0 {
                target.to_string()
            } else {
                format!("{}.{}", segs[..take].join("."), target)
            };
            if self.functions.contains_key(&candidate) || self.modules.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Resolve a callee text inside `file` to a qualified function key.
    ///
    /// Order: cache -> exact -> own module -> import alias rewrite ->
    /// `self.method` within the file's classes -> suffix scan.
    pub fn resolve_callee(&self, file: &str, callee: &str) -> Option<String> {
        if callee.is_empty() {
            return None;
        }
        let key = (file.to_string(), callee.to_string());
        if let Some(hit) = self.callee_cache.get(&key) {
            return hit.clone();
        }
        let resolved = self.resolve_callee_uncached(file, callee);
        self.callee_cache.insert(key, resolved.clone());
        resolved
    }

    fn resolve_callee_uncached(&self, file: &str, callee: &str) -> Option<String> {
        // 1. Exact match.
        if self.functions.contains_key(callee) {
            return Some(callee.to_string());
        }
        // 2. Same module (`fetch` in `services/fetcher.py`).
        let module_path = self
            .modules
            .iter()
            .find(|e| e.value() == file)
            .map(|e| e.key().clone())
            .unwrap_or_default();
        let own = format!("{module_path}.{callee}");
        if self.functions.contains_key(&own) {
            return Some(own);
        }
        // 3. Import alias rewrite: `sf.fetch` where `sf` -> `services.fetcher`.
        if let Some(map) = self.resolved.get(file) {
            if let Some((first, rest)) = callee.split_once('.') {
                if let Some(target) = map.get(first) {
                    let candidate = if rest.is_empty() {
                        target.clone()
                    } else {
                        format!("{target}.{rest}")
                    };
                    if self.functions.contains_key(&candidate) {
                        return Some(candidate);
                    }
                    // target may be a module prefix (`import pkg.mod`).
                    if self.modules.contains_key(&candidate) {
                        return None; // module attribute, not a tracked function
                    }
                    // Relative-prefix retry on the rewritten candidate.
                    if let Some(r) = self.resolve_binding(&candidate, &module_path) {
                        if self.functions.contains_key(&r) {
                            return Some(r);
                        }
                    }
                }
            }
        }
        // 4. `self.method` / `cls.method` within this file's classes.
        if let Some(method) = callee.strip_prefix("self.").or_else(|| callee.strip_prefix("cls.")) {
            if let Some(classes) = self.classes.get(file) {
                for class in classes.iter() {
                    let candidate = format!("{module_path}.{class}.{method}");
                    if self.functions.contains_key(&candidate) {
                        return Some(candidate);
                    }
                }
            }
        }
        // 5. Suffix fallback: any tracked function ending with `.{callee}`
        //    (single segment only, to avoid absurd scans).
        if !callee.contains('.') {
            let suffix = format!(".{callee}");
            let mut best: Option<String> = None;
            for entry in self.functions.iter() {
                let q = entry.key();
                if q.ends_with(&suffix) {
                    let better = best.as_deref().map_or(true, |b| q.len() < b.len());
                    if better {
                        best = Some(q.to_string());
                    }
                }
            }
            if best.is_some() {
                return best;
            }
        }
        None
    }

    /// All endpoint handlers with their summaries (file, endpoint, function).
    #[allow(dead_code)]
    pub fn endpoint_functions(&self) -> Vec<(Endpoint, String)> {
        let mut out = Vec::new();
        for entry in self.functions_by_file.iter() {
            let file = entry.key().clone();
            let Some(eps) = self.endpoints.get(&file) else { continue };
            for ep in eps.iter() {
                for q in entry.value() {
                    if q.rsplit('.').next() == Some(ep.func.as_str()) {
                        out.push((ep.clone(), q.clone()));
                        break;
                    }
                }
            }
        }
        out
    }
}
