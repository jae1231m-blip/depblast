//! File discovery built on the `ignore` crate: respects `.gitignore`,
//! skips dependency/build directories, and is shared by every scanner.

use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

pub fn collect_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(root);
    // Defaults: hidden files/dirs (incl. `.git`) are skipped; gitignore rules
    // are honored inside git repositories.
    builder.filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy().to_string();
        !crate::scanner::SKIP_DIRS.contains(&name.as_str())
    });

    let mut files = Vec::new();
    for entry in builder.build() {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().map_or(false, |t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if crate::scanner::is_source_ext(ext) {
                files.push(path.to_path_buf());
            }
        }
    }
    files.sort();
    Ok(files)
}
