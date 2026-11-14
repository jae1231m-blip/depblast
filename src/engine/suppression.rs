//! Inline suppression: a `# sast-ignore` (or `// sast-ignore`) comment on the
//! same line as a finding, or on the line immediately above it, silences it.
//!
//! For Python the comment nodes come from the tree-sitter AST; for other
//! languages a lightweight line scan is used.

use std::collections::HashSet;

use tree_sitter::Node;

/// Rows (0-based) that carry a `sast-ignore` marker; a marker on row `r`
/// suppresses findings on `r` and `r + 1`.
pub fn suppressed_rows(comments: &[(usize, &str)]) -> HashSet<usize> {
    let mut rows = HashSet::new();
    for &(row, text) in comments {
        if text.contains("sast-ignore") {
            rows.insert(row);
            rows.insert(row + 1);
        }
    }
    rows
}

/// Collect `comment` nodes from a Python AST as (row, text).
pub fn python_comments(root: Node, src: &str) -> Vec<(usize, String)> {
    let bytes = src.as_bytes();
    fn walk<'a>(node: Node<'a>, bytes: &'a [u8], out: &mut Vec<(usize, String)>) {
        if node.kind() == "comment" {
            if let Ok(text) = node.utf8_text(bytes) {
                out.push((node.start_position().row, text.to_string()));
            }
        }
        let mut i = 0;
        while let Some(child) = node.named_child(i) {
            walk(child, bytes, out);
            i += 1;
        }
    }
    let mut out = Vec::new();
    walk(root, bytes, &mut out);
    out
}
