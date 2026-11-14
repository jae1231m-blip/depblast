//! Shared tree-sitter Python parser with a thread-local parser instance.

use std::cell::RefCell;

use tree_sitter::{Parser, Tree};

thread_local! {
    static PY_PARSER: RefCell<Parser> = RefCell::new(make_parser());
}

fn make_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load tree-sitter-python grammar");
    parser
}

/// Parse Python source into an AST. Returns `None` only if the parser fails
/// outright; syntactically invalid files still produce a partial tree.
pub fn parse_python(src: &str) -> Option<Tree> {
    PY_PARSER.with(|p| p.borrow_mut().parse(src, None))
}
