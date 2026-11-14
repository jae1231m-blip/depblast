//! Thread-local tree-sitter parsers for Python and JavaScript/TypeScript.

use std::cell::RefCell;

use tree_sitter::{Language, Parser, Tree};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Python,
    JavaScript,
}

thread_local! {
    static PY_PARSER: RefCell<Parser> = RefCell::new(make_parser(python_language()));
    static JS_PARSER: RefCell<Parser> = RefCell::new(make_parser(tree_sitter_javascript::LANGUAGE.into()));
}

fn python_language() -> Language {
    tree_sitter_python::LANGUAGE.into()
}

fn make_parser(lang: Language) -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&lang)
        .expect("failed to load tree-sitter grammar");
    parser
}

/// Parse source with the parser for `lang`. Returns `None` only if the parser
/// fails outright; syntactically invalid files still produce a partial tree.
pub fn parse(lang: Lang, src: &str) -> Option<Tree> {
    match lang {
        Lang::Python => PY_PARSER.with(|p| p.borrow_mut().parse(src, None)),
        Lang::JavaScript => JS_PARSER.with(|p| p.borrow_mut().parse(src, None)),
    }
}

/// Extension -> language mapping for the indexer.
pub fn lang_for_ext(ext: &str) -> Option<Lang> {
    match ext {
        "py" | "pyw" => Some(Lang::Python),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Some(Lang::JavaScript),
        _ => None,
    }
}
