//! Data structures for the global symbol table (v4).
//!
//! Pass 1 extracts, per function, a small ordered IR (`Step`s with `Rhs`
//! provenance). Pass 2 simulates that IR with tainted argument bindings,
//! which is what makes cross-file taint propagation cheap: evaluating a
//! callee never re-parses its source.

use std::collections::HashMap;

/// Function parameter with its annotation text (used to detect framework
/// sources like FastAPI's `Query(...)`, `UploadFile`, ...).
#[derive(Debug, Clone)]
pub struct ParamInfo {
    pub name: String,
    pub annotation: String,
}

/// Summary of a top-level function, class method, or the module top level
/// (`__module__` pseudo-function), extracted in Pass 1.
#[derive(Debug, Clone)]
pub struct FnSummary {
    /// Fully qualified key in the symbol table (`services.fetcher.fetch`).
    pub qualified: String,
    /// Source file path (relative to scan root).
    pub file: String,
    /// 1-based line of the `def` (or 0 for the module pseudo-function).
    pub line: usize,
    /// Parameters in declaration order.
    pub params: Vec<ParamInfo>,
    /// Ordered IR: assignments, calls, returns.
    pub steps: Vec<Step>,
}

/// Right-hand side provenance of an expression, captured in Pass 1.
#[derive(Debug, Clone)]
pub enum Rhs {
    /// The function's own parameter `name`.
    Param(String),
    /// Reads an untrusted source with the given origin tag
    /// (`request.*`, `input()`, `os.environ`, `sys.argv`).
    Source(String),
    /// Hardcoded literal (value text kept for checks like `shell=True`).
    Literal(String),
    /// Opaque literal blob kept as raw text (dict/set literals — used for
    /// restricted-execution detection: `{"__builtins__": {}}`).
    Raw(String),
    /// Call with optional tainted receiver and argument provenance.
    Call {
        callee: String,
        recv: Option<Box<Rhs>>,
        args: Vec<CallArg>,
    },
    /// List/tuple: taint if any element is tainted.
    Container(Vec<Rhs>),
    /// Anything else (unknown local, complex expression).
    Unknown,
}

/// One call argument: optional keyword name + value provenance.
#[derive(Debug, Clone)]
pub struct CallArg {
    pub kw: Option<String>,
    pub rhs: Rhs,
}

/// One ordered IR step inside a function body.
#[derive(Debug, Clone)]
pub enum Step {
    Assign { var: String, rhs: Rhs, line: usize },
    Call { callee: String, recv: Option<Rhs>, args: Vec<CallArg>, line: usize },
    Return { rhs: Rhs, line: usize },
}

/// A resolved import binding.
#[derive(Debug, Clone)]
#[allow(dead_code)] // full binding schema kept for completeness/future passes
pub struct ImportBinding {
    /// Fully qualified target (`utils.net.fetch`) or module (`utils.net`).
    pub alias: String,
    /// Dotted module path (`services.fetcher`), empty for plain imports.
    pub module: String,
    /// Imported symbol (`fetch`), empty for `import module`.
    pub symbol: String,
    /// Local name actually used in code.
    pub local: String,
    /// 1-based import line.
    pub line: usize,
}

/// An HTTP endpoint discovered from route decorators.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub file: String,
    /// 1-based line of the decorated function.
    pub line: usize,
    /// HTTP method (`GET`, `POST`, ...), uppercased.
    pub method: String,
    /// Route path text when available (`/users/{id}`).
    pub path: String,
    /// Function name.
    pub func: String,
    /// True when authentication is detected (Depends/auth decorator/user param).
    pub authenticated: bool,
}

/// Local name -> resolved dotted symbol (`fetch` -> `services.fetcher.fetch`).
pub type ImportMap = HashMap<String, String>;
