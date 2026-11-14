//! Shared, high-confidence rules: token-shaped secrets, entropy-verified
//! credential literals, and TODO/FIXME markers.

use std::sync::LazyLock;

use regex::Regex;

use crate::entropy;
use crate::model::{SlopCategory, SlopFinding};

/// Values that are obviously not real credentials even when they sit in a
/// "secret-looking" assignment.
const DUMMY_VALUES: &[&str] = &[
    "your", "xxx", "<", "${", "%s", "{}", "example", "placeholder",
    "changeme", "change_me", "dummy", "fake", "todo", "insert_", "****",
    "...", "test_", "12345", "sample", "redacted", "not_a_secret",
];

pub fn is_dummy(value: &str) -> bool {
    let v = value.to_lowercase();
    DUMMY_VALUES.iter().any(|m| v.contains(m))
}

/// Narrower filter for structured tokens (`sk-…`, `AKIA…`): only values that
/// are *documented examples* are skipped — a real token containing a run of
/// digits (`…12345…`) must still be reported.
fn is_doc_example(token: &str) -> bool {
    let v = token.to_lowercase();
    ["example", "xxxx", "your_", "your-", "todo", "dummy", "fake", "sample", "redacted"]
        .iter()
        .any(|m| v.contains(m))
}

struct TokenRule {
    re: Regex,
    rule: &'static str,
    severity: &'static str,
    detail: &'static str,
    tip: &'static str,
}

/// Structured token shapes — high confidence on their own (no entropy needed),
/// but documented example values are filtered via `is_dummy`.
static TOKEN_RULES: LazyLock<Vec<TokenRule>> = LazyLock::new(|| {
    vec![
        TokenRule {
            re: Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").unwrap(),
            rule: "embedded-private-key",
            severity: "CRITICAL",
            detail: "Private key material embedded in source code",
            tip: "Keep private keys in a secrets manager or a protected key file; rotate any key that was committed.",
        },
        TokenRule {
            re: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b").unwrap(),
            rule: "github-token",
            severity: "HIGH",
            detail: "GitHub token (ghp_/gho_/ghs_/...) hardcoded",
            tip: "Use `gh auth` / an environment variable instead; revoke the leaked token immediately.",
        },
        TokenRule {
            re: Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b").unwrap(),
            rule: "github-pat",
            severity: "HIGH",
            detail: "GitHub fine-grained personal access token hardcoded",
            tip: "Move the PAT to an environment variable and revoke the exposed one.",
        },
        TokenRule {
            re: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            rule: "aws-access-key",
            severity: "HIGH",
            detail: "AWS access key id (AKIA…) hardcoded",
            tip: "Rotate the key pair, then use short-lived roles or env vars instead of static keys.",
        },
        TokenRule {
            re: Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap(),
            rule: "bearer-style-api-key",
            severity: "HIGH",
            detail: "API key literal (sk-…, e.g. OpenAI/Anthropic style) hardcoded",
            tip: "Load the key from an environment variable or secret manager and rotate the exposed key.",
        },
        TokenRule {
            re: Regex::new(r"\bsk_live_[A-Za-z0-9]{20,}\b").unwrap(),
            rule: "stripe-live-key",
            severity: "CRITICAL",
            detail: "Stripe live secret key (sk_live_…) hardcoded",
            tip: "Roll the key in the Stripe dashboard and read it from the environment at runtime.",
        },
        TokenRule {
            re: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
            rule: "slack-token",
            severity: "HIGH",
            detail: "Slack token (xoxb-/xoxp-/…) hardcoded",
            tip: "Store Slack tokens in env vars and regenerate the leaked one.",
        },
        TokenRule {
            re: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(),
            rule: "google-api-key",
            severity: "HIGH",
            detail: "Google API key (AIza…) hardcoded",
            tip: "Restrict and rotate the key, then inject it via the environment.",
        },
    ]
});

/// `api_key = "..."`, `password: "..."`, `const authToken = "..."` etc.
static SECRET_ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(api[_-]?key|api[_-]?secret|secret|client[_-]?secret|secret[_-]?key|password|passwd|pwd|token|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[=:]\s*["']([^"']{8,})["']"#,
    )
    .unwrap()
});

static TODO_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(TODO|FIXME|XXX)\b").unwrap());

/// Line-level checks shared by the AST engine (Python) and the legacy path
/// (JS/TS): token-shaped secrets, entropy-verified credential literals and
/// TODO/FIXME markers.
pub fn line_checks(rel: &str, src: &str, out: &mut Vec<SlopFinding>) {
    for (idx, raw) in src.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        // Token-shaped secrets (works on comment lines too — a committed
        // token is leaked whether or not the line is commented out).
        for rule in TOKEN_RULES.iter() {
            if let Some(m) = rule.re.find(line) {
                if is_doc_example(m.as_str()) {
                    continue;
                }
                out.push(SlopFinding::new(
                    rel, line_no, SlopCategory::Secret, rule.severity, rule.rule,
                    rule.detail, rule.tip,
                ));
            }
        }

        // Generic credential literal — only reported when the value passes
        // the entropy check (v3: no more "long normal string" FPs).
        let is_comment = trimmed.starts_with('#') || trimmed.starts_with("//");
        if !is_comment {
            if let Some(m) = SECRET_ASSIGN.captures(line) {
                let value = &m[2];
                if entropy::looks_like_secret(value) {
                    out.push(SlopFinding::new(
                        rel,
                        line_no,
                        SlopCategory::Secret,
                        "HIGH",
                        "hardcoded-secret",
                        format!("hardcoded credential literal for `{}`", &m[1]),
                        "Load credentials from the environment or a secrets manager — never commit literals.",
                    ));
                }
            }
        }

        // Unfinished AI placeholders: TODO / FIXME markers.
        if TODO_MARKER.is_match(line) {
            out.push(SlopFinding::new(
                rel,
                line_no,
                SlopCategory::AiSlop,
                "LOW",
                "todo-marker",
                "leftover TODO/FIXME marker (possibly an unfinished AI-generated stub)",
                "Finish the work or convert it to a tracked ticket before merging.",
            ));
        }
    }
}
