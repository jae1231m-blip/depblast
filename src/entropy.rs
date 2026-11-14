//! Shannon-entropy verification for secret detection (v3).
//!
//! Prefix-shaped tokens (`sk-…`, `AKIA…`) stay high-confidence without
//! entropy, but *generic* credential literals (`api_key = "…"`) are only
//! reported when the assigned value actually looks random — killing the
//! "long normal string" false positives of v2.

/// Character-level Shannon entropy of `data`, in bits per character.
pub fn shannon_entropy(data: &str) -> f64 {
    let bytes = data.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    freq[..]
        .iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Minimum length for a literal to even be considered a secret candidate.
pub const MIN_SECRET_LEN: usize = 12;

/// Substrings that betray a non-secret even when the entropy is high
/// (keyboard walks, common passwords, doc examples, ...).
const COMMON_NON_SECRETS: &[&str] = &[
    "qwerty", "password", "letmein", "iloveyou", "admin", "welcome",
    "abcdefgh", "1234567", "asdfgh", "zxcvbn",
];

/// True when a candidate literal is long and random enough to plausibly be a
/// real credential. The threshold scales with the character set used: strings
/// containing symbols need less observed entropy than pure alphanumeric ones.
pub fn looks_like_secret(value: &str) -> bool {
    let v = value.trim();
    let n = v.chars().count();
    if n < MIN_SECRET_LEN {
        return false;
    }
    let lowered = v.to_lowercase();
    if crate::rules::secrets::is_dummy(v) {
        return false;
    }
    if COMMON_NON_SECRETS.iter().any(|s| lowered.contains(s)) {
        return false;
    }
    let e = shannon_entropy(v);
    let has_special = v.chars().any(|c| !c.is_ascii_alphanumeric());
    // v4 threshold (per audit spec): > 4.2 bits for alphanumeric values;
    // symbol-bearing values get a small allowance because their charset is
    // already larger (still well above prose-level entropy ~3.0).
    let threshold = if has_special { 3.8 } else { 4.2 };
    e >= threshold
}
