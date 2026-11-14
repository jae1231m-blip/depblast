//! Context-aware path classification: findings inside test / fixture / mock
//! paths are downgraded to `INFO` and isolated in the report so that
//! production findings stay clean.

use globset::{Glob, GlobSet, GlobSetBuilder};
use std::sync::LazyLock;

static TEST_PATHS: LazyLock<GlobSet> = LazyLock::new(|| {
    let mut builder = GlobSetBuilder::new();
    for pattern in [
        // Python test layouts
        "**/tests/**", "**/test/**", "**/testing/**", "**/conftest.py",
        "**/test_*.py", "**/*_test.py",
        // Mock / fixture data
        "**/fixtures/**", "**/fixture/**", "**/mock/**", "**/mocks/**",
        "**/mock*.py", "**/*_mock.py", "**/testdata/**",
        // JS/TS test conventions
        "**/*.test.js", "**/*.test.ts", "**/*.test.tsx", "**/*.test.jsx",
        "**/*.spec.js", "**/*.spec.ts", "**/*.spec.tsx", "**/*_test.go",
    ] {
        builder.add(Glob::new(pattern).expect("valid glob"));
    }
    builder.build().expect("valid globset")
});

/// True when `rel` (forward-slash separated path relative to the scan root)
/// lives in a test/fixture/mock context.
pub fn is_test_path(rel: &str) -> bool {
    TEST_PATHS.is_match(rel)
}
