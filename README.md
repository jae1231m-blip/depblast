# depblast

**Ultra-fast SAST & dependency vulnerability scanner with source blast radius — AST-based AI slop & vibe-coding security audit.**

depblast resolves your lockfiles/manifests, checks every dependency against the
[OSV](https://osv.dev) vulnerability database, then traces where vulnerable
packages are actually *imported* in your code — so you see the real blast
radius, not just a list of CVEs. Its `--slop` audit (v3) is a low-false-positive
SAST engine built on **tree-sitter ASTs**, **intra-procedural taint analysis**
and **Shannon-entropy secret verification** — large repos scan in well under a
second.

Supported ecosystems:

| Manifest | Ecosystem |
|---|---|
| `package-lock.json` | npm |
| `requirements.txt` | PyPI |
| `pyproject.toml` (PEP 621, Poetry, PEP 735) | PyPI |

Source import scanning supports Python, JS/TS/JSX/TSX, and many more
extensions (Go, Ruby, PHP, Rust, ...).

## Install

### One-line install (recommended — no build required)

```bash
curl -fsSL https://raw.githubusercontent.com/jae1231m-blip/depblast/main/install.sh | bash
```

This downloads the prebuilt binary for your platform (Linux x86_64/aarch64,
macOS Apple Silicon/Intel) into `~/.local/bin/` and makes it executable.

**Windows:** download `depblast-x86_64-windows.exe` from the
[latest release](https://github.com/jae1231m-blip/depblast/releases/latest)
and put it on your `PATH`.

### Manual download

Grab the binary for your platform from
[Releases](https://github.com/jae1231m-blip/depblast/releases/latest):

```bash
curl -fsSL -o ~/.local/bin/depblast \
  https://github.com/jae1231m-blip/depblast/releases/latest/download/depblast-x86_64-linux
chmod +x ~/.local/bin/depblast
```

### Build from source (alternative)

```bash
cargo install --git https://github.com/jae1231m-blip/depblast
# or clone and build locally
cargo build --release
```

> Note: building from source compiles with LTO and takes a few minutes —
> prefer the prebuilt binary above.

## Usage

```bash
# Scan dependencies + blast radius in the current directory
depblast

# Machine-readable output
depblast --json

# Only look at one package
depblast --package lodash

# Include dev-only dependencies
depblast --dev

# Refresh the local OSV cache (30-day TTL otherwise)
depblast --update

# CI-friendly thresholds
depblast --fail-on high     # exit 1 if any HIGH/CRITICAL finding
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean (no findings above the threshold) |
| `1` | Findings at/above the threshold |
| `2` | Runtime error (missing manifest, bad lockfile, ...) |

## The `--slop` flag: AI Slop & Vibe-Coding Security Audit

AI-generated code is fast to ship and easy to trust too much. `--slop` runs a
fast, **high-signal / low-false-positive** audit over your Python and JS/TS
sources, alongside the dependency scan:

```bash
# Dependency scan + slop audit
depblast --slop

# Everything (dependency scan + slop audit)
depblast --all

# Skip dependency scanning entirely (works even without a manifest)
depblast --slop-only
```

The audit reports every finding with `file:line`, a `category`, a `severity`
and a short actionable fix tip — in the terminal table and in `--json` output,
and it respects `--fail-on` for CI gating.

### What it checks

1. **`SECRET` — Hardcoded secrets & tokens** (`HIGH`, private keys `CRITICAL`)
   - Known token shapes: `sk-…` (OpenAI/Anthropic-style), `ghp_/gho_/ghs_`,
     `github_pat_…`, `AKIA…` (AWS), `sk_live_…` (Stripe), `xox…` (Slack),
     `AIza…` (Google), `-----BEGIN … PRIVATE KEY-----`.
   - Generic `api_key = "…"`, `password = "…"`, `token: "…"` literals.
   - Obvious placeholders (`YOUR_API_KEY`, `${…}`, `example`, …) and
     env lookups (`process.env`, `os.environ`) are **excluded**.

2. **`LAZY_CONFIG` — Lazy AI security defaults** (`HIGH`/`MEDIUM`)
   - Python: `verify=False` (SSL bypass), `debug=True`, `host="0.0.0.0"`,
     `allow_origins=["*"]`.
   - JS/TS: `rejectUnauthorized: false`, CORS `origin: "*"`.

3. **`DANGEROUS_SINK` — Dangerous execution sinks** (`HIGH`)
   - `eval(`, `exec(`, `pickle.loads(`, `yaml.load(` without `SafeLoader`,
     `shell=True` in subprocess, `child_process.exec(` with template literals,
     `new Function(`.

4. **`AI_SLOP` — AI slop code smells** (`LOW`, placeholders `MEDIUM`)
   - Unused imports (imported but never referenced in the same file).
   - Unfinished placeholders: leftover `TODO`/`FIXME`, `pass  # implement later`,
     `raise NotImplementedError`, `throw new Error("Not implemented")`.

### Example output

```
$ depblast --slop-only ./my-app

depblast v0.2.0 — scanning ./my-app (14 files)

AI slop & security audit — 3 findings:
  SECRET HIGH app/auth.py:12 — API key literal (sk-…, e.g. OpenAI/Anthropic style) hardcoded
    fix: Load the key from an environment variable or secret manager — never commit literals.
  LAZY_CONFIG HIGH app/api.py:30 — SSL certificate verification disabled (`verify=False`)
    fix: Remove verify=False; pass a CA bundle (e.g. certifi) instead — disabled checks enable MITM attacks.
  AI_SLOP LOW app/utils.py:2 — unused import: `sys`
    fix: Remove the unused import — dead code is a typical AI-slop artifact.
```

### JSON schema

With `--json`, slop findings appear under the `slop` key:

```json
{
  "hits": [ ... ],
  "slop": [
    {
      "file": "app/auth.py",
      "line": 12,
      "category": "SECRET",
      "severity": "HIGH",
      "rule": "bearer-style-api-key",
      "detail": "API key literal (sk-…, e.g. OpenAI/Anthropic style) hardcoded",
      "fix_tip": "Load the key from an environment variable or secret manager — never commit literals."
    }
  ],
  "slop_only": false
}
```

### Design notes

#### The v3 SAST engine (low false positives by design)

v3 replaces v2's regex-only matching with a real analysis pipeline in
`src/engine/`, `src/rules/`, `src/taint.rs` and `src/entropy.rs`:

1. **AST-based analysis** (`tree-sitter` + `tree-sitter-python`): rules match
   real syntax nodes. A standalone builtin call (`eval(x)`) is flagged, while
   object-method calls (`session.exec(x)`) are ignored. `from __future__`
   imports are explicitly whitelisted from unused-import / AI-slop rules.
2. **Intra-procedural taint analysis**: assignments are tracked within each
   function scope from untrusted **sources** (`request.*`, `input()`,
   `sys.argv`, `os.environ`) to dangerous **sinks** (`eval`, `exec`,
   `subprocess.*` with `shell=True`, `pickle.loads`, `os.system`). A tainted
   value reaching a sink is `CRITICAL`; hardcoded-literal arguments are
   downgraded to `LOW`; known sanitizers (`shlex.quote`, `html.escape`,
   `int()`, ...) clear taint.
3. **Context-aware path filtering** (`globset`): findings under `tests/`,
   `**/test_*.py`, `**/fixtures/**`, `**/mock*`, ... are downgraded to `INFO`
   and isolated in a separate report section — production findings stay clean
   and never compete with mock data.
4. **Smart secret detection**: prefix-shaped tokens (`sk-`, `AKIA`, PEM, ...)
   stay high-confidence, while *generic* credential literals are only reported
   when a **Shannon entropy** check confirms the value is actually random
   (and it is not a known dummy value like `dummy`, `changeme`, `test_`,
   `xxxx`, `12345`).
5. **Inline suppression**: a `# sast-ignore` comment (parsed from AST comment
   nodes) on a finding's line — or the line above — silences it.
6. **Parallel execution**: `ignore::WalkBuilder` (respects `.gitignore`)
   feeding `rayon` parallel iterators — one AST parse per file, spread across
   all cores. A full scan of a mid-size repo runs in well under 0.5s.

- **Secrets are never echoed:** findings describe the match but never print
  the credential value.

## Local CVE cache

OSV responses are cached under your platform cache directory
(`~/.cache/depblast` on Linux) for 30 days. Use `--update` to force a refresh.

## License

MIT
