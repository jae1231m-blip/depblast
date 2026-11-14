# depblast

**Ultra-fast SAST & dependency vulnerability scanner with source blast radius — cross-file taint analysis, framework-aware audit, SARIF export.**

depblast resolves your lockfiles/manifests, checks every dependency against the
[OSV](https://osv.dev) vulnerability database, then traces where vulnerable
packages are actually *imported* in your code — so you see the real blast
radius, not just a list of CVEs. Its `--slop` audit (v4) is a two-pass,
**cross-file taint analysis engine** built on tree-sitter ASTs, a global
symbol table and a dynamic YAML rule engine — rivaling Semgrep-class depth
while scanning large repos in well under a second.

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

#### The v4 cross-file taint engine (two passes, global symbol table)

v4 turns the per-file v3 scanner into a repo-wide analysis engine
(`src/indexer/`, `src/taint/xfile.rs`, `src/rules/taint_rules.rs`,
`src/framework/`):

1. **Pass 1 — parallel indexing** (`ignore::WalkBuilder` + `rayon`): every
   Python/JS/TS file is parsed and a global concurrent `SymbolTable` (DashMap)
   records dotted module paths, import bindings with aliases (`from utils.net
   import fetch as get_url`), per-function IR summaries (parameters with
   annotations, ordered assignment/call/return steps with argument
   provenance), classes and HTTP endpoints.
2. **Pass 2 — parallel inter-procedural analysis**: each function's IR is
   simulated with tainted argument bindings; callees are resolved through the
   symbol table (aliases, relative imports, `self.method`, suffix fallback)
   and taint propagates across files up to `--max-call-depth` hops
   (default 4).
3. **Full trace paths**: every taint finding carries a structured chain,
   e.g. `Source (routes.py:15) -> Call (services/fetcher.py:5) ->
   Sink (utils/http.py:5)`, rendered as a trace tree in text output and as
   SARIF `codeFlows`.
4. **Dynamic YAML rule engine** (`serde_yaml` + `include_str!` embedded
   defaults): rules declare `id`, `severity`, `category`, `languages`,
   `sources`, `sanitizers`, `sinks`, `message`, `remediation`. Built-in
   rulesets: SSRF (requests/httpx/urllib/aiohttp), Path Traversal
   (open/pathlib/send_file/shutil with basename/secure_filename sanitizers),
   Command & Code Injection (eval/exec/os.system/pickle.loads/subprocess
   shell=True). Load extra rulesets with `--rules <file-or-dir>`.
5. **Framework awareness** (`src/framework/`): FastAPI/Flask route decorators
   are parsed into endpoints; state-changing endpoints (POST/PUT/PATCH/DELETE)
   without authentication (`Depends(get_current_user)`, `@login_required`,
   ...) are flagged as broken access control; `Query()/Body()/Form()/File()/
   UploadFile` parameters are taint sources. An **attack surface summary**
   (endpoints, unauthenticated count, network sinks, OS command sinks) prints
   before the findings.
6. **Precision false-positive suppression**:
   - `__init__.py` / barrel re-export files are exempt from unused-import.
   - `eval(x, {"__builtins__": {}})` — restricted globals — is downgraded to
     `LOW (restricted-execution)` instead of full RCE.
   - tests/, fixtures/, mocks/, docs/, docs_src/, examples/, tutorials/ are
     isolated as non-blocking `INFO` findings.
   - generic credential literals require Shannon entropy > 4.2 (3.8 with
     symbols) and pass placeholder exclusion (`example`, `dummy`, `changeme`,
     ...).
7. **SARIF v2.1.0**: `--format sarif` emits GitHub Code Scanning-compatible
   output with stable `partialFingerprints` and taint `codeFlows`.
8. **Sanitizers strip taint along the branch**: `shlex.quote`,
   `ast.literal_eval`, `os.path.basename`, `secure_filename`, `bleach.clean`,
   URL validators — a value sanitized before a sink is not reported.

#### The v3 SAST engine (still the per-file backbone)

- **AST rules** (tree-sitter-python): standalone builtin calls (`eval(x)`)
  flagged, object-method calls (`session.exec(x)`) ignored;
  `from __future__` imports whitelisted; insecure defaults matched as real
  keyword arguments / assignments (`verify=False`, `shell=True`,
  `debug=True`, `0.0.0.0`, CORS wildcards, unsafe `yaml.load`).
- **Intra-procedural taint** drives sink severity; **inline suppression**
  via `# sast-ignore` (parsed from AST comment nodes).
- **Parallel execution**: `ignore::WalkBuilder` (respects `.gitignore`)
  feeding `rayon` — typical repos scan in well under 0.5s.

- **Secrets are never echoed:** findings describe the match but never print
  the credential value.

## Local CVE cache

OSV responses are cached under your platform cache directory
(`~/.cache/depblast` on Linux) for 30 days. Use `--update` to force a refresh.

## License

MIT
