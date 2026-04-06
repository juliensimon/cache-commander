# Changelog

## [0.2.0] — 2026-04-06

### Added
- **MCP server**: `ccmd mcp` starts an MCP (Model Context Protocol) server that lets AI assistants like Claude query caches, scan for vulnerabilities, check for outdated packages, and delete cache entries — all conversationally. Available tools: `list_caches`, `get_summary`, `search_packages`, `get_package_details`, `scan_vulnerabilities`, `check_outdated`, `preview_delete`, `delete_packages`. Requires `--features mcp` at build time.
- **Delete safety enforcement**: MCP deletions use a three-tier safety system (Safe/Caution/Unsafe) to prevent accidental removal of config or state
- **Shell injection protection**: `upgrade_command` now rejects package names containing shell metacharacters
- **MSRV enforcement**: `rust-version = "1.85"` in Cargo.toml

### Fixed
- **Mutex poisoning crash**: `fetch_fix_versions` and `check_versions` no longer panic if a worker thread fails — they recover gracefully and return partial results
- **Hardcoded User-Agent**: HTTP requests now use the actual package version and correct repository URL instead of `ccmd/0.1 (https://github.com/ccmd)`
- **Empty version strings**: all registry parsers (PyPI, crates.io, npm) now return `None` for empty version strings instead of `Some("")`, which caused incorrect "outdated" comparisons
- **`brew outdated` exit status**: the scanner now checks the exit status before parsing output, preventing garbage results when `brew` fails

### Changed
- Release pipeline accepts pre-release tags (`v0.2.0-rc1`), marks them as pre-release on GitHub, and skips Homebrew tap updates for RCs

## [0.1.1] — 2026-04-05

### Added
- **Homebrew cache enrichment**: parse bottle and manifest symlinks into readable semantic names (`[bottle] awscli 2.34.24`, `[manifest] awscli 2.34.24`)
- **Bottle manifest metadata**: extract license, installed size, architecture, and runtime dependency count from Homebrew bottle manifest JSON files
- **Background `brew outdated`**: run `brew outdated --json=v2` on startup when Homebrew caches are present, show outdated icon in tree and version info in detail panel
- **Tap-qualified name support**: handle names like `anomalyco/tap/opencode` by indexing both full and short names
- **cargo-binstall support**: prebuilt binary installs via `cargo binstall ccmd`

### Changed
- Optimized release binary size with LTO and strip
- Added pre-commit hook for `cargo fmt` and `cargo clippy` checks
- Added author and repo link to help overlay

### Fixed
- Robust package name lookup in detail panel using path-based fallback when semantic names aren't available

## [0.1.0] — 2026-04-04

Initial release.

- TUI for browsing and managing cache directories
- Providers: Homebrew, npm, pip, uv, Cargo, Hugging Face, pre-commit, Whisper, GitHub CLI, PyTorch, Chroma, Prisma
- Safety levels for deletion guidance (Safe / Caution / Unsafe)
- Vulnerability scanning via OSV.dev
- Version checking against package registries
- Keyboard-driven navigation with vim bindings
- Detail panel with provider metadata
- Bulk mark and delete operations
