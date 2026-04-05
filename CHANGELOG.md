# Changelog

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
