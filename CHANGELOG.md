# Changelog

## [Unreleased]

### Added
- **SwiftPM provider (#11)**: detects `~/Library/Caches/org.swift.swiftpm`
  (macOS) and `~/.cache/org.swift.swiftpm` (Linux). Classifies
  `repositories/` as Caution (re-clone cost on rebuild) and
  `artifacts/`/`manifests/` as Safe. Repository directories render with
  the trailing git-URL hash stripped (e.g. `swift-collections-abc1234`
  → `swift-collections`). **No OSV or version-check**: package identity
  in SwiftPM's `repositories/` requires git-ref parsing that is too
  brittle for v1, and OSV's `SwiftURL` coverage is sparse. Pressing `c`
  on a SwiftPM entry is a no-op by design — Swift package upgrades are
  project-local (`Package.swift` / `Package.resolved`), not global.
- **Xcode provider (#17)**: detects `~/Library/Developer/Xcode/DerivedData`,
  `~/Library/Developer/Xcode/iOS DeviceSupport`, and
  `~/Library/Developer/CoreSimulator/Caches` — often the single largest
  caches on macOS dev machines (DerivedData alone is routinely 50–200 GB).
  DerivedData is classified as Caution (rebuild takes 5–30 min); the
  other two are Safe. DerivedData project directories show the original
  workspace path (extracted from `Info.plist` `WORKSPACE_PATH`) in the
  detail panel so you can confirm which project you're about to delete.
  **No OSV, no version-check, no upgrade command** — these are build
  artifacts, not packages.
- **Maven / Gradle upgrade snippets**: pressing `c` on a Maven or Gradle
  artifact now copies a paste-ready snippet to the clipboard — a
  `<dependency>…</dependency>` block for Maven, an `implementation
  'group:artifact:version'` line for Gradle. Previously a silent no-op
  because there is no single-line CLI equivalent for JVM dependencies.

### Fixed
- Dropped duplicate MCP screenshots at repo root (~150 KiB per published
  crate tarball); README now points at `docs/ccmd-mcp-*.png`.
- README screenshot reference switched to the GitHub raw URL so it
  renders on the crates.io page (the local `screenshot.png` is excluded
  from the crate).
- Rust MSRV badge corrected from 1.85 to 1.88 to match `Cargo.toml` and
  the CI job.

## [0.3.1] — 2026-04-17

### Added
- **JVM ecosystem support (#25)**: new `Maven` and `Gradle` cache providers.
  `~/.m2/repository` and `~/.gradle/caches` are auto-detected as roots and
  parsed into `group:artifact version` semantic names. Gradle's `files-2.1`
  layout is handled. Both share the OSV `Maven` ecosystem for vulnerability
  scanning. Maven Central `maven-metadata.xml` backs the version-check
  pipeline (prefers `<release>` over `<latest>` to avoid SNAPSHOT drift).
  Scanner depth raised from 6 to 12 to fit deep group hierarchies.
  Note: `c`-to-copy upgrade command is not yet wired up for Maven/Gradle
  (no clean single-line upgrade — pom/gradle files need editing).
- **Startup version check (#26)**: when a newer `ccmd` release is available
  on GitHub, the bottom bar shows `↑ ccmd X.Y.Z available`. Runs on a
  background thread, caches results for 24 h at `<cache-dir>/update-check.json`.
  Opt-out via `--no-update-check`, `CCMD_NO_UPDATE_CHECK=1`, or
  `[updater] enabled = false` in the config file. Pre-release builds
  (`0.4.0-dev`) never show the badge.
- **Persistent scan cache (#27)**: OSV vulnerability results and registry
  version-check results are cached to
  `<cache-dir>/{vuln,version}_cache.json` with a 24 h TTL. Subsequent
  launches re-use fresh cached results instead of re-hitting the network.
  Atomic save via temp-file + rename, `prune_expired` before save so the
  file doesn't grow unbounded, and a cache-hit percentage surfaced in the
  status bar (integer math; `100%` reserved for full hits only).

### Fixed
- Opus 4.7 code review pass: 7 HIGH, 10 MEDIUM, 8 LOW findings addressed
  across the tree (TOCTOU in MCP delete, pnpm multi-byte filename panic,
  status-message clobbering under concurrent scans, etc.). See commit
  `36af04f` for the full list.
- Bumped `rustls-webpki` to 0.103.12 for RUSTSEC-2026-0098/0099.
- Stable clippy 1.95 and MSRV (1.88) CI failures.

### Changed
- `send_scan_request` helper with a `scanner_dead` flag replaces 11 silent
  `let _ = scan_tx.send(...)` sites; the status bar now surfaces scanner
  death instead of silently hanging.
- `Config::default_for_test()` skips subprocess probes so tests don't
  couple to host-tool availability.
- Coverage job emits full lcov with DA records (Codecov can compute
  coverage deltas on PRs).

### Tests & infrastructure
- Net ~+100 unit and integration tests (1495 → 1736+ passing). Project
  coverage now ≥ 93%.
- MSRV (1.88) CI job, nightly `--features e2e` cron, and an E2E JVM
  providers job.
- Mocked HTTP tests for OSV and registry via a self-contained
  `TcpListener` helper (no new dev-deps).

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
- CI and release pipelines hardened with `cargo-deny`, SHA-pinned GitHub Actions, and build provenance attestation
- `.deb` packages now built for both Linux targets (x86_64, aarch64) with man page included
- All release binaries now include MCP server support (no longer requires `--features mcp`)

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
