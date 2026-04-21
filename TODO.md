# TODO — Cache Commander (ccmd)

## New Providers

- [ ] **Yarn** — `~/.cache/yarn`, Berry PnP cache (`#1`)
- [ ] **pnpm** — `~/.local/share/pnpm/store` (`#1`)
- [x] **Go modules** — `~/go/pkg/mod`, `~/go/pkg/mod/cache` (#8)
- [ ] **Conda / Mamba** — `~/anaconda3/pkgs`, `~/.conda/pkgs`, `~/miniforge3/pkgs`
- [ ] **Docker** — `~/Library/Containers/com.docker.docker/Data/vms` (macOS), `/var/lib/docker` (Linux), BuildKit cache
- [x] **Maven** — `~/.m2/repository` (#25)
- [x] **Gradle** — `~/.gradle/caches`, `~/.gradle/wrapper/dists` (#25)
- [ ] **CocoaPods** — `~/Library/Caches/CocoaPods`
- [x] **Xcode DerivedData** — `~/Library/Developer/Xcode/DerivedData` (#17)
- [x] **Swift Package Manager** — `~/Library/Caches/org.swift.swiftpm` (#11)
- [ ] **Composer** (PHP) — `~/.cache/composer`, `~/.composer/cache`
- [ ] **Ruby gems** — `~/.gem`, `~/.bundle/cache`
- [ ] **Bazel** — `~/.cache/bazel`
- [ ] **ccache / sccache** — `~/.cache/ccache`, `~/.cache/sccache`
- [ ] **Nix** — `~/.cache/nix`

## Cache Analysis

- [ ] **Stale cache detection** — flag caches not accessed in N days (configurable threshold, e.g. 90 days)
- [ ] **Duplicate detection** — find identical files across providers (content-hash based)
- [ ] **Disk usage trends** — store periodic snapshots in `~/.config/ccmd/history.json`, show sparkline in TUI
- [ ] **Space reclaim estimate** — "you could free X GB" summary for stale + vulnerable + outdated items
- [ ] **Per-project usage** — link cached packages back to projects that use them (scan Cargo.lock, package-lock.json, etc.)
- [ ] **License scanning** — identify licenses of cached packages (SPDX from registry metadata)

## Cleanup Automation

- [ ] **Cleanup policies** — TOML rules: `max_age = "90d"`, `max_size = "10GB"`, per-provider overrides
- [ ] **Dry-run mode** — `ccmd clean --dry-run` to preview what policies would delete
- [ ] **Scheduled cleanup** — `ccmd clean --schedule` via launchd (macOS) or systemd timer (Linux)
- [ ] **Pin/protect** — mark specific caches as protected (never auto-delete)
- [ ] **Undo / trash** — move to trash instead of permanent delete, with `ccmd restore` to recover

## TUI Enhancements

- [ ] **Regex search** — extend `/` filter to support regex patterns
- [ ] **Mark by pattern** — `M` to mark all items matching a glob/regex
- [ ] **Bulk mark outdated** — one-key mark all outdated or vulnerable items for deletion
- [ ] **Size bar visualization** — proportional size bars in tree panel (like `dust`)
- [ ] **Multi-column sort** — secondary sort key (e.g. sort by provider then size)
- [ ] **Treemap view** — alternate visualization showing cache usage as nested rectangles
- [ ] **Mouse support** — click to select, scroll, expand/collapse

## CLI / Non-Interactive

- [ ] **JSON output** — `ccmd --json` for scripting and piping
- [ ] **CSV export** — `ccmd export --format csv` for spreadsheet analysis
- [ ] **One-shot commands** — `ccmd scan --vulns`, `ccmd scan --outdated`, `ccmd clean --stale 90d` without TUI
- [ ] **Shell completions** — generate completions for bash, zsh, fish via clap
- [ ] **Exit codes** — meaningful exit codes for CI (e.g. non-zero if vulns found)

## Security Improvements

- [ ] **SBOM generation** — export cached packages as CycloneDX or SPDX SBOM
- [ ] **Severity filtering** — filter vulns by CVSS score threshold (e.g. only critical/high)
- [ ] **Auto-remediation** — option to run upgrade commands directly from ccmd
- [ ] **Vulnerability alerting** — notify when new CVEs affect cached packages (via MCP or webhook)
- [ ] **Install script auditing** — expand npm install-script detection to show script contents

## MCP Server

- [ ] **Watch mode** — MCP resource subscriptions for real-time cache change notifications
- [ ] **Cleanup policy management** — CRUD policies via MCP tools
- [ ] **History queries** — "how much cache did I clean this week?" via MCP
- [ ] **Batch operations** — delete all outdated/vulnerable in one MCP call

## Windows Support

- [ ] **Add `windows-latest` to CI test matrix** — catch compile errors and test failures early
- [ ] **Default cache roots** — add `%LOCALAPPDATA%` via `BaseDirs::cache_dir()` in `config.rs`
- [ ] **Per-provider Windows paths** — npm (`%AppData%/npm-cache`), pip (`%LOCALAPPDATA%/pip/Cache`), Cargo (`%USERPROFILE%\.cargo\registry`), uv, Go, etc.
- [ ] **Clipboard** — add `clip.exe` branch in `copy_to_clipboard()` (`app.rs`)
- [ ] **Guard unix-only code** — `#[cfg(unix)]` on symlink tests in `huggingface.rs` and `mcp/mod.rs`
- [ ] **Scheduled cleanup** — add Windows Task Scheduler support alongside launchd/systemd
- [ ] **Release binaries** — add `x86_64-pc-windows-msvc` target to `release.yml`, produce `.exe`
- [ ] **Windows installer** — optional `.msi` via `cargo-wix`
- [ ] **TUI smoke test** — verify rendering on Windows Terminal / ConPTY (needs a Windows tester)

## Code Quality (from REVIEW-0.2.0.md)

- [ ] Wire up `SafetyLevel::Unsafe` or remove dead code (M5)
- [ ] Handle `scan_tx.send()` failures instead of `let _ =` (M2)
- [ ] Fix status message overwriting on rapid scan completion (M3)
- [ ] Fix UTF-8 unsafe byte-level parsing in homebrew.rs (M4)
- [ ] Enable clippy pedantic lints in CI (M6)
- [ ] Add mocked HTTP tests for OSV and registry APIs
- [ ] Add tests for `perform_delete` error paths
- [ ] Add tests for scanner threading behavior
- [ ] Add MSRV enforcement in CI
