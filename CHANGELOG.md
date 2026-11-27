# Changelog

## [Unreleased]

## [0.4.5] — 2026-11-27

Security hardening, found by an Aikido scan and by review rounds on each fix:
deletion is confined to what a scan discovers, vulnerability matching fails
closed, symlinks below a root are no longer followed, and CI is pinned. New:
private package names can be kept off OSV and the registries (`[privacy]`),
pnpm 11+ global stores are scanned, and a scan now says what it could not
identify instead of skipping it silently.

Behavior changes to know about before upgrading:
- A config file with **any unknown key** (at any level) is now unusable and
  disables all package lookups until fixed, instead of being half-ignored.
- An MCP agent can no longer delete roots, containers, symlinks or paths inside
  a package; the TUI refuses symlink candidates.
- A symlink below a root is shown as a leaf: not expanded, classified or sized.
- The vulnerability and version caches are rebuilt once on first use.
- **Building from source** needs a C compiler (bundled SQLite) and Rust 1.89 or
  newer (MSRV was 1.88). Release binaries are unaffected.

### Security
- **Private package names can be kept off the network (#95)**: a
  `[privacy] private_packages` list in the config file withholds matching
  packages from OSV.dev and the registries, for the TUI and the MCP tools. The
  policy is applied before a request is built, so nothing is sent, cached, or
  reported as clean; the status line and the MCP reports count what was
  withheld. A config file that exists but cannot be used disables all package
  lookups instead of falling back to defaults. The file is now strict: any
  unknown key at any level (not only under `[privacy]`) makes it unusable, so a
  misspelt `[privcy]`, or a list written inside `[vulncheck]`, cannot leave the
  list silently empty. Packages marked private are also removed from the
  on-disk lookup caches the next time a scan runs. Config files with
  stale or misspelt keys that used to be ignored now disable lookups until
  they are fixed; the warning and the status line name the cause.
- **Symlinks below a root are leaves (#92, #93)**: package discovery skips
  them, so a package behind a link is no longer read and its name no longer
  sent to OSV or a registry; tree expansion lists a link but does not open,
  classify or size it, and the MCP listing does the same; `v` / `o` on a
  selected link say so instead of scanning it. Sizing already
  ignored links (#127). A root that is itself a link is still followed.
- **MCP delete is limited to discovered entries (#119)**: `delete_packages`
  only removes entries that discovery lists (what `search_packages` returns),
  never a configured root, a provider container, a symlink, or a path inside a
  package. `preview_delete` applies the same scope.
- **TUI delete stays inside its cache root (#120, #90)**: a candidate that is a
  symlink, resolves outside its own tree root, or has no tree node is refused
  and counted in the status line. The size walk, the provider hook and the
  removal use the validated location.
- **Protected directories are recognised by file identity, not by name (#129,
  #122)**: with `~/.bun` a symlink to another directory, the Bun runtime was
  classified by its path string and could be deleted (MCP with
  `confirm_caution`, TUI as an ordinary candidate). The directories a provider
  protects are now resolved to (device, inode) and checked for the target, what
  lies under it, and, for a child entry, what it contains. The MCP delete
  additionally refuses everything while the route to a protected directory is a
  chain of symlinks it cannot reason about. Deleting a whole configured root in
  the TUI stays allowed. Only Bun has a protected location today.
- **Vulnerability matching fails closed (#121, #123, #124, #125, #100)**: OSV
  ranges are read as ordered intervals; Git commit hashes and tags are no
  longer taken as fix versions; versions are ordered by each ecosystem's own
  rules (SemVer, Go with its `v` prefix, PEP 440 including local versions, and
  a port of Maven's `ComparableVersion` validated against Maven 3.10.0 on about
  674k pairs with no disagreement). A version that cannot be ordered is treated
  as possibly affected, and an outdated check that cannot order two versions is
  reported as unchecked instead of up to date.
- **Terminal output (#126, #94)**: control characters in names and paths are
  shown as a visible U+FFFD and no longer misalign the tree columns. They were
  already filtered before reaching the terminal by ratatui; a byte-level test
  now pins that.
- **Symlinks in sizing (#127, part of #93)**: `quick_size` followed symlinks
  (counting bytes outside the directory, and recursing through links back at it:
  two such links turned a 100-byte directory into 8.8 s and 6.5 MB). It no
  longer follows them, like `dir_size`.
- **CI supply chain (#106, #68, #108, #110, #112, #113, #130)**: `--locked` on
  every cargo build, test, lint and install command (`cargo fmt`,
  `llvm-cov report` and `deb --no-build` do not resolve dependencies, so they
  take none), `persist-credentials: false` on checkouts,
  `--ignore-scripts` on package-manager installs, and exact `pnpm` and
  `yarn@1` versions in the PR-gating E2E job. The nightly E2E job still floats
  on purpose, to surface upstream releases.

### Changed
- **Maven repository root from `settings.xml` (#118)**: when
  `~/.m2/settings.xml` declares a `<localRepository>`, a path inside it is read
  relative to that directory, so a repository not named `repository` keeps its
  full group id. Paths outside it, and installs with no declaration, parse as
  before.
- **Behavior change (tree)**: a symlink below a root is shown as a leaf with no
  size and is not classified. For a directory, such as `~/.cache/pip` pointing
  at another volume, that also means it cannot be expanded: add its target as a
  root to browse it. For a file, such as the links to blobs in a Hugging Face
  snapshot, the size is the blob's, counted where the blob lives; the parent
  directory already treated links as 0.
- **pnpm 11+ global stores are scanned (#39)**: package names and versions are
  read from the keys of the store's SQLite `index.db` (`<integrity>\t<name>@<version>`,
  so no MessagePack decoding is needed), opened read-only, with `immutable`
  mode, used outright when there is no write-ahead log (so a scan writes
  nothing into the store) and as the fallback when a store with one refuses a
  plain read-only open, in which case the scan says recent packages may be
  missing. The file is treated as untrusted: row (250,000) and time limits,
  past which the packages already read are kept and the rest is reported as not
  scanned, and `package_index` must be a real table. Names and versions are validated as npm
  coordinates. A package there is
  reported under a virtual path below `index.db`, so a result marks that entry
  and the folders above it. Rows that are not a registry `name@version`, and an
  `index.db` that cannot be read, are counted as unidentified (#117), one per
  unusable row, instead of skipped. Verified against a store written by pnpm 12.23.0.
- **Build requirements**: adds `rusqlite` with its bundled SQLite, which is
  built from C source, so building needs a C compiler (release binaries are
  unaffected). The MSRV moves from 1.88 to 1.89: the patched SQLite
  (RUSTSEC-2026-0459, fixed in `libsqlite3-sys` 0.39) ships with `rusqlite`
  0.41, which needs 1.89. `cargo deny` is clean.
- **Unidentified npm manifests are reported (#117)**: a package directory under
  `node_modules` whose `package.json` is missing, malformed, over 1 MiB, or has
  an invalid name or version used to vanish from the scan, so the package looked
  absent or clean. The TUI status line now says how many were skipped, and the
  MCP `scan_vulnerabilities` / `check_outdated` reports carry
  `unidentified_manifests` and `unidentified` (the first 100, with path and
  reason). It covers the vulnerability scan and the version check. The count is
  of directories, so the same broken package copied into several caches counts
  once per copy, and each path is listed; for a pnpm `index.db` it is one per
  unusable row, and a database that could not be read at all counts as one, so
  it is a lower bound. Only npm manifests are
  covered; other providers identify a package from its path or file name.
- **Behavior change (MCP)**: an agent can no longer delete a root, a container
  such as `~/.cache/huggingface`, a symlink, or a path inside a package. Delete
  the discovered entries instead.
- **Behavior change (TUI)**: symlink candidates are refused rather than
  unlinked; remove a stale link with `rm`. A child directory that contains a
  protected runtime is refused.
- **Cache format**: the vulnerability and version caches carry a schema number;
  caches written by earlier versions are discarded and rebuilt on first use.
- **npm (#109, #114, #116)**: upgrade commands keep the package scope;
  `package.json` is parsed with `serde_json` for package identity and read up to
  1 MiB.
- **Maven (#115)**: coordinates are read relative to the first `repository`
  directory after `.m2`, so a group id containing `repository` keeps its full
  name.
- **CI (#87)**: `fail-fast: false` on the test matrix, so a failing Ubuntu job
  no longer cancels macOS.
- **Docs (#111, #131)**: an Aikido badge, and a README section on exactly what
  leaves the machine (what each scan sends, and that the update check is on by
  default).

### Known limitations
- The lookup caches are last-writer-wins across ccmd processes, as they always
  were. A process that loaded a cache before a package was marked private can
  write that entry back when it saves; the next scan under the new list removes
  it again. Nothing is sent meanwhile: the list is applied before any request.
- A symlinked *file* inside a package directory (for example a `package.json`
  that is a link) is still read by the provider that parses it. Directories
  reached through links are no longer entered (#92, #93).
- A custom-named Maven repository inside `~/.m2` whose group id contains a
  `repository` component can be mis-parsed unless `~/.m2/settings.xml` declares
  it with an absolute `<localRepository>` (#118); the path alone cannot tell it
  from a nested standard repository. Only an absolute path or `${user.home}` is
  understood, and the file is read once per process.
- Packages found inside a pnpm `index.db` are reported under a path below it
  that does not exist on disk, so the MCP `get_package_details`,
  `search_packages` and `delete_packages` do not apply to them (scan reports do
  show them).
- PEP 440 and SemVer ordering rest on spec-derived tests, not a reference
  implementation (Maven is checked against the real one).

## [0.4.4] — 2026-11-24

Maintenance release: restores green CI (new stable cargo and clippy lints
had broken every stable job and the Nightly E2E since 2026-11-13), fixes
eleven RustSec advisories in dependencies, and ports the HTTP client to
ureq 3. One behavior change: HTTP(S) proxy environment variables are now
honored (see Changed). pnpm 11 `index.db` package scanning (#39) and the
E2E tool-pinning work (#68) move to the next release.

### Security
- **Dependencies (#83)**: `cargo update` plus an `rmcp` floor of 3.9.
  `rmcp` 3.4.1 → 3.11.0 (RUSTSEC-2026-0457, -0461, -0462: OAuth SSRF
  filter, unbounded schema cache and response buffering, all in the
  Streamable HTTP/OAuth code that ccmd never enables). `rustls` 0.23.46
  (RUSTSEC-2026-0346 to -0349: `Debug` leaking session secrets, ECH
  rejection data leak, Brotli certificate decompression allocation, key
  exchange downgrade), `rustls-webpki` 0.103.17 (RUSTSEC-2026-0382,
  distrusted intermediates accepted), `webpki-roots` 1.0.12
  (RUSTSEC-2026-0381, distrusted emSign intermediates), and `tokio`
  1.54.1. `url` (RUSTSEC-2026-0592, stack overflow in `Url::origin()`) is
  no longer a dependency at all, since ureq 3 dropped it. The TLS fixes are reached through `ureq` when ccmd queries OSV.dev
  and the package registries.
- **`chrono` unmaintained (RUSTSEC-2026-0543)**: no fix exists and `rmcp`
  and `schemars` also depend on it, so `deny.toml` carries a dated ignore
  (revisit 2026-12-31).

### Changed
- **HTTP client (#84)**: `ureq` 2 → 3 (request builder API, per-request
  `timeout_global`, `body_mut().read_to_string()`); the four call sites
  in the registry, OSV and updater code were ported with the same
  timeouts, status-error handling and 10 MiB body cap, and checked against
  live PyPI, crates.io, OSV and GitHub endpoints. **Behavior change**:
  ureq 3 reads `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` (honoring
  `NO_PROXY`) by default, so OSV, registry and update-check requests now go
  through a configured proxy; ureq 2 ignored them. The redirect limit also
  rose from 5 to 10.
- **Dependencies**: `toml` 0.8 → 1.2, `directories` 5 → 6,
  `jwalk` 0.8 → 0.9 (all drop-in; no source changes).

### CI
- **New stable toolchain (#80, #82)**: removed `package.homepage`
  (redundant with `repository`, now linted by cargo and denied under
  `CARGO_BUILD_WARNINGS`) and rewrote an index loop in `tree/state.rs`
  flagged by clippy's `needless_range_loop`.
- **Actions group (#78)**: setup-rust-toolchain 2.0.1, cargo-deny-action
  2.1.3, install-action 2.90.x, upload-artifact 7.0.2, setup-java 6.3.0,
  setup-gradle 6.4.1, download-artifact 8.0.2, action-gh-release 3.0.4.
- **Release workflow**: releases are now created as drafts and published
  as the last step, with provenance attestation for the macOS DMG, to
  comply with immutable releases.

## [0.4.3] — 2026-09-27

Maintenance release: every known advisory fixed rather than ignored
(`deny.toml` ignore list is now empty), Hugging Face shared-blob support,
and a CI refresh. pnpm 11 `index.db` package scanning (#39) moves to 0.4.4.

### Security
- **Dependencies (#49)**: `cargo update` within existing semver ranges,
  pulling `rustls` 0.23.37 → 0.23.45 (RUSTSEC-2026-0285: TLS 1.3 handshake
  messages accepted across encryption-level boundaries, reached via `ureq`)
  and `rustls-webpki` 0.103.15, plus routine patch/minor bumps. MSRV
  unchanged (1.88).
- **TUI stack (#55)**: ratatui 0.29 → 0.30 and crossterm 0.28 → 0.29.
  Replaces `lru` 0.12.5 (RUSTSEC-2026-0002, unsound) with 0.18.5 and drops
  the unmaintained `paste` (RUSTSEC-2024-0436), whose `deny.toml` ignore is
  removed. No API changes were needed.
- **MCP (#45)**: rmcp 0.16 → 3.4.1, fixing RUSTSEC-2026-0189 (DNS rebinding
  in the Streamable HTTP transport, which ccmd never enabled) and removing its
  `deny.toml` ignore. The MCP server now negotiates protocol `2025-11-25`
  with current clients (previously capped at `2025-03-26`); `2024-11-05`
  clients see an identical handshake. Tool input schemas now express
  optional fields as standard JSON Schema `["string", "null"]` instead of
  `nullable: true`; tool names and required fields are unchanged.

### Fixed
- **Hugging Face (#52)**: support the shared Xet blob store introduced in
  huggingface_hub 1.32. Large files now live once in `hub/blobs/<prefix>/`
  with per-repo symlinks, so model directories looked nearly empty and the
  real payload showed as an anonymous `[hash]`. The store root is labeled
  `[shared blobs]`, each shared blob is named after the repo(s) in its
  `.refs` manifest, model details show the shared data they link to (and
  that deleting the model does not free it), and shared-blob details list
  the referencing repos.

### CI
- **CI hygiene (#51)**: node20 actions moved to their node24 majors and
  SHA-pinned (`setup-java` and `setup-gradle` were floating on `@v4`);
  `cargo deny` now audits all features, so the `mcp` dependency tree that
  ships in release binaries is covered; Dependabot added for GitHub Actions
  and Cargo (weekly, minor/patch grouped).
- **Dependabot follow-ups (#62, #63, #64, #67)**: cargo-deny-action 2.1.1,
  install-action 2.87.20, attest-build-provenance 4.2.2, codecov-action
  7.1.1 (pin comment corrected in #67), and setup-rust-toolchain 2.0.0.
  v2 denies warnings via `CARGO_BUILD_WARNINGS`, which cargo only honors
  from 1.97, so the MSRV (1.88) job now sets `rustflags: "-D warnings"`
  explicitly to keep failing on warnings.

## [0.4.2] — 2026-08-09

Provider-layout refresh: an audit of all 21 providers against the latest
package-manager releases (#35–#38) found four stale assumptions, fixed here.

### Fixed
- **Xcode (#35)**: Xcode 26 renamed the DerivedData `Info.plist` key from
  `WORKSPACE_PATH` to `WorkspacePath`, so the Workspace safety cue never
  appeared on modern Xcode. The modern key is now tried first with a
  legacy fallback.
- **uv (#36)**: cache buckets are matched by prefix instead of exact
  versioned names (uv had moved to `sdists-v9` / `simple-v24`, leaving
  those buckets unlabeled), and the newer `environments-` / `python-` /
  `binaries-` / `git-` / `flat-index-` buckets get labels.
- **pip (#37)**: the `http-v2` HTTP cache directory (pip ≥ 23.3) is now
  recognized alongside the legacy `http`.
- **pnpm (#38)**: pnpm 11 (store v11) replaced the per-package JSON index
  with a SQLite `index.db`; it and its WAL/SHM sidecars are now labeled
  "Package Index (SQLite)". Reading package identities out of the SQLite
  index for OSV scanning is tracked in #39.
- CI: new clippy `question_mark` lint in `scanner/walker.rs`; bumped
  `crossbeam-epoch` to 0.9.20 (RUSTSEC-2026-0204); documented deny.toml
  ignore for RUSTSEC-2026-0189 (rmcp Streamable HTTP transport, which
  ccmd does not compile — stdio only; upgrade tracked in #45).

### Tests & infrastructure
- New replayable TUI smoke test (`scripts/tui-smoke-test.sh`): drives the
  real binary in tmux against a fabricated cache fixture, 16 assertions
  covering the provider fixes above. Requires tmux; not wired into CI.

### Docs
- Freshness pass: version-check registry lists now include Maven Central
  and proxy.golang.org; default cache roots described accurately; pip/uv/
  pnpm locations updated; pnpm 11 limitation footnote; `--no-update-check`
  documented.

## [0.4.1] — 2026-05-15

### Added
- **Poetry provider (#21)**: new `CacheKind::Poetry` covers Poetry's
  `~/.cache/pypoetry` (Linux) and `~/Library/Caches/pypoetry` (macOS).
  Parses semantic names from `.whl` and `.tar.gz` filenames under
  `artifacts/` for OSV `PyPI` scanning and PyPI version checks. Press
  `c` to copy a `poetry add '<pkg>>=<version>'` upgrade command.
  `artifacts/` and `cache/repositories/` are Safe; `virtualenvs/` is
  Caution (re-creating an env takes time). Brings provider count to 21.

### Fixed
- Bumped `rustls-webpki` to patch RUSTSEC-2026-0104.
- OSV client: package names are no longer percent-encoded in JSON
  request bodies (only in URL paths). The previous behavior caused
  lookup misses for any package whose name contained a character that
  triggered percent-encoding.

### Tests & infrastructure
- E2E JVM provider workflow gained a `continue-on-error` knob so a
  transient Maven Central / Gradle distribution outage no longer fails
  the nightly run.

## [0.4.0] — 2026-04-21

### Added
- **Go provider (#8)**: new `CacheKind::Go` covers the module cache
  (`$GOMODCACHE`, default `~/go/pkg/mod`) and the build cache
  (`$GOCACHE`, default `~/Library/Caches/go-build` on macOS,
  `~/.cache/go-build` on Linux). Full OSV scanning via the `Go`
  ecosystem and version-check against `proxy.golang.org /@v/list`
  (filters pseudo-versions and `+incompatible` tags). Module-path
  bang-escapes (`!uber` → `Uber`) are decoded at `semantic_name` /
  `package_id` time so OSV sees the real module path. `c` copies a
  `go get <module>@<version>` upgrade command. Module cache is Safe;
  build cache is Caution.
- **`providers::pre_delete` hook**: new dispatch that lets providers
  prepare a subtree before `remove_dir_all`. Default is a no-op so
  existing providers are unaffected. The Go provider implements it to
  `chmod -R +w` the module tree — Go `chmod -w`'s extracted modules
  by design, and without the hook `remove_dir_all` fails silently.
  Additional future use-cases: stripping macOS `com.apple.quarantine`
  xattrs, releasing file handles, pausing watchers.
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
