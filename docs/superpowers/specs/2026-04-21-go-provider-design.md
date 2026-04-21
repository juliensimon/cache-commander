# Go modules + build cache Provider Support

**Date:** 2026-04-21
**Issue:** [#8](https://github.com/juliensimon/cache-commander/issues/8)
**Status:** Design

## Summary

Add a `Go` cache provider covering both the **module cache** (`$GOMODCACHE`, default `~/go/pkg/mod`) and the **build cache** (`$GOCACHE`, default `~/Library/Caches/go-build` on macOS / `~/.cache/go-build` on Linux). Module cache supports full OSV + version-check + upgrade-command; build cache is disk-hygiene only. Ships alongside a new `providers::pre_delete` dispatch — the Go module cache is `chmod -w`'d by design, so `remove_dir_all` needs a preparatory `chmod -R +w` walk. The hook is a no-op for every other existing provider.

## Approach

One `CacheKind::Go` variant covering both caches, with safety + semantic_name dispatched by path component (same pattern as Gradle's mixed Safe/Caution subtrees).

## Provider: Go (`src/providers/go_mod.rs`)

Module file named `go_mod` because `go.rs` collides with Rust's tendency to attract `go`-prefixed identifier confusion, and Cargo's file-name lowercase convention preserves readability.

### Detection

`detect(path)` returns `CacheKind::Go` when any of these hold:
- Direct-name match on `go-build` (build cache root).
- Ancestor walk: any ancestor named `mod` with parent named `pkg` (module cache — matches `$GOPATH/pkg/mod`). Component-based to avoid L1 substring leaks; `has_adjacent_components(path, "pkg", "mod")` is the canonical check.

Negative cases (tests):
- `pkg-mod-backup/...` → must NOT detect (L1 confusable suffix).
- `go-build-backup/...` → must NOT detect.
- A random `mod/` directory not under `pkg/` → Unknown.

### Module-path bang-decoding

Go bang-escapes uppercase letters to `!<lowercase>` on disk (e.g. `Uber` → `!uber`) so that case-insensitive filesystems don't collide `github.com/GoGo/protobuf` with `github.com/gogo/protobuf`. Applied everywhere the module path appears on disk: `cache/download/<module>/@v/...` and extracted `<module>@<version>/`.

A single `decode_module_path(s: &str) -> String` helper decodes `!x` → uppercase `X`. Used by `semantic_name` and `package_id` so OSV + display both see the real module path.

Edge cases (tests):
- `!u!ber` → `Uber`
- `github.com/!golang/!mock` → `github.com/Golang/Mock`
- Trailing lone `!` → pass through unchanged (not a valid escape; we never introduce panics).
- Non-ASCII chars → pass through (L2 guard).

### Semantic Names

**Module cache:**
- `.../cache/download/<module>/@v/<version>.zip` → `<decoded-module> <version>`
  - Module path is the relative path from `download/` up to (but excluding) `@v`, joined with `/`.
  - Version is the filename with the `.zip` suffix stripped. Go versions look like `v1.2.3`, `v1.2.3-alpha.1`, `v0.0.0-20210101120000-abc123def456` (pseudo-version), or `v2.0.0+incompatible` — all pass through as-is to the display.
- `.../pkg/mod/<module>@<version>/` extracted dir → same format, derived from the `@`-split of the last path component *and* any parent components that form the module path.
- `.../cache/download/sumdb/<host>/lookup/<module>@<version>` → `None` (internal checksum data).
- `.info`, `.mod`, `.ziphash` files → `None` (sibling metadata of the canonical `.zip`).

**Build cache:**
- All entries under `go-build/` → `None`. Content-addressed hex blobs (`<2hex>/<hash>-<action>`); no human-meaningful name.

**Root directories themselves** (`go-build`, `mod`) → `None`. Tree renders them literally.

### Package Identification

`package_id()` returns `Some(PackageId)` **only** for `.zip` files in `cache/download/.../@v/`. Ecosystem `"Go"`. Name is the decoded module path. Version is the filename stem.

Dedup rationale (L9): `cache/download/<module>/@v/<version>.{info,mod,zip,ziphash}` are four sibling files per package; without restricting to `.zip`, every module would count 4×. Maven's `.jar`-only rule is the direct precedent.

Extracted directories under `pkg/mod/` also get `package_id: None` — we count only the canonical artifact to avoid double-counting the same package under two layouts.

### Metadata

Contextual `Contents:` labels on the known roots:
- `pkg/mod` → `Module cache (re-downloadable from proxy.golang.org / VCS)`.
- `go-build` → `Build cache (rebuildable, cold rebuild is minutes on large repos)`.
- `cache/download/sumdb` → `Module checksum database (authoritative; re-downloadable)`.

No per-file metadata.

### Safety

- `pkg/mod` subtree → `SafetyLevel::Safe` (re-resolvable).
- `go-build` subtree → `SafetyLevel::Caution` (cold rebuild cost; matches Gradle `build-cache-*` / `transforms-*`).
- Unknown subdirs under either root → `Caution` (conservative).

Classification uses component-level matching (L1), not substring.

### Upgrade Command

`go get <module>@<version>` via the existing `upgrade_command` dispatch. Module paths contain `/`, which is in the `is_safe_for_shell` allowlist. `@` is also allowed. No new shell sanitization needed.

### Registry / OSV

- OSV ecosystem `Go` — no `registry.rs` arm needed for OSV (dispatched by ecosystem string).
- Version-check registry: `https://proxy.golang.org/<module-path>/@v/list` returns newline-delimited versions (UTF-8, no JSON). Parser picks the highest non-pseudo semver:
  - Skip lines matching the pseudo-version regex `v0\.0\.0-\d{14}-[0-9a-f]{12}` (timestamped git-hash format).
  - Skip lines ending in `+incompatible` when a non-incompatible option exists; fall back to `+incompatible` if that's all there is.
  - Compare via the existing `compare_versions` helper; L3 lesson says pre-release (`-alpha.1`) must compare correctly.

Module path in the URL uses the **decoded** form (no bang-escapes), per proxy.golang.org spec. But the module path stored in `PackageId.name` is decoded already, so the URL builder just URL-escapes slashes-as-slashes and passes through.

## New architecture: pre-delete hook

Add to `src/providers/mod.rs`:

```rust
/// Custodial setup before the tree attempts `remove_dir_all` on a cache
/// subtree. Default is a no-op; providers override when the filesystem
/// needs preparation (e.g. stripping read-only flags). Errors surface
/// as the existing `errored` counter in the delete status line.
pub fn pre_delete(kind: CacheKind, path: &Path) -> Result<(), String> {
    match kind {
        CacheKind::Go => go_mod::pre_delete(path),
        _ => Ok(()),
    }
}
```

`go_mod::pre_delete` walks `path` (if it's under `pkg/mod`) and `chmod -R +w`'s each entry. On the build cache path it's a no-op — Go keeps those writable. Errors from individual `chmod` calls are swallowed; only a catastrophic walk failure returns `Err`.

Call site: `src/app.rs::perform_delete`, immediately before the `remove_dir_all` / `remove_file` branch. If `pre_delete` returns `Err`, increment `errored` and skip the delete for that path.

Why a new trait method (Approach A), not an inline chmod for `CacheKind::Go` in the delete site:
- The delete site stays provider-agnostic. Adding a `if kind == CacheKind::Go` branch there bakes Go semantics into a generic code path.
- Future providers that need similar setup (xattr strip, file-handle release, inotify pause) have a clean seam.
- Cost is minimal: ~15 lines of dispatch + a Go-provider function, all testable in isolation.

## Config (`src/config.rs`)

Add `probe_go_paths()` following the `probe_yarn_paths()` pattern:

```rust
fn probe_go_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(output) = run_with_timeout("go", &["env", "GOMODCACHE"])
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path = PathBuf::from(&path_str);
        if path.exists() {
            paths.push(path);
        }
    }

    if let Some(output) = run_with_timeout("go", &["env", "GOCACHE"])
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path = PathBuf::from(&path_str);
        if path.exists() && !paths.contains(&path) {
            paths.push(path);
        }
    }

    // Fallback when `go` isn't on PATH: add well-known default locations.
    let home = dirs_home();
    let fallback_mod = home.join("go/pkg/mod");
    if fallback_mod.exists() && !paths.contains(&fallback_mod) {
        paths.push(fallback_mod);
    }

    paths
}
```

Filter against `is_ancestor_or_descendant(&existing_roots)` before pushing, so `$GOCACHE = ~/.cache/go-build` (Linux default) or `~/Library/Caches/go-build` (macOS default) gets dropped when `~/.cache` / `~/Library/Caches` are already roots. Same fix as SwiftPM — prevents the duplicate-TreeNode bug.

`default_for_test()` remains empty. A config test asserts the Go module cache root appears when `~/go/pkg/mod` exists; skips cleanly otherwise (L6 / L9 patterns).

## Dispatch Integration (`src/providers/mod.rs`)

Add `pub mod go_mod;`. Add `CacheKind::Go` arms to:
- `detect()` — direct-name on `go-build`, adjacent-components on `pkg/mod`.
- `semantic_name()` → `go_mod::semantic_name`.
- `metadata()` → `go_mod::metadata`.
- `package_id()` → `go_mod::package_id`.
- `upgrade_command()` — `Some(format!("go get {name}@{version}"))`.
- `safety()` — Safe for `pkg/mod`, Caution for `go-build`, component-based.
- `pre_delete()` — new dispatch (see above).

## CacheKind Enum (`src/tree/node.rs`)

Add `Go` variant with:
- `label()` → `"Go"`
- `description()` → `"Go module cache and build cache"`
- `url()` → `"https://go.dev"`

Placed alphabetically between `Gradle` and `SwiftPm`.

## Registry (`src/security/registry.rs`)

Add:

```rust
pub fn parse_go_proxy_list(body: &str) -> Option<String> {
    body.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter(|l| !is_pseudo_version(l))
        .filter(|l| !l.ends_with("+incompatible"))
        .max_by(|a, b| compare_versions(a, b))
        .or_else(|| {
            // All versions are pseudo or +incompatible — fall back to max.
            body.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .max_by(|a, b| compare_versions(a, b))
        })
        .map(|s| s.to_string())
}

fn is_pseudo_version(v: &str) -> bool {
    // vX.Y.Z-YYYYMMDDHHMMSS-<12hex>  (Go pseudo-version format)
    // Cheap check: split on '-', look for a 14-digit timestamp chunk
    // followed by a 12-hex-digit chunk.
    let parts: Vec<&str> = v.split('-').collect();
    if parts.len() < 3 {
        return false;
    }
    let ts = parts[parts.len() - 2];
    let hash = parts[parts.len() - 1];
    ts.len() == 14
        && ts.chars().all(|c| c.is_ascii_digit())
        && hash.len() == 12
        && hash.chars().all(|c| c.is_ascii_hexdigit())
}
```

Update `build_registry_url` to emit `https://proxy.golang.org/<url-escaped-module>/@v/list` for `"Go"`. Update `parse_registry_response` to dispatch to `parse_go_proxy_list`.

## UI Impact

None. Existing tree/detail-panel/delete flow is provider-agnostic once `pre_delete` is wired; the Go variant gets detail-panel labels, safety icons, and upgrade-command copy for free.

## Testing Strategy

### Tier 1: Unit Tests (in-module)

All strict TDD (RED → GREEN → refactor).

**Detection:**
- `detect_go_build_root`, `detect_go_mod_cache_deep_path`, `detect_go_rejects_pkg_mod_backup` (L1), `detect_go_rejects_go_build_backup` (L1), `detect_go_rejects_unrelated_mod_dir`.

**Bang-decoding:**
- `decode_module_path_single_uppercase` (`!u!ber` → `Uber`).
- `decode_module_path_in_real_module_path` (`github.com/!golang/!mock` → `github.com/Golang/Mock`).
- `decode_module_path_trailing_lone_bang_passes_through`.
- `decode_module_path_non_ascii_passes_through` (L2).

**Semantic names:**
- `semantic_name_zip_file` → `"<module> <version>"`.
- `semantic_name_extracted_dir` → same format.
- `semantic_name_sumdb_file_returns_none`.
- `semantic_name_info_mod_ziphash_return_none`.
- `semantic_name_build_cache_entry_returns_none`.
- `semantic_name_bang_decoded_module`.

**Package identity:**
- `package_id_from_zip`.
- `package_id_from_info_returns_none` (dedup guard, L9).
- `package_id_from_mod_returns_none`.
- `package_id_from_ziphash_returns_none`.
- `package_id_from_extracted_dir_returns_none` (dedup — counted via `.zip`).
- `package_id_module_path_is_decoded`.

**Safety:**
- `safety_pkg_mod_is_safe`.
- `safety_go_build_is_caution`.
- `safety_unknown_subdir_is_caution`.
- `safety_rejects_confusable_suffix` (L1).

**Metadata:**
- Three `metadata_<root>_reports_contents` tests.
- `metadata_leaf_file_returns_empty`.

**Registry parser:**
- `parse_go_proxy_list_picks_highest_semver`.
- `parse_go_proxy_list_skips_pseudo_versions`.
- `parse_go_proxy_list_prefers_non_incompatible`.
- `parse_go_proxy_list_handles_pre_release`.
- `parse_go_proxy_list_empty_body_returns_none`.

**Pre-delete:**
- `pre_delete_chmods_read_only_module_cache` — create a fake mod cache with `chmod -w` files, call `pre_delete`, assert files are writable afterwards.
- `pre_delete_on_build_cache_path_is_noop`.
- `pre_delete_default_dispatch_is_ok_for_all_other_kinds` — loop through every `CacheKind` and assert `pre_delete` returns `Ok(())`.
- `perform_delete_calls_pre_delete_before_remove` — integration test in `src/app.rs` tests, using a synthetic read-only fixture.

### Tier 2: Integration Tests (`tests/integration_go.rs`)

Synthetic fixtures:
- Build a tempdir shaped like `$GOMODCACHE`: `cache/download/github.com/!uber/zap/@v/v1.27.0.zip`, sibling `.info` / `.mod`.
- Verify full pipeline: detect → semantic_name (`github.com/Uber/zap 1.27.0`) → safety (Safe) → package_id dedup (exactly one per unique module).
- Build cache fixture with synthetic `go-build/ab/abcdef-link` — verify detect=Go, semantic_name=None, safety=Caution.

### Tier 3: E2E Tests (`tests/e2e_go_provider.rs`, feature-gated `e2e`)

Per `feedback_e2e_full_pipeline`:
1. Install `go` if not on PATH (skip cleanly on Windows-style hosts with a clear message).
2. Create tempdir. Set `GOMODCACHE=<tmp>/mod`, `GOCACHE=<tmp>/build`, `GOPATH=<tmp>/gopath`.
3. Run `go get github.com/gin-gonic/gin@v1.6.0` — known outdated (latest is 1.10+) and has at least one OSV-tracked CVE (CVE-2023-26125, CVE-2023-29401 etc.).
4. Verify scanner pipeline:
   - `discover_packages` finds `github.com/gin-gonic/gin` with version `v1.6.0`.
   - `scan_vulns` returns at least one vuln.
   - `check_latest` against proxy.golang.org returns a version strictly greater than `v1.6.0`.
5. **Delete-flow verification**: invoke `perform_delete` on the module cache path. Assert deletion succeeds end-to-end (the pre-delete hook unblocks `remove_dir_all`). Without the hook, this step fails — canary for the main motivator.
6. Teardown: tempdir drops (auto-cleaned on green per `feedback_e2e_automated_and_cleaned_up`).

## Docs Updates

- `README.md` — add a row to Supported Caches (19 → 20 providers), add a row to the Provider Capabilities matrix, bump the Features count.
- `CHANGELOG.md` — `[Unreleased]` Added bullet covering both module + build caches, noting the new `pre_delete` hook.
- `docs/user-guide.md` — list Go under the vuln / outdated / upgrade-cmd participating providers.
- `docs/adding-a-provider.md` — **document the new pre-delete hook** in §2's wire-up checklist. Add a Lessons Learned line.
- `TODO.md` — tick issue #8.

## Files Changed

| File | Change |
|------|--------|
| `src/tree/node.rs` | Add `Go` variant |
| `src/providers/mod.rs` | Add `pub mod go_mod;`, dispatch arms, new `pre_delete` dispatch |
| `src/providers/go_mod.rs` | **New** — provider |
| `src/config.rs` | `probe_go_paths()`, subsumed-by-parent-root filter |
| `src/security/registry.rs` | `parse_go_proxy_list`, `is_pseudo_version`, `Go` URL arm |
| `src/app.rs` | Call `providers::pre_delete` in `perform_delete` |
| `tests/integration_go.rs` | **New** — Tier 2 pipeline |
| `tests/e2e_go_provider.rs` | **New** — Tier 3 real-tool |
| `README.md`, `CHANGELOG.md`, `docs/user-guide.md`, `docs/adding-a-provider.md`, `TODO.md` | docs |

## Out of Scope

- **Nested vendored module caches** (`<repo>/vendor/`). Different layout, not a user-wide cache.
- **Go workspace cache** (`go.work` / `go.work.sum`). Project-local.
- **Garbage collection of stale modules** per Go 1.22+'s `GOMODCACHE` hygiene. Different feature — user wants to understand what's there and delete selectively, not auto-GC.

## Risks

- **Proxy endpoint availability**: `proxy.golang.org` occasionally rate-limits. The existing 10s `ureq` timeout + partial-failure reporting (L7) handles this; no new work needed.
- **Bang-decoding edge case**: a pathological module path with lone `!` could theoretically confuse decoder. Tests cover trailing-bang pass-through to make the behavior explicit.
- **Pre-delete hook blast radius**: a bug in the default `Ok(())` dispatch could accidentally block deletes for unrelated providers. Mitigated by the mandatory `pre_delete_default_dispatch_is_ok_for_all_other_kinds` regression test.
