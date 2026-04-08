# Yarn & pnpm Provider Support

**Date:** 2026-04-08
**Issue:** [juliensimon/cache-commander#1](https://github.com/juliensimon/cache-commander/issues/1)
**Status:** Design

## Summary

Add Yarn (Classic + Berry) and pnpm cache providers to cache-explorer, enabling detection, display, vulnerability scanning, version checking, and cleanup for all three major JS package managers.

## Approach

Approach A: One `CacheKind::Yarn` (handles both Yarn 1 and 2+ internally) and one `CacheKind::Pnpm`. Auto-detection of cache paths via CLI probing, with config overrides.

## Provider: Yarn (`src/providers/yarn.rs`)

### Detection

`detect(path)` returns `CacheKind::Yarn` when path components match:
- `.yarn-cache/` or `.cache/yarn/` (Yarn 1 Classic global cache)
- `.yarn/cache/` (Yarn 2+ Berry per-project cache)
- `Library/Caches/Yarn/` (macOS Yarn 1)
- `berry/cache/` inside Yarn global folder

### Package Identification

Two formats, branched internally:

**Yarn 1 (Classic):** Tarballs named `npm-<name>-<version>-<hash>.tgz`
- Parse filename: strip `npm-` prefix, extract name and version
- Scoped packages: `npm-@scope-name-<version>-<hash>.tgz`
- `PackageId { ecosystem: "npm", name, version }`

**Yarn 2+ (Berry):** Zip archives named `<name>-npm-<version>-<hash>.zip`
- Parse filename: split on `-npm-`, extract name and version before hash
- Scoped packages: `@scope-name-npm-<version>-<hash>.zip`
- `PackageId { ecosystem: "npm", name, version }`

### Semantic Names

- Yarn 1 tarball: `"lodash 4.17.21"` (parsed from filename)
- Berry zip: `"lodash 4.17.21"` (parsed from filename)
- Known directories: `"Yarn Cache"`, `"Yarn Logs"`, etc.

### Metadata

- Package format (tgz vs zip)
- Yarn version detected (Classic vs Berry)
- File size
- Install script detection (if extractable)

### Safety

All Yarn cache entries: `SafetyLevel::Safe` (re-downloadable from npm registry).

### Upgrade Command

`yarn add <name>@<version>`

## Provider: pnpm (`src/providers/pnpm.rs`)

### Detection

`detect(path)` returns `CacheKind::Pnpm` when path components match:
- `.pnpm-store/` (global content-addressed store)
- `node_modules/.pnpm/` (project-level virtual store)
- `pnpm/store/` inside XDG cache directories

### Package Identification

**`node_modules/.pnpm/` (reliable path):** Directories named `<name>@<version>/node_modules/<name>`
- Parse folder name: split on `@` to extract name and version
- Scoped packages: `@scope+name@<version>` (pnpm uses `+` as path separator for scopes)
- `PackageId { ecosystem: "npm", name, version }`

**`.pnpm-store/` (content-addressed):** Hash-based blobs with no package identity in path.
- `package_id()` returns `None` for store-level entries
- Still detected as `CacheKind::Pnpm` for display and cleanup

### Semantic Names

- `node_modules/.pnpm/lodash@4.17.21/...` -> `"lodash 4.17.21"`
- `.pnpm-store/v3/` -> `"pnpm Content Store"`
- `.pnpm-store/v3/files/` -> `"Content Files"`

### Metadata

- Package name and version (from `node_modules/.pnpm/` path)
- Store version (v3, etc.)
- File count and size
- Whether entry is content-addressed or virtual store

### Safety

- `.pnpm-store/` entries: `SafetyLevel::Safe` (re-downloadable, pnpm re-fetches on next install)
- `node_modules/.pnpm/` entries: `SafetyLevel::Caution` (deletion triggers re-install in that project)

### Upgrade Command

`pnpm add <name>@<version>`

## Auto-Detection of Cache Paths (`src/config.rs`)

### CLI Probing (at startup)

If tool is on PATH:
- `yarn cache dir` -> Yarn 1 global cache path
- `yarn config get cacheFolder` -> Yarn 2+ cache path
- `pnpm store path` -> pnpm global store path

Add discovered paths to scan roots. Timeout: 2 seconds per command. Failures are silent (tool may not be installed).

### Fallback Locations (checked even if tool not installed)

Orphaned caches are valuable cleanup targets:

| Path | OS | Tool |
|------|----|------|
| `~/.cache/yarn/` | Linux | Yarn 1 |
| `~/.yarn-cache/` | Linux/macOS | Yarn 1 |
| `~/Library/Caches/Yarn/` | macOS | Yarn 1 |
| `~/.yarn/berry/cache/` | All | Yarn 2+ |
| `~/.pnpm-store/` | All | pnpm |
| `~/.local/share/pnpm/store/` | Linux | pnpm |

### Config Override

Users can add/remove roots in `~/.config/ccmd/config.toml`. Config entries take precedence over auto-detection.

## Dispatch Integration (`src/providers/mod.rs`)

Add `mod yarn;` and `mod pnpm;` declarations. Add `CacheKind::Yarn` and `CacheKind::Pnpm` arms to:

- `detect()` — path-based detection as described above
- `semantic_name()` — dispatch to `yarn::semantic_name` / `pnpm::semantic_name`
- `metadata()` — dispatch to `yarn::metadata` / `pnpm::metadata`
- `package_id()` — dispatch to `yarn::package_id` / `pnpm::package_id`
- `upgrade_command()` — `yarn add` / `pnpm add`

## CacheKind Enum (`src/tree/node.rs`)

Add two variants:

| Variant | `label()` | `description()` | `url()` |
|---------|-----------|------------------|---------|
| `Yarn` | `"Yarn"` | `"Yarn package manager cache"` | `"https://yarnpkg.com"` |
| `Pnpm` | `"pnpm"` | `"pnpm package manager cache"` | `"https://pnpm.io"` |

## UI Impact

None. The existing tree view, detail panel, and deletion flow work generically off `CacheKind`, `MetadataField`, and `SafetyLevel`. New providers slot in automatically.

## Testing Strategy

### Tier 1: Unit Tests (in-module, `#[cfg(test)]`)

Located in `yarn.rs` and `pnpm.rs`. Use `tempfile::tempdir()` to create synthetic cache structures.

**Yarn tests:**
- Detect Yarn 1 cache from `.yarn-cache/` path
- Detect Yarn 2+ cache from `.yarn/cache/` path
- Parse Yarn 1 tarball filename: `npm-lodash-4.17.21-<hash>.tgz` -> name=lodash, version=4.17.21
- Parse Berry zip filename: `lodash-npm-4.17.21-<hash>.zip` -> name=lodash, version=4.17.21
- Parse scoped packages: `npm-@babel-core-7.24.0-<hash>.tgz`, `@babel-core-npm-7.24.0-<hash>.zip`
- Semantic name formatting
- Metadata field generation
- Edge cases: malformed filenames return None, pre-release versions, very long package names

**pnpm tests:**
- Detect pnpm store from `.pnpm-store/` path
- Detect virtual store from `node_modules/.pnpm/` path
- Parse `lodash@4.17.21` folder name -> name=lodash, version=4.17.21
- Parse scoped: `@babel+core@7.24.0` -> name=@babel/core, version=7.24.0
- `package_id()` returns None for content-addressed store entries
- Safety levels: Safe for store, Caution for virtual store

### Tier 2: Integration Tests (`tests/integration.rs`)

Extend existing integration test file:
- Create tempdir with Yarn + pnpm cache fixtures alongside existing npm/pip/cargo fixtures
- Run `discover_packages()` and verify Yarn/pnpm packages found
- Run scanner pipeline (via channels) and verify tree expansion shows correct semantic names
- Verify deduplication: same package in npm and Yarn cache counted once in vulnerability scan

### Tier 3: End-to-End Tests (`tests/e2e_js_providers.rs`)

Gated behind `#[cfg(feature = "e2e")]`. Require real Yarn + pnpm installed.

**Setup per test:**
1. Create temp project directory
2. Install tool if not present (or skip test with clear message)
3. `npm init -y` in temp dir
4. Install real packages (e.g., `lodash@4.17.21`)

**Yarn 1 E2E:**
- Set up Yarn Classic environment, install packages
- Run `yarn cache dir` to find cache
- Point scanner at cache, verify `lodash` discovered with correct version

**Yarn 2+ E2E:**
- `corepack enable && yarn init -2` in temp dir
- `yarn add lodash@4.17.21`
- Verify `.yarn/cache/` contains zip, scanner finds it

**pnpm E2E:**
- `pnpm init && pnpm add lodash@4.17.21`
- Verify `node_modules/.pnpm/lodash@4.17.21` exists
- Scanner discovers package with correct PackageId
- Run `pnpm store path`, verify auto-detection returns valid path

**CI:** Separate workflow job that installs yarn + pnpm, runs `cargo test --features e2e`.

## Files Changed

| File | Change |
|------|--------|
| `src/tree/node.rs` | Add `Yarn`, `Pnpm` to `CacheKind` enum with label/description/url |
| `src/providers/mod.rs` | Add `mod yarn; mod pnpm;`, add match arms to all dispatch functions |
| `src/providers/yarn.rs` | **New** — Yarn 1 + 2+ provider |
| `src/providers/pnpm.rs` | **New** — pnpm provider |
| `src/config.rs` | Add auto-detection probing and fallback paths |
| `Cargo.toml` | Add `e2e` feature flag |
| `tests/integration.rs` | Add Yarn/pnpm fixture tests |
| `tests/e2e_js_providers.rs` | **New** — E2E tests with real tools |
| `.github/workflows/ci.yml` | Add E2E test job with yarn + pnpm installation |

## Out of Scope

- Bun package manager support (separate future enhancement)
- pnpm package identification from content-addressed store hashes (only virtual store `node_modules/.pnpm/` paths)
- Yarn PnP (Plug'n'Play) `.pnp.cjs` file parsing
- Custom registry support (all packages assumed from npm registry)
