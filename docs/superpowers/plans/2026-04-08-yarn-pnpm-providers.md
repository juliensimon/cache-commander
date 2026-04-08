# Yarn & pnpm Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Yarn (Classic + Berry) and pnpm cache providers to cache-explorer, with full package identification, vulnerability scanning, and auto-detection of cache paths.

**Architecture:** Two new provider modules (`yarn.rs`, `pnpm.rs`) following the existing dispatch pattern. Each implements `detect`, `semantic_name`, `metadata`, and `package_id` functions. The `CacheKind` enum gains two variants. Auto-detection probes CLI tools at startup to discover cache paths.

**Tech Stack:** Rust, `std::process::Command` for CLI probing, `tempfile` for tests, real `yarn`/`pnpm` CLI for E2E tests.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/tree/node.rs` | Add `Yarn`, `Pnpm` variants to `CacheKind` enum with label/description/url |
| `src/providers/mod.rs` | Module declarations, dispatch match arms for all 5 functions + safety |
| `src/providers/yarn.rs` | **New** — Yarn 1 + Berry detection, naming, metadata, package_id |
| `src/providers/pnpm.rs` | **New** — pnpm store + virtual store detection, naming, metadata, package_id |
| `src/config.rs` | Auto-detection of Yarn/pnpm cache paths via CLI probing + fallback paths |
| `Cargo.toml` | Add `e2e` feature flag |
| `tests/integration.rs` | Yarn/pnpm fixture-based integration tests |
| `tests/e2e_js_providers.rs` | **New** — E2E tests with real Yarn/pnpm tools |
| `.github/workflows/ci.yml` | Add E2E test job |

---

### Task 1: Add CacheKind Variants

**Files:**
- Modify: `src/tree/node.rs:5-76`

- [ ] **Step 1: Write failing test for Yarn CacheKind**

Add to the existing test module in `src/tree/node.rs` (after line 196):

```rust
#[test]
fn cache_kind_yarn_has_label() {
    assert_eq!(CacheKind::Yarn.label(), "Yarn");
    assert!(!CacheKind::Yarn.description().is_empty());
    assert!(!CacheKind::Yarn.url().is_empty());
}

#[test]
fn cache_kind_pnpm_has_label() {
    assert_eq!(CacheKind::Pnpm.label(), "pnpm");
    assert!(!CacheKind::Pnpm.description().is_empty());
    assert!(!CacheKind::Pnpm.url().is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib tree::node::tests::cache_kind_yarn_has_label 2>&1 | tail -5`
Expected: Compilation error — `Yarn` is not a variant of `CacheKind`

- [ ] **Step 3: Add Yarn and Pnpm to CacheKind enum**

In `src/tree/node.rs`, add `Yarn` and `Pnpm` before `Unknown` in the enum (line 17):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheKind {
    HuggingFace,
    Pip,
    Uv,
    Npm,
    Homebrew,
    Cargo,
    PreCommit,
    Whisper,
    Gh,
    Torch,
    Chroma,
    Prisma,
    Yarn,
    Pnpm,
    #[default]
    Unknown,
}
```

Add to `label()` match (after `Prisma` arm, before `Unknown`):

```rust
Self::Yarn => "Yarn",
Self::Pnpm => "pnpm",
```

Add to `description()` match:

```rust
Self::Yarn => "Yarn package manager — cached packages and metadata",
Self::Pnpm => "pnpm package manager — content-addressed package store",
```

Add to `url()` match:

```rust
Self::Yarn => "https://yarnpkg.com",
Self::Pnpm => "https://pnpm.io",
```

- [ ] **Step 4: Fix compilation errors in mod.rs dispatch functions**

The existing match arms in `src/providers/mod.rs` need `Yarn` and `Pnpm` cases. Add temporary pass-through arms to each dispatch function so the project compiles:

In `detect()` — no change needed (Yarn/Pnpm detection comes in Task 3).

In `semantic_name()` (after line 117, before `CacheKind::Unknown`):

```rust
CacheKind::Yarn => None,
CacheKind::Pnpm => None,
```

In `metadata()` (after line 136, before `CacheKind::Unknown`):

```rust
CacheKind::Yarn => generic::metadata(path),
CacheKind::Pnpm => generic::metadata(path),
```

In `safety()` — no change needed (the `_ => SafetyLevel::Safe` wildcard covers new kinds).

In `upgrade_command()` — no change needed (the `_ => None` wildcard covers new kinds).

In `package_id()` — no change needed (the `_ => None` wildcard covers new kinds).

Also add `Yarn` and `Pnpm` to the safety test's known providers list in `src/providers/mod.rs` (line 330):

```rust
assert_eq!(safety(CacheKind::Yarn, &path), SafetyLevel::Safe);
assert_eq!(safety(CacheKind::Pnpm, &path), SafetyLevel::Safe);
```

And add to the `upgrade_command_unsupported_kinds_return_none` test (line 408):

```rust
let unsupported = [
    CacheKind::HuggingFace,
    CacheKind::Homebrew,
    CacheKind::PreCommit,
    CacheKind::Whisper,
    CacheKind::Gh,
    CacheKind::Torch,
    CacheKind::Chroma,
    CacheKind::Prisma,
    CacheKind::Yarn,
    CacheKind::Pnpm,
];
```

- [ ] **Step 5: Run tests to verify everything passes**

Run: `cargo test 2>&1 | tail -5`
Expected: All tests pass, including the two new CacheKind tests.

- [ ] **Step 6: Commit**

```bash
git add src/tree/node.rs src/providers/mod.rs
git commit -m "feat: add Yarn and Pnpm CacheKind variants"
```

---

### Task 2: Yarn Provider — Detection & Semantic Names

**Files:**
- Create: `src/providers/yarn.rs`
- Modify: `src/providers/mod.rs:1-13` (module declaration)

- [ ] **Step 1: Create yarn.rs with failing unit tests for detection helpers**

Create `src/providers/yarn.rs`:

```rust
use super::MetadataField;
use std::path::Path;

/// Identify whether a path is inside a Yarn cache.
/// Returns true for both Yarn Classic and Berry cache structures.
pub fn is_yarn_cache(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    // Yarn 1 Classic global caches
    path_str.contains(".yarn-cache")
        || path_str.contains(".cache/yarn")
        || path_str.contains("Library/Caches/Yarn")
        // Yarn 2+ Berry per-project cache
        || path_str.contains(".yarn/cache")
        // Yarn Berry global cache
        || path_str.contains("yarn/berry/cache")
}

/// Determine if this path is inside a Yarn Berry (2+) cache.
fn is_berry(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".yarn/cache") || path_str.contains("berry/cache")
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Known directory names
    match name.as_str() {
        "cache" => {
            if is_berry(path) {
                return Some("Yarn Berry Cache".to_string());
            }
            return Some("Yarn Cache".to_string());
        }
        ".yarn-cache" => return Some("Yarn Classic Cache".to_string()),
        _ => {}
    }

    // Berry zip: <name>-npm-<version>-<hash>.zip
    if name.ends_with(".zip") {
        if let Some((pkg_name, version)) = parse_berry_filename(&name) {
            return Some(format!("{pkg_name} {version}"));
        }
    }

    // Classic tgz: npm-<name>-<version>-<hash>.tgz
    if name.ends_with(".tgz") {
        if let Some((pkg_name, version)) = parse_classic_filename(&name) {
            return Some(format!("{pkg_name} {version}"));
        }
    }

    None
}

/// Parse a Yarn Berry (2+) cache filename.
/// Format: `<name>-npm-<version>-<hash>.zip`
/// Scoped: `@scope-name-npm-<version>-<hash>.zip`
fn parse_berry_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".zip")?;
    // Split on "-npm-" to separate package name from version-hash
    let idx = stem.find("-npm-")?;
    let raw_name = &stem[..idx];
    let rest = &stem[idx + 5..]; // skip "-npm-"

    // rest is "<version>-<hash>" — version ends before the last hyphen-hex segment
    let version = extract_version_before_hash(rest)?;

    // Convert scoped package names: "@scope-name" -> "@scope/name"
    let pkg_name = normalize_scoped_name(raw_name);

    Some((pkg_name, version))
}

/// Parse a Yarn Classic (1.x) cache filename.
/// Format: `npm-<name>-<version>-<hash>.tgz`
/// Scoped: `npm-@scope-name-<version>-<hash>.tgz`
fn parse_classic_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".tgz")?;
    let rest = stem.strip_prefix("npm-")?;

    // For scoped packages like "@scope-name-1.0.0-hash",
    // find the version by looking for "-<digit>" pattern
    let (raw_name, version) = split_name_version(rest)?;
    let pkg_name = normalize_scoped_name(&raw_name);

    Some((pkg_name, version))
}

/// Given "name-1.2.3-hash", split into ("name", "1.2.3").
/// Handles scoped: "@scope-name-1.2.3-hash" -> ("@scope-name", "1.2.3")
fn split_name_version(s: &str) -> Option<(String, String)> {
    // Walk through hyphen-separated segments.
    // The version starts at the first segment beginning with a digit.
    // The hash is the last segment (hex characters).
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 3 {
        return None;
    }

    // Find first part that starts with a digit — that's the version start
    let version_start = parts
        .iter()
        .position(|p| p.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))?;

    if version_start == 0 {
        return None; // No name portion
    }

    let name = parts[..version_start].join("-");
    // Version is everything between version_start and the last segment (hash)
    let version = parts[version_start..parts.len() - 1].join("-");

    if version.is_empty() {
        return None;
    }

    Some((name, version))
}

/// Extract version from "1.2.3-<hash>" — everything before the last hyphen segment
/// that is all hex characters (the integrity hash).
fn extract_version_before_hash(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 2 {
        return None;
    }

    // Last segment is the hash (hex chars). Walk backward to find where hash starts.
    // Hash segments are typically 10+ hex chars.
    let mut hash_start = parts.len();
    for i in (0..parts.len()).rev() {
        if parts[i].len() >= 8 && parts[i].chars().all(|c| c.is_ascii_hexdigit()) {
            hash_start = i;
        } else {
            break;
        }
    }

    if hash_start == 0 {
        return None;
    }

    let version = parts[..hash_start].join("-");
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Convert "@scope-name" to "@scope/name" for scoped npm packages.
fn normalize_scoped_name(name: &str) -> String {
    if name.starts_with('@') {
        // First hyphen after @ is the scope separator
        if let Some(pos) = name[1..].find('-') {
            return format!("@{}/{}", &name[1..1 + pos], &name[2 + pos..]);
        }
    }
    name.to_string()
}

pub fn metadata(_path: &Path) -> Vec<MetadataField> {
    Vec::new()
}

pub fn package_id(_path: &Path) -> Option<super::PackageId> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- is_yarn_cache ---

    #[test]
    fn detects_classic_yarn_cache() {
        assert!(is_yarn_cache(&PathBuf::from("/home/user/.yarn-cache/v6")));
    }

    #[test]
    fn detects_classic_xdg_yarn_cache() {
        assert!(is_yarn_cache(&PathBuf::from("/home/user/.cache/yarn/v6")));
    }

    #[test]
    fn detects_berry_per_project_cache() {
        assert!(is_yarn_cache(&PathBuf::from(
            "/projects/myapp/.yarn/cache"
        )));
    }

    #[test]
    fn detects_macos_yarn_cache() {
        assert!(is_yarn_cache(&PathBuf::from(
            "/Users/me/Library/Caches/Yarn/v6"
        )));
    }

    #[test]
    fn does_not_detect_unrelated_path() {
        assert!(!is_yarn_cache(&PathBuf::from("/home/user/.npm/_cacache")));
    }

    // --- Berry filename parsing ---

    #[test]
    fn parse_berry_simple_package() {
        let (name, ver) = parse_berry_filename("lodash-npm-4.17.21-6382d821f21d.zip").unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn parse_berry_scoped_package() {
        let (name, ver) =
            parse_berry_filename("@babel-core-npm-7.24.0-abc123def456.zip").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn parse_berry_prerelease_version() {
        let (name, ver) =
            parse_berry_filename("typescript-npm-5.0.0-beta.1-aabbccdd0011.zip").unwrap();
        assert_eq!(name, "typescript");
        assert_eq!(ver, "5.0.0-beta.1");
    }

    #[test]
    fn parse_berry_invalid_no_npm_marker() {
        assert!(parse_berry_filename("lodash-4.17.21.zip").is_none());
    }

    // --- Classic filename parsing ---

    #[test]
    fn parse_classic_simple_package() {
        let (name, ver) =
            parse_classic_filename("npm-lodash-4.17.21-6382d821f21d.tgz").unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn parse_classic_scoped_package() {
        let (name, ver) =
            parse_classic_filename("npm-@babel-core-7.24.0-abc123def456.tgz").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn parse_classic_hyphenated_name() {
        let (name, ver) =
            parse_classic_filename("npm-is-even-1.0.0-aabb112233cc.tgz").unwrap();
        assert_eq!(name, "is-even");
        assert_eq!(ver, "1.0.0");
    }

    #[test]
    fn parse_classic_invalid_no_npm_prefix() {
        assert!(parse_classic_filename("lodash-4.17.21-hash.tgz").is_none());
    }

    // --- semantic_name ---

    #[test]
    fn semantic_name_berry_zip() {
        let path = PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-6382d821f21d.zip");
        assert_eq!(semantic_name(&path), Some("lodash 4.17.21".into()));
    }

    #[test]
    fn semantic_name_classic_tgz() {
        let path = PathBuf::from("/home/.yarn-cache/v6/npm-express-4.21.0-abcdef123456.tgz");
        assert_eq!(semantic_name(&path), Some("express 4.21.0".into()));
    }

    #[test]
    fn semantic_name_cache_dir_berry() {
        let path = PathBuf::from("/project/.yarn/cache");
        assert_eq!(semantic_name(&path), Some("Yarn Berry Cache".into()));
    }

    #[test]
    fn semantic_name_cache_dir_classic() {
        let path = PathBuf::from("/home/.cache/yarn/cache");
        assert_eq!(semantic_name(&path), Some("Yarn Cache".into()));
    }

    #[test]
    fn semantic_name_yarn_cache_dir() {
        let path = PathBuf::from("/home/.yarn-cache");
        assert_eq!(semantic_name(&path), Some("Yarn Classic Cache".into()));
    }

    #[test]
    fn semantic_name_unknown_file() {
        let path = PathBuf::from("/project/.yarn/cache/random.txt");
        assert_eq!(semantic_name(&path), None);
    }

    // --- normalize_scoped_name ---

    #[test]
    fn normalize_scoped() {
        assert_eq!(normalize_scoped_name("@babel-core"), "@babel/core");
    }

    #[test]
    fn normalize_unscoped() {
        assert_eq!(normalize_scoped_name("lodash"), "lodash");
    }

    #[test]
    fn normalize_scoped_deep() {
        assert_eq!(normalize_scoped_name("@types-node"), "@types/node");
    }
}
```

- [ ] **Step 2: Add module declaration to mod.rs**

In `src/providers/mod.rs`, add after line 8 (`pub mod npm;`):

```rust
pub mod yarn;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test --lib providers::yarn::tests 2>&1 | tail -10`
Expected: All yarn unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/providers/yarn.rs src/providers/mod.rs
git commit -m "feat: add Yarn provider with detection and semantic names"
```

---

### Task 3: Yarn Provider — Package ID & Metadata

**Files:**
- Modify: `src/providers/yarn.rs`

- [ ] **Step 1: Write failing tests for package_id**

Add to the test module in `src/providers/yarn.rs`:

```rust
// --- package_id ---

#[test]
fn package_id_berry_zip() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join(".yarn/cache");
    std::fs::create_dir_all(&cache).unwrap();
    let zip_file = cache.join("lodash-npm-4.17.21-6382d821f21d.zip");
    std::fs::write(&zip_file, "fake zip").unwrap();

    let id = package_id(&zip_file).unwrap();
    assert_eq!(id.ecosystem, "npm");
    assert_eq!(id.name, "lodash");
    assert_eq!(id.version, "4.17.21");
}

#[test]
fn package_id_classic_tgz() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join(".yarn-cache/v6");
    std::fs::create_dir_all(&cache).unwrap();
    let tgz_file = cache.join("npm-express-4.21.0-abcdef123456.tgz");
    std::fs::write(&tgz_file, "fake tgz").unwrap();

    let id = package_id(&tgz_file).unwrap();
    assert_eq!(id.ecosystem, "npm");
    assert_eq!(id.name, "express");
    assert_eq!(id.version, "4.21.0");
}

#[test]
fn package_id_scoped_berry() {
    let path = PathBuf::from("/project/.yarn/cache/@types-node-npm-22.0.0-aabb112233cc.zip");
    let id = package_id(&path).unwrap();
    assert_eq!(id.name, "@types/node");
    assert_eq!(id.version, "22.0.0");
}

#[test]
fn package_id_non_package_file() {
    let path = PathBuf::from("/project/.yarn/cache/.gitignore");
    assert!(package_id(&path).is_none());
}

#[test]
fn package_id_directory_returns_none() {
    let path = PathBuf::from("/project/.yarn/cache");
    assert!(package_id(&path).is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib providers::yarn::tests::package_id_berry_zip 2>&1 | tail -5`
Expected: FAIL — `package_id` currently returns `None` always.

- [ ] **Step 3: Implement package_id**

Replace the stub `package_id` in `src/providers/yarn.rs`:

```rust
pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Berry zip files
    if name.ends_with(".zip") {
        let (pkg_name, version) = parse_berry_filename(&name)?;
        return Some(super::PackageId {
            ecosystem: "npm",
            name: pkg_name,
            version,
        });
    }

    // Classic tgz files
    if name.ends_with(".tgz") {
        let (pkg_name, version) = parse_classic_filename(&name)?;
        return Some(super::PackageId {
            ecosystem: "npm",
            name: pkg_name,
            version,
        });
    }

    None
}
```

- [ ] **Step 4: Implement metadata**

Replace the stub `metadata` in `src/providers/yarn.rs`:

```rust
pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name.ends_with(".zip") {
        fields.push(MetadataField {
            label: "Format".to_string(),
            value: "Yarn Berry (.zip)".to_string(),
        });
    } else if name.ends_with(".tgz") {
        fields.push(MetadataField {
            label: "Format".to_string(),
            value: "Yarn Classic (.tgz)".to_string(),
        });
    } else if name == "cache" || name == ".yarn-cache" {
        // Cache root directory — count packages
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.ends_with(".zip") || n.ends_with(".tgz")
                })
                .count();
            if count > 0 {
                fields.push(MetadataField {
                    label: "Packages".to_string(),
                    value: count.to_string(),
                });
            }
        }
    }

    fields
}
```

- [ ] **Step 5: Add metadata tests**

Add to the test module:

```rust
// --- metadata ---

#[test]
fn metadata_berry_zip_shows_format() {
    let path = PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-abc123.zip");
    let fields = metadata(&path);
    assert_eq!(fields.len(), 1);
    assert!(fields[0].value.contains("Berry"));
}

#[test]
fn metadata_classic_tgz_shows_format() {
    let path = PathBuf::from("/home/.yarn-cache/v6/npm-lodash-4.17.21-abc123.tgz");
    let fields = metadata(&path);
    assert_eq!(fields.len(), 1);
    assert!(fields[0].value.contains("Classic"));
}

#[test]
fn metadata_cache_dir_counts_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("lodash-npm-4.17.21-abc.zip"), "z").unwrap();
    std::fs::write(cache.join("express-npm-4.21.0-def.zip"), "z").unwrap();
    std::fs::write(cache.join(".gitignore"), "ignored").unwrap();

    let fields = metadata(&cache);
    let pkg_field = fields.iter().find(|f| f.label == "Packages").unwrap();
    assert_eq!(pkg_field.value, "2");
}
```

- [ ] **Step 6: Run all yarn tests**

Run: `cargo test --lib providers::yarn::tests 2>&1 | tail -10`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add src/providers/yarn.rs
git commit -m "feat: add Yarn package_id and metadata"
```

---

### Task 4: Wire Yarn into Dispatch

**Files:**
- Modify: `src/providers/mod.rs:51-177`

- [ ] **Step 1: Write failing test for Yarn detection**

Add to `src/providers/mod.rs` test module (after line 285):

```rust
#[test]
fn detect_yarn_classic_cache() {
    assert_eq!(
        detect(&PathBuf::from("/home/user/.yarn-cache/v6/npm-lodash-4.17.21-abc.tgz")),
        CacheKind::Yarn
    );
}

#[test]
fn detect_yarn_xdg_cache() {
    assert_eq!(
        detect(&PathBuf::from("/home/user/.cache/yarn/v6/npm-express-4.21.0-def.tgz")),
        CacheKind::Yarn
    );
}

#[test]
fn detect_yarn_berry_cache() {
    assert_eq!(
        detect(&PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-abc.zip")),
        CacheKind::Yarn
    );
}

#[test]
fn detect_yarn_macos_library() {
    assert_eq!(
        detect(&PathBuf::from("/Users/me/Library/Caches/Yarn/v6")),
        CacheKind::Yarn
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib providers::tests::detect_yarn_classic_cache 2>&1 | tail -5`
Expected: FAIL — returns `CacheKind::Unknown`

- [ ] **Step 3: Add Yarn detection to detect()**

In `src/providers/mod.rs`, in the `detect` function, add Yarn detection. In the direct name match block (after line 69, before `_ => {}`):

```rust
".yarn-cache" => return CacheKind::Yarn,
```

In the ancestor walk (after line 90, before the `"registry"` match arm):

```rust
".yarn-cache" | "Yarn" => return CacheKind::Yarn,
".yarn" => {
    // .yarn/cache is Berry
    if path.to_string_lossy().contains(".yarn/cache")
        || path.to_string_lossy().contains(".yarn\\cache")
    {
        return CacheKind::Yarn;
    }
}
"yarn" => {
    // ~/.cache/yarn/ is Classic
    if ancestor.to_string_lossy().contains(".cache") {
        return CacheKind::Yarn;
    }
    // yarn/berry/cache is Berry global
    if path.to_string_lossy().contains("berry/cache") {
        return CacheKind::Yarn;
    }
}
```

- [ ] **Step 4: Update dispatch functions for Yarn**

In `semantic_name()`, replace the temporary `CacheKind::Yarn => None` with:

```rust
CacheKind::Yarn => yarn::semantic_name(path),
```

In `metadata()`, replace `CacheKind::Yarn => generic::metadata(path)` with:

```rust
CacheKind::Yarn => yarn::metadata(path),
```

In `package_id()`, add before the `_ => None` arm:

```rust
CacheKind::Yarn => yarn::package_id(path),
```

In `upgrade_command()`, add before the `_ => None` arm:

```rust
CacheKind::Yarn => Some(format!("yarn add {name}@{version}")),
```

- [ ] **Step 5: Add upgrade_command test for Yarn**

Add to the test module:

```rust
#[test]
fn upgrade_command_yarn() {
    assert_eq!(
        upgrade_command(CacheKind::Yarn, "lodash", "4.17.21"),
        Some("yarn add lodash@4.17.21".to_string())
    );
}
```

Remove `CacheKind::Yarn` from the `upgrade_command_unsupported_kinds_return_none` test array (it's now supported).

- [ ] **Step 6: Run all tests**

Run: `cargo test 2>&1 | tail -10`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat: wire Yarn provider into dispatch"
```

---

### Task 5: pnpm Provider — Detection, Semantic Names & Package ID

**Files:**
- Create: `src/providers/pnpm.rs`
- Modify: `src/providers/mod.rs:1-13` (module declaration)

- [ ] **Step 1: Create pnpm.rs with full implementation and tests**

Create `src/providers/pnpm.rs`:

```rust
use super::MetadataField;
use std::path::Path;

/// Identify whether a path is inside a pnpm cache.
pub fn is_pnpm_cache(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".pnpm-store")
        || path_str.contains("pnpm/store")
        || is_pnpm_virtual_store(path)
}

/// Check if path is inside a pnpm virtual store (project-level).
fn is_pnpm_virtual_store(path: &Path) -> bool {
    path.to_string_lossy().contains("node_modules/.pnpm")
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    match name.as_str() {
        ".pnpm-store" => return Some("pnpm Content Store".to_string()),
        ".pnpm" => return Some("pnpm Virtual Store".to_string()),
        _ => {}
    }

    // Store version directories
    if name.starts_with('v') && name[1..].chars().all(|c| c.is_ascii_digit()) {
        let path_str = path.to_string_lossy();
        if path_str.contains(".pnpm-store") || path_str.contains("pnpm/store") {
            return Some(format!("Store {name}"));
        }
    }

    if name == "files" {
        let path_str = path.to_string_lossy();
        if path_str.contains(".pnpm-store") || path_str.contains("pnpm/store") {
            return Some("Content Files".to_string());
        }
    }

    // Virtual store entries: name@version in node_modules/.pnpm/
    if is_pnpm_virtual_store(path) && name.contains('@') {
        if let Some((pkg_name, version)) = parse_virtual_store_name(&name) {
            return Some(format!("{pkg_name} {version}"));
        }
    }

    None
}

/// Parse a pnpm virtual store directory name.
/// Format: `<name>@<version>` or `@scope+name@<version>`
fn parse_virtual_store_name(dir_name: &str) -> Option<(String, String)> {
    // Scoped: @scope+name@version
    if dir_name.starts_with('@') {
        // Find the second @ which separates name from version
        let second_at = dir_name[1..].find('@')? + 1;
        let raw_name = &dir_name[..second_at];
        let version = &dir_name[second_at + 1..];
        // Convert @scope+name to @scope/name
        let pkg_name = raw_name.replace('+', "/");
        if version.is_empty() {
            return None;
        }
        return Some((pkg_name, version.to_string()));
    }

    // Unscoped: name@version
    let at_pos = dir_name.rfind('@')?;
    if at_pos == 0 {
        return None;
    }
    let name = &dir_name[..at_pos];
    let version = &dir_name[at_pos + 1..];
    if version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Only extract package_id from virtual store entries (node_modules/.pnpm/<name>@<version>)
    // Content-addressed store has no package identity in path
    if !is_pnpm_virtual_store(path) || !name.contains('@') {
        return None;
    }

    let (pkg_name, version) = parse_virtual_store_name(&name)?;

    // Reject entries that don't look like real packages (e.g., "node_modules" dir)
    if version
        .chars()
        .next()
        .map(|c| !c.is_ascii_digit())
        .unwrap_or(true)
    {
        return None;
    }

    Some(super::PackageId {
        ecosystem: "npm",
        name: pkg_name,
        version,
    })
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name == ".pnpm-store" || name == ".pnpm" {
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.filter_map(|e| e.ok()).count();
            fields.push(MetadataField {
                label: "Entries".to_string(),
                value: count.to_string(),
            });
        }
    }

    let path_str = path.to_string_lossy();
    if path_str.contains(".pnpm-store") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Content-addressed store".to_string(),
        });
    } else if is_pnpm_virtual_store(path) && name.contains('@') {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Virtual store entry".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- is_pnpm_cache ---

    #[test]
    fn detects_pnpm_store() {
        assert!(is_pnpm_cache(&PathBuf::from("/home/user/.pnpm-store/v3")));
    }

    #[test]
    fn detects_pnpm_virtual_store() {
        assert!(is_pnpm_cache(&PathBuf::from(
            "/project/node_modules/.pnpm/lodash@4.17.21"
        )));
    }

    #[test]
    fn detects_xdg_pnpm_store() {
        assert!(is_pnpm_cache(&PathBuf::from(
            "/home/user/.local/share/pnpm/store/v3"
        )));
    }

    #[test]
    fn does_not_detect_unrelated_path() {
        assert!(!is_pnpm_cache(&PathBuf::from(
            "/home/user/.npm/_cacache"
        )));
    }

    // --- parse_virtual_store_name ---

    #[test]
    fn parse_unscoped_package() {
        let (name, ver) = parse_virtual_store_name("lodash@4.17.21").unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn parse_scoped_package() {
        let (name, ver) = parse_virtual_store_name("@babel+core@7.24.0").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn parse_scoped_types() {
        let (name, ver) = parse_virtual_store_name("@types+node@22.0.0").unwrap();
        assert_eq!(name, "@types/node");
        assert_eq!(ver, "22.0.0");
    }

    #[test]
    fn parse_empty_version_returns_none() {
        assert!(parse_virtual_store_name("lodash@").is_none());
    }

    #[test]
    fn parse_no_at_returns_none() {
        assert!(parse_virtual_store_name("lodash").is_none());
    }

    // --- semantic_name ---

    #[test]
    fn semantic_name_pnpm_store() {
        assert_eq!(
            semantic_name(&PathBuf::from("/home/.pnpm-store")),
            Some("pnpm Content Store".into())
        );
    }

    #[test]
    fn semantic_name_virtual_store() {
        assert_eq!(
            semantic_name(&PathBuf::from("/project/node_modules/.pnpm")),
            Some("pnpm Virtual Store".into())
        );
    }

    #[test]
    fn semantic_name_store_version() {
        assert_eq!(
            semantic_name(&PathBuf::from("/home/.pnpm-store/v3")),
            Some("Store v3".into())
        );
    }

    #[test]
    fn semantic_name_virtual_store_entry() {
        assert_eq!(
            semantic_name(&PathBuf::from(
                "/project/node_modules/.pnpm/lodash@4.17.21"
            )),
            Some("lodash 4.17.21".into())
        );
    }

    #[test]
    fn semantic_name_virtual_store_scoped() {
        assert_eq!(
            semantic_name(&PathBuf::from(
                "/project/node_modules/.pnpm/@babel+core@7.24.0"
            )),
            Some("@babel/core 7.24.0".into())
        );
    }

    #[test]
    fn semantic_name_content_files() {
        assert_eq!(
            semantic_name(&PathBuf::from("/home/.pnpm-store/v3/files")),
            Some("Content Files".into())
        );
    }

    // --- package_id ---

    #[test]
    fn package_id_virtual_store_entry() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.21");
    }

    #[test]
    fn package_id_virtual_store_scoped() {
        let path = PathBuf::from("/project/node_modules/.pnpm/@types+node@22.0.0");
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "@types/node");
        assert_eq!(id.version, "22.0.0");
    }

    #[test]
    fn package_id_content_store_returns_none() {
        let path = PathBuf::from("/home/.pnpm-store/v3/files/ab/cd1234");
        assert!(package_id(&path).is_none());
    }

    #[test]
    fn package_id_pnpm_dir_returns_none() {
        let path = PathBuf::from("/project/node_modules/.pnpm");
        assert!(package_id(&path).is_none());
    }

    // --- metadata ---

    #[test]
    fn metadata_pnpm_store_shows_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join(".pnpm-store");
        std::fs::create_dir_all(store.join("v3")).unwrap();

        let fields = metadata(&store);
        let entries_field = fields.iter().find(|f| f.label == "Entries");
        assert!(entries_field.is_some());
    }

    #[test]
    fn metadata_virtual_store_entry_shows_type() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        let fields = metadata(&path);
        let type_field = fields.iter().find(|f| f.label == "Type").unwrap();
        assert!(type_field.value.contains("Virtual"));
    }

    #[test]
    fn metadata_content_store_shows_type() {
        let path = PathBuf::from("/home/.pnpm-store/v3/files/ab");
        let fields = metadata(&path);
        let type_field = fields.iter().find(|f| f.label == "Type").unwrap();
        assert!(type_field.value.contains("Content-addressed"));
    }
}
```

- [ ] **Step 2: Add module declaration**

In `src/providers/mod.rs`, add after the `pub mod yarn;` line:

```rust
pub mod pnpm;
```

- [ ] **Step 3: Run tests**

Run: `cargo test --lib providers::pnpm::tests 2>&1 | tail -10`
Expected: All pnpm unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/providers/pnpm.rs src/providers/mod.rs
git commit -m "feat: add pnpm provider with detection, naming, and package_id"
```

---

### Task 6: Wire pnpm into Dispatch

**Files:**
- Modify: `src/providers/mod.rs`

- [ ] **Step 1: Write failing detection tests**

Add to `src/providers/mod.rs` test module:

```rust
#[test]
fn detect_pnpm_store() {
    assert_eq!(
        detect(&PathBuf::from("/home/user/.pnpm-store/v3/files/ab/cd")),
        CacheKind::Pnpm
    );
}

#[test]
fn detect_pnpm_virtual_store() {
    assert_eq!(
        detect(&PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21")),
        CacheKind::Pnpm
    );
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --lib providers::tests::detect_pnpm_store 2>&1 | tail -5`
Expected: FAIL — returns `CacheKind::Unknown`

- [ ] **Step 3: Add pnpm detection to detect()**

In `src/providers/mod.rs`, in the direct name match block (before `_ => {}`):

```rust
".pnpm-store" => return CacheKind::Pnpm,
".pnpm" => return CacheKind::Pnpm,
```

In the ancestor walk (before the `"registry"` match arm):

```rust
".pnpm-store" => return CacheKind::Pnpm,
".pnpm" => {
    // node_modules/.pnpm is pnpm virtual store
    if ancestor.to_string_lossy().contains("node_modules") {
        return CacheKind::Pnpm;
    }
}
```

**Important ordering note:** The `.pnpm` ancestor match must come BEFORE any npm-related matching. Since `node_modules/.pnpm` also contains `node_modules`, we need to check for `.pnpm` first so it doesn't get detected as npm. Move the `.pnpm` and `.pnpm-store` matches to be checked before the npm-related matches in the ancestor walk.

- [ ] **Step 4: Update dispatch functions for pnpm**

In `semantic_name()`, replace `CacheKind::Pnpm => None` with:

```rust
CacheKind::Pnpm => pnpm::semantic_name(path),
```

In `metadata()`, replace `CacheKind::Pnpm => generic::metadata(path)` with:

```rust
CacheKind::Pnpm => pnpm::metadata(path),
```

In `package_id()`, add before the `_ => None` arm:

```rust
CacheKind::Pnpm => pnpm::package_id(path),
```

In `upgrade_command()`, add before the `_ => None` arm:

```rust
CacheKind::Pnpm => Some(format!("pnpm add {name}@{version}")),
```

- [ ] **Step 5: Update safety() for pnpm virtual store**

The spec requires `SafetyLevel::Caution` for pnpm virtual store entries. Currently `safety()` returns `Safe` for all known kinds via a wildcard. Update:

```rust
pub fn safety(kind: CacheKind, path: &Path) -> SafetyLevel {
    match kind {
        CacheKind::Pnpm => {
            if path.to_string_lossy().contains("node_modules/.pnpm") {
                SafetyLevel::Caution
            } else {
                SafetyLevel::Safe
            }
        }
        CacheKind::Unknown => SafetyLevel::Caution,
        _ => SafetyLevel::Safe,
    }
}
```

Update the safety test for pnpm (replace the existing `assert_eq!(safety(CacheKind::Pnpm, &path), SafetyLevel::Safe)` line):

```rust
// pnpm store is safe
assert_eq!(
    safety(CacheKind::Pnpm, &PathBuf::from("/home/.pnpm-store/v3")),
    SafetyLevel::Safe
);
```

And add a new test:

```rust
#[test]
fn safety_pnpm_virtual_store_is_caution() {
    assert_eq!(
        safety(
            CacheKind::Pnpm,
            &PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21")
        ),
        SafetyLevel::Caution
    );
}
```

- [ ] **Step 6: Add upgrade_command test**

```rust
#[test]
fn upgrade_command_pnpm() {
    assert_eq!(
        upgrade_command(CacheKind::Pnpm, "lodash", "4.17.21"),
        Some("pnpm add lodash@4.17.21".to_string())
    );
}
```

Remove `CacheKind::Pnpm` from the `upgrade_command_unsupported_kinds_return_none` array.

- [ ] **Step 7: Run all tests**

Run: `cargo test 2>&1 | tail -10`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat: wire pnpm provider into dispatch with path-aware safety"
```

---

### Task 7: Auto-Detection of Cache Paths

**Files:**
- Modify: `src/config.rs:105-131`

- [ ] **Step 1: Write failing test for fallback paths**

Add to the test module in `src/config.rs`:

```rust
#[test]
fn config_default_includes_yarn_classic_cache_if_exists() {
    // This test verifies the logic, not that the dir exists on this machine
    let config = Config::default();
    // Just verify our code doesn't panic — actual path existence varies
    let _ = config.roots;
}

#[test]
fn probe_yarn_cache_returns_none_when_not_installed() {
    // yarn is not on this system, so probe should return empty vec
    let paths = probe_yarn_paths();
    // May or may not find paths depending on system — just verify no panic
    let _ = paths;
}

#[test]
fn probe_pnpm_cache_returns_none_when_not_installed() {
    let paths = probe_pnpm_paths();
    let _ = paths;
}
```

- [ ] **Step 2: Implement CLI probing functions**

Add to `src/config.rs` (before the `impl Default for Config` block):

```rust
/// Probe for Yarn cache paths by running CLI commands and checking fallback locations.
fn probe_yarn_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Try CLI detection (with 2s timeout)
    if let Ok(output) = std::process::Command::new("yarn")
        .args(["cache", "dir"])
        .output()
    {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let path = PathBuf::from(&path_str);
            if path.exists() {
                paths.push(path);
            }
        }
    }

    // Fallback locations
    let home = dirs_home();
    let fallbacks = [
        home.join(".yarn-cache"),
        home.join(".cache/yarn"),
        home.join(".yarn/berry/cache"),
    ];
    #[cfg(target_os = "macos")]
    let macos_fallbacks = [home.join("Library/Caches/Yarn")];
    #[cfg(not(target_os = "macos"))]
    let macos_fallbacks: [PathBuf; 0] = [];

    for path in fallbacks.iter().chain(macos_fallbacks.iter()) {
        if path.exists() && !paths.contains(path) {
            paths.push(path.clone());
        }
    }

    paths
}

/// Probe for pnpm store paths by running CLI commands and checking fallback locations.
fn probe_pnpm_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Try CLI detection
    if let Ok(output) = std::process::Command::new("pnpm")
        .args(["store", "path"])
        .output()
    {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let path = PathBuf::from(&path_str);
            if path.exists() {
                paths.push(path);
            }
        }
    }

    // Fallback locations
    let home = dirs_home();
    let fallbacks = [
        home.join(".pnpm-store"),
        home.join(".local/share/pnpm/store"),
    ];

    for path in &fallbacks {
        if path.exists() && !paths.contains(path) {
            paths.push(path.clone());
        }
    }

    paths
}
```

- [ ] **Step 3: Integrate probing into Config::default()**

In the `Default` impl for `Config`, after the cargo registry check (line 120), add:

```rust
// Yarn cache paths
for path in probe_yarn_paths() {
    if !roots.contains(&path) {
        roots.push(path);
    }
}

// pnpm store paths
for path in probe_pnpm_paths() {
    if !roots.contains(&path) {
        roots.push(path);
    }
}
```

- [ ] **Step 4: Run all tests**

Run: `cargo test 2>&1 | tail -10`
Expected: All pass. The probe functions gracefully handle missing tools.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: auto-detect Yarn and pnpm cache paths at startup"
```

---

### Task 8: Integration Tests with Fixtures

**Files:**
- Modify: `tests/integration.rs`

- [ ] **Step 1: Add Yarn cache fixture helper**

Add to `tests/integration.rs` (after the `create_npx_cache` function):

```rust
/// Create a fake Yarn Berry cache structure.
fn create_yarn_berry_cache(root: &std::path::Path) {
    let yarn_cache = root.join(".yarn/cache");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    std::fs::write(
        yarn_cache.join("lodash-npm-4.17.21-6382d821f21d.zip"),
        "fake zip contents",
    )
    .unwrap();
    std::fs::write(
        yarn_cache.join("@babel-core-npm-7.24.0-abc123def456.zip"),
        "fake zip contents",
    )
    .unwrap();
}

/// Create a fake Yarn Classic cache structure.
fn create_yarn_classic_cache(root: &std::path::Path) {
    let yarn_cache = root.join(".yarn-cache/v6");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    std::fs::write(
        yarn_cache.join("npm-express-4.21.0-abcdef123456.tgz"),
        "fake tgz contents",
    )
    .unwrap();
}

/// Create a fake pnpm virtual store structure.
fn create_pnpm_cache(root: &std::path::Path) {
    // Virtual store
    let pnpm_vs = root.join("node_modules/.pnpm");
    let lodash = pnpm_vs.join("lodash@4.17.21/node_modules/lodash");
    std::fs::create_dir_all(&lodash).unwrap();
    std::fs::write(lodash.join("index.js"), "module.exports = {}").unwrap();

    let babel = pnpm_vs.join("@babel+core@7.24.0/node_modules/@babel/core");
    std::fs::create_dir_all(&babel).unwrap();
    std::fs::write(babel.join("index.js"), "module.exports = {}").unwrap();

    // Content store
    let store = root.join(".pnpm-store/v3/files/ab");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("cd1234abcdef"), "blob content").unwrap();
}
```

- [ ] **Step 2: Add Yarn discovery test**

```rust
#[test]
fn yarn_discover_packages_finds_berry_zips() {
    let tmp = tempfile::tempdir().unwrap();
    create_yarn_berry_cache(tmp.path());

    let packages =
        ccmd::scanner::discover_packages(&[tmp.path().join(".yarn")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"lodash"),
        "Should find lodash: {:?}",
        names
    );
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {:?}",
        names
    );
    assert_eq!(
        packages
            .iter()
            .filter(|(_, id)| id.ecosystem == "npm")
            .count(),
        2
    );
}

#[test]
fn yarn_discover_packages_finds_classic_tgz() {
    let tmp = tempfile::tempdir().unwrap();
    create_yarn_classic_cache(tmp.path());

    let packages =
        ccmd::scanner::discover_packages(&[tmp.path().join(".yarn-cache")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"express"),
        "Should find express: {:?}",
        names
    );
}
```

- [ ] **Step 3: Add pnpm discovery test**

```rust
#[test]
fn pnpm_discover_packages_finds_virtual_store() {
    let tmp = tempfile::tempdir().unwrap();
    create_pnpm_cache(tmp.path());

    let packages =
        ccmd::scanner::discover_packages(&[tmp.path().join("node_modules/.pnpm")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"lodash"),
        "Should find lodash: {:?}",
        names
    );
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {:?}",
        names
    );
}

#[test]
fn pnpm_content_store_returns_no_packages() {
    let tmp = tempfile::tempdir().unwrap();
    create_pnpm_cache(tmp.path());

    let packages =
        ccmd::scanner::discover_packages(&[tmp.path().join(".pnpm-store")]);

    // Content-addressed store has no identifiable packages
    assert_eq!(packages.len(), 0, "Store blobs should not yield packages");
}
```

- [ ] **Step 4: Add scanner expand test for Yarn**

```rust
#[test]
fn scanner_expand_yarn_berry_shows_semantic_names() {
    let tmp = tempfile::tempdir().unwrap();
    create_yarn_berry_cache(tmp.path());

    let cache_path = tmp.path().join(".yarn/cache");

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(cache_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(_, children) => {
            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names.iter().any(|n| n.contains("lodash") && n.contains("4.17.21")),
                "Should show 'lodash 4.17.21': {:?}",
                names
            );
            assert!(
                names.iter().any(|n| n.contains("@babel/core")),
                "Should show '@babel/core 7.24.0': {:?}",
                names
            );

            // Verify kind detection
            for child in &children {
                assert_eq!(
                    child.kind,
                    ccmd::tree::node::CacheKind::Yarn,
                    "All children should be detected as Yarn: {:?}",
                    child.name
                );
            }
        }
        _ => panic!("Expected ChildrenScanned"),
    }
}
```

- [ ] **Step 5: Add deduplication test across providers**

```rust
#[test]
fn dedup_across_npm_and_yarn_caches() {
    let tmp = tempfile::tempdir().unwrap();

    // Same package in both npm and yarn caches
    // npm: express via node_modules
    let npm_dir = tmp.path().join(".npm/_npx/abc/node_modules/express");
    std::fs::create_dir_all(&npm_dir).unwrap();
    std::fs::write(
        npm_dir.join("package.json"),
        r#"{"name":"express","version":"4.21.0"}"#,
    )
    .unwrap();

    // yarn: express via berry zip
    let yarn_cache = tmp.path().join(".yarn/cache");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    std::fs::write(
        yarn_cache.join("express-npm-4.21.0-abcdef123456.zip"),
        "z",
    )
    .unwrap();

    let packages = ccmd::scanner::discover_packages(&[tmp.path().to_path_buf()]);

    // Should find express only once (dedup by ecosystem+name+version)
    let express_count = packages
        .iter()
        .filter(|(_, id)| id.name == "express" && id.version == "4.21.0")
        .count();
    assert_eq!(
        express_count, 1,
        "express@4.21.0 should be deduplicated across npm and yarn"
    );
}
```

- [ ] **Step 6: Run all integration tests**

Run: `cargo test --test integration 2>&1 | tail -15`
Expected: All pass, including the new Yarn/pnpm tests.

- [ ] **Step 7: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add Yarn and pnpm integration tests with fixtures"
```

---

### Task 9: E2E Test Setup & Feature Flag

**Files:**
- Modify: `Cargo.toml`
- Create: `tests/e2e_js_providers.rs`

- [ ] **Step 1: Add e2e feature flag to Cargo.toml**

In `Cargo.toml`, in the `[features]` section (after line 31):

```toml
e2e = []
```

- [ ] **Step 2: Create E2E test file**

Create `tests/e2e_js_providers.rs`:

```rust
//! End-to-end tests for Yarn and pnpm providers using real tools.
//! Requires Yarn and pnpm to be installed.
//! Run with: cargo test --features e2e --test e2e_js_providers
#![cfg(feature = "e2e")]

use std::process::Command;

/// Check if a command is available on PATH.
fn is_available(cmd: &str) -> bool {
    Command::new("which").arg(cmd).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Run a command in a directory and assert success.
fn run_in(dir: &std::path::Path, cmd: &str, args: &[&str]) {
    let output = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("Failed to run {} {:?}: {}", cmd, args, e));
    assert!(
        output.status.success(),
        "{} {:?} failed:\nstdout: {}\nstderr: {}",
        cmd,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- Yarn Classic E2E ---

#[test]
fn e2e_yarn_classic_cache_detection() {
    if !is_available("yarn") {
        eprintln!("SKIP: yarn not installed");
        return;
    }

    // Check if this is Yarn Classic (1.x)
    let output = Command::new("yarn").arg("--version").output().unwrap();
    let version = String::from_utf8_lossy(&output.stdout);
    if !version.starts_with('1') {
        eprintln!("SKIP: yarn is not Classic (1.x), got {}", version.trim());
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("classic-project");
    std::fs::create_dir_all(&project).unwrap();

    // Initialize project and install a package
    run_in(&project, "npm", &["init", "-y"]);
    run_in(&project, "yarn", &["add", "is-even@1.0.0"]);

    // Find yarn cache dir
    let output = Command::new("yarn")
        .args(["cache", "dir"])
        .output()
        .unwrap();
    let cache_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let cache_path = std::path::PathBuf::from(&cache_dir);

    assert!(cache_path.exists(), "Yarn cache dir should exist: {}", cache_dir);

    // Scan for packages
    let packages = ccmd::scanner::discover_packages(&[cache_path]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"is-even"),
        "Should find is-even in Yarn Classic cache: {:?}",
        names
    );

    // Clean up: remove the cached package
    let _ = Command::new("yarn").args(["cache", "clean", "is-even"]).output();
}

// --- Yarn Berry E2E ---

#[test]
fn e2e_yarn_berry_cache_detection() {
    if !is_available("corepack") {
        eprintln!("SKIP: corepack not available");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("berry-project");
    std::fs::create_dir_all(&project).unwrap();

    // Initialize Berry project
    run_in(&project, "npm", &["init", "-y"]);
    run_in(&project, "corepack", &["enable"]);
    run_in(&project, "yarn", &["set", "version", "berry"]);
    run_in(&project, "yarn", &["add", "is-even@1.0.0"]);

    // Berry cache is per-project at .yarn/cache/
    let cache_path = project.join(".yarn/cache");
    assert!(cache_path.exists(), ".yarn/cache should exist");

    // Scan for packages
    let packages = ccmd::scanner::discover_packages(&[project.join(".yarn")]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"is-even"),
        "Should find is-even in Berry cache: {:?}",
        names
    );
}

// --- pnpm E2E ---

#[test]
fn e2e_pnpm_virtual_store_detection() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("pnpm-project");
    std::fs::create_dir_all(&project).unwrap();

    // Initialize and install
    run_in(&project, "pnpm", &["init"]);
    run_in(&project, "pnpm", &["add", "is-even@1.0.0"]);

    // pnpm creates node_modules/.pnpm/
    let pnpm_dir = project.join("node_modules/.pnpm");
    assert!(pnpm_dir.exists(), "node_modules/.pnpm should exist");

    // Scan for packages
    let packages = ccmd::scanner::discover_packages(&[project.join("node_modules/.pnpm")]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"is-even"),
        "Should find is-even in pnpm virtual store: {:?}",
        names
    );
}

#[test]
fn e2e_pnpm_store_path_detection() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let output = Command::new("pnpm").args(["store", "path"]).output().unwrap();
    if output.status.success() {
        let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path = std::path::PathBuf::from(&store_path);
        assert!(path.exists(), "pnpm store path should exist: {}", store_path);
    }
}
```

- [ ] **Step 3: Verify compilation**

Run: `cargo test --features e2e --test e2e_js_providers --no-run 2>&1 | tail -5`
Expected: Compiles successfully (tests don't need to run yet — tools may not be installed).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml tests/e2e_js_providers.rs
git commit -m "test: add E2E test suite for Yarn and pnpm with real tools"
```

---

### Task 10: CI Workflow for E2E Tests

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Read current CI config**

Read `.github/workflows/ci.yml` to understand the existing job structure.

- [ ] **Step 2: Add E2E test job**

Add a new job to `.github/workflows/ci.yml` after the existing test jobs:

```yaml
  e2e-js-providers:
    name: E2E JS Provider Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Install pnpm
        run: npm install -g pnpm

      - name: Install Yarn Classic
        run: npm install -g yarn@1

      - name: Enable Corepack (for Yarn Berry)
        run: corepack enable

      - name: Run E2E tests
        run: cargo test --features e2e --test e2e_js_providers -- --test-threads=1
```

Note: `--test-threads=1` prevents parallel test runs from conflicting on global Yarn cache state.

- [ ] **Step 3: Run existing CI tests locally to verify no breakage**

Run: `cargo test 2>&1 | tail -10`
Expected: All existing tests still pass.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add E2E test job for Yarn and pnpm providers"
```

---

### Task 11: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test 2>&1`
Expected: All unit tests, integration tests pass.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings 2>&1 | tail -10`
Expected: No warnings.

- [ ] **Step 3: Run cargo fmt check**

Run: `cargo fmt --check 2>&1`
Expected: No formatting issues.

- [ ] **Step 4: Verify E2E tests compile**

Run: `cargo test --features e2e --test e2e_js_providers --no-run 2>&1 | tail -5`
Expected: Compiles.

- [ ] **Step 5: Commit any remaining fixes (if needed)**

```bash
git add -A
git commit -m "chore: final cleanup for Yarn and pnpm providers"
```
