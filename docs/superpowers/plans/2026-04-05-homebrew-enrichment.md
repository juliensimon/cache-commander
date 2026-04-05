# Homebrew Cache Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Homebrew provider to parity with npm/pip/cargo by parsing bottle names, extracting manifest metadata, and running `brew audit` in the background.

**Architecture:** The work lives primarily in `src/providers/homebrew.rs` (parsing logic), with integration points in `src/scanner/mod.rs` (new `BrewAudit` pipeline variant), `src/app.rs` (state + triggering), and `src/ui/detail_panel.rs` (rendering). All parsing is pure functions for testability. TDD throughout — tests first, then implementation.

**Tech Stack:** Rust, ratatui, std::process::Command, hand-rolled JSON extraction (no new deps)

**Spec:** `docs/superpowers/specs/2026-04-05-homebrew-enrichment-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `src/providers/homebrew.rs` | `semantic_name()`, `metadata()`, `parse_bottle_name()`, `parse_manifest_name()`, `extract_manifest_metadata()`, `parse_brew_audit()` |
| `src/scanner/mod.rs` | `ScanRequest::BrewAudit`, `ScanResult::BrewAuditCompleted`, background thread |
| `src/app.rs` | `brew_audit_results` field, trigger on startup, handle result |
| `src/ui/detail_panel.rs` | Render brew audit warnings in detail panel |

---

### Task 1: Create feature branch

- [ ] **Step 1: Create and switch to feature branch**

```bash
git checkout -b feat/homebrew-enrichment
```

- [ ] **Step 2: Verify branch**

Run: `git branch --show-current`
Expected: `feat/homebrew-enrichment`

---

### Task 2: Semantic name parsing — bottle symlinks

**Files:**
- Modify: `src/providers/homebrew.rs`
- Test: `src/providers/homebrew.rs` (inline `#[cfg(test)]` module)

- [ ] **Step 1: Write failing tests for bottle name parsing**

Add to `src/providers/homebrew.rs` at the bottom, replacing the empty test module or adding one:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- parse_bottle_name ---

    #[test]
    fn parse_bottle_simple() {
        assert_eq!(
            parse_bottle_name("awscli--2.34.24"),
            Some(("awscli".to_string(), "2.34.24".to_string()))
        );
    }

    #[test]
    fn parse_bottle_hyphenated_name() {
        assert_eq!(
            parse_bottle_name("json-c--0.18"),
            Some(("json-c".to_string(), "0.18".to_string()))
        );
    }

    #[test]
    fn parse_bottle_version_with_revision() {
        assert_eq!(
            parse_bottle_name("git--2.53.0_1"),
            Some(("git".to_string(), "2.53.0_1".to_string()))
        );
    }

    #[test]
    fn parse_bottle_single_char_version() {
        // Edge: very short version
        assert_eq!(
            parse_bottle_name("xz--5"),
            Some(("xz".to_string(), "5".to_string()))
        );
    }

    #[test]
    fn parse_bottle_no_double_dash() {
        assert_eq!(parse_bottle_name("downloads"), None);
    }

    #[test]
    fn parse_bottle_empty() {
        assert_eq!(parse_bottle_name(""), None);
    }

    #[test]
    fn parse_bottle_only_double_dash() {
        assert_eq!(parse_bottle_name("--"), None);
    }

    #[test]
    fn parse_bottle_no_version_after_dash() {
        assert_eq!(parse_bottle_name("awscli--"), None);
    }

    #[test]
    fn parse_bottle_no_name_before_dash() {
        assert_eq!(parse_bottle_name("--2.34.24"), None);
    }

    // --- semantic_name with bottle patterns ---

    #[test]
    fn semantic_name_bottle_symlink() {
        let path = PathBuf::from("/Library/Caches/Homebrew/awscli--2.34.24");
        assert_eq!(
            semantic_name(&path),
            Some("[bottle] awscli 2.34.24".to_string())
        );
    }

    #[test]
    fn semantic_name_bottle_hyphenated() {
        let path = PathBuf::from("/Library/Caches/Homebrew/json-c--0.18");
        assert_eq!(
            semantic_name(&path),
            Some("[bottle] json-c 0.18".to_string())
        );
    }

    #[test]
    fn semantic_name_existing_downloads() {
        let path = PathBuf::from("/Library/Caches/Homebrew/downloads");
        assert_eq!(
            semantic_name(&path),
            Some("Downloaded Bottles".to_string())
        );
    }

    #[test]
    fn semantic_name_existing_cask_dir() {
        let path = PathBuf::from("/Library/Caches/Homebrew/Cask");
        assert_eq!(
            semantic_name(&path),
            Some("Cask Downloads".to_string())
        );
    }

    #[test]
    fn semantic_name_existing_api() {
        let path = PathBuf::from("/Library/Caches/Homebrew/api");
        assert_eq!(
            semantic_name(&path),
            Some("API Cache".to_string())
        );
    }

    #[test]
    fn semantic_name_unknown() {
        let path = PathBuf::from("/Library/Caches/Homebrew/.cleaned");
        assert_eq!(semantic_name(&path), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib providers::homebrew::tests -- --nocapture 2>&1 | head -40`
Expected: compilation errors — `parse_bottle_name` not found

- [ ] **Step 3: Implement `parse_bottle_name` and update `semantic_name`**

Replace the contents of `src/providers/homebrew.rs` above the `#[cfg(test)]` module:

```rust
use super::MetadataField;
use std::path::Path;

/// Parse a Homebrew bottle symlink name like "awscli--2.34.24" into (name, version).
/// Returns None if the name doesn't match the bottle pattern.
pub fn parse_bottle_name(s: &str) -> Option<(String, String)> {
    let (name, version) = s.split_once("--")?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Parse a manifest symlink name like "awscli_bottle_manifest--2.34.24" into (name, version).
/// Returns None if the name doesn't match the manifest pattern.
pub fn parse_manifest_name(s: &str) -> Option<(String, String)> {
    let (prefix, version) = s.split_once("--")?;
    let name = prefix.strip_suffix("_bottle_manifest")?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Existing directory labels
    match name.as_str() {
        "downloads" => return Some("Downloaded Bottles".to_string()),
        "Cask" => return Some("Cask Downloads".to_string()),
        "api" => return Some("API Cache".to_string()),
        "bootsnap" => return Some("Bootsnap Cache".to_string()),
        _ => {}
    }

    // Manifest symlinks: "name_bottle_manifest--version"
    if let Some((pkg, ver)) = parse_manifest_name(&name) {
        return Some(format!("[manifest] {pkg} {ver}"));
    }

    // Bottle symlinks: "name--version"
    if let Some((pkg, ver)) = parse_bottle_name(&name) {
        return Some(format!("[bottle] {pkg} {ver}"));
    }

    None
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match name.as_str() {
        "downloads" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded package bottles (.tar.gz)".to_string(),
            });
            if let Ok(entries) = std::fs::read_dir(path) {
                let count = entries.filter_map(|e| e.ok()).count();
                fields.push(MetadataField {
                    label: "Bottles".to_string(),
                    value: count.to_string(),
                });
            }
        }
        "Cask" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded cask installers".to_string(),
            });
        }
        "api" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Homebrew formula/cask API cache".to_string(),
            });
        }
        _ => {}
    }

    fields
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib providers::homebrew::tests -- --nocapture`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/providers/homebrew.rs
git commit -m "feat(homebrew): add bottle symlink name parsing with TDD"
```

---

### Task 3: Semantic name parsing — manifest symlinks

**Files:**
- Modify: `src/providers/homebrew.rs`

- [ ] **Step 1: Write failing tests for manifest name parsing**

Add these tests to the existing `tests` module in `src/providers/homebrew.rs`:

```rust
    // --- parse_manifest_name ---

    #[test]
    fn parse_manifest_simple() {
        assert_eq!(
            parse_manifest_name("awscli_bottle_manifest--2.34.24"),
            Some(("awscli".to_string(), "2.34.24".to_string()))
        );
    }

    #[test]
    fn parse_manifest_hyphenated_name() {
        assert_eq!(
            parse_manifest_name("json-c_bottle_manifest--0.18"),
            Some(("json-c".to_string(), "0.18".to_string()))
        );
    }

    #[test]
    fn parse_manifest_version_with_revision() {
        assert_eq!(
            parse_manifest_name("git_bottle_manifest--2.53.0_1"),
            Some(("git".to_string(), "2.53.0_1".to_string()))
        );
    }

    #[test]
    fn parse_manifest_not_a_manifest() {
        assert_eq!(parse_manifest_name("awscli--2.34.24"), None);
    }

    #[test]
    fn parse_manifest_empty() {
        assert_eq!(parse_manifest_name(""), None);
    }

    #[test]
    fn parse_manifest_no_version() {
        assert_eq!(parse_manifest_name("awscli_bottle_manifest--"), None);
    }

    // --- semantic_name with manifest patterns ---

    #[test]
    fn semantic_name_manifest_symlink() {
        let path = PathBuf::from("/Library/Caches/Homebrew/awscli_bottle_manifest--2.34.24");
        assert_eq!(
            semantic_name(&path),
            Some("[manifest] awscli 2.34.24".to_string())
        );
    }

    #[test]
    fn semantic_name_manifest_hyphenated() {
        let path = PathBuf::from("/Library/Caches/Homebrew/svt-av1_bottle_manifest--4.1.0");
        assert_eq!(
            semantic_name(&path),
            Some("[manifest] svt-av1 4.1.0".to_string())
        );
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test --lib providers::homebrew::tests -- --nocapture`
Expected: all pass — `parse_manifest_name` was already implemented in Task 2 Step 3

- [ ] **Step 3: Commit**

```bash
git add src/providers/homebrew.rs
git commit -m "test(homebrew): add manifest symlink parsing tests"
```

---

### Task 4: Manifest metadata extraction — pure parsing

**Files:**
- Modify: `src/providers/homebrew.rs`

- [ ] **Step 1: Write failing tests for manifest metadata extraction**

Add these tests to the `tests` module in `src/providers/homebrew.rs`:

```rust
    // --- extract_manifest_metadata ---

    fn sample_manifest() -> &'static str {
        r#"{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:abc123",
      "size": 5581,
      "platform": {
        "architecture": "arm64",
        "os": "macOS",
        "os.version": "macOS 15"
      },
      "annotations": {
        "org.opencontainers.image.ref.name": "2.34.24.arm64_tahoe",
        "sh.brew.bottle.size": "23222962",
        "sh.brew.bottle.installed_size": "162136325",
        "sh.brew.license": "Apache-2.0",
        "sh.brew.tab": "{\"runtime_dependencies\":[{\"full_name\":\"openssl@3\",\"version\":\"3.6.1\",\"declared_directly\":true},{\"full_name\":\"python@3.14\",\"version\":\"3.14.3\",\"declared_directly\":true},{\"full_name\":\"ncurses\",\"version\":\"6.6\",\"declared_directly\":false}]}"
      }
    }
  ]
}"#
    }

    #[test]
    fn extract_metadata_license() {
        let fields = extract_manifest_metadata(sample_manifest());
        let license = fields.iter().find(|f| f.label == "License");
        assert!(license.is_some());
        assert_eq!(license.unwrap().value, "Apache-2.0");
    }

    #[test]
    fn extract_metadata_installed_size() {
        let fields = extract_manifest_metadata(sample_manifest());
        let size = fields.iter().find(|f| f.label == "Installed");
        assert!(size.is_some());
        assert_eq!(size.unwrap().value, "154.6 MiB");
    }

    #[test]
    fn extract_metadata_architecture() {
        let fields = extract_manifest_metadata(sample_manifest());
        let arch = fields.iter().find(|f| f.label == "Arch");
        assert!(arch.is_some());
        assert_eq!(arch.unwrap().value, "arm64 macOS");
    }

    #[test]
    fn extract_metadata_deps_count() {
        let fields = extract_manifest_metadata(sample_manifest());
        let deps = fields.iter().find(|f| f.label == "Deps");
        assert!(deps.is_some());
        // 3 total, 2 direct
        assert_eq!(deps.unwrap().value, "3 (2 direct)");
    }

    #[test]
    fn extract_metadata_empty_json() {
        let fields = extract_manifest_metadata("");
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_metadata_malformed_json() {
        let fields = extract_manifest_metadata("{not valid json at all");
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_metadata_no_manifests_key() {
        let fields = extract_manifest_metadata(r#"{"schemaVersion": 2}"#);
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_metadata_no_annotations() {
        let fields = extract_manifest_metadata(r#"{
  "manifests": [{"platform": {"architecture": "arm64", "os": "macOS"}}]
}"#);
        // Should still extract architecture
        let arch = fields.iter().find(|f| f.label == "Arch");
        assert!(arch.is_some());
        assert_eq!(arch.unwrap().value, "arm64 macOS");
    }

    #[test]
    fn extract_metadata_no_tab() {
        let fields = extract_manifest_metadata(r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {"sh.brew.license": "MIT"}
  }]
}"#);
        let license = fields.iter().find(|f| f.label == "License");
        assert!(license.is_some());
        assert_eq!(license.unwrap().value, "MIT");
        // No deps field when tab is missing
        let deps = fields.iter().find(|f| f.label == "Deps");
        assert!(deps.is_none());
    }

    #[test]
    fn extract_metadata_empty_runtime_deps() {
        let fields = extract_manifest_metadata(r#"{
  "manifests": [{
    "platform": {"architecture": "x86_64", "os": "linux"},
    "annotations": {
      "sh.brew.license": "MIT",
      "sh.brew.tab": "{\"runtime_dependencies\":[]}"
    }
  }]
}"#);
        let deps = fields.iter().find(|f| f.label == "Deps");
        assert!(deps.is_some());
        assert_eq!(deps.unwrap().value, "0");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib providers::homebrew::tests -- --nocapture 2>&1 | head -10`
Expected: compilation error — `extract_manifest_metadata` not found

- [ ] **Step 3: Implement `extract_manifest_metadata`**

Add this function to `src/providers/homebrew.rs` (above the `metadata` function):

```rust
/// Extract metadata fields from a Homebrew bottle manifest JSON string.
/// This is a pure function for testability — takes the raw JSON content, returns metadata fields.
pub fn extract_manifest_metadata(json: &str) -> Vec<MetadataField> {
    let mut fields = Vec::new();

    // Find the first manifest entry
    let manifests_pos = match json.find("\"manifests\"") {
        Some(p) => p,
        None => return fields,
    };
    let rest = &json[manifests_pos..];

    // Extract architecture and OS from platform block
    if let Some(arch) = extract_json_string_field(rest, "architecture") {
        let os = extract_json_string_field(rest, "os").unwrap_or_default();
        // Skip os.version-style values (contain spaces like "Ubuntu 22.04")
        if !os.is_empty() {
            fields.push(MetadataField {
                label: "Arch".to_string(),
                value: format!("{arch} {os}"),
            });
        } else {
            fields.push(MetadataField {
                label: "Arch".to_string(),
                value: arch,
            });
        }
    }

    // Extract license from annotations
    if let Some(license) = extract_json_string_field(rest, "sh.brew.license") {
        fields.push(MetadataField {
            label: "License".to_string(),
            value: license,
        });
    }

    // Extract installed size
    if let Some(size_str) = extract_json_string_field(rest, "sh.brew.bottle.installed_size") {
        if let Ok(bytes) = size_str.parse::<u64>() {
            fields.push(MetadataField {
                label: "Installed".to_string(),
                value: format_bytes(bytes),
            });
        }
    }

    // Extract runtime dependencies from sh.brew.tab (embedded JSON string)
    if let Some(tab_str) = extract_json_string_field(rest, "sh.brew.tab") {
        // tab_str is an escaped JSON string — unescape it
        let tab = tab_str.replace("\\\"", "\"").replace("\\\\", "\\");
        if let Some(deps_info) = parse_runtime_deps(&tab) {
            fields.push(MetadataField {
                label: "Deps".to_string(),
                value: deps_info,
            });
        }
    }

    fields
}

/// Extract a JSON string value for a given key using simple string matching.
/// Looks for "key": "value" patterns.
fn extract_json_string_field(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let pos = json.find(&pattern)?;
    let after_key = &json[pos + pattern.len()..];
    // Skip whitespace and colon
    let after_colon = after_key.find(':').map(|p| &after_key[p + 1..])?;
    let trimmed = after_colon.trim_start();
    if trimmed.starts_with('"') {
        // Find the closing quote (handling escaped quotes)
        let content = &trimmed[1..];
        let mut end = 0;
        let bytes = content.as_bytes();
        while end < bytes.len() {
            if bytes[end] == b'"' && (end == 0 || bytes[end - 1] != b'\\') {
                break;
            }
            end += 1;
        }
        if end < bytes.len() {
            return Some(content[..end].to_string());
        }
    }
    None
}

/// Parse runtime_dependencies from the brew tab JSON to produce a summary string.
fn parse_runtime_deps(tab_json: &str) -> Option<String> {
    let deps_pos = tab_json.find("\"runtime_dependencies\"")?;
    let rest = &tab_json[deps_pos..];
    let arr_start = rest.find('[')?;
    let arr_end = rest.find(']')?;
    if arr_end <= arr_start {
        return None;
    }
    let arr_content = &rest[arr_start + 1..arr_end];

    if arr_content.trim().is_empty() {
        return Some("0".to_string());
    }

    // Count total deps by counting "full_name" occurrences
    let total = arr_content.matches("\"full_name\"").count();
    // Count direct deps
    let direct = arr_content.matches("\"declared_directly\":true").count();

    if total == 0 {
        return Some("0".to_string());
    }
    if direct > 0 && direct < total {
        Some(format!("{total} ({direct} direct)"))
    } else if direct == total {
        Some(format!("{total}"))
    } else {
        Some(format!("{total}"))
    }
}

/// Format bytes as human-readable size (matching humansize BINARY style).
fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib providers::homebrew::tests -- --nocapture`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/providers/homebrew.rs
git commit -m "feat(homebrew): extract metadata from bottle manifests with TDD"
```

---

### Task 5: Wire manifest metadata into `metadata()` function

**Files:**
- Modify: `src/providers/homebrew.rs`

- [ ] **Step 1: Write failing tests for metadata reading manifest from filesystem**

Add these tests to the `tests` module in `src/providers/homebrew.rs`:

```rust
    // --- metadata with manifest files on disk ---

    #[test]
    fn metadata_bottle_reads_companion_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        // Create a bottle symlink (just a file for testing)
        let bottle = tmp.path().join("awscli--2.34.24");
        std::fs::write(&bottle, "fake bottle").unwrap();
        // Create companion manifest
        let manifest = tmp.path().join("awscli_bottle_manifest--2.34.24");
        std::fs::write(&manifest, r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {
      "sh.brew.license": "Apache-2.0",
      "sh.brew.bottle.installed_size": "162136325",
      "sh.brew.tab": "{\"runtime_dependencies\":[{\"full_name\":\"openssl@3\",\"version\":\"3.6.1\",\"declared_directly\":true}]}"
    }
  }]
}"#).unwrap();

        let fields = metadata(&bottle);
        let license = fields.iter().find(|f| f.label == "License");
        assert!(license.is_some(), "Expected License field, got: {:?}", fields);
        assert_eq!(license.unwrap().value, "Apache-2.0");
    }

    #[test]
    fn metadata_bottle_no_companion_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let bottle = tmp.path().join("awscli--2.34.24");
        std::fs::write(&bottle, "fake bottle").unwrap();
        // No manifest file
        let fields = metadata(&bottle);
        // Should return empty — no static match, no manifest found
        assert!(fields.is_empty(), "Expected empty, got: {:?}", fields);
    }

    #[test]
    fn metadata_manifest_reads_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("awscli_bottle_manifest--2.34.24");
        std::fs::write(&manifest, r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {"sh.brew.license": "MIT"}
  }]
}"#).unwrap();

        let fields = metadata(&manifest);
        let license = fields.iter().find(|f| f.label == "License");
        assert!(license.is_some());
        assert_eq!(license.unwrap().value, "MIT");
    }

    #[test]
    fn metadata_downloads_dir_counts_files() {
        let tmp = tempfile::tempdir().unwrap();
        let downloads = tmp.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        std::fs::write(downloads.join("file1.tar.gz"), "x").unwrap();
        std::fs::write(downloads.join("file2.tar.gz"), "x").unwrap();
        std::fs::write(downloads.join("file3.json"), "x").unwrap();

        let fields = metadata(&downloads);
        let bottles = fields.iter().find(|f| f.label == "Bottles");
        assert!(bottles.is_some());
        assert_eq!(bottles.unwrap().value, "3");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib providers::homebrew::tests::metadata_bottle_reads_companion_manifest -- --nocapture 2>&1`
Expected: FAIL — metadata returns empty for bottle entries (no manifest lookup yet)

- [ ] **Step 3: Update `metadata()` to read manifest files**

Replace the `metadata` function in `src/providers/homebrew.rs`:

```rust
pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match name.as_str() {
        "downloads" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded package bottles (.tar.gz)".to_string(),
            });
            if let Ok(entries) = std::fs::read_dir(path) {
                let count = entries.filter_map(|e| e.ok()).count();
                fields.push(MetadataField {
                    label: "Bottles".to_string(),
                    value: count.to_string(),
                });
            }
        }
        "Cask" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded cask installers".to_string(),
            });
        }
        "api" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Homebrew formula/cask API cache".to_string(),
            });
        }
        _ => {
            // Try to read manifest metadata
            if let Some(manifest_json) = read_manifest_for(path, &name) {
                fields.extend(extract_manifest_metadata(&manifest_json));
            }
        }
    }

    fields
}

/// Read the manifest JSON content for a given Homebrew cache entry.
/// For bottle entries, finds the companion manifest file.
/// For manifest entries, reads the file itself.
fn read_manifest_for(path: &Path, name: &str) -> Option<String> {
    // If this IS a manifest file, read it directly
    if parse_manifest_name(name).is_some() {
        return std::fs::read_to_string(path).ok();
    }

    // If this is a bottle, find its companion manifest
    if let Some((pkg, ver)) = parse_bottle_name(name) {
        let parent = path.parent()?;
        let manifest_name = format!("{pkg}_bottle_manifest--{ver}");
        let manifest_path = parent.join(manifest_name);
        return std::fs::read_to_string(manifest_path).ok();
    }

    None
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib providers::homebrew::tests -- --nocapture`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/providers/homebrew.rs
git commit -m "feat(homebrew): wire manifest metadata into metadata() with TDD"
```

---

### Task 6: `brew audit` output parsing

**Files:**
- Modify: `src/providers/homebrew.rs`

- [ ] **Step 1: Write failing tests for `parse_brew_audit`**

Add these tests to the `tests` module in `src/providers/homebrew.rs`:

```rust
    // --- parse_brew_audit ---

    #[test]
    fn parse_brew_audit_single_formula_one_warning() {
        let output = "awscli:\n  * Python formula detected\n";
        let result = parse_brew_audit(output);
        assert_eq!(result.len(), 1);
        assert_eq!(result["awscli"], vec!["Python formula detected"]);
    }

    #[test]
    fn parse_brew_audit_single_formula_multiple_warnings() {
        let output = "node:\n  * Missing license\n  * Deprecated dependency\n";
        let result = parse_brew_audit(output);
        assert_eq!(result.len(), 1);
        assert_eq!(result["node"].len(), 2);
        assert_eq!(result["node"][0], "Missing license");
        assert_eq!(result["node"][1], "Deprecated dependency");
    }

    #[test]
    fn parse_brew_audit_multiple_formulae() {
        let output = "git:\n  * Audit warning 1\nnode:\n  * Audit warning 2\n";
        let result = parse_brew_audit(output);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("git"));
        assert!(result.contains_key("node"));
    }

    #[test]
    fn parse_brew_audit_empty_output() {
        let result = parse_brew_audit("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_brew_audit_whitespace_only() {
        let result = parse_brew_audit("  \n  \n");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_brew_audit_no_warnings_lines() {
        // Formula header but no * lines
        let result = parse_brew_audit("git:\n");
        assert!(result.is_empty(), "Formula with no warnings should not appear");
    }

    #[test]
    fn parse_brew_audit_mixed_noise() {
        // Some lines that don't match the pattern
        let output = "Some header text\ngit:\n  * Warning 1\nrandom noise\nnode:\n  * Warning 2\n";
        let result = parse_brew_audit(output);
        assert_eq!(result.len(), 2);
        assert_eq!(result["git"], vec!["Warning 1"]);
        assert_eq!(result["node"], vec!["Warning 2"]);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib providers::homebrew::tests::parse_brew_audit -- --nocapture 2>&1 | head -10`
Expected: compilation error — `parse_brew_audit` not found

- [ ] **Step 3: Implement `parse_brew_audit`**

Add this function to `src/providers/homebrew.rs`:

```rust
/// Parse the output of `brew audit --installed` into a map of formula name → warnings.
/// Output format:
///   formula_name:
///     * warning text
///     * another warning
pub fn parse_brew_audit(output: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut results = std::collections::HashMap::new();
    let mut current_formula: Option<String> = None;
    let mut current_warnings: Vec<String> = Vec::new();

    for line in output.lines() {
        if let Some(name) = line.strip_suffix(':') {
            // Flush previous formula
            if let Some(formula) = current_formula.take() {
                if !current_warnings.is_empty() {
                    results.insert(formula, std::mem::take(&mut current_warnings));
                }
            }
            let trimmed = name.trim();
            if !trimmed.is_empty() && !trimmed.contains(' ') {
                current_formula = Some(trimmed.to_string());
            }
        } else if let Some(warning) = line.trim().strip_prefix("* ") {
            if current_formula.is_some() {
                current_warnings.push(warning.to_string());
            }
        }
    }

    // Flush last formula
    if let Some(formula) = current_formula {
        if !current_warnings.is_empty() {
            results.insert(formula, current_warnings);
        }
    }

    results
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib providers::homebrew::tests::parse_brew_audit -- --nocapture`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/providers/homebrew.rs
git commit -m "feat(homebrew): add brew audit output parser with TDD"
```

---

### Task 7: Scanner pipeline — `BrewAudit` request/result

**Files:**
- Modify: `src/scanner/mod.rs`

- [ ] **Step 1: Add `BrewAudit` variants to `ScanRequest` and `ScanResult`**

In `src/scanner/mod.rs`, add to the `ScanRequest` enum:

```rust
pub enum ScanRequest {
    ScanRoots(Vec<PathBuf>),
    ExpandNode(PathBuf),
    /// Walk given paths to discover packages, then query OSV.dev
    ScanVulns(Vec<PathBuf>),
    /// Walk given paths to discover packages, then query registries
    CheckVersions(Vec<PathBuf>),
    /// Run `brew audit --installed` in the background
    BrewAudit,
}
```

Add to the `ScanResult` enum:

```rust
pub enum ScanResult {
    RootsScanned(Vec<TreeNode>),
    ChildrenScanned(PathBuf, Vec<TreeNode>),
    SizeUpdated(PathBuf, u64),
    /// (packages_scanned, results)
    VulnsScanned(
        usize,
        std::collections::HashMap<PathBuf, crate::security::SecurityInfo>,
    ),
    /// (packages_checked, results)
    VersionsChecked(
        usize,
        std::collections::HashMap<PathBuf, crate::security::VersionInfo>,
    ),
    /// formula name → list of audit warnings
    BrewAuditCompleted(std::collections::HashMap<String, Vec<String>>),
}
```

- [ ] **Step 2: Add the handler in the `start()` function's match block**

Add this arm inside the `match request` block in `start()`:

```rust
                ScanRequest::BrewAudit => {
                    let tx = result_tx.clone();
                    std::thread::spawn(move || {
                        let results = run_brew_audit();
                        let _ = tx.send(ScanResult::BrewAuditCompleted(results));
                    });
                }
```

- [ ] **Step 3: Add the `run_brew_audit` function**

Add this function to `src/scanner/mod.rs`:

```rust
/// Run `brew audit --installed` and parse the output.
/// Returns an empty map if brew is not found or the command fails.
fn run_brew_audit() -> std::collections::HashMap<String, Vec<String>> {
    let output = match std::process::Command::new("brew")
        .args(["audit", "--installed"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return std::collections::HashMap::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // brew audit outputs to both stdout and stderr depending on version
    let combined = format!("{stdout}{stderr}");
    crate::providers::homebrew::parse_brew_audit(&combined)
}
```

- [ ] **Step 4: Run build to verify compilation**

Run: `cargo build 2>&1 | tail -5`
Expected: compiles successfully (may have warnings about unused BrewAuditCompleted in app.rs — that's expected, we wire it in the next task)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/mod.rs
git commit -m "feat(scanner): add BrewAudit request/result pipeline"
```

---

### Task 8: App state — store and trigger brew audit

**Files:**
- Modify: `src/app.rs`

- [ ] **Step 1: Add brew audit state to `App` struct**

In `src/app.rs`, add these fields to the `App` struct after `versioncheck_in_progress`:

```rust
    pub brew_audit_results: HashMap<String, Vec<String>>,
    brew_audit_in_progress: bool,
    auto_brew_audit_pending: bool,
```

- [ ] **Step 2: Initialize the new fields in `App::new()`**

Add these to the `Self { ... }` block in `new()`, after `versioncheck_in_progress: false`:

```rust
            brew_audit_results: HashMap::new(),
            brew_audit_in_progress: false,
            auto_brew_audit_pending: true,
```

- [ ] **Step 3: Handle `BrewAuditCompleted` in `tick()`**

Add this arm to the `match result` block in `tick()`, after the `VersionsChecked` arm:

```rust
                ScanResult::BrewAuditCompleted(results) => {
                    let warning_count: usize = results.values().map(|w| w.len()).sum();
                    self.brew_audit_results = results;
                    self.brew_audit_in_progress = false;
                    if warning_count > 0 {
                        self.status_msg = Some(format!(
                            "brew audit: {} warning{} found",
                            warning_count,
                            if warning_count == 1 { "" } else { "s" }
                        ));
                    }
                }
```

- [ ] **Step 4: Trigger brew audit on startup**

In `tick()`, add this block after the existing auto-scan block (after the `if (self.auto_vulnscan_pending || self.auto_versioncheck_pending)` block):

```rust
        // Auto-trigger brew audit when Homebrew roots are present
        if self.auto_brew_audit_pending && !self.tree.nodes.is_empty() {
            let has_homebrew = self.tree.nodes.iter().any(|n| {
                n.path.to_string_lossy().contains("Homebrew")
            });
            if has_homebrew {
                self.auto_brew_audit_pending = false;
                self.brew_audit_in_progress = true;
                let _ = self
                    .scan_tx
                    .send(crate::scanner::ScanRequest::BrewAudit);
            } else {
                self.auto_brew_audit_pending = false;
            }
        }
```

- [ ] **Step 5: Run build to verify compilation**

Run: `cargo build 2>&1 | tail -5`
Expected: compiles successfully

- [ ] **Step 6: Commit**

```bash
git add src/app.rs
git commit -m "feat(app): store brew audit results and trigger on startup"
```

---

### Task 9: Detail panel — render brew audit warnings

**Files:**
- Modify: `src/ui/detail_panel.rs`

- [ ] **Step 1: Update `render()` signature to accept brew audit results**

Change the `render` function signature in `src/ui/detail_panel.rs`:

```rust
pub fn render(
    f: &mut Frame,
    area: Rect,
    tree: &TreeState,
    vuln_results: &std::collections::HashMap<std::path::PathBuf, crate::security::SecurityInfo>,
    version_results: &std::collections::HashMap<std::path::PathBuf, crate::security::VersionInfo>,
    brew_audit_results: &std::collections::HashMap<String, Vec<String>>,
) {
```

- [ ] **Step 2: Add brew audit rendering**

Add this block after the version info section (after the `if let Some(ver) = version_results.get(...)` block) and before the "Contextual delete hint" section:

```rust
    // Brew audit warnings
    // Match by extracting package name from the node's semantic name
    let audit_name = extract_package_name(&node.name);
    if let Some(warnings) = brew_audit_results.get(&audit_name) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("BREW AUDIT ({})", warnings.len()),
            theme::CAUTION,
        )));
        for warning in warnings {
            lines.push(Line::from(Span::styled(
                format!("  ⚠ {warning}"),
                theme::CAUTION,
            )));
        }
    }
```

- [ ] **Step 3: Update the call site in `src/app.rs:684`**

Change the `detail_panel::render` call at line 684:

```rust
        detail_panel::render(
            f,
            chunks[1],
            &self.tree,
            &self.vuln_results,
            &self.version_results,
            &self.brew_audit_results,
        );
```

- [ ] **Step 4: Run build to verify compilation**

Run: `cargo build 2>&1 | tail -5`
Expected: compiles successfully

- [ ] **Step 5: Run all tests**

Run: `cargo test 2>&1 | tail -20`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add src/ui/detail_panel.rs src/app.rs src/ui/mod.rs
git commit -m "feat(ui): render brew audit warnings in detail panel"
```

---

### Task 10: Full integration test — fake Homebrew cache tree

**Files:**
- Modify: `src/providers/homebrew.rs`

- [ ] **Step 1: Write filesystem integration test**

Add this test to the `tests` module in `src/providers/homebrew.rs`:

```rust
    #[test]
    fn integration_full_homebrew_cache_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Create directory structure
        let downloads = root.join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        std::fs::write(
            downloads.join("abc123--awscli--2.34.24.arm64_tahoe.bottle.tar.gz"),
            "fake bottle",
        ).unwrap();

        // Create bottle symlink
        let bottle_link = root.join("awscli--2.34.24");
        std::fs::write(&bottle_link, "fake").unwrap();

        // Create manifest with real-ish content
        let manifest_content = r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {
      "sh.brew.license": "Apache-2.0",
      "sh.brew.bottle.installed_size": "162136325",
      "sh.brew.tab": "{\"runtime_dependencies\":[{\"full_name\":\"openssl@3\",\"version\":\"3.6.1\",\"declared_directly\":true},{\"full_name\":\"python@3.14\",\"version\":\"3.14.3\",\"declared_directly\":true},{\"full_name\":\"ncurses\",\"version\":\"6.6\",\"declared_directly\":false}]}"
    }
  }]
}"#;
        let manifest_link = root.join("awscli_bottle_manifest--2.34.24");
        std::fs::write(&manifest_link, manifest_content).unwrap();

        // Create Cask dir
        let cask = root.join("Cask");
        std::fs::create_dir(&cask).unwrap();

        // Create api dir
        let api = root.join("api");
        std::fs::create_dir(&api).unwrap();

        // Verify semantic names
        assert_eq!(
            semantic_name(&bottle_link),
            Some("[bottle] awscli 2.34.24".to_string())
        );
        assert_eq!(
            semantic_name(&manifest_link),
            Some("[manifest] awscli 2.34.24".to_string())
        );
        assert_eq!(
            semantic_name(&downloads),
            Some("Downloaded Bottles".to_string())
        );
        assert_eq!(
            semantic_name(&cask),
            Some("Cask Downloads".to_string())
        );
        assert_eq!(
            semantic_name(&api),
            Some("API Cache".to_string())
        );

        // Verify metadata from bottle reads companion manifest
        let bottle_meta = metadata(&bottle_link);
        let license = bottle_meta.iter().find(|f| f.label == "License");
        assert!(license.is_some(), "Bottle should have license from manifest");
        assert_eq!(license.unwrap().value, "Apache-2.0");

        let deps = bottle_meta.iter().find(|f| f.label == "Deps");
        assert!(deps.is_some(), "Bottle should have deps from manifest");
        assert_eq!(deps.unwrap().value, "3 (2 direct)");

        // Verify metadata from manifest reads itself
        let manifest_meta = metadata(&manifest_link);
        let license2 = manifest_meta.iter().find(|f| f.label == "License");
        assert!(license2.is_some());
        assert_eq!(license2.unwrap().value, "Apache-2.0");

        // Verify downloads metadata
        let dl_meta = metadata(&downloads);
        let contents = dl_meta.iter().find(|f| f.label == "Contents");
        assert!(contents.is_some());
        let bottles_count = dl_meta.iter().find(|f| f.label == "Bottles");
        assert!(bottles_count.is_some());
        assert_eq!(bottles_count.unwrap().value, "1");
    }
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test --lib providers::homebrew::tests::integration_full_homebrew_cache_tree -- --nocapture`
Expected: PASS (all implementation is already done)

- [ ] **Step 3: Run the full test suite**

Run: `cargo test 2>&1 | tail -20`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add src/providers/homebrew.rs
git commit -m "test(homebrew): add full integration test for Homebrew cache tree"
```

---

### Task 11: Final verification and clippy

- [ ] **Step 1: Run clippy**

Run: `cargo clippy -- -D warnings 2>&1 | tail -20`
Expected: no warnings

- [ ] **Step 2: Run fmt check**

Run: `cargo fmt --check`
Expected: no formatting issues

- [ ] **Step 3: Run full test suite one final time**

Run: `cargo test`
Expected: all tests pass

- [ ] **Step 4: Fix any issues found, then commit if needed**

If clippy or fmt found issues:
```bash
cargo fmt
git add -A
git commit -m "chore: fix clippy/fmt issues"
```
