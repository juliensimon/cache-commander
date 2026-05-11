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

/// Extract metadata fields from a Homebrew bottle manifest JSON string.
/// This is a pure function for testability — takes the raw JSON content, returns metadata fields.
pub fn extract_manifest_metadata(json: &str) -> Vec<MetadataField> {
    let mut fields = Vec::new();

    #[derive(serde::Deserialize)]
    struct Manifest {
        manifests: Vec<ManifestEntry>,
    }
    #[derive(serde::Deserialize)]
    struct ManifestEntry {
        platform: Option<Platform>,
        annotations: Option<Annotations>,
    }
    #[derive(serde::Deserialize)]
    struct Platform {
        architecture: Option<String>,
        os: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Annotations {
        #[serde(rename = "sh.brew.license")]
        license: Option<String>,
        #[serde(rename = "sh.brew.bottle.installed_size")]
        installed_size: Option<String>,
        #[serde(rename = "sh.brew.tab")]
        tab: Option<String>,
    }

    let manifests: Manifest = match serde_json::from_str(json) {
        Ok(m) => m,
        Err(_) => return fields,
    };

    if let Some(entry) = manifests.manifests.first() {
        // Architecture and OS
        if let Some(platform) = &entry.platform
            && let Some(arch) = &platform.architecture
        {
            let os = platform.os.clone().unwrap_or_default();
            if !os.is_empty() {
                fields.push(MetadataField {
                    label: "Arch".to_string(),
                    value: format!("{arch} {os}"),
                });
            } else {
                fields.push(MetadataField {
                    label: "Arch".to_string(),
                    value: arch.clone(),
                });
            }
        }

        // Annotations
        if let Some(annotations) = &entry.annotations {
            if let Some(license) = &annotations.license {
                fields.push(MetadataField {
                    label: "License".to_string(),
                    value: license.clone(),
                });
            }

            if let Some(size_str) = &annotations.installed_size
                && let Ok(bytes) = size_str.parse::<u64>()
            {
                fields.push(MetadataField {
                    label: "Installed".to_string(),
                    value: format_bytes(bytes),
                });
            }

            if let Some(tab_str) = &annotations.tab
                && let Some(deps_info) = parse_runtime_deps(tab_str)
            {
                fields.push(MetadataField {
                    label: "Deps".to_string(),
                    value: deps_info,
                });
            }
        }
    }

    fields
}

fn parse_runtime_deps(tab_json: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Tab {
        #[serde(rename = "runtime_dependencies")]
        runtime_dependencies: Option<Vec<RuntimeDep>>,
    }
    #[derive(serde::Deserialize)]
    struct RuntimeDep {
        #[serde(rename = "full_name")]
        _full_name: Option<String>,
        #[serde(rename = "declared_directly")]
        declared_directly: Option<bool>,
    }
    let tab: Tab = serde_json::from_str(tab_json).ok()?;
    let deps = tab.runtime_dependencies?;
    let total = deps.len();
    if total == 0 {
        return Some("0".to_string());
    }
    let direct = deps
        .iter()
        .filter(|d| d.declared_directly == Some(true))
        .count();
    if direct > 0 && direct < total {
        Some(format!("{total} ({direct} direct)"))
    } else {
        Some(format!("{total}"))
    }
}

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
                let count = entries.filter(|e| e.is_ok()).count();
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
            if let Some(manifest_json) = read_manifest_for(path, &name) {
                fields.extend(extract_manifest_metadata(&manifest_json));
            }
        }
    }

    fields
}

fn read_manifest_for(path: &Path, name: &str) -> Option<String> {
    if parse_manifest_name(name).is_some() {
        return std::fs::read_to_string(path).ok();
    }

    if let Some((pkg, ver)) = parse_bottle_name(name) {
        let parent = path.parent()?;
        let manifest_name = format!("{pkg}_bottle_manifest--{ver}");
        let manifest_path = parent.join(manifest_name);
        return std::fs::read_to_string(manifest_path).ok();
    }

    None
}

#[derive(Debug, Clone)]
pub struct BrewOutdatedEntry {
    pub installed: String,
    pub current: String,
    pub pinned: bool,
}

/// Parse the JSON output of `brew outdated --json=v2` into a map of formula name → outdated info.
pub fn parse_brew_outdated(json: &str) -> std::collections::HashMap<String, BrewOutdatedEntry> {
    #[derive(serde::Deserialize)]
    struct BrewOutdatedJson {
        formulae: Vec<BrewFormula>,
    }
    #[derive(serde::Deserialize)]
    struct BrewFormula {
        name: String,
        #[serde(rename = "current_version")]
        current_version: Option<String>,
        #[serde(rename = "installed_versions")]
        installed_versions: Option<Vec<String>>,
        pinned: bool,
    }

    let parsed: BrewOutdatedJson = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(_) => return Default::default(),
    };

    let mut results = std::collections::HashMap::new();
    for formula in parsed.formulae {
        let installed = formula
            .installed_versions
            .as_ref()
            .and_then(|v| v.first().cloned())
            .unwrap_or_default();
        let current = formula.current_version.unwrap_or_default();

        let entry = BrewOutdatedEntry {
            installed,
            current,
            pinned: formula.pinned,
        };
        // Also insert under short name for tap-qualified names like "user/tap/formula"
        if let Some(short) = formula.name.rsplit('/').next()
            && short != formula.name
        {
            results.insert(short.to_string(), entry.clone());
        }
        results.insert(formula.name, entry);
    }

    results
}

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
        assert_eq!(semantic_name(&path), Some("Downloaded Bottles".to_string()));
    }

    #[test]
    fn semantic_name_existing_cask_dir() {
        let path = PathBuf::from("/Library/Caches/Homebrew/Cask");
        assert_eq!(semantic_name(&path), Some("Cask Downloads".to_string()));
    }

    #[test]
    fn semantic_name_existing_api() {
        let path = PathBuf::from("/Library/Caches/Homebrew/api");
        assert_eq!(semantic_name(&path), Some("API Cache".to_string()));
    }

    #[test]
    fn semantic_name_bottle_with_zip_extension() {
        let path = PathBuf::from("/Library/Caches/Homebrew/opencode--1.3.14.zip");
        assert_eq!(
            semantic_name(&path),
            Some("[bottle] opencode 1.3.14.zip".to_string())
        );
    }

    #[test]
    fn semantic_name_unknown() {
        let path = PathBuf::from("/Library/Caches/Homebrew/.cleaned");
        assert_eq!(semantic_name(&path), None);
    }

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
        let fields = extract_manifest_metadata(
            r#"{
  "manifests": [{"platform": {"architecture": "arm64", "os": "macOS"}}]
}"#,
        );
        let arch = fields.iter().find(|f| f.label == "Arch");
        assert!(arch.is_some());
        assert_eq!(arch.unwrap().value, "arm64 macOS");
    }

    #[test]
    fn extract_metadata_no_tab() {
        let fields = extract_manifest_metadata(
            r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {"sh.brew.license": "MIT"}
  }]
}"#,
        );
        let license = fields.iter().find(|f| f.label == "License");
        assert!(license.is_some());
        assert_eq!(license.unwrap().value, "MIT");
        let deps = fields.iter().find(|f| f.label == "Deps");
        assert!(deps.is_none());
    }

    #[test]
    fn extract_metadata_empty_runtime_deps() {
        let fields = extract_manifest_metadata(
            r#"{
  "manifests": [{
    "platform": {"architecture": "x86_64", "os": "linux"},
    "annotations": {
      "sh.brew.license": "MIT",
      "sh.brew.tab": "{\"runtime_dependencies\":[]}"
    }
  }]
}"#,
        );
        let deps = fields.iter().find(|f| f.label == "Deps");
        assert!(deps.is_some());
        assert_eq!(deps.unwrap().value, "0");
    }

    // --- metadata with manifest files on disk ---

    #[test]
    fn metadata_bottle_reads_companion_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let bottle = tmp.path().join("awscli--2.34.24");
        std::fs::write(&bottle, "fake bottle").unwrap();
        let manifest = tmp.path().join("awscli_bottle_manifest--2.34.24");
        std::fs::write(
            &manifest,
            r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {
      "sh.brew.license": "Apache-2.0",
      "sh.brew.bottle.installed_size": "162136325",
      "sh.brew.tab": "{\"runtime_dependencies\":[{\"full_name\":\"openssl@3\",\"version\":\"3.6.1\",\"declared_directly\":true}]}"
    }
  }]
}"#,
        )
        .unwrap();

        let fields = metadata(&bottle);
        let license = fields.iter().find(|f| f.label == "License");
        assert!(
            license.is_some(),
            "Expected License field, got: {:?}",
            fields
        );
        assert_eq!(license.unwrap().value, "Apache-2.0");
    }

    #[test]
    fn metadata_bottle_no_companion_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let bottle = tmp.path().join("awscli--2.34.24");
        std::fs::write(&bottle, "fake bottle").unwrap();
        let fields = metadata(&bottle);
        assert!(fields.is_empty(), "Expected empty, got: {:?}", fields);
    }

    #[test]
    fn metadata_manifest_reads_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("awscli_bottle_manifest--2.34.24");
        std::fs::write(
            &manifest,
            r#"{
  "manifests": [{
    "platform": {"architecture": "arm64", "os": "macOS"},
    "annotations": {"sh.brew.license": "MIT"}
  }]
}"#,
        )
        .unwrap();

        let fields = metadata(&manifest);
        let license = fields.iter().find(|f| f.label == "License");
        assert!(license.is_some());
        assert_eq!(license.unwrap().value, "MIT");
    }

    // --- parse_brew_outdated ---

    #[test]
    fn parse_brew_outdated_single_formula() {
        let json = r#"{"formulae":[{"name":"opencode","installed_versions":["1.3.14"],"current_version":"1.3.15","pinned":false,"pinned_version":null}],"casks":[]}"#;
        let result = parse_brew_outdated(json);
        assert_eq!(result.len(), 1);
        let entry = &result["opencode"];
        assert_eq!(entry.installed, "1.3.14");
        assert_eq!(entry.current, "1.3.15");
        assert!(!entry.pinned);
    }

    #[test]
    fn parse_brew_outdated_multiple_formulae() {
        let json = r#"{"formulae":[{"name":"git","installed_versions":["2.44.0"],"current_version":"2.45.0","pinned":false,"pinned_version":null},{"name":"node","installed_versions":["21.0.0"],"current_version":"22.0.0","pinned":false,"pinned_version":null}],"casks":[]}"#;
        let result = parse_brew_outdated(json);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("git"));
        assert!(result.contains_key("node"));
    }

    #[test]
    fn parse_brew_outdated_pinned_formula() {
        let json = r#"{"formulae":[{"name":"pinned-pkg","installed_versions":["1.0.0"],"current_version":"2.0.0","pinned":true,"pinned_version":"1.0.0"}],"casks":[]}"#;
        let result = parse_brew_outdated(json);
        assert_eq!(result.len(), 1);
        assert!(result["pinned-pkg"].pinned);
    }

    #[test]
    fn parse_brew_outdated_empty_formulae() {
        let json = r#"{"formulae":[],"casks":[]}"#;
        let result = parse_brew_outdated(json);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_brew_outdated_empty_string() {
        let result = parse_brew_outdated("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_brew_outdated_malformed_json() {
        let result = parse_brew_outdated("{not valid json");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_brew_outdated_no_formulae_key() {
        let result = parse_brew_outdated(r#"{"casks":[]}"#);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_brew_outdated_tap_qualified_name() {
        let json = r#"{"formulae":[{"name":"anomalyco/tap/opencode","installed_versions":["1.3.14"],"current_version":"1.3.15","pinned":false,"pinned_version":null}],"casks":[]}"#;
        let result = parse_brew_outdated(json);
        // Should be findable by both full name and short name
        assert!(result.contains_key("anomalyco/tap/opencode"));
        assert!(result.contains_key("opencode"));
        assert_eq!(result["opencode"].current, "1.3.15");
    }

    #[test]
    fn parse_brew_outdated_multiple_installed_versions() {
        let json = r#"{"formulae":[{"name":"llvm","installed_versions":["21.1.8","22.1.2"],"current_version":"22.1.2","pinned":false,"pinned_version":null}],"casks":[]}"#;
        let result = parse_brew_outdated(json);
        assert_eq!(result.len(), 1);
        // Should grab the first installed version
        assert_eq!(result["llvm"].installed, "21.1.8");
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
        )
        .unwrap();

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
        assert_eq!(semantic_name(&cask), Some("Cask Downloads".to_string()));
        assert_eq!(semantic_name(&api), Some("API Cache".to_string()));

        // Verify metadata from bottle reads companion manifest
        let bottle_meta = metadata(&bottle_link);
        let license = bottle_meta.iter().find(|f| f.label == "License");
        assert!(
            license.is_some(),
            "Bottle should have license from manifest"
        );
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
}
