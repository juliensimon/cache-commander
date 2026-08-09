// Xcode provider (DerivedData, iOS DeviceSupport, CoreSimulator Caches).
//
// No package identity / OSV / version-check / upgrade-command: these are
// build artifacts, not packages. Tier-3 E2E tests intentionally exempt
// (see design spec 2026-04-20-swiftpm-xcode-providers-design.md).

use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Known root subdirs — let the tree render them literally.
    if matches!(
        name.as_str(),
        "DerivedData" | "iOS DeviceSupport" | "Caches"
    ) {
        return None;
    }

    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if parent_name == "DerivedData" {
        if let Some(workspace_path) = read_workspace_path(path) {
            let basename = workspace_path
                .rsplit('/')
                .next()
                .unwrap_or(&workspace_path)
                .to_string();
            return Some(format!("{basename} (at {workspace_path})"));
        }
        return Some(name);
    }

    if parent_name == "iOS DeviceSupport" {
        return Some(name);
    }

    // CoreSimulator/Caches entries: opaque, no semantic name.
    None
}

/// Read the workspace path from `Info.plist` (XML variant).
/// Xcode 26+ writes `WorkspacePath`; older Xcode wrote `WORKSPACE_PATH`.
/// Returns None on any failure (missing file, malformed XML, missing key).
fn read_workspace_path(dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(dir.join("Info.plist")).ok()?;
    extract_plist_string(&content, "WorkspacePath")
        .or_else(|| extract_plist_string(&content, "WORKSPACE_PATH"))
}

/// Extract a string value by key from an XML plist body. Avoids a
/// `plist` crate dependency — Xcode consistently emits XML for
/// DerivedData Info.plist. Uses only char-boundary-safe string APIs
/// (`find`, `str` slicing by returned byte indices) so multi-byte
/// content does not panic (L2, L5).
fn extract_plist_string(xml: &str, key: &str) -> Option<String> {
    let key_tag = format!("<key>{key}</key>");
    let key_pos = xml.find(&key_tag)?;
    let after_key = &xml[key_pos + key_tag.len()..];
    let open = "<string>";
    let open_pos = after_key.find(open)?;
    let value_start = open_pos + open.len();
    let close_pos = after_key[value_start..].find("</string>")?;
    let value = &after_key[value_start..value_start + close_pos];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Root-level labels.
    match name.as_str() {
        "DerivedData" => {
            fields.push(MetadataField {
                label: "Contents".into(),
                value: "Xcode build products and indexes (rebuildable, 5–30 min cost)".into(),
            });
            return fields;
        }
        "iOS DeviceSupport" => {
            fields.push(MetadataField {
                label: "Contents".into(),
                value:
                    "Symbol files for connected iOS devices (re-downloadable on device reconnect)"
                        .into(),
            });
            return fields;
        }
        "Caches" if parent_name == "CoreSimulator" => {
            fields.push(MetadataField {
                label: "Contents".into(),
                value: "iOS Simulator caches (safe to clear)".into(),
            });
            return fields;
        }
        _ => {}
    }

    // DerivedData project dir: surface WORKSPACE_PATH so the user sees
    // which project they're about to nuke.
    if parent_name == "DerivedData"
        && let Some(wp) = read_workspace_path(path)
    {
        fields.push(MetadataField {
            label: "Workspace".into(),
            value: wp,
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_derived_data_dir(tmp: &TempDir, workspace_path: Option<&str>) -> PathBuf {
        make_derived_data_dir_with_key(tmp, workspace_path, "WorkspacePath")
    }

    fn make_derived_data_dir_with_key(
        tmp: &TempDir,
        workspace_path: Option<&str>,
        key: &str,
    ) -> PathBuf {
        let root = tmp
            .path()
            .join("Library/Developer/Xcode/DerivedData/MyApp-abc123def");
        std::fs::create_dir_all(&root).unwrap();
        if let Some(wp) = workspace_path {
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>{key}</key>
    <string>{wp}</string>
</dict>
</plist>"#
            );
            std::fs::write(root.join("Info.plist"), plist).unwrap();
        }
        root
    }

    #[test]
    fn semantic_name_derived_data_from_info_plist() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_derived_data_dir(&tmp, Some("/Users/j/dev/MyApp/MyApp.xcworkspace"));
        assert_eq!(
            semantic_name(&dir),
            Some("MyApp.xcworkspace (at /Users/j/dev/MyApp/MyApp.xcworkspace)".into())
        );
    }

    #[test]
    fn semantic_name_derived_data_legacy_workspace_path_key() {
        // Pre-Xcode-26 plists use WORKSPACE_PATH; keep the fallback working.
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_derived_data_dir_with_key(
            &tmp,
            Some("/Users/j/dev/Old/Old.xcworkspace"),
            "WORKSPACE_PATH",
        );
        assert_eq!(
            semantic_name(&dir),
            Some("Old.xcworkspace (at /Users/j/dev/Old/Old.xcworkspace)".into())
        );
    }

    #[test]
    fn semantic_name_derived_data_missing_plist_falls_back_to_dirname() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_derived_data_dir(&tmp, None);
        assert_eq!(semantic_name(&dir), Some("MyApp-abc123def".into()));
    }

    #[test]
    fn semantic_name_derived_data_malformed_plist_falls_back_to_dirname() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp
            .path()
            .join("Library/Developer/Xcode/DerivedData/Broken-xyz");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Info.plist"), "<plist><incomplete").unwrap();
        assert_eq!(semantic_name(&root), Some("Broken-xyz".into()));
    }

    #[test]
    fn semantic_name_derived_data_non_ascii_workspace_path() {
        // L2 / L5: multi-byte chars in workspace path must not panic.
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_derived_data_dir(&tmp, Some("/Users/j/日本語/App.xcworkspace"));
        assert_eq!(
            semantic_name(&dir),
            Some("App.xcworkspace (at /Users/j/日本語/App.xcworkspace)".into())
        );
    }

    #[test]
    fn semantic_name_ios_device_support_uses_dirname() {
        let path =
            PathBuf::from("/Users/j/Library/Developer/Xcode/iOS DeviceSupport/17.4 (21E213)");
        assert_eq!(semantic_name(&path), Some("17.4 (21E213)".into()));
    }

    #[test]
    fn semantic_name_core_simulator_returns_none() {
        let path = PathBuf::from(
            "/Users/j/Library/Developer/CoreSimulator/Caches/com.apple.SimulatorTrampoline",
        );
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_known_roots_return_none() {
        for p in [
            "/Users/j/Library/Developer/Xcode/DerivedData",
            "/Users/j/Library/Developer/Xcode/iOS DeviceSupport",
            "/Users/j/Library/Developer/CoreSimulator/Caches",
        ] {
            assert_eq!(semantic_name(&PathBuf::from(p)), None, "{p}");
        }
    }

    #[test]
    fn metadata_derived_data_root_reports_contents() {
        let path = PathBuf::from("/Users/j/Library/Developer/Xcode/DerivedData");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Contents" && f.value.contains("build products")),
            "got {fields:?}"
        );
    }

    #[test]
    fn metadata_ios_device_support_root_reports_contents() {
        let path = PathBuf::from("/Users/j/Library/Developer/Xcode/iOS DeviceSupport");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Contents" && f.value.contains("Symbol files")),
            "got {fields:?}"
        );
    }

    #[test]
    fn metadata_core_simulator_caches_root_reports_contents() {
        let path = PathBuf::from("/Users/j/Library/Developer/CoreSimulator/Caches");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Contents" && f.value.contains("Simulator")),
            "got {fields:?}"
        );
    }

    #[test]
    fn metadata_derived_data_project_dir_emits_workspace_path_when_available() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_derived_data_dir(&tmp, Some("/Users/j/dev/MyApp/MyApp.xcworkspace"));
        let fields = metadata(&dir);
        assert!(
            fields.iter().any(
                |f| f.label == "Workspace" && f.value == "/Users/j/dev/MyApp/MyApp.xcworkspace"
            ),
            "expected Workspace field, got {fields:?}"
        );
    }

    #[test]
    fn metadata_derived_data_project_dir_without_plist_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_derived_data_dir(&tmp, None);
        assert!(metadata(&dir).is_empty());
    }
}
