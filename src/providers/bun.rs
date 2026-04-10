use super::{MetadataField, PackageId};
use std::path::Path;

/// Parse a Bun cache directory path into (package_name, version).
///
/// Bun stores packages as `name@version` directories under `~/.bun/install/cache/`.
/// Scoped packages use real subdirectories: `@scope/name@version`.
///
/// Examples:
/// - `.../lodash@4.17.21` → `("lodash", "4.17.21")`
/// - `.../react-dom@18.2.0` → `("react-dom", "18.2.0")`
/// - `.../@babel/core@7.24.0` → `("@babel/core", "7.24.0")`
/// - `.../@types/node@22.0.0` → `("@types/node", "22.0.0")`
fn parse_package_from_path(path: &Path) -> Option<(String, String)> {
    let filename = path.file_name()?.to_str()?;

    // Skip Bun's internal metadata directory
    if filename == ".cache" {
        return None;
    }

    // Strip Bun's dedup suffix "@@@N" (e.g. "lodash@4.17.21@@@1" → "lodash@4.17.21")
    let filename = filename
        .find("@@@")
        .map_or(filename, |pos| &filename[..pos]);

    // The filename must contain '@' to separate name from version
    let at_pos = filename.rfind('@')?;
    let raw_name = &filename[..at_pos];
    let version = &filename[at_pos + 1..];

    if raw_name.is_empty() || version.is_empty() {
        return None;
    }

    // Version must start with a digit
    if !version
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_digit())
    {
        return None;
    }

    // Check if parent directory is a scope (starts with '@')
    let name = if let Some(parent) = path.parent() {
        if let Some(parent_name) = parent.file_name().and_then(|n| n.to_str()) {
            if parent_name.starts_with('@') {
                format!("{parent_name}/{raw_name}")
            } else {
                raw_name.to_string()
            }
        } else {
            raw_name.to_string()
        }
    } else {
        raw_name.to_string()
    };

    Some((name, version.to_string()))
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let filename = path.file_name()?.to_str()?;

    match filename {
        ".bun" => return Some("Bun Runtime".into()),
        "install" => {
            if path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == ".bun")
            {
                return Some("Bun Install Cache".into());
            }
        }
        "cache" => {
            if path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == "install")
                && path
                    .parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.file_name())
                    .is_some_and(|n| n == ".bun")
            {
                return Some("Bun Package Cache".into());
            }
        }
        ".cache" => return Some("Bun Internal Metadata".into()),
        _ => {}
    }

    // Scope directories (e.g., @babel, @types) — have a leading '@' but no
    // second '@' separating name from version.
    if filename.starts_with('@') && filename.rfind('@') == Some(0) {
        return None;
    }

    let (name, version) = parse_package_from_path(path)?;
    Some(format!("{name} {version}"))
}

pub fn package_id(path: &Path) -> Option<PackageId> {
    let (name, version) = parse_package_from_path(path)?;
    Some(PackageId {
        ecosystem: "npm",
        name,
        version,
    })
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match filename.as_str() {
        ".bun" | "install" | "cache" => {
            let count = path.read_dir().map(|d| d.count()).unwrap_or(0);
            vec![MetadataField {
                label: "Entries".into(),
                value: count.to_string(),
            }]
        }
        ".cache" => vec![MetadataField {
            label: "Type".into(),
            value: "Bun internal metadata".into(),
        }],
        _ => {
            if filename.starts_with('@') && !filename.contains('/') {
                // Scope directory (e.g., @babel, @types)
                let count = path.read_dir().map(|d| d.count()).unwrap_or(0);
                vec![
                    MetadataField {
                        label: "Type".into(),
                        value: "npm scope".into(),
                    },
                    MetadataField {
                        label: "Packages".into(),
                        value: count.to_string(),
                    },
                ]
            } else if parse_package_from_path(path).is_some() {
                vec![MetadataField {
                    label: "Type".into(),
                    value: "Cached package".into(),
                }]
            } else {
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- parse_package_from_path ---

    #[test]
    fn parse_non_scoped_package() {
        let path = PathBuf::from("/home/user/.bun/install/cache/lodash@4.17.21");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(version, "4.17.21");
    }

    #[test]
    fn parse_hyphenated_package() {
        let path = PathBuf::from("/home/user/.bun/install/cache/react-dom@18.2.0");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "react-dom");
        assert_eq!(version, "18.2.0");
    }

    #[test]
    fn parse_scoped_package() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@babel/core@7.24.0");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(version, "7.24.0");
    }

    #[test]
    fn parse_scoped_types_package() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@types/node@22.0.0");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "@types/node");
        assert_eq!(version, "22.0.0");
    }

    #[test]
    fn parse_rejects_dot_cache() {
        let path = PathBuf::from("/home/user/.bun/install/cache/.cache");
        assert!(parse_package_from_path(&path).is_none());
    }

    #[test]
    fn parse_rejects_no_at_sign() {
        let path = PathBuf::from("/home/user/.bun/install/cache/just-a-dir");
        assert!(parse_package_from_path(&path).is_none());
    }

    #[test]
    fn parse_rejects_empty_version() {
        let path = PathBuf::from("/home/user/.bun/install/cache/lodash@");
        assert!(parse_package_from_path(&path).is_none());
    }

    #[test]
    fn parse_rejects_non_digit_version() {
        let path = PathBuf::from("/home/user/.bun/install/cache/lodash@latest");
        assert!(parse_package_from_path(&path).is_none());
    }

    #[test]
    fn parse_rejects_bare_at_sign() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@");
        assert!(parse_package_from_path(&path).is_none());
    }

    // --- semantic_name ---

    #[test]
    fn semantic_name_bun_root() {
        let path = PathBuf::from("/home/user/.bun");
        assert_eq!(semantic_name(&path), Some("Bun Runtime".into()));
    }

    #[test]
    fn semantic_name_install_dir() {
        let path = PathBuf::from("/home/user/.bun/install");
        assert_eq!(semantic_name(&path), Some("Bun Install Cache".into()));
    }

    #[test]
    fn semantic_name_cache_dir() {
        let path = PathBuf::from("/home/user/.bun/install/cache");
        assert_eq!(semantic_name(&path), Some("Bun Package Cache".into()));
    }

    #[test]
    fn semantic_name_internal_metadata() {
        let path = PathBuf::from("/home/user/.bun/install/cache/.cache");
        assert_eq!(semantic_name(&path), Some("Bun Internal Metadata".into()));
    }

    #[test]
    fn semantic_name_non_scoped_package() {
        let path = PathBuf::from("/home/user/.bun/install/cache/express@4.18.2");
        assert_eq!(semantic_name(&path), Some("express 4.18.2".into()));
    }

    #[test]
    fn semantic_name_scoped_package() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@babel/core@7.24.0");
        assert_eq!(semantic_name(&path), Some("@babel/core 7.24.0".into()));
    }

    #[test]
    fn semantic_name_scope_dir_returns_none() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@babel");
        assert_eq!(semantic_name(&path), None);
    }

    // --- package_id ---

    #[test]
    fn package_id_non_scoped() {
        let path = PathBuf::from("/home/user/.bun/install/cache/lodash@4.17.21");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.21");
    }

    #[test]
    fn package_id_scoped() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@types/node@22.0.0");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@types/node");
        assert_eq!(id.version, "22.0.0");
    }

    #[test]
    fn package_id_dot_cache_returns_none() {
        let path = PathBuf::from("/home/user/.bun/install/cache/.cache");
        assert!(package_id(&path).is_none());
    }

    #[test]
    fn package_id_structural_dir_returns_none() {
        let path = PathBuf::from("/home/user/.bun/install/cache");
        assert!(package_id(&path).is_none());
    }

    // =================================================================
    // Adversarial tests
    // =================================================================

    #[test]
    fn parse_multiple_at_signs_uses_last() {
        // rfind('@') picks the last '@', so name="foo@bar", version="1.0.0"
        let path = PathBuf::from("/home/user/.bun/install/cache/foo@bar@1.0.0");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "foo@bar");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn parse_prerelease_version_accepted() {
        // Pre-release versions start with a digit, so they pass
        let path = PathBuf::from("/home/user/.bun/install/cache/pkg@1.0.0-beta.1");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "pkg");
        assert_eq!(version, "1.0.0-beta.1");
    }

    #[test]
    fn parse_root_path_returns_none() {
        let path = PathBuf::from("/");
        assert!(parse_package_from_path(&path).is_none());
    }

    #[test]
    fn parse_path_traversal_normalised_by_file_name() {
        // file_name() returns just the last component
        let path = PathBuf::from("/home/user/.bun/install/cache/../../../etc/passwd@1.0.0");
        let result = parse_package_from_path(&path);
        // file_name() returns "passwd@1.0.0", which is a valid parse
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "passwd");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn semantic_name_cache_rejects_non_bun_path() {
        // "cache" dir that is NOT under .bun/install — should NOT match
        let path = PathBuf::from("/home/user/.bun-tools/install-scripts/cache");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_install_rejects_non_bun_parent() {
        // "install" dir not under .bun — should NOT match
        let path = PathBuf::from("/home/user/install");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn metadata_scope_dir_has_type_field() {
        // Scope directories should have metadata, not empty vec
        let path = PathBuf::from("/home/user/.bun/install/cache/@babel");
        let fields = metadata(&path);
        assert!(!fields.is_empty());
        assert_eq!(fields[0].value, "npm scope");
    }

    // =================================================================
    // Dedup suffix (@@@N) tests
    // =================================================================

    #[test]
    fn parse_dedup_suffix_stripped() {
        let path = PathBuf::from("/home/user/.bun/install/cache/lodash@4.17.21@@@1");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(version, "4.17.21");
    }

    #[test]
    fn parse_dedup_suffix_higher_number() {
        let path = PathBuf::from("/home/user/.bun/install/cache/express@5.2.1@@@42");
        let (name, version) = parse_package_from_path(&path).unwrap();
        assert_eq!(name, "express");
        assert_eq!(version, "5.2.1");
    }

    #[test]
    fn semantic_name_dedup_suffix() {
        let path = PathBuf::from("/home/user/.bun/install/cache/tar@6.1.11@@@1");
        assert_eq!(semantic_name(&path), Some("tar 6.1.11".into()));
    }

    #[test]
    fn package_id_dedup_suffix() {
        let path = PathBuf::from("/home/user/.bun/install/cache/jsonwebtoken@8.5.1@@@1");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "jsonwebtoken");
        assert_eq!(id.version, "8.5.1");
    }

    #[test]
    fn package_id_scoped_with_dedup_suffix() {
        let path = PathBuf::from("/home/user/.bun/install/cache/@types/node@22.0.0@@@1");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@types/node");
        assert_eq!(id.version, "22.0.0");
    }
}
