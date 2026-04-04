use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    match name.as_str() {
        "archive-v0" => Some("Package Archives".to_string()),
        "simple-v20" => Some("Package Index Cache".to_string()),
        "wheels-v6" => Some("Built Wheels".to_string()),
        "interpreter-v4" => Some("Interpreter Cache".to_string()),
        "sdists-v7" => Some("Source Distributions".to_string()),
        "builds-v0" => Some("Build Cache".to_string()),
        _ if name.starts_with("archive-") => Some("Package Archives".to_string()),
        _ if name.starts_with("simple-") => Some("Package Index".to_string()),
        _ if name.starts_with("wheels-") => Some("Built Wheels".to_string()),
        _ if name.starts_with(".tmp") => Some("[tmp] build artifact".to_string()),
        _ => {
            // Hash directories inside archive-v0: try to identify by dist-info
            if path.is_dir() {
                if let Some(pkg) = identify_package_from_dist_info(path) {
                    return Some(pkg);
                }
            }
            None
        }
    }
}

/// Look for *.dist-info directories inside a hash dir to identify the package.
fn identify_package_from_dist_info(path: &Path) -> Option<String> {
    let entries = std::fs::read_dir(path).ok()?;
    let mut packages: Vec<String> = Vec::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let entry_name = entry.file_name().to_string_lossy().to_string();
        if entry_name.ends_with(".dist-info") {
            let stem = entry_name.strip_suffix(".dist-info")?;
            // Format: package_name-version.dist-info
            if let Some(pos) = stem.rfind('-') {
                let pkg = &stem[..pos];
                let ver = &stem[pos + 1..];
                packages.push(format!("{} {}", pkg.replace('_', "-"), ver));
            } else {
                packages.push(stem.replace('_', "-"));
            }
        }
    }

    if packages.is_empty() {
        // Try pyvenv.cfg for virtual environments
        let pyvenv = path.join("pyvenv.cfg");
        if pyvenv.exists() {
            return Some("[venv]".to_string());
        }
        return None;
    }

    if packages.len() == 1 {
        Some(packages.into_iter().next().unwrap())
    } else {
        // Multiple packages — show count with first package
        let first = packages[0].clone();
        Some(format!("{} (+{} more)", first, packages.len() - 1))
    }
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name.starts_with("archive") {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Downloaded package archives (.tar.gz, .zip)".to_string(),
        });
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.filter_map(|e| e.ok()).count();
            fields.push(MetadataField {
                label: "Packages".to_string(),
                value: count.to_string(),
            });
        }
    } else if name.starts_with("simple") {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "PyPI simple API response cache".to_string(),
        });
    } else if name.starts_with("wheels") {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Pre-built wheel cache".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_archive_v0() {
        let path = PathBuf::from("/cache/uv/archive-v0");
        assert_eq!(semantic_name(&path), Some("Package Archives".into()));
    }

    #[test]
    fn semantic_name_simple_v20() {
        let path = PathBuf::from("/cache/uv/simple-v20");
        assert_eq!(semantic_name(&path), Some("Package Index Cache".into()));
    }

    #[test]
    fn semantic_name_wheels_v6() {
        let path = PathBuf::from("/cache/uv/wheels-v6");
        assert_eq!(semantic_name(&path), Some("Built Wheels".into()));
    }

    #[test]
    fn semantic_name_interpreter_v4() {
        let path = PathBuf::from("/cache/uv/interpreter-v4");
        assert_eq!(semantic_name(&path), Some("Interpreter Cache".into()));
    }

    #[test]
    fn semantic_name_future_archive_version() {
        let path = PathBuf::from("/cache/uv/archive-v5");
        assert_eq!(semantic_name(&path), Some("Package Archives".into()));
    }

    #[test]
    fn semantic_name_tmp_build_artifact() {
        let path = PathBuf::from("/cache/uv/.tmpABCDEF");
        assert_eq!(semantic_name(&path), Some("[tmp] build artifact".into()));
    }

    #[test]
    fn semantic_name_unknown_returns_none() {
        let path = PathBuf::from("/cache/uv/random_unknown_dir");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn metadata_archive_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("archive-v0");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::write(archive.join("pkg1.tar.gz"), "x").unwrap();
        std::fs::write(archive.join("pkg2.tar.gz"), "x").unwrap();

        let fields = metadata(&archive);
        assert_eq!(fields[0].value, "Downloaded package archives (.tar.gz, .zip)");
        let pkg_field = fields.iter().find(|f| f.label == "Packages").unwrap();
        assert_eq!(pkg_field.value, "2");
    }

    #[test]
    fn metadata_simple_dir() {
        let path = PathBuf::from("/tmp/nonexistent/simple-v20");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("PyPI"));
    }

    #[test]
    fn semantic_name_hash_dir_with_single_dist_info() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("rXLghEMZZDXLRnlqsigtc");
        std::fs::create_dir_all(hash_dir.join("requests-2.31.0.dist-info")).unwrap();
        assert_eq!(semantic_name(&hash_dir), Some("requests 2.31.0".into()));
    }

    #[test]
    fn semantic_name_hash_dir_with_multiple_dist_infos() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("abc123");
        std::fs::create_dir_all(hash_dir.join("flask-3.0.0.dist-info")).unwrap();
        std::fs::create_dir_all(hash_dir.join("werkzeug-3.0.1.dist-info")).unwrap();
        std::fs::create_dir_all(hash_dir.join("jinja2-3.1.3.dist-info")).unwrap();
        let result = semantic_name(&hash_dir).unwrap();
        assert!(result.contains("+2 more"), "Should show count: {}", result);
    }

    #[test]
    fn semantic_name_hash_dir_with_underscore_package() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("xyz");
        std::fs::create_dir_all(hash_dir.join("annotated_types-0.7.0.dist-info")).unwrap();
        assert_eq!(semantic_name(&hash_dir), Some("annotated-types 0.7.0".into()));
    }

    #[test]
    fn semantic_name_hash_dir_empty_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("empty_hash");
        std::fs::create_dir_all(&hash_dir).unwrap();
        assert_eq!(semantic_name(&hash_dir), None);
    }
}
