use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // pip cache uses directories like "wheels/xx/yy/hash/package-version-*.whl"
    // or "http-v2/hash" for HTTP responses ("http" before pip 23.3)
    if name == "wheels" || name == "http" || name == "http-v2" || name == "selfcheck" {
        return None; // Keep directory names as-is
    }

    // Check for .whl files
    if name.ends_with(".whl") {
        // Format: package-version-pythonversion-abi-platform.whl
        let parts: Vec<&str> = name.splitn(3, '-').collect();
        if parts.len() >= 2 {
            return Some(format!("{} {}", parts[0], parts[1]));
        }
    }

    None
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();
    if name.ends_with(".whl") {
        let parts: Vec<&str> = name.splitn(3, '-').collect();
        if parts.len() >= 2 {
            return Some(super::PackageId {
                ecosystem: "PyPI",
                name: parts[0].replace('_', "-").to_lowercase(),
                version: parts[1].to_string(),
            });
        }
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
        "wheels" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Cached wheel packages".to_string(),
            });
            // Count wheels recursively
            let count = count_files_with_ext(path, "whl");
            if count > 0 {
                fields.push(MetadataField {
                    label: "Packages".to_string(),
                    value: count.to_string(),
                });
            }
        }
        "http" | "http-v2" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "HTTP response cache".to_string(),
            });
        }
        "selfcheck" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "pip self-check data".to_string(),
            });
        }
        _ => {}
    }

    fields
}

fn count_files_with_ext(path: &Path, ext: &str) -> usize {
    jwalk::WalkDir::new(path)
        .skip_hidden(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == ext).unwrap_or(false))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_wheel_file() {
        let p = PathBuf::from("/cache/pip/wheels/requests-2.31.0-py3-none-any.whl");
        assert_eq!(semantic_name(&p), Some("requests 2.31.0".into()));
    }

    #[test]
    fn semantic_name_returns_none_for_toplevel_dirs() {
        assert_eq!(semantic_name(&PathBuf::from("/cache/pip/wheels")), None);
        assert_eq!(semantic_name(&PathBuf::from("/cache/pip/http")), None);
        assert_eq!(semantic_name(&PathBuf::from("/cache/pip/selfcheck")), None);
    }

    #[test]
    fn semantic_name_returns_none_for_non_wheel() {
        assert_eq!(semantic_name(&PathBuf::from("/cache/pip/readme.txt")), None);
    }

    #[test]
    fn package_id_from_wheel() {
        // Underscores in distribution name are normalized to hyphens and lowercased.
        let p = PathBuf::from("/cache/pip/wheels/Django_REST_framework-3.14.0-py3-none-any.whl");
        let id = package_id(&p).unwrap();
        assert_eq!(id.ecosystem, "PyPI");
        assert_eq!(id.name, "django-rest-framework");
        assert_eq!(id.version, "3.14.0");
    }

    #[test]
    fn package_id_none_for_non_wheel() {
        assert!(package_id(&PathBuf::from("/cache/pip/http/abc")).is_none());
    }

    #[test]
    fn metadata_http_dir() {
        let fields = metadata(&PathBuf::from("/cache/pip/http"));
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("HTTP"));
    }

    #[test]
    fn metadata_http_v2_dir() {
        // pip >= 23.3 stores HTTP responses under http-v2.
        let fields = metadata(&PathBuf::from("/cache/pip/http-v2"));
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("HTTP"));
    }

    #[test]
    fn metadata_selfcheck_dir() {
        let fields = metadata(&PathBuf::from("/cache/pip/selfcheck"));
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("self-check"));
    }

    #[test]
    fn metadata_wheels_dir_counts_whl_files() {
        let tmp = tempfile::tempdir().unwrap();
        let wheels = tmp.path().join("wheels");
        std::fs::create_dir_all(wheels.join("sub/a")).unwrap();
        std::fs::write(wheels.join("sub/a/pkg1-1.0.0-py3.whl"), "").unwrap();
        std::fs::write(wheels.join("sub/a/pkg2-2.0.0-py3.whl"), "").unwrap();
        std::fs::write(wheels.join("ignored.txt"), "").unwrap();
        let fields = metadata(&wheels);
        // "Contents" + "Packages"
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].label, "Packages");
        assert_eq!(fields[1].value, "2");
    }

    #[test]
    fn metadata_unknown_name_returns_empty() {
        assert!(metadata(&PathBuf::from("/cache/pip/weird")).is_empty());
    }
}
