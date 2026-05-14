use super::MetadataField;
use std::path::Path;

/// True when `path` is under a Poetry cache root (`.../pypoetry/...`).
fn is_under_pypoetry(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "pypoetry")
}

pub fn semantic_name(path: &Path) -> Option<String> {
    if !is_under_pypoetry(path) {
        return None;
    }

    let name = path.file_name()?.to_string_lossy().to_string();

    if matches!(name.as_str(), "artifacts" | "cache" | "virtualenvs") {
        return None;
    }

    if name.ends_with(".whl") {
        let parts: Vec<&str> = name.splitn(3, '-').collect();
        if parts.len() >= 2 {
            return Some(format!("{} {}", parts[0], parts[1]));
        }
    }

    if let Some(stem) = name.strip_suffix(".tar.gz")
        && let Some((pkg, ver)) = parse_sdist_stem(stem)
    {
        return Some(format!("{pkg} {ver}"));
    }

    None
}

/// Parse `distribution-version` from an sdist filename stem (without `.tar.gz`).
fn parse_sdist_stem(stem: &str) -> Option<(String, String)> {
    let (pkg, ver) = stem.rsplit_once('-')?;
    if pkg.is_empty() || ver.is_empty() {
        return None;
    }
    // Version should start with a digit (PEP 440 / common sdist layout).
    if !ver
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || c == 'v')
    {
        return None;
    }
    Some((pkg.replace('_', "-"), ver.to_string()))
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    if !is_under_pypoetry(path) {
        return None;
    }

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

    if let Some(stem) = name.strip_suffix(".tar.gz")
        && let Some((pkg, ver)) = parse_sdist_stem(stem)
    {
        return Some(super::PackageId {
            ecosystem: "PyPI",
            name: pkg.to_lowercase(),
            version: ver,
        });
    }

    None
}

fn count_artifacts(path: &Path) -> (usize, usize) {
    let mut wheels = 0usize;
    let mut sdists = 0usize;
    for entry in jwalk::WalkDir::new(path)
        .skip_hidden(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            match ext {
                "whl" => wheels += 1,
                "gz" if p.to_string_lossy().ends_with(".tar.gz") => sdists += 1,
                _ => {}
            }
        }
    }
    (wheels, sdists)
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match name.as_str() {
        "artifacts" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded wheels and source distributions (.whl, .tar.gz)".to_string(),
            });
            let (wheels, sdists) = count_artifacts(path);
            let total = wheels + sdists;
            if total > 0 {
                fields.push(MetadataField {
                    label: "Packages".to_string(),
                    value: total.to_string(),
                });
            }
        }
        "repositories" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "PyPI simple / repository index cache".to_string(),
            });
        }
        "virtualenvs" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Poetry-managed virtual environments (recreated on poetry install)"
                    .to_string(),
            });
        }
        _ => {}
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_wheel_under_artifacts() {
        let p = PathBuf::from(
            "/home/user/.cache/pypoetry/artifacts/ab/requests-2.31.0-py3-none-any.whl",
        );
        assert_eq!(semantic_name(&p), Some("requests 2.31.0".into()));
    }

    #[test]
    fn semantic_name_sdist_under_artifacts() {
        let p = PathBuf::from("/home/user/.cache/pypoetry/artifacts/xx/requests-2.31.0.tar.gz");
        assert_eq!(semantic_name(&p), Some("requests 2.31.0".into()));
    }

    #[test]
    fn semantic_name_sdist_with_hyphenated_name() {
        let p =
            PathBuf::from("/home/user/.cache/pypoetry/artifacts/xx/opencv-python-4.5.5.64.tar.gz");
        assert_eq!(semantic_name(&p), Some("opencv-python 4.5.5.64".into()));
    }

    #[test]
    fn semantic_name_returns_none_for_bucket_dirs() {
        assert_eq!(
            semantic_name(&PathBuf::from("/.cache/pypoetry/artifacts")),
            None
        );
        assert_eq!(
            semantic_name(&PathBuf::from("/.cache/pypoetry/cache")),
            None
        );
        assert_eq!(
            semantic_name(&PathBuf::from("/.cache/pypoetry/virtualenvs")),
            None
        );
    }

    #[test]
    fn semantic_name_returns_none_outside_pypoetry() {
        let p = PathBuf::from("/tmp/requests-2.31.0-py3-none-any.whl");
        assert_eq!(semantic_name(&p), None);
    }

    #[test]
    fn package_id_from_wheel() {
        let p = PathBuf::from(
            "/Library/Caches/pypoetry/artifacts/z/Django_REST_framework-3.14.0-py3-none-any.whl",
        );
        let id = package_id(&p).unwrap();
        assert_eq!(id.ecosystem, "PyPI");
        assert_eq!(id.name, "django-rest-framework");
        assert_eq!(id.version, "3.14.0");
    }

    #[test]
    fn package_id_from_sdist() {
        let p = PathBuf::from("/home/user/.cache/pypoetry/artifacts/a/my_pkg-1.2.3.tar.gz");
        let id = package_id(&p).unwrap();
        assert_eq!(id.ecosystem, "PyPI");
        assert_eq!(id.name, "my-pkg");
        assert_eq!(id.version, "1.2.3");
    }

    #[test]
    fn package_id_none_outside_pypoetry() {
        assert!(package_id(&PathBuf::from("/tmp/pkg-1.0.0-py3-none-any.whl")).is_none());
    }

    #[test]
    fn metadata_artifacts_counts_wheels_and_sdist() {
        let tmp = tempfile::tempdir().unwrap();
        let artifacts = tmp.path().join("pypoetry").join("artifacts");
        std::fs::create_dir_all(artifacts.join("sub/a")).unwrap();
        std::fs::write(artifacts.join("sub/a/p-1.0.0-py3.whl"), "").unwrap();
        std::fs::write(artifacts.join("sub/a/q-2.0.0.tar.gz"), "").unwrap();
        std::fs::write(artifacts.join("ignored.txt"), "").unwrap();

        let fields = metadata(&artifacts);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].label, "Packages");
        assert_eq!(fields[1].value, "2");
    }

    #[test]
    fn metadata_repositories_dir() {
        let p = PathBuf::from("/home/u/Library/Caches/pypoetry/cache/repositories");
        let fields = metadata(&p);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("PyPI") || fields[0].value.contains("index"));
    }

    #[test]
    fn metadata_virtualenvs_dir() {
        let p = PathBuf::from("/home/u/Library/Caches/pypoetry/virtualenvs");
        let fields = metadata(&p);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("virtual") || fields[0].value.contains("Poetry"));
    }

    #[test]
    fn metadata_unknown_name_returns_empty() {
        assert!(metadata(&PathBuf::from("/cache/pypoetry/weird")).is_empty());
    }
}
