use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Cargo registry cache has directories like "index.crates.io-xxxx"
    if name.starts_with("index.crates.io") {
        return Some("crates.io Index".to_string());
    }

    // Cache directory has .crate files: package-version.crate
    if name.ends_with(".crate") {
        let stem = name.strip_suffix(".crate")?;
        // Find last hyphen before version number
        if let Some(pos) = stem.rfind('-') {
            let pkg = &stem[..pos];
            let ver = &stem[pos + 1..];
            if ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                return Some(format!("{pkg} {ver}"));
            }
        }
    }

    // src directory has extracted source: package-version/
    if name.contains('-') {
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();
        if parts.len() == 2 {
            let ver = parts[0];
            let pkg = parts[1];
            if ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                return Some(format!("{pkg} {ver}"));
            }
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

    if name == "cache" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Downloaded .crate files".to_string(),
        });
        if let Ok(entries) = std::fs::read_dir(path) {
            // Count .crate files in subdirs
            let mut count = 0;
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().is_dir() {
                    if let Ok(sub) = std::fs::read_dir(entry.path()) {
                        count += sub
                            .filter_map(|e| e.ok())
                            .filter(|e| {
                                e.path()
                                    .extension()
                                    .map(|x| x == "crate")
                                    .unwrap_or(false)
                            })
                            .count();
                    }
                }
            }
            if count > 0 {
                fields.push(MetadataField {
                    label: "Crates".to_string(),
                    value: count.to_string(),
                });
            }
        }
    } else if name == "src" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Extracted crate source code".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_crates_io_index() {
        let path = PathBuf::from("/cargo/registry/index.crates.io-6f17d22bba15001f");
        assert_eq!(semantic_name(&path), Some("crates.io Index".into()));
    }

    #[test]
    fn semantic_name_crate_file() {
        let path = PathBuf::from("/cargo/registry/cache/serde-1.0.200.crate");
        assert_eq!(semantic_name(&path), Some("serde 1.0.200".into()));
    }

    #[test]
    fn semantic_name_crate_with_hyphen_in_name() {
        let path = PathBuf::from("/cache/serde-derive-1.0.200.crate");
        assert_eq!(semantic_name(&path), Some("serde-derive 1.0.200".into()));
    }

    #[test]
    fn semantic_name_src_directory() {
        let path = PathBuf::from("/cargo/registry/src/tokio-1.37.0");
        assert_eq!(semantic_name(&path), Some("tokio 1.37.0".into()));
    }

    #[test]
    fn semantic_name_src_dir_hyphenated_pkg() {
        let path = PathBuf::from("/cargo/registry/src/serde-json-1.0.120");
        assert_eq!(semantic_name(&path), Some("serde-json 1.0.120".into()));
    }

    #[test]
    fn semantic_name_no_version_returns_none() {
        let path = PathBuf::from("/cargo/registry/src/cache");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_plain_name_no_hyphen_returns_none() {
        let path = PathBuf::from("/cargo/registry/src/README");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn metadata_cache_dir_with_crates() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("cache");
        let sub = cache_dir.join("index.crates.io-abc");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("serde-1.0.crate"), "x").unwrap();
        std::fs::write(sub.join("tokio-1.0.crate"), "x").unwrap();
        std::fs::write(sub.join("not-a-crate.txt"), "x").unwrap();

        let fields = metadata(&cache_dir);
        assert_eq!(fields[0].label, "Contents");
        let crates_field = fields.iter().find(|f| f.label == "Crates");
        assert!(crates_field.is_some());
        assert_eq!(crates_field.unwrap().value, "2");
    }

    #[test]
    fn metadata_src_dir() {
        let path = PathBuf::from("/tmp/nonexistent/src");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("source code"));
    }
}
