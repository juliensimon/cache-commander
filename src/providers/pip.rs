use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // pip cache uses directories like "wheels/xx/yy/hash/package-version-*.whl"
    // or "http/hash" for HTTP responses
    if name == "wheels" || name == "http" || name == "selfcheck" {
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
        "http" => {
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
