use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    match name.as_str() {
        "_cacache" => Some("Content Cache".to_string()),
        "_logs" => Some("Install Logs".to_string()),
        "_npx" => Some("npx Cache".to_string()),
        _ => {
            // Hash directories inside _npx: read package.json for package name
            if path.is_dir() {
                if let Some(pkg) = npx_package_name(path) {
                    return Some(pkg);
                }
            }
            None
        }
    }
}

/// Read package.json inside an npx hash dir to find the package name.
fn npx_package_name(path: &Path) -> Option<String> {
    let pkg_json = path.join("package.json");
    let content = std::fs::read_to_string(pkg_json).ok()?;

    // Look for "_npx": { "packages": ["name"] }
    // Simple JSON parsing without a dependency
    if let Some(npx_pos) = content.find("\"_npx\"") {
        let rest = &content[npx_pos..];
        if let Some(pkg_pos) = rest.find("\"packages\"") {
            let pkg_rest = &rest[pkg_pos..];
            // Find the array contents
            if let Some(bracket_start) = pkg_rest.find('[') {
                if let Some(bracket_end) = pkg_rest.find(']') {
                    let array_str = &pkg_rest[bracket_start + 1..bracket_end];
                    let packages: Vec<&str> = array_str
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').trim())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if packages.len() == 1 {
                        return Some(format!("[npx] {}", packages[0]));
                    } else if packages.len() > 1 {
                        return Some(format!(
                            "[npx] {} (+{} more)",
                            packages[0],
                            packages.len() - 1
                        ));
                    }
                }
            }
        }
    }

    // Fallback: look at dependencies
    if let Some(deps_pos) = content.find("\"dependencies\"") {
        let rest = &content[deps_pos..];
        if let Some(brace_start) = rest.find('{') {
            if let Some(brace_end) = rest.find('}') {
                let deps_str = &rest[brace_start + 1..brace_end];
                let dep_names: Vec<&str> = deps_str
                    .split(',')
                    .filter_map(|entry| {
                        let parts: Vec<&str> = entry.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            Some(parts[0].trim().trim_matches('"').trim())
                        } else {
                            None
                        }
                    })
                    .filter(|s| !s.is_empty())
                    .collect();
                if dep_names.len() == 1 {
                    return Some(format!("[npx] {}", dep_names[0]));
                } else if dep_names.len() > 1 {
                    return Some(format!(
                        "[npx] {} (+{} more)",
                        dep_names[0],
                        dep_names.len() - 1
                    ));
                }
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

    match name.as_str() {
        "_cacache" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "npm content-addressable cache".to_string(),
            });
            let content_dir = path.join("content-v2");
            if content_dir.exists() {
                fields.push(MetadataField {
                    label: "Format".to_string(),
                    value: "content-v2 + index-v5".to_string(),
                });
            }
        }
        "_logs" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "npm install/update logs".to_string(),
            });
            if let Ok(entries) = std::fs::read_dir(path) {
                let count = entries.filter_map(|e| e.ok()).count();
                fields.push(MetadataField {
                    label: "Log files".to_string(),
                    value: count.to_string(),
                });
            }
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
    fn semantic_name_cacache() {
        assert_eq!(semantic_name(&PathBuf::from("/npm/_cacache")), Some("Content Cache".into()));
    }

    #[test]
    fn semantic_name_npx() {
        assert_eq!(semantic_name(&PathBuf::from("/npm/_npx")), Some("npx Cache".into()));
    }

    #[test]
    fn semantic_name_npx_hash_with_package() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("abc123");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{"dependencies":{"lighthouse":"^12"},"_npx":{"packages":["lighthouse"]}}"#,
        ).unwrap();

        assert_eq!(semantic_name(&hash_dir), Some("[npx] lighthouse".into()));
    }

    #[test]
    fn semantic_name_npx_hash_with_multiple_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("def456");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{"_npx":{"packages":["create-react-app","typescript"]}}"#,
        ).unwrap();

        let result = semantic_name(&hash_dir).unwrap();
        assert!(result.contains("[npx] create-react-app"), "{}", result);
        assert!(result.contains("+1 more"), "{}", result);
    }

    #[test]
    fn semantic_name_npx_hash_no_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("xyz");
        std::fs::create_dir_all(&hash_dir).unwrap();
        assert_eq!(semantic_name(&hash_dir), None);
    }
}
