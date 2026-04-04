use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    if !name.starts_with("repo") {
        return None;
    }

    // Try git remote to get the repo URL → extract org/name
    if let Some(repo_name) = repo_name_from_git_remote(path) {
        return Some(repo_name);
    }

    // Try .pre-commit-hooks.yaml for the hook name
    if let Some(hook_name) = hook_name_from_config(path) {
        return Some(hook_name);
    }

    None
}

fn repo_name_from_git_remote(path: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["-C", &path.to_string_lossy(), "remote", "get-url", "origin"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // https://github.com/org/repo.git → org/repo
    // https://github.com/org/repo     → org/repo
    let cleaned = url.strip_suffix(".git").unwrap_or(&url);

    // Extract last two path segments
    let parts: Vec<&str> = cleaned.rsplitn(3, '/').collect();
    if parts.len() >= 2 {
        Some(format!("{}/{}", parts[1], parts[0]))
    } else {
        None
    }
}

fn hook_name_from_config(path: &Path) -> Option<String> {
    let hooks_file = path.join(".pre-commit-hooks.yaml");
    let content = std::fs::read_to_string(hooks_file).ok()?;
    // Simple YAML: find first "name: ..." line
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("name:") {
            let name = name.trim().trim_matches('"').trim_matches('\'');
            if !name.is_empty() {
                return Some(name.to_string());
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

    if name.starts_with("repo") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "pre-commit hook repository".to_string(),
        });

        // Show the remote URL
        if let Some(url) = git_remote_url(path) {
            fields.push(MetadataField {
                label: "Remote".to_string(),
                value: url,
            });
        }
    }

    fields
}

fn git_remote_url(path: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["-C", &path.to_string_lossy(), "remote", "get-url", "origin"])
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_non_repo_returns_none() {
        let path = PathBuf::from("/cache/pre-commit/patch12345");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_repo_with_hooks_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo_test");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            repo.join(".pre-commit-hooks.yaml"),
            "- id: mycheck\n  name: My Check Tool\n  entry: mycheck\n",
        )
        .unwrap();

        let result = semantic_name(&repo);
        assert_eq!(result, Some("My Check Tool".into()));
    }

    #[test]
    fn hook_name_extracts_first_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".pre-commit-hooks.yaml"),
            "- id: a\n  name: First Hook\n- id: b\n  name: Second Hook\n",
        )
        .unwrap();
        assert_eq!(hook_name_from_config(&dir), Some("First Hook".into()));
    }
}
