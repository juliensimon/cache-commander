use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // master/ or main/ branch dirs
    if name == "master" || name == "main" {
        return Some(format!("[branch] {name}"));
    }

    // Commit hash dirs inside master/
    if name.len() == 40 && name.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(format!("[engine] {}", &name[..8]));
    }

    // Platform dirs: darwin-arm64, linux-x64, etc.
    if name.contains('-')
        && (name.starts_with("darwin") || name.starts_with("linux") || name.starts_with("windows"))
    {
        return Some(format!("[platform] {name}"));
    }

    None
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name.len() == 40 && name.chars().all(|c| c.is_ascii_hexdigit()) {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Prisma engine binary release".to_string(),
        });
        fields.push(MetadataField {
            label: "Commit".to_string(),
            value: name,
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_master() {
        let path = PathBuf::from("/cache/prisma/master");
        assert_eq!(semantic_name(&path), Some("[branch] master".into()));
    }

    #[test]
    fn semantic_name_commit_hash() {
        let path = PathBuf::from("/cache/prisma/master/0c8ef2ce45c83248ab3df073180d5eda9e8be7a3");
        assert_eq!(semantic_name(&path), Some("[engine] 0c8ef2ce".into()));
    }

    #[test]
    fn semantic_name_platform() {
        let path = PathBuf::from("/cache/prisma/master/abc123/darwin-arm64");
        assert_eq!(semantic_name(&path), Some("[platform] darwin-arm64".into()));
    }
}
