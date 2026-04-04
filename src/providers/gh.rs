use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // run-log-RUNID-TIMESTAMP.zip → [run log] RUNID
    if name.starts_with("run-log-") && name.ends_with(".zip") {
        let stem = name.strip_prefix("run-log-")?.strip_suffix(".zip")?;
        if let Some(pos) = stem.find('-') {
            let run_id = &stem[..pos];
            return Some(format!("[run log] {run_id}"));
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

    if name.starts_with("run-log-") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "GitHub Actions workflow run log".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_run_log() {
        let path = PathBuf::from("/cache/gh/run-log-23703509146-1774766949.zip");
        assert_eq!(semantic_name(&path), Some("[run log] 23703509146".into()));
    }

    #[test]
    fn semantic_name_non_run_log_returns_none() {
        let path = PathBuf::from("/cache/gh/config.yml");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn metadata_run_log() {
        let path = PathBuf::from("/cache/gh/run-log-12345-67890.zip");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("Actions"));
    }
}
