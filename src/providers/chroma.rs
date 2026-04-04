use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    if name == "onnx_models" {
        return Some("Embedding Models".to_string());
    }
    if name == "onnx" {
        return Some("ONNX Runtime".to_string());
    }

    // Model directories inside onnx_models/
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if parent_name == "onnx_models" {
        return Some(format!("[embed] {name}"));
    }

    None
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name == "onnx_models" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "ONNX embedding models for vector similarity".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_onnx_models() {
        let path = PathBuf::from("/cache/chroma/onnx_models");
        assert_eq!(semantic_name(&path), Some("Embedding Models".into()));
    }

    #[test]
    fn semantic_name_model_dir() {
        let path = PathBuf::from("/cache/chroma/onnx_models/all-MiniLM-L6-v2");
        assert_eq!(
            semantic_name(&path),
            Some("[embed] all-MiniLM-L6-v2".into())
        );
    }
}
