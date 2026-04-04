use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // hub/checkpoints/mobilenet_v2-b0353104.pth → [checkpoint] mobilenet_v2
    if name.ends_with(".pth") || name.ends_with(".pt") {
        let stem = name.rsplitn(2, '.').last()?;
        // Split on last hyphen to separate model name from hash
        if let Some(pos) = stem.rfind('-') {
            let model = &stem[..pos];
            let hash = &stem[pos + 1..];
            if hash.len() >= 6 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(format!("[checkpoint] {model}"));
            }
        }
        return Some(format!("[checkpoint] {stem}"));
    }

    // hub/ dir itself
    if name == "checkpoints" {
        return Some("Model Checkpoints".to_string());
    }

    None
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    if name.ends_with(".pth") || name.ends_with(".pt") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "PyTorch model checkpoint".to_string(),
        });
    } else if name == "checkpoints" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Pre-trained model weight files".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_pth_with_hash() {
        let path = PathBuf::from("/cache/torch/hub/checkpoints/mobilenet_v2-b0353104.pth");
        assert_eq!(semantic_name(&path), Some("[checkpoint] mobilenet_v2".into()));
    }

    #[test]
    fn semantic_name_pt_file() {
        let path = PathBuf::from("/cache/torch/hub/checkpoints/resnet50-0676ba61.pth");
        assert_eq!(semantic_name(&path), Some("[checkpoint] resnet50".into()));
    }

    #[test]
    fn semantic_name_checkpoints_dir() {
        let path = PathBuf::from("/cache/torch/hub/checkpoints");
        assert_eq!(semantic_name(&path), Some("Model Checkpoints".into()));
    }

    #[test]
    fn semantic_name_other_returns_none() {
        let path = PathBuf::from("/cache/torch/hub/README");
        assert_eq!(semantic_name(&path), None);
    }
}
