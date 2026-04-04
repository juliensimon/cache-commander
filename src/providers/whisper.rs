use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    if name.ends_with(".pt") {
        let model = name.strip_suffix(".pt")?;
        let formatted = model
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(c) => format!("{}{}", c.to_uppercase(), chars.as_str()),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        return Some(format!("Whisper {formatted}"));
    }

    None
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name.ends_with(".pt") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "OpenAI Whisper model weights".to_string(),
        });
        fields.push(MetadataField {
            label: "Format".to_string(),
            value: "PyTorch checkpoint (.pt)".to_string(),
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_large_v3() {
        let path = PathBuf::from("/cache/whisper/large-v3.pt");
        assert_eq!(semantic_name(&path), Some("Whisper Large V3".into()));
    }

    #[test]
    fn semantic_name_medium() {
        let path = PathBuf::from("/cache/whisper/medium.pt");
        assert_eq!(semantic_name(&path), Some("Whisper Medium".into()));
    }

    #[test]
    fn semantic_name_tiny_en() {
        let path = PathBuf::from("/cache/whisper/tiny.en.pt");
        // .en.pt — file_name is "tiny.en.pt", ends with ".pt"
        // strip_suffix gives "tiny.en", split by '-' gives ["tiny.en"]
        assert_eq!(semantic_name(&path), Some("Whisper Tiny.en".into()));
    }

    #[test]
    fn semantic_name_non_pt_returns_none() {
        let path = PathBuf::from("/cache/whisper/README.md");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn metadata_pt_file() {
        let path = PathBuf::from("/cache/whisper/large-v3.pt");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].label, "Type");
        assert!(fields[0].value.contains("Whisper"));
        assert_eq!(fields[1].label, "Format");
        assert!(fields[1].value.contains(".pt"));
    }

    #[test]
    fn metadata_non_pt_is_empty() {
        let path = PathBuf::from("/cache/whisper/config.json");
        assert!(metadata(&path).is_empty());
    }
}
