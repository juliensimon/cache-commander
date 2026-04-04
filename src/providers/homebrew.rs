use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    match name.as_str() {
        "downloads" => Some("Downloaded Bottles".to_string()),
        "Cask" => Some("Cask Downloads".to_string()),
        "api" => Some("API Cache".to_string()),
        "bootsnap" => Some("Bootsnap Cache".to_string()),
        _ => None,
    }
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match name.as_str() {
        "downloads" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded package bottles (.tar.gz)".to_string(),
            });
            if let Ok(entries) = std::fs::read_dir(path) {
                let count = entries.filter_map(|e| e.ok()).count();
                fields.push(MetadataField {
                    label: "Bottles".to_string(),
                    value: count.to_string(),
                });
            }
        }
        "Cask" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Downloaded cask installers".to_string(),
            });
        }
        "api" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "Homebrew formula/cask API cache".to_string(),
            });
        }
        _ => {}
    }

    fields
}
