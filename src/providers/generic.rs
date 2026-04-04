use super::MetadataField;
use std::path::Path;

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();

    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            let mut files = 0;
            let mut dirs = 0;
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().is_dir() {
                    dirs += 1;
                } else {
                    files += 1;
                }
            }
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: format!("{files} files, {dirs} directories"),
            });
        }
    }

    fields
}
