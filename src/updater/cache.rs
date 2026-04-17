// `allow(dead_code)` until consumed by `check()` in Task 5.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub last_checked: String, // RFC3339
    pub latest_seen: String,
    pub html_url: String,
}

/// Reads the cache file. Returns `None` on any error (missing file,
/// malformed JSON, permission denied).
pub fn read_cache(path: &Path) -> Option<CacheEntry> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Writes the cache entry. Best-effort — returns `false` on failure.
pub fn write_cache(path: &Path, entry: &CacheEntry) -> bool {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    match serde_json::to_string(entry) {
        Ok(s) => std::fs::write(path, s).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn entry() -> CacheEntry {
        CacheEntry {
            last_checked: "2026-04-17T10:00:00Z".into(),
            latest_seen: "0.3.1".into(),
            html_url: "https://github.com/juliensimon/cache-commander/releases/tag/v0.3.1".into(),
        }
    }

    #[test]
    fn read_missing_file_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        assert_eq!(read_cache(&path), None);
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        let e = entry();
        assert!(write_cache(&path, &e));
        assert_eq!(read_cache(&path), Some(e));
    }

    #[test]
    fn write_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/dir/update-check.json");
        assert!(write_cache(&path, &entry()));
        assert!(path.exists());
    }

    #[test]
    fn read_malformed_json_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        std::fs::write(&path, "{not valid json").unwrap();
        assert_eq!(read_cache(&path), None);
    }

    #[test]
    fn read_valid_but_wrong_schema_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        std::fs::write(&path, r#"{"unrelated":"field"}"#).unwrap();
        assert_eq!(read_cache(&path), None);
    }
}
