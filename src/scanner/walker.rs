use std::path::Path;

/// Compute the total size of a directory recursively.
/// Uses jwalk with limited parallelism to avoid thread explosion
/// when multiple dir_size calls run concurrently.
pub fn dir_size(path: &Path) -> u64 {
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }

    jwalk::WalkDir::new(path)
        .skip_hidden(false)
        .parallelism(jwalk::Parallelism::RayonNewPool(2))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

/// Quick size for small directories — avoids jwalk overhead.
/// Returns None if the dir has too many entries (caller should use dir_size).
pub fn quick_size(path: &Path) -> Option<u64> {
    if path.is_file() {
        return Some(path.metadata().map(|m| m.len()).unwrap_or(0));
    }
    let entries: Vec<_> = std::fs::read_dir(path).ok()?.take(50).collect();
    if entries.len() >= 50 {
        return None; // Too many entries, use full walk
    }
    let mut total = 0u64;
    for entry in entries.into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() {
            total += p.metadata().map(|m| m.len()).unwrap_or(0);
        } else if p.is_dir() {
            // Recurse but only if shallow
            match quick_size(&p) {
                Some(s) => total += s,
                None => return None,
            }
        }
    }
    Some(total)
}

/// List immediate children of a directory.
pub fn list_children(path: &Path) -> Vec<std::path::PathBuf> {
    match std::fs::read_dir(path) {
        Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_size_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap(); // 11 bytes
        assert_eq!(dir_size(&file), 11);
    }

    #[test]
    fn dir_size_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "aaaa").unwrap(); // 4
        std::fs::write(tmp.path().join("b.txt"), "bb").unwrap(); // 2
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("c.txt"), "ccc").unwrap(); // 3
        assert_eq!(dir_size(tmp.path()), 9);
    }

    #[test]
    fn dir_size_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(dir_size(tmp.path()), 0);
    }

    #[test]
    fn dir_size_nonexistent_returns_zero() {
        assert_eq!(dir_size(Path::new("/nonexistent/path/12345")), 0);
    }

    #[test]
    fn list_children_returns_immediate_entries() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file1.txt"), "").unwrap();
        std::fs::write(tmp.path().join("file2.txt"), "").unwrap();
        let sub = tmp.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("nested.txt"), "").unwrap();

        let children = list_children(tmp.path());
        assert_eq!(children.len(), 3); // file1, file2, subdir
                                       // nested.txt should NOT appear
        assert!(!children
            .iter()
            .any(|p| p.file_name().unwrap() == "nested.txt"));
    }

    #[test]
    fn list_children_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(list_children(tmp.path()).is_empty());
    }

    #[test]
    fn list_children_nonexistent_returns_empty() {
        assert!(list_children(Path::new("/nonexistent/path/12345")).is_empty());
    }

    #[test]
    fn list_children_includes_hidden_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".hidden"), "").unwrap();
        std::fs::write(tmp.path().join("visible"), "").unwrap();

        let children = list_children(tmp.path());
        assert_eq!(children.len(), 2);
    }
}
