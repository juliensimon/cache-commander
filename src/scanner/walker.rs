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

/// Quick size for small directories — avoids jwalk overhead. Like `dir_size` it
/// does not follow symlinks below `path` (`path` itself may be a symlink).
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
        // `DirEntry::file_type` and `DirEntry::metadata` do not follow symlinks
        // (unlike `Path::is_file`/`is_dir`/`metadata`), so a link counts for
        // nothing, exactly as in `dir_size`. Following them measured bytes outside
        // the directory and, through links back at it, recursed to the kernel's
        // symlink limit with a branch per link.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        } else if file_type.is_dir() {
            // Recurse but only if shallow
            total += quick_size(&entry.path())?;
        }
    }
    Some(total)
}

/// Whether `path` is itself a symbolic link. Does not follow it, and a path that
/// cannot be inspected is not one.
///
/// Below a configured root a link is a leaf: it is shown, but never entered,
/// sized or read through (#92, #93), because it can point anywhere. The roots
/// themselves are exempt, since the user named them and relocating a cache
/// behind a link is common.
pub fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
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

    /// `quick_size` and `dir_size` must agree on a directory that contains
    /// symlinks, and neither may follow them: a link out of the directory would
    /// count (and read) bytes that are not in it, and a link back at it would
    /// recurse until the kernel's symlink limit, branching at every level.
    #[cfg(unix)]
    mod symlinks {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::sync::mpsc;
        use std::time::Duration;

        /// Run `f` on a thread and fail instead of hanging if it does not finish.
        fn within_ten_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(Duration::from_secs(10))
                .expect("did not finish within 10s: it is following symlinks in a loop")
        }

        #[test]
        fn quick_size_does_not_follow_symlinks_out_of_or_back_into_the_directory() {
            let tmp = tempfile::tempdir().unwrap();
            let pkg = tmp.path().join("pkg");
            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(pkg.join("a.bin"), vec![0u8; 100]).unwrap();
            std::fs::write(outside.join("secret.bin"), vec![0u8; 5000]).unwrap();
            symlink(&outside, pkg.join("escape_dir")).unwrap();
            symlink(outside.join("secret.bin"), pkg.join("escape_file")).unwrap();
            // Two links back at the directory itself: each level branches twice.
            symlink(&pkg, pkg.join("loop1")).unwrap();
            symlink(&pkg, pkg.join("loop2")).unwrap();

            let p = pkg.clone();
            assert_eq!(
                within_ten_seconds(move || quick_size(&p)),
                Some(100),
                "only the 100-byte regular file is inside the directory"
            );
            // The two walkers must agree, since callers pick one by entry count.
            assert_eq!(dir_size(&pkg), 100);
        }

        #[test]
        fn a_symlinked_root_is_still_measured_because_relocated_caches_are_common() {
            let tmp = tempfile::tempdir().unwrap();
            let real = tmp.path().join("real");
            std::fs::create_dir_all(real.join("sub")).unwrap();
            std::fs::write(real.join("sub/a.bin"), vec![0u8; 40]).unwrap();
            let linked = tmp.path().join("cache");
            symlink(&real, &linked).unwrap();
            assert_eq!(quick_size(&linked), Some(40));
            assert_eq!(dir_size(&linked), 40);
        }
    }

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
        assert!(
            !children
                .iter()
                .any(|p| p.file_name().unwrap() == "nested.txt")
        );
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
