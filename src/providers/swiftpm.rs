// SwiftPM provider.
//
// No `package_id` / `upgrade_command` arms — SwiftPM's package identity
// requires git-ref parsing that is too brittle for v1, and there's no
// public registry for version lookups. OSV `SwiftURL` coverage is
// sparse. Tier-3 E2E tests are intentionally exempt (see design spec
// 2026-04-20-swiftpm-xcode-providers-design.md).

use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Skip the three known subdir roots themselves — tree renders them
    // literally.
    if matches!(name.as_str(), "repositories" | "artifacts" | "manifests") {
        return None;
    }

    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match parent_name.as_str() {
        "repositories" => Some(strip_hash_suffix(&name)),
        "artifacts" => Some(name),
        // manifests/ holds files whose names are internal hashes — no
        // meaningful display, fall back to raw file name via None (tree
        // shows the basename anyway).
        "manifests" => None,
        _ => None,
    }
}

/// Strip a trailing `-<hex>` where hex is 7 or more lowercase-hex chars.
/// Returns the input unchanged if no such suffix exists.
fn strip_hash_suffix(s: &str) -> String {
    let Some(dash_idx) = s.rfind('-') else {
        return s.to_string();
    };
    let suffix = &s[dash_idx + 1..];
    if suffix.len() >= 7
        && suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        s[..dash_idx].to_string()
    } else {
        s.to_string()
    }
}

pub fn metadata(_path: &Path) -> Vec<MetadataField> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_strips_hash_suffix_from_repository() {
        let path = PathBuf::from(
            "/Users/j/Library/Caches/org.swift.swiftpm/repositories/swift-collections-abc1234",
        );
        assert_eq!(semantic_name(&path), Some("swift-collections".into()));
    }

    #[test]
    fn semantic_name_strips_long_hash_suffix() {
        let path = PathBuf::from(
            "/Users/j/Library/Caches/org.swift.swiftpm/repositories/swift-nio-0123456789abcdef",
        );
        assert_eq!(semantic_name(&path), Some("swift-nio".into()));
    }

    #[test]
    fn semantic_name_passes_through_artifacts_dir() {
        let path = PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/artifacts/MyBinaryDep");
        assert_eq!(semantic_name(&path), Some("MyBinaryDep".into()));
    }

    #[test]
    fn semantic_name_returns_none_for_manifests_file() {
        // manifest filenames are internal hashes; no meaningful display.
        let path =
            PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/manifests/deadbeef1234");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_returns_none_for_known_subdir_roots() {
        for subdir in ["repositories", "artifacts", "manifests"] {
            let path = PathBuf::from(format!(
                "/Users/j/Library/Caches/org.swift.swiftpm/{subdir}"
            ));
            assert_eq!(semantic_name(&path), None, "{subdir}");
        }
    }

    #[test]
    fn semantic_name_handles_non_ascii_package_name() {
        // L2: no byte-boundary panic on multi-byte package names.
        let path =
            PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/repositories/café-abc1234");
        assert_eq!(semantic_name(&path), Some("café".into()));
    }

    #[test]
    fn semantic_name_falls_back_to_dirname_without_hash_suffix() {
        let path =
            PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/repositories/plain-name");
        assert_eq!(semantic_name(&path), Some("plain-name".into()));
    }
}
