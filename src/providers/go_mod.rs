// Go module cache + build cache provider.
//
// Two logical caches under one CacheKind::Go:
// - Module cache (`$GOMODCACHE`, default `~/go/pkg/mod`): Safe.
//   Tarballs at `cache/download/<module>/@v/<version>.zip` plus extracted
//   copies at `pkg/mod/<module>@<version>/`. Go chmod -w's the extracted
//   tree, which is why this provider ships a pre_delete hook.
// - Build cache (`$GOCACHE`, default `~/Library/Caches/go-build` on
//   macOS, `~/.cache/go-build` on Linux): Caution (cold rebuild cost).

use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Build cache entries are opaque content-addressed hex blobs; no
    // meaningful semantic name.
    if path_has_component(path, "go-build") {
        return None;
    }

    // sumdb entries under cache/download/ are internal checksum data;
    // the user has no use for per-file names there.
    if path_has_component(path, "sumdb") {
        return None;
    }

    // Known cache-root names render literally.
    if matches!(name.as_str(), "mod" | "go-build") {
        return None;
    }

    // Module zip in the canonical download layout:
    // .../cache/download/<module>/@v/<version>.zip
    if let Some((module, version)) = parse_download_zip(path) {
        return Some(format!("{module} {version}"));
    }

    // Extracted module directory: .../pkg/mod/<module>@<version>
    if let Some((module, version)) = parse_extracted_module_dir(path) {
        return Some(format!("{module} {version}"));
    }

    None
}

fn path_has_component(path: &Path, target: &str) -> bool {
    path.components().any(|c| c.as_os_str() == target)
}

/// Parse `.../cache/download/<module-path>/@v/<version>.zip` into
/// `(decoded-module, version)`. The module path is the chain of
/// components between `download/` and `@v/`, joined by `/`.
fn parse_download_zip(path: &Path) -> Option<(String, String)> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let version = name.strip_suffix(".zip")?.to_string();

    // Immediate parent must be `@v`.
    let mut ancestors = path.ancestors();
    ancestors.next(); // skip the file itself
    let at_v = ancestors.next()?;
    if at_v.file_name()?.to_string_lossy() != "@v" {
        return None;
    }

    // Walk up from `@v`'s parent to the `download` marker, collecting
    // module-path components.
    let mut components: Vec<String> = Vec::new();
    let mut current = at_v.parent()?;
    loop {
        let comp = current.file_name()?.to_string_lossy().to_string();
        if comp == "download" {
            break;
        }
        components.push(decode_module_path(&comp));
        current = current.parent()?;
    }
    if components.is_empty() {
        return None;
    }
    components.reverse();
    Some((components.join("/"), version))
}

/// Parse `.../pkg/mod/<module-path>@<version>` (extracted source dir)
/// into `(decoded-module, version)`. Last component carries `@`; the
/// module path may span multiple parent components above `pkg/mod`.
fn parse_extracted_module_dir(path: &Path) -> Option<(String, String)> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let (last_module_part, version) = name.split_once('@')?;
    if version.is_empty() {
        return None;
    }

    // Parent chain up to `mod` (under `pkg`) carries the rest of the
    // module path.
    let mut components: Vec<String> = vec![decode_module_path(last_module_part)];
    let mut current = path.parent()?;
    loop {
        let comp_name = current.file_name()?.to_string_lossy().to_string();
        if comp_name == "mod" {
            let grandparent = current.parent()?;
            if grandparent.file_name()?.to_string_lossy() == "pkg" {
                break;
            } else {
                return None; // `mod/` not under `pkg/` — not the Go layout.
            }
        }
        components.push(decode_module_path(&comp_name));
        current = current.parent()?;
    }
    components.reverse();
    Some((components.join("/"), version.to_string()))
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match name.as_str() {
        "mod" if parent_name == "pkg" => {
            fields.push(MetadataField {
                label: "Contents".into(),
                value: "Module cache (re-downloadable from proxy.golang.org / VCS)".into(),
            });
        }
        "go-build" => {
            fields.push(MetadataField {
                label: "Contents".into(),
                value: "Build cache (rebuildable, cold rebuild is minutes on large repos)".into(),
            });
        }
        "sumdb" if parent_name == "download" => {
            fields.push(MetadataField {
                label: "Contents".into(),
                value: "Module checksum database (authoritative; re-downloadable)".into(),
            });
        }
        _ => {}
    }

    fields
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    // Dedup canonical file (L9): `cache/download/<module>/@v/<version>.{zip,info,mod,ziphash}`
    // produces four sibling files per package. Only `.zip` is the
    // identity source — the others sit alongside.
    let name = path.file_name()?.to_string_lossy().to_string();
    if !name.ends_with(".zip") {
        return None;
    }
    // sumdb entries live under cache/download/ but aren't packages.
    if path_has_component(path, "sumdb") {
        return None;
    }
    let (module, version) = parse_download_zip(path)?;
    Some(super::PackageId {
        ecosystem: "Go",
        name: module,
        version,
    })
}

/// Prepare a subtree under the Go cache for deletion by stripping
/// read-only flags. Go `chmod -R -w`'s the extracted module tree
/// (`pkg/mod/<module>@<version>/`), so `remove_dir_all` fails without
/// this step.
///
/// On the build cache (`go-build/`) this is a no-op because Go keeps
/// those files writable — but we still walk safely: any per-entry
/// chmod failure is swallowed (the subsequent remove_dir_all will
/// produce the more informative error). A missing path is OK too —
/// the caller surfaces the real error.
pub fn pre_delete(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    chmod_plus_w_recursive(path);
    Ok(())
}

#[cfg(unix)]
fn chmod_plus_w_recursive(path: &Path) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    // Set the entry itself writable first so we can descend into it.
    if let Ok(metadata) = fs::symlink_metadata(path) {
        let mode = metadata.permissions().mode();
        // Add owner write (0o200). Leave group/other bits untouched.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200));
        if metadata.is_dir()
            && let Ok(entries) = fs::read_dir(path)
        {
            for entry in entries.flatten() {
                chmod_plus_w_recursive(&entry.path());
            }
        }
    }
}

#[cfg(not(unix))]
fn chmod_plus_w_recursive(_path: &Path) {
    // Windows / other platforms: Go doesn't ship on the unsupported
    // ones we care about, and std::fs::remove_dir_all on Windows
    // handles read-only files via a compatibility path since Rust
    // 1.77. Leave this as a no-op rather than maintain a parallel
    // implementation.
}

/// Decode Go's on-disk bang-escape scheme for module paths.
/// `!<lowercase>` → uppercase, so `github.com/!uber/zap` → `github.com/Uber/zap`.
/// Any `!` not followed by a lowercase ASCII letter passes through unchanged.
fn decode_module_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '!' {
            match chars.peek() {
                Some(&next) if next.is_ascii_lowercase() => {
                    out.push(next.to_ascii_uppercase());
                    chars.next();
                }
                _ => out.push('!'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_module_path_single_uppercase() {
        // Go only bang-escapes uppercase letters, one `!` per uppercase.
        // `Uber` → on-disk `!uber`; `UBer` → `!u!ber`.
        assert_eq!(decode_module_path("!uber"), "Uber");
        assert_eq!(decode_module_path("!u!ber"), "UBer");
    }

    #[test]
    fn decode_module_path_in_real_module_path() {
        assert_eq!(
            decode_module_path("github.com/!golang/!mock"),
            "github.com/Golang/Mock"
        );
    }

    #[test]
    fn decode_module_path_trailing_lone_bang_passes_through() {
        // Not a valid escape; preserve the trailing `!` rather than
        // panicking.
        assert_eq!(decode_module_path("github.com/foo!"), "github.com/foo!");
    }

    #[test]
    fn decode_module_path_non_ascii_passes_through() {
        // L2: multi-byte chars must not panic. Bang-escape only applies
        // to uppercase ASCII; other codepoints pass through untouched.
        assert_eq!(decode_module_path("github.com/café"), "github.com/café");
    }

    #[test]
    fn decode_module_path_bang_followed_by_non_letter_passes_through() {
        // `!-` isn't a valid bang-escape; preserve literally.
        assert_eq!(decode_module_path("foo!-bar"), "foo!-bar");
    }

    #[test]
    fn decode_module_path_empty_string() {
        assert_eq!(decode_module_path(""), "");
    }

    use std::path::PathBuf;

    // --- semantic_name ---

    #[test]
    fn semantic_name_module_zip() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.zip",
        );
        assert_eq!(
            semantic_name(&path),
            Some("github.com/stretchr/testify v1.8.4".into())
        );
    }

    #[test]
    fn semantic_name_module_zip_decodes_bang_escape() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/!uber-go/zap/@v/v1.27.0.zip",
        );
        assert_eq!(
            semantic_name(&path),
            Some("github.com/Uber-go/zap v1.27.0".into())
        );
    }

    #[test]
    fn semantic_name_extracted_module_dir() {
        let path = PathBuf::from("/Users/j/go/pkg/mod/github.com/stretchr/testify@v1.8.4");
        assert_eq!(
            semantic_name(&path),
            Some("github.com/stretchr/testify v1.8.4".into())
        );
    }

    #[test]
    fn semantic_name_extracted_module_dir_decodes_bang_escape() {
        let path = PathBuf::from("/Users/j/go/pkg/mod/github.com/!uber-go/zap@v1.27.0");
        assert_eq!(
            semantic_name(&path),
            Some("github.com/Uber-go/zap v1.27.0".into())
        );
    }

    #[test]
    fn semantic_name_info_file_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.info",
        );
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_mod_file_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.mod",
        );
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_ziphash_file_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.ziphash",
        );
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_sumdb_file_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/sumdb/sum.golang.org/lookup/github.com/foo/bar@v1.0.0",
        );
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_build_cache_entry_returns_none() {
        let path = PathBuf::from("/Users/j/Library/Caches/go-build/ab/abcdef123456-d");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_known_roots_return_none() {
        for p in ["/Users/j/go/pkg/mod", "/Users/j/Library/Caches/go-build"] {
            assert_eq!(semantic_name(&PathBuf::from(p)), None, "{p}");
        }
    }

    // --- package_id ---

    #[test]
    fn package_id_from_zip() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.zip",
        );
        let id = package_id(&path).expect("expected PackageId");
        assert_eq!(id.ecosystem, "Go");
        assert_eq!(id.name, "github.com/stretchr/testify");
        assert_eq!(id.version, "v1.8.4");
    }

    #[test]
    fn package_id_module_path_is_decoded() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/!uber-go/zap/@v/v1.27.0.zip",
        );
        let id = package_id(&path).expect("expected PackageId");
        assert_eq!(id.name, "github.com/Uber-go/zap");
        assert_eq!(id.version, "v1.27.0");
    }

    #[test]
    fn package_id_from_info_returns_none() {
        // L9: dedup canonical-file guard — only .zip produces a PackageId.
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.info",
        );
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_from_mod_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.mod",
        );
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_from_ziphash_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.ziphash",
        );
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_from_extracted_dir_returns_none() {
        // Extracted dir shares the same (module, version); counting it
        // would double-count. Only the .zip produces identity.
        let path = PathBuf::from("/Users/j/go/pkg/mod/github.com/stretchr/testify@v1.8.4");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_from_build_cache_entry_returns_none() {
        let path = PathBuf::from("/Users/j/Library/Caches/go-build/ab/abcdef-d");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_from_sumdb_returns_none() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/sumdb/sum.golang.org/lookup/github.com/foo/bar@v1.0.0",
        );
        assert_eq!(package_id(&path), None);
    }

    // --- metadata ---

    #[test]
    fn metadata_pkg_mod_root_reports_contents() {
        let path = PathBuf::from("/Users/j/go/pkg/mod");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Contents" && f.value.contains("Module cache")),
            "got {fields:?}"
        );
    }

    #[test]
    fn metadata_go_build_root_reports_contents() {
        let path = PathBuf::from("/Users/j/Library/Caches/go-build");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Contents" && f.value.contains("Build cache")),
            "got {fields:?}"
        );
    }

    #[test]
    fn metadata_sumdb_reports_contents() {
        let path = PathBuf::from("/Users/j/go/pkg/mod/cache/download/sumdb");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Contents" && f.value.contains("checksum")),
            "got {fields:?}"
        );
    }

    #[test]
    fn metadata_leaf_file_returns_empty() {
        let path = PathBuf::from(
            "/Users/j/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.8.4.zip",
        );
        assert!(metadata(&path).is_empty());
    }

    // --- pre_delete ---
    //
    // Go chmod -w's the extracted module tree (cache/download/ keeps
    // its zips writable). Without a pre-delete +w walk,
    // remove_dir_all fails on those directories.

    #[cfg(unix)]
    #[test]
    fn pre_delete_chmods_read_only_module_subtree() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let module_dir = tmp
            .path()
            .join("pkg/mod/github.com/stretchr/testify@v1.8.4");
        fs::create_dir_all(&module_dir).unwrap();
        let file = module_dir.join("README.md");
        fs::write(&file, "readme").unwrap();

        // Simulate Go's chmod -R -w on the module tree.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&module_dir, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            !file.metadata().unwrap().permissions().readonly() == false,
            "sanity: file should be read-only before pre_delete runs"
        );
        // (Write flag is off on the file.)
        assert!(fs::write(&file, "still writable?").is_err());

        // Run the hook.
        assert!(pre_delete(&module_dir).is_ok());

        // Now both dir and file should be writable; remove_dir_all should succeed.
        assert!(fs::write(&file, "ok now").is_ok());
        assert!(fs::remove_dir_all(&module_dir).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn pre_delete_on_build_cache_path_is_noop() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let build_dir = tmp.path().join("Library/Caches/go-build/ab");
        fs::create_dir_all(&build_dir).unwrap();
        let file = build_dir.join("abcdef-d");
        fs::write(&file, "").unwrap();
        // Should succeed and not mess with permissions.
        assert!(pre_delete(&build_dir).is_ok());
    }

    #[test]
    fn pre_delete_on_nonexistent_path_is_ok() {
        // Don't error on paths that don't exist — the caller is about
        // to try remove_dir_all anyway and that will produce a more
        // informative error if the path truly is wrong.
        let tmp = tempfile::tempdir().unwrap();
        let ghost = tmp.path().join("pkg/mod/does-not-exist");
        assert!(pre_delete(&ghost).is_ok());
    }
}
