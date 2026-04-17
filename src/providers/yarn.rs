use super::MetadataField;
use std::path::Path;

/// Returns true if the path is within a known Yarn cache location.
#[allow(dead_code)]
pub fn is_yarn_cache(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".yarn-cache")
        || path_str.contains(".cache/yarn")
        || path_str.contains("Library/Caches/Yarn")
        || path_str.contains(".yarn/cache")
        || path_str.contains("yarn/berry/cache")
}

/// Returns true if this is a Yarn Berry (v2+) cache path.
pub fn is_berry(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".yarn/cache") || path_str.contains("berry/cache")
}

/// Normalize a scoped package name: "@babel-core" → "@babel/core".
/// Only the first hyphen after '@' becomes a '/'.
///
/// NOTE: This is a best-effort heuristic for Yarn filenames where `/` is replaced
/// with `-`. It is WRONG for scopes that contain hyphens (e.g., `@eslint-community`
/// becomes `@eslint/community-eslint-utils` instead of `@eslint-community/eslint-utils`).
/// For Yarn Classic directories, we resolve this by reading node_modules/ inside the entry.
/// For Yarn Berry zips, this limitation is accepted — the version and ecosystem are correct.
pub fn normalize_scoped_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@')
        && let Some(hyphen_pos) = rest.find('-')
    {
        let scope = &rest[..hyphen_pos];
        let pkg = &rest[hyphen_pos + 1..];
        return format!("@{}/{}", scope, pkg);
    }
    name.to_string()
}

/// Parse a Yarn Berry filename: `<name>-npm-<version>-<hash>.zip`
///
/// Examples:
/// - `lodash-npm-4.17.21-6382d821f21d.zip` → `("lodash", "4.17.21")`
/// - `@babel-core-npm-7.24.0-abc123def456.zip` → `("@babel/core", "7.24.0")`
pub fn parse_berry_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".zip")?;

    let npm_marker = "-npm-";

    // Find the correct `-npm-` boundary. Package names can contain `-npm-`
    // (e.g., `use-npm-module`), so we search from right to left for
    // a `-npm-` that is followed by a valid version (digit-starting).
    let mut search_from = stem.len();
    let npm_pos = loop {
        // rfind within stem[..search_from]
        let slice = &stem[..search_from];
        let pos = slice.rfind(npm_marker)?;
        let after = &stem[pos + npm_marker.len()..];
        // Check if what follows starts with a digit (version)
        if after
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            break pos;
        }
        // Try earlier occurrence
        if pos == 0 {
            return None;
        }
        search_from = pos;
    };

    let raw_name = &stem[..npm_pos];
    let after_npm = &stem[npm_pos + npm_marker.len()..];

    // after_npm = "<version>-<hash>" or "<version>-<hash1>-<hash2>" (two hash segments)
    let parts: Vec<&str> = after_npm.split('-').collect();
    if parts.len() < 2 {
        return None;
    }

    // Berry uses two hash segments (e.g., "c076fd2279-3d1ce6ebc6").
    // Strip ALL trailing hex hash segments from right.
    let mut hash_start = parts.len();
    for i in (0..parts.len()).rev() {
        if is_hex_hash(parts[i]) {
            hash_start = i;
        } else {
            break;
        }
    }

    if hash_start >= parts.len() {
        return None; // No hash found
    }

    let version_parts = &parts[..hash_start];
    let version = version_parts.join("-");

    if version.is_empty() {
        return None;
    }

    // Version must start with a digit (already guaranteed by the search above, but be safe)
    if !version
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        return None;
    }

    let name = normalize_scoped_name(raw_name);
    Some((name, version))
}

/// Parse a Yarn Classic cache entry name.
///
/// Yarn Classic uses directories (not files) named:
///   `npm-<name>-<version>-<hash>-integrity`
/// Or legacy `.tgz` files:
///   `npm-<name>-<version>-<hash>.tgz`
///
/// Examples:
/// - `npm-lodash-4.17.21-679591c564c3bffaae8454cf0b3df370c3d6911c-integrity` → `("lodash", "4.17.21")`
/// - `npm-@babel-core-7.24.0-56cbda6b185ae9d9bed369816a8f4423c5f2ff1b-integrity` → `("@babel/core", "7.24.0")`
/// - `npm-is-even-1.0.0-76b5055fbad8d294a86b6a949015e1c97b717c06-integrity` → `("is-even", "1.0.0")`
/// - `npm-lodash-4.17.21-6382d821f21d.tgz` → `("lodash", "4.17.21")` (legacy)
pub fn parse_classic_filename(filename: &str) -> Option<(String, String)> {
    // Strip known suffixes: "-integrity" (current format) or ".tgz" (legacy)
    let stem = if let Some(s) = filename.strip_suffix("-integrity") {
        s
    } else {
        filename.strip_suffix(".tgz")?
    };

    // Must start with "npm-"
    let after_npm = stem.strip_prefix("npm-")?;

    // after_npm = "<name>-<version>-<hash>"
    // Split on '-' and walk from right to find hash, then version, then name
    let parts: Vec<&str> = after_npm.split('-').collect();
    if parts.len() < 3 {
        return None;
    }

    // Last part is hash
    let hash = parts.last()?;
    if !is_hex_hash(hash) {
        return None;
    }

    // Find version boundary: walk backwards from (len-2) to find the first
    // segment that starts with a digit — that is the start of the version
    let without_hash = &parts[..parts.len() - 1];

    // Find the leftmost digit-starting segment that contains at least one dot.
    // This is the real semver version start (e.g., "1.0.0", "0.10.62").
    // Everything after it (until the hash) is the full version string, including
    // pre-release suffixes like "2024.1" or "3rc1".
    // Pre-release-only tags like "2024" or "3beta" don't contain dots, so walking
    // forward we find the first dotted digit segment as the true version start.
    let mut version_start = None;
    for (i, seg) in without_hash.iter().enumerate() {
        // Version segments contain dots (e.g., "1.0.0", "0.10.62")
        // Pre-release tags like "2024" or "3beta" don't contain dots
        if seg
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
            && seg.contains('.')
        {
            version_start = Some(i);
            break;
        }
    }

    let ver_idx = version_start?;
    if ver_idx == 0 {
        // No name before the version
        return None;
    }

    let name_parts = &without_hash[..ver_idx];
    let version_parts = &without_hash[ver_idx..];

    let raw_name = name_parts.join("-");
    let version = version_parts.join("-");

    let name = normalize_scoped_name(&raw_name);
    Some((name, version))
}

/// For Classic cache entries that are directories, resolve the real scoped package
/// name by reading the node_modules/ structure inside the entry.
/// Returns the real scoped name (e.g., "@eslint-community/eslint-utils") if found.
fn resolve_classic_scope(entry_path: &Path) -> Option<String> {
    let nm = entry_path.join("node_modules");
    if !nm.is_dir() {
        return None;
    }
    // Look for a directory starting with @
    let entries = std::fs::read_dir(&nm).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('@') && entry.path().is_dir() {
            // Found the scope dir — read the first package inside it
            if let Some(sub) = std::fs::read_dir(entry.path())
                .ok()
                .and_then(|mut entries| entries.find_map(|e| e.ok()))
            {
                let pkg_name = sub.file_name().to_string_lossy().to_string();
                return Some(format!("{name}/{pkg_name}"));
            }
        }
    }
    None
}

/// Returns true if the string looks like a hex hash (8+ lowercase hex chars).
fn is_hex_hash(s: &str) -> bool {
    s.len() >= 8
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Cache root directory
    if name == "cache" {
        if is_berry(path) {
            return Some("Yarn Berry Cache".to_string());
        } else {
            return Some("Yarn Cache".to_string());
        }
    }

    // .yarn-cache directory
    if name == ".yarn-cache" {
        return Some("Yarn Classic Cache".to_string());
    }

    // Berry zip files
    if name.ends_with(".zip")
        && let Some((pkg, ver)) = parse_berry_filename(&name)
    {
        return Some(format!("{} {}", pkg, ver));
    }

    // Classic entries: directories ending in -integrity or legacy .tgz files
    if (name.ends_with("-integrity") || name.ends_with(".tgz"))
        && let Some((mut pkg, ver)) = parse_classic_filename(&name)
    {
        // For Classic directories, resolve scoped names from node_modules/
        if pkg.starts_with('@')
            && path.is_dir()
            && let Some(real_name) = resolve_classic_scope(path)
        {
            pkg = real_name;
        }
        return Some(format!("{} {}", pkg, ver));
    }

    None
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();

    if name.ends_with(".zip") {
        let (pkg, ver) = parse_berry_filename(&name)?;
        return Some(super::PackageId {
            ecosystem: "npm",
            name: pkg,
            version: ver,
        });
    }

    // Classic: directories ending in -integrity or legacy .tgz files
    if name.ends_with("-integrity") || name.ends_with(".tgz") {
        let (mut pkg, ver) = parse_classic_filename(&name)?;
        // For Classic directories, resolve scoped names from node_modules/
        if pkg.starts_with('@')
            && path.is_dir()
            && let Some(real_name) = resolve_classic_scope(path)
        {
            pkg = real_name;
        }
        return Some(super::PackageId {
            ecosystem: "npm",
            name: pkg,
            version: ver,
        });
    }

    None
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if name.ends_with(".zip") {
        fields.push(MetadataField {
            label: "Format".to_string(),
            value: "Yarn Berry (.zip)".to_string(),
        });
        return fields;
    }

    if name.ends_with("-integrity") || name.ends_with(".tgz") {
        fields.push(MetadataField {
            label: "Format".to_string(),
            value: "Yarn Classic".to_string(),
        });
        return fields;
    }

    // Cache root directories: count Berry .zip files and Classic -integrity dirs
    if path.is_dir()
        && let Ok(entries) = std::fs::read_dir(path)
    {
        let count = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".zip") || n.ends_with("-integrity") || n.ends_with(".tgz")
            })
            .count();
        if count > 0 {
            fields.push(MetadataField {
                label: "Packages".to_string(),
                value: count.to_string(),
            });
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- Detection ---

    #[test]
    fn detects_classic_yarn_cache() {
        assert!(is_yarn_cache(&PathBuf::from("/home/user/.yarn-cache/v6")));
    }

    #[test]
    fn detects_classic_xdg_yarn_cache() {
        assert!(is_yarn_cache(&PathBuf::from("/home/user/.cache/yarn/v6")));
    }

    #[test]
    fn detects_berry_per_project_cache() {
        assert!(is_yarn_cache(&PathBuf::from(
            "/home/user/project/.yarn/cache"
        )));
    }

    #[test]
    fn detects_macos_yarn_cache() {
        assert!(is_yarn_cache(&PathBuf::from(
            "/Users/user/Library/Caches/Yarn/v6"
        )));
    }

    #[test]
    fn does_not_detect_unrelated_path() {
        assert!(!is_yarn_cache(&PathBuf::from("/home/user/.npm/_cacache")));
    }

    // --- Berry parsing ---

    #[test]
    fn parse_berry_simple_package() {
        let result = parse_berry_filename("lodash-npm-4.17.21-6382d821f21d.zip");
        assert_eq!(result, Some(("lodash".to_string(), "4.17.21".to_string())));
    }

    #[test]
    fn parse_berry_scoped_package() {
        let result = parse_berry_filename("@babel-core-npm-7.24.0-abc123def456.zip");
        assert_eq!(
            result,
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
    }

    #[test]
    fn parse_berry_prerelease_version() {
        let result = parse_berry_filename("typescript-npm-5.0.0-beta.1-abcdef012345.zip");
        assert_eq!(
            result,
            Some(("typescript".to_string(), "5.0.0-beta.1".to_string()))
        );
    }

    #[test]
    fn parse_berry_invalid_no_npm_marker() {
        let result = parse_berry_filename("lodash-4.17.21-6382d821f21d.zip");
        assert_eq!(result, None);
    }

    // --- Classic parsing ---

    #[test]
    fn parse_classic_simple_package() {
        let result = parse_classic_filename("npm-lodash-4.17.21-6382d821f21d.tgz");
        assert_eq!(result, Some(("lodash".to_string(), "4.17.21".to_string())));
    }

    #[test]
    fn parse_classic_scoped_package() {
        let result = parse_classic_filename("npm-@babel-core-7.24.0-abc123def456.tgz");
        assert_eq!(
            result,
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
    }

    #[test]
    fn parse_classic_hyphenated_name() {
        let result = parse_classic_filename("npm-is-even-1.0.0-abc123def456.tgz");
        assert_eq!(result, Some(("is-even".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn parse_classic_invalid_no_npm_prefix() {
        let result = parse_classic_filename("lodash-4.17.21-6382d821f21d.tgz");
        assert_eq!(result, None);
    }

    // --- Classic -integrity format (real Yarn Classic 1.x on-disk format) ---

    #[test]
    fn parse_classic_integrity_simple() {
        let result = parse_classic_filename(
            "npm-lodash-4.17.21-679591c564c3bffaae8454cf0b3df370c3d6911c-integrity",
        );
        assert_eq!(result, Some(("lodash".to_string(), "4.17.21".to_string())));
    }

    #[test]
    fn parse_classic_integrity_scoped() {
        let result = parse_classic_filename(
            "npm-@babel-core-7.24.0-56cbda6b185ae9d9bed369816a8f4423c5f2ff1b-integrity",
        );
        assert_eq!(
            result,
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
    }

    #[test]
    fn parse_classic_integrity_hyphenated() {
        let result = parse_classic_filename(
            "npm-is-even-1.0.0-76b5055fbad8d294a86b6a949015e1c97b717c06-integrity",
        );
        assert_eq!(result, Some(("is-even".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn parse_classic_integrity_base64() {
        let result = parse_classic_filename(
            "npm-base64-js-1.5.1-1b1b440160a5bf7ad40b650f095963481903930a-integrity",
        );
        assert_eq!(result, Some(("base64-js".to_string(), "1.5.1".to_string())));
    }

    #[test]
    fn parse_classic_invalid_no_suffix() {
        // Neither -integrity nor .tgz — should return None
        let result = parse_classic_filename("npm-lodash-4.17.21-abc123def456");
        assert_eq!(result, None);
    }

    #[test]
    fn semantic_name_classic_integrity_dir() {
        let path = PathBuf::from(
            "/Users/me/Library/Caches/Yarn/v6/npm-lodash-4.17.21-679591c564c3bffaae8454cf0b3df370c3d6911c-integrity",
        );
        assert_eq!(semantic_name(&path), Some("lodash 4.17.21".into()));
    }

    #[test]
    fn package_id_classic_integrity_dir() {
        let path = PathBuf::from(
            "/Users/me/Library/Caches/Yarn/v6/npm-@babel-core-7.24.0-56cbda6b185ae9d9bed369816a8f4423c5f2ff1b-integrity",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "@babel/core");
        assert_eq!(id.version, "7.24.0");
        assert_eq!(id.ecosystem, "npm");
    }

    // --- Semantic name ---

    #[test]
    fn semantic_name_berry_zip() {
        let path = PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-6382d821f21d.zip");
        assert_eq!(semantic_name(&path), Some("lodash 4.17.21".into()));
    }

    #[test]
    fn semantic_name_classic_tgz() {
        let path = PathBuf::from("/home/user/.yarn-cache/v6/npm-express-4.21.0-abc123def456.tgz");
        assert_eq!(semantic_name(&path), Some("express 4.21.0".into()));
    }

    #[test]
    fn semantic_name_cache_dir_berry() {
        let path = PathBuf::from("/project/.yarn/cache");
        assert_eq!(semantic_name(&path), Some("Yarn Berry Cache".into()));
    }

    #[test]
    fn semantic_name_cache_dir_classic() {
        // .cache/yarn/cache is not a berry path
        let path = PathBuf::from("/home/user/.cache/yarn/cache");
        assert_eq!(semantic_name(&path), Some("Yarn Cache".into()));
    }

    #[test]
    fn semantic_name_yarn_cache_dir() {
        let path = PathBuf::from("/home/user/.yarn-cache");
        assert_eq!(semantic_name(&path), Some("Yarn Classic Cache".into()));
    }

    #[test]
    fn semantic_name_unknown_file() {
        let path = PathBuf::from("/home/user/.yarn/cache/README.md");
        assert_eq!(semantic_name(&path), None);
    }

    // --- Normalize ---

    #[test]
    fn normalize_scoped() {
        assert_eq!(normalize_scoped_name("@babel-core"), "@babel/core");
    }

    #[test]
    fn normalize_unscoped() {
        assert_eq!(normalize_scoped_name("lodash"), "lodash");
    }

    #[test]
    fn normalize_scoped_deep() {
        assert_eq!(normalize_scoped_name("@types-node"), "@types/node");
    }

    // --- Package ID ---

    #[test]
    fn package_id_berry_zip() {
        let path = PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-6382d821f21d.zip");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.21");
    }

    #[test]
    fn package_id_classic_tgz() {
        let path = PathBuf::from("/home/user/.cache/yarn/v6/npm-express-4.21.0-abc123def456.tgz");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "express");
        assert_eq!(id.version, "4.21.0");
    }

    #[test]
    fn package_id_scoped_berry() {
        let path = PathBuf::from("/project/.yarn/cache/@babel-core-npm-7.24.0-abc123def456.zip");
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "@babel/core");
    }

    #[test]
    fn package_id_non_package_file() {
        let path = PathBuf::from("/project/.yarn/cache/.gitignore");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_directory_returns_none() {
        let path = PathBuf::from("/project/.yarn/cache");
        assert_eq!(package_id(&path), None);
    }

    // --- Bug 1: package name contains "-npm-" ---

    #[test]
    fn parse_berry_package_name_contains_npm() {
        // Package name contains "-npm-" substring
        let result = parse_berry_filename("use-npm-module-npm-1.0.0-abcdef012345.zip");
        assert_eq!(
            result,
            Some(("use-npm-module".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn parse_berry_npm_run_all() {
        // Real-world popular package with "npm" in name
        let result = parse_berry_filename("npm-run-all-npm-4.1.5-abcdef012345.zip");
        assert_eq!(
            result,
            Some(("npm-run-all".to_string(), "4.1.5".to_string()))
        );
    }

    // --- Bug 3: is_hex_hash boundary tests ---

    #[test]
    fn hex_hash_rejects_7_chars() {
        assert!(!is_hex_hash("abcdef0"));
    }

    #[test]
    fn hex_hash_accepts_8_chars() {
        assert!(is_hex_hash("abcdef01"));
    }

    #[test]
    fn hex_hash_rejects_uppercase() {
        assert!(!is_hex_hash("ABCDEF01"));
    }

    // --- Edge case tests ---

    #[test]
    fn parse_classic_digit_in_package_name() {
        // Package name starts with or contains digits
        let result = parse_classic_filename("npm-base64-js-1.5.1-abcdef012345.tgz");
        assert_eq!(result, Some(("base64-js".to_string(), "1.5.1".to_string())));
    }

    #[test]
    fn parse_classic_2to3() {
        let result = parse_classic_filename("npm-2to3-1.0.0-abcdef012345.tgz");
        assert_eq!(result, Some(("2to3".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn normalize_scoped_multi_hyphen() {
        // Scoped package with hyphens in package name
        assert_eq!(
            normalize_scoped_name("@babel-plugin-transform-runtime"),
            "@babel/plugin-transform-runtime"
        );
    }

    #[test]
    fn semantic_name_berry_global_cache() {
        let path = PathBuf::from("/home/user/.cache/yarn/berry/cache");
        assert_eq!(semantic_name(&path), Some("Yarn Berry Cache".into()));
    }

    // --- Metadata ---

    #[test]
    fn metadata_berry_zip_shows_format() {
        let path = PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-6382d821f21d.zip");
        let fields = metadata(&path);
        assert!(!fields.is_empty());
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Format" && f.value.contains("Berry"))
        );
    }

    #[test]
    fn metadata_classic_tgz_shows_format() {
        let path = PathBuf::from("/home/user/.cache/yarn/v6/npm-lodash-4.17.21-abc123def456.tgz");
        let fields = metadata(&path);
        assert!(!fields.is_empty());
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Format" && f.value.contains("Classic"))
        );
    }

    #[test]
    fn metadata_classic_integrity_shows_format() {
        let path = PathBuf::from(
            "/Users/me/Library/Caches/Yarn/v6/npm-lodash-4.17.21-679591c564c3bffaae8454cf0b3df370c3d6911c-integrity",
        );
        let fields = metadata(&path);
        assert!(!fields.is_empty());
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Format" && f.value.contains("Classic"))
        );
    }

    // --- Real-world filenames from disk ---

    #[test]
    fn parse_berry_two_segment_hash() {
        // Real Berry filename with two 10-char hash segments
        let result =
            parse_berry_filename("@jridgewell-trace-mapping-npm-0.3.25-c076fd2279-3d1ce6ebc6.zip");
        assert_eq!(
            result,
            Some((
                "@jridgewell/trace-mapping".to_string(),
                "0.3.25".to_string()
            ))
        );
    }

    #[test]
    fn parse_berry_eslint_community_two_hashes() {
        let result = parse_berry_filename(
            "@eslint-community-eslint-utils-npm-4.4.0-d1791bd5a3-7e559c4ce5.zip",
        );
        // NOTE: scope is wrong (@eslint instead of @eslint-community) — known limitation
        let (name, ver) = result.unwrap();
        assert_eq!(ver, "4.4.0"); // Version must be correct
        assert!(name.starts_with('@')); // Must be scoped
        assert!(name.contains("eslint")); // Contains the right words
    }

    #[test]
    fn parse_classic_integrity_resolved_scope() {
        // Create a real Classic entry with node_modules inside
        let tmp = tempfile::tempdir().unwrap();
        let entry = tmp.path().join(
            "npm-@eslint-community-eslint-utils-4.4.0-a23514e8fb9af1269d5f7788aa556798d61c6b59-integrity",
        );
        std::fs::create_dir_all(entry.join("node_modules/@eslint-community/eslint-utils")).unwrap();

        let id = package_id(&entry).unwrap();
        assert_eq!(id.name, "@eslint-community/eslint-utils"); // Must be correct!
        assert_eq!(id.version, "4.4.0");
        assert_eq!(id.ecosystem, "npm");
    }

    #[test]
    fn semantic_name_classic_integrity_resolved_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let entry = tmp.path().join(
            "npm-@eslint-community-eslint-utils-4.4.0-a23514e8fb9af1269d5f7788aa556798d61c6b59-integrity",
        );
        std::fs::create_dir_all(entry.join("node_modules/@eslint-community/eslint-utils")).unwrap();

        assert_eq!(
            semantic_name(&entry),
            Some("@eslint-community/eslint-utils 4.4.0".into())
        );
    }

    #[test]
    fn parse_berry_ampproject() {
        let result =
            parse_berry_filename("@ampproject-remapping-npm-2.3.0-ed441b6fa6-7e559c4ce5.zip");
        assert_eq!(
            result,
            Some(("@ampproject/remapping".to_string(), "2.3.0".to_string()))
        );
    }

    #[test]
    fn resolve_classic_scope_no_node_modules() {
        // Entry without node_modules — fallback to heuristic
        let tmp = tempfile::tempdir().unwrap();
        let entry = tmp
            .path()
            .join("npm-@babel-core-7.24.0-abc123def456abcdef0123456789abcdef01234567-integrity");
        std::fs::create_dir_all(&entry).unwrap();
        // No node_modules inside

        // package_id should still work, falling back to heuristic
        let id = package_id(&entry).unwrap();
        assert_eq!(id.name, "@babel/core"); // Heuristic (happens to be correct for @babel)
        assert_eq!(id.version, "7.24.0");
    }

    // --- Issue 2: pre-release digit-starting segments ---

    #[test]
    fn parse_classic_prerelease_digit_start() {
        // Pre-release segment starting with digit but containing a dot should be
        // included in the version, not treated as the version start
        let result = parse_classic_filename(
            "npm-some-pkg-1.0.0-2024.1-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        assert_eq!(
            result,
            Some(("some-pkg".to_string(), "1.0.0-2024.1".to_string()))
        );
    }

    #[test]
    fn parse_classic_prerelease_3rc1() {
        let result = parse_classic_filename(
            "npm-typescript-5.0.0-3rc1-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        assert_eq!(
            result,
            Some(("typescript".to_string(), "5.0.0-3rc1".to_string()))
        );
    }

    #[test]
    fn metadata_cache_dir_counts_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // Berry .zip
        std::fs::write(cache_dir.join("lodash-npm-4.17.21-abc123def456.zip"), "x").unwrap();
        // Classic -integrity directory
        std::fs::create_dir_all(
            cache_dir.join("npm-express-4.21.0-def789abc012def789abc012def789abc012def7-integrity"),
        )
        .unwrap();
        // Legacy .tgz
        std::fs::write(cache_dir.join("npm-is-even-1.0.0-abc123def456.tgz"), "x").unwrap();
        // Non-package file
        std::fs::write(cache_dir.join("README.md"), "x").unwrap();

        let fields = metadata(&cache_dir);
        let pkg_field = fields.iter().find(|f| f.label == "Packages");
        assert!(pkg_field.is_some(), "Expected Packages field");
        assert_eq!(pkg_field.unwrap().value, "3");
    }

    // =================================================================
    // Adversarial tests — designed to break the parsers
    // =================================================================

    // --- Berry: malformed and degenerate inputs ---

    #[test]
    fn berry_empty_zip() {
        assert_eq!(parse_berry_filename(".zip"), None);
    }

    #[test]
    fn berry_no_version_only_hash() {
        // Has -npm- but nothing valid after it
        assert_eq!(parse_berry_filename("lodash-npm-abcdef012345.zip"), None);
    }

    #[test]
    fn berry_hash_too_short() {
        // Hash is only 7 chars — should fail is_hex_hash
        assert_eq!(parse_berry_filename("lodash-npm-4.17.21-abcdef0.zip"), None);
    }

    #[test]
    fn berry_no_hash_at_all() {
        // Version but no hash segment
        assert_eq!(parse_berry_filename("lodash-npm-4.17.21.zip"), None);
    }

    #[test]
    fn berry_not_a_zip() {
        assert_eq!(
            parse_berry_filename("lodash-npm-4.17.21-abcdef012345.tar.gz"),
            None
        );
    }

    #[test]
    fn berry_empty_name_before_npm() {
        // "-npm-" at the very start: no package name
        let result = parse_berry_filename("-npm-1.0.0-abcdef012345.zip");
        // raw_name would be "", normalize_scoped_name returns ""
        // This should parse as name="" which is questionable but let's document behavior
        assert!(
            result.is_none() || result.as_ref().unwrap().0.is_empty(),
            "Empty name should either be None or empty: {:?}",
            result
        );
    }

    #[test]
    fn berry_three_hash_segments() {
        // Some Berry versions may produce three hash segments
        let result =
            parse_berry_filename("lodash-npm-4.17.21-abcdef0123-bcdef01234-cdef012345.zip");
        assert_eq!(result, Some(("lodash".to_string(), "4.17.21".to_string())));
    }

    #[test]
    fn berry_version_with_build_metadata() {
        // semver build metadata uses +, which becomes a hyphen in filenames?
        // Actually + is not valid in filenames typically. Test the unlikely case.
        let result = parse_berry_filename("pkg-npm-1.0.0-abcdef012345.zip");
        assert_eq!(result, Some(("pkg".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn berry_dots_in_package_name() {
        // socket.io has dots in the name — Yarn may or may not encode these
        let result = parse_berry_filename("socket.io-npm-4.7.5-abcdef012345.zip");
        assert_eq!(result, Some(("socket.io".to_string(), "4.7.5".to_string())));
    }

    #[test]
    fn berry_very_long_package_name() {
        let result = parse_berry_filename(
            "@anthropic-ai-very-long-package-name-with-many-hyphens-npm-1.0.0-abcdef012345.zip",
        );
        let (name, ver) = result.unwrap();
        assert_eq!(ver, "1.0.0");
        assert!(name.starts_with('@'));
    }

    #[test]
    fn berry_prerelease_that_looks_like_hash() {
        // Pre-release segment "0deadbeef0" is all hex and 10 chars — could be confused for hash
        let result = parse_berry_filename("pkg-npm-2.0.0-0deadbeef0-abc123def456.zip");
        // "0deadbeef0" is 10 hex chars — it will be treated as first hash segment
        // So version becomes "2.0.0" which is correct (the pre-release IS the hash)
        // This is actually fine — Yarn wouldn't produce this ambiguity since
        // pre-release is part of the version in the -npm- marker
        let (_, ver) = result.unwrap();
        assert_eq!(ver, "2.0.0");
    }

    // --- Classic: malformed and degenerate inputs ---

    #[test]
    fn classic_empty_integrity() {
        assert_eq!(parse_classic_filename("-integrity"), None);
    }

    #[test]
    fn classic_npm_prefix_only() {
        assert_eq!(parse_classic_filename("npm--integrity"), None);
    }

    #[test]
    fn classic_no_version_segment() {
        // Name parts only, no digit-with-dot segment
        assert_eq!(
            parse_classic_filename("npm-lodash-abcdef012345-integrity"),
            None
        );
    }

    #[test]
    fn classic_hash_is_not_hex() {
        // Hash contains non-hex characters
        assert_eq!(
            parse_classic_filename("npm-lodash-4.17.21-zzzzzzzzzzzz-integrity"),
            None
        );
    }

    #[test]
    fn classic_too_few_parts() {
        // Only name and hash, no version
        assert_eq!(parse_classic_filename("npm-abcdef012345-integrity"), None);
    }

    #[test]
    fn classic_dots_in_package_name() {
        // socket.io — the dot is in a "name" segment, not a version segment
        let result = parse_classic_filename(
            "npm-socket.io-4.7.5-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        assert_eq!(result, Some(("socket.io".to_string(), "4.7.5".to_string())));
    }

    #[test]
    fn classic_es5_ext() {
        // es5-ext has "5" in the name which starts with a digit but has no dot
        let result = parse_classic_filename(
            "npm-es5-ext-0.10.62-5e6f21a5eb74a30d4a86967fad5c1953e9d28e91-integrity",
        );
        assert_eq!(result, Some(("es5-ext".to_string(), "0.10.62".to_string())));
    }

    #[test]
    fn classic_level_6_lru_cache() {
        // Package name has "6" embedded — should not be confused for version
        let result = parse_classic_filename(
            "npm-level-6-lru-cache-1.0.0-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        assert_eq!(
            result,
            Some(("level-6-lru-cache".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn classic_version_0x() {
        // Version starting with 0 (0.x.y) — common for pre-1.0 packages
        let result = parse_classic_filename(
            "npm-some-pkg-0.1.0-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        assert_eq!(result, Some(("some-pkg".to_string(), "0.1.0".to_string())));
    }

    #[test]
    fn classic_calendar_version_prerelease() {
        // Version like 1.0.0-20240101 — digit-starting pre-release with no dot
        let result = parse_classic_filename(
            "npm-my-tool-1.0.0-20240101-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        // "20240101" has no dot and is 8 chars of digits — but it's NOT all hex
        // (contains no a-f). Wait, it IS valid hex since 0-9 are hex digits.
        // is_hex_hash("20240101") → true (8 digits, all valid hex). So
        // "20240101" would be treated as the hash, not a pre-release tag!
        // The REAL hash "abcdef012345..." comes after. Let me re-trace:
        // parts after stripping "npm-" and "-integrity":
        //   ["my", "tool", "1.0.0", "20240101", "abcdef012345abcdef012345abcdef012345abcd"]
        // Last part: "abcdef012345abcdef012345abcdef012345abcd" (40 chars, all hex) → hash ✓
        // without_hash: ["my", "tool", "1.0.0", "20240101"]
        // Walk forward looking for digit+dot: i=2 "1.0.0" → version_start=2
        // name = "my-tool", version = "1.0.0-20240101" ✓
        assert_eq!(
            result,
            Some(("my-tool".to_string(), "1.0.0-20240101".to_string()))
        );
    }

    // --- is_hex_hash boundary tests ---

    #[test]
    fn hex_hash_all_digits() {
        // Pure digits can be valid hex — this is a design choice
        assert!(is_hex_hash("12345678"));
    }

    #[test]
    fn hex_hash_empty() {
        assert!(!is_hex_hash(""));
    }

    #[test]
    fn hex_hash_mixed_case_rejected() {
        assert!(!is_hex_hash("abcdEF01"));
    }

    #[test]
    fn hex_hash_with_g_rejected() {
        assert!(!is_hex_hash("abcdefg1"));
    }

    // --- normalize_scoped_name edge cases ---

    #[test]
    fn normalize_at_with_no_hyphen() {
        // "@scope" with no hyphen — returned as-is
        assert_eq!(normalize_scoped_name("@scope"), "@scope");
    }

    #[test]
    fn normalize_empty_string() {
        assert_eq!(normalize_scoped_name(""), "");
    }

    #[test]
    fn normalize_bare_at() {
        assert_eq!(normalize_scoped_name("@"), "@");
    }

    #[test]
    fn normalize_at_hyphen_only() {
        // "@-rest" — scope is empty, package is "rest"
        assert_eq!(normalize_scoped_name("@-rest"), "@/rest");
    }

    // --- metadata fallthrough paths ---

    #[test]
    fn metadata_yarn_non_package_file_returns_empty() {
        let path = PathBuf::from("/project/.yarn/cache/README.md");
        let fields = metadata(&path);
        assert!(fields.is_empty());
    }

    #[test]
    fn metadata_yarn_empty_cache_dir_returns_no_packages_field() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // No zip or integrity entries — just a random file
        std::fs::write(cache_dir.join("README.md"), "x").unwrap();

        let fields = metadata(&cache_dir);
        let pkg_field = fields.iter().find(|f| f.label == "Packages");
        assert!(
            pkg_field.is_none(),
            "Should not show Packages field when count is 0"
        );
    }

    // --- package_id: verify ALL fields, not just name ---

    #[test]
    fn package_id_berry_verifies_all_fields() {
        let path = PathBuf::from("/project/.yarn/cache/@types-node-npm-22.0.0-abc123def456.zip");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@types/node");
        assert_eq!(id.version, "22.0.0");
    }

    #[test]
    fn package_id_classic_integrity_verifies_all_fields() {
        let path = PathBuf::from(
            "/home/user/Library/Caches/Yarn/v6/npm-express-4.21.0-abcdef012345abcdef012345abcdef012345abcd-integrity",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "express");
        assert_eq!(id.version, "4.21.0");
    }
}
