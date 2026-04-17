use super::MetadataField;
use std::path::Path;

/// Returns true if the path is within a known pnpm cache/store location.
#[allow(dead_code)]
pub fn is_pnpm_cache(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".pnpm-store")
        || path_str.contains("pnpm/store")
        || path_str.contains("node_modules/.pnpm")
}

/// Returns true if the path is within the pnpm virtual store (node_modules/.pnpm).
pub fn is_pnpm_virtual_store(path: &Path) -> bool {
    path.to_string_lossy().contains("node_modules/.pnpm")
}

/// Parse a pnpm virtual store directory name into (name, version).
///
/// Examples:
/// - `"lodash@4.17.21"` → `("lodash", "4.17.21")`
/// - `"@babel+core@7.24.0"` → `("@babel/core", "7.24.0")`
/// - `"@types+node@22.0.0"` → `("@types/node", "22.0.0")`
/// - `"react-dom@18.2.0_react@18.2.0"` → `("react-dom", "18.2.0")`
pub fn parse_virtual_store_name(dir_name: &str) -> Option<(String, String)> {
    // pnpm v9+ appends peer dependency info after '_':
    // e.g., "react-dom@18.2.0_react@18.2.0"
    // Strip everything after the first '_' that follows a version.
    let base = strip_peer_deps(dir_name);

    // Find the last '@' which separates name from version
    let at_pos = base.rfind('@')?;
    let version = &base[at_pos + 1..];

    if version.is_empty() {
        return None;
    }

    let raw_name = &base[..at_pos];
    if raw_name.is_empty() {
        return None;
    }

    // Convert '+' back to '/' for scoped packages: @babel+core → @babel/core
    let name = raw_name.replace('+', "/");

    // Reject degenerate names like bare "@"
    if name == "@" {
        return None;
    }

    Some((name, version.to_string()))
}

/// Strip peer dependency suffix from a pnpm virtual store directory name.
/// pnpm uses '_' to separate the base package from peer deps:
/// `react-dom@18.2.0_react@18.2.0` → `react-dom@18.2.0`
/// But scoped packages use '+' not '_' for the scope separator,
/// so `_` always indicates peer deps in practice.
fn strip_peer_deps(dir_name: &str) -> &str {
    // Find the version '@': for scoped packages, skip the leading '@'
    let search_start = if let Some(after_at) = dir_name.strip_prefix('@') {
        // Find the second '@' (version delimiter)
        match after_at.find('@') {
            Some(pos) => pos + 1, // position in dir_name
            None => return dir_name,
        }
    } else {
        match dir_name.find('@') {
            Some(pos) => pos,
            None => return dir_name,
        }
    };

    // Now look for '_' after the version '@'
    match dir_name[search_start..].find('_') {
        Some(pos) => &dir_name[..search_start + pos],
        None => dir_name,
    }
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let path_str = path.to_string_lossy();

    // Top-level store directories
    if name == ".pnpm-store" {
        return Some("pnpm Content Store".to_string());
    }

    if name == ".pnpm" {
        return Some("pnpm Virtual Store".to_string());
    }

    // Subdirectories inside the content store
    if path_str.contains(".pnpm-store") || path_str.contains("pnpm/store") {
        if let Some(version) = name.strip_prefix('v')
            && version.chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("Store v{version}"));
        }
        if name == "files" {
            return Some("Content Files".to_string());
        }
        if name == "index" {
            return Some("Package Index".to_string());
        }
    }

    // Index files: {hash}-name@version.json → "name version"
    if name.ends_with(".json")
        && path_str.contains("/index/")
        && let Some(id) = parse_index_filename(&name)
    {
        return Some(format!("{} {}", id.name, id.version));
    }

    // Virtual store entries: name@version directories
    if name.contains('@')
        && is_pnpm_virtual_store(path)
        && let Some((pkg, ver)) = parse_virtual_store_name(&name)
    {
        return Some(format!("{} {}", pkg, ver));
    }

    None
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // pnpm v10 index files: {hash}-{name}@{version}.json
    if name.ends_with(".json") {
        let path_str = path.to_string_lossy();
        if path_str.contains("/index/") {
            return parse_index_filename(&name);
        }
    }

    // Virtual store entries: name@version directories
    if is_pnpm_virtual_store(path) && name.contains('@') {
        let (pkg, ver) = parse_virtual_store_name(&name)?;
        if ver.starts_with(|c: char| c.is_ascii_digit()) {
            return Some(super::PackageId {
                ecosystem: "npm",
                name: pkg,
                version: ver,
            });
        }
    }

    None
}

/// Parse a pnpm v10 index filename into a PackageId.
///
/// Format: `{62-hex-chars}-{name}@{version}.json`
/// Scoped: `{62-hex-chars}-@{scope}+{name}@{version}.json`
///
/// The filename hash is 62 hex chars (the parent directory has the first 2,
/// making 64 total = SHA-256).
fn parse_index_filename(filename: &str) -> Option<super::PackageId> {
    let base = filename.strip_suffix(".json")?;

    // The hash is 62 hex chars, followed by '-', then the package spec.
    // Validate and skip the hash prefix. The byte-indexed slicing below is
    // safe only if the first 63 bytes are ASCII — guard against multi-byte
    // chars landing on byte 62 (would otherwise panic at the slice).
    if base.len() < 64 || !base.is_char_boundary(62) || !base.is_char_boundary(63) {
        return None;
    }
    let hash_part = &base[..62];
    if !hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if base.as_bytes()[62] != b'-' {
        return None;
    }
    let spec = &base[63..]; // "name@version" or "@scope+name@version"

    // Find the last '@' which separates name from version
    let at_pos = spec.rfind('@')?;
    let version = &spec[at_pos + 1..];
    if version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }

    let raw_name = &spec[..at_pos];
    if raw_name.is_empty() {
        return None;
    }

    // Only replace '+' with '/' for scoped packages (@scope+name → @scope/name)
    let name = if raw_name.starts_with('@') {
        if let Some(pos) = raw_name.find('+') {
            format!("{}/{}", &raw_name[..pos], &raw_name[pos + 1..])
        } else {
            raw_name.to_string()
        }
    } else {
        raw_name.to_string()
    };

    Some(super::PackageId {
        ecosystem: "npm",
        name,
        version: version.to_string(),
    })
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let path_str = path.to_string_lossy();

    // Top-level store and virtual store dirs: count entries
    if name == ".pnpm-store" || name == ".pnpm" {
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.filter_map(|e| e.ok()).count();
            fields.push(MetadataField {
                label: "Entries".to_string(),
                value: count.to_string(),
            });
        }
        return fields;
    }

    // Inside content store
    if path_str.contains(".pnpm-store") || path_str.contains("pnpm/store") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Content-addressed store".to_string(),
        });
        return fields;
    }

    // Virtual store entries with @
    if name.contains('@') && is_pnpm_virtual_store(path) {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Virtual store entry".to_string(),
        });
        return fields;
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- Detection ---

    #[test]
    fn detects_pnpm_store() {
        assert!(is_pnpm_cache(&PathBuf::from("/home/user/.pnpm-store/v3")));
    }

    #[test]
    fn detects_pnpm_virtual_store() {
        assert!(is_pnpm_cache(&PathBuf::from(
            "/project/node_modules/.pnpm/lodash@4.17.21"
        )));
    }

    #[test]
    fn detects_xdg_pnpm_store() {
        assert!(is_pnpm_cache(&PathBuf::from(
            "/home/user/.local/share/pnpm/store/v3"
        )));
    }

    #[test]
    fn does_not_detect_unrelated_path() {
        assert!(!is_pnpm_cache(&PathBuf::from("/home/user/.npm/_cacache")));
    }

    // --- Parsing ---

    #[test]
    fn parse_unscoped_package() {
        assert_eq!(
            parse_virtual_store_name("lodash@4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
    }

    #[test]
    fn parse_scoped_package() {
        assert_eq!(
            parse_virtual_store_name("@babel+core@7.24.0"),
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
    }

    #[test]
    fn parse_scoped_types() {
        assert_eq!(
            parse_virtual_store_name("@types+node@22.0.0"),
            Some(("@types/node".to_string(), "22.0.0".to_string()))
        );
    }

    #[test]
    fn parse_empty_version_returns_none() {
        assert_eq!(parse_virtual_store_name("lodash@"), None);
    }

    #[test]
    fn parse_no_at_returns_none() {
        assert_eq!(parse_virtual_store_name("lodash"), None);
    }

    // --- Semantic name ---

    #[test]
    fn semantic_name_pnpm_store() {
        let path = PathBuf::from("/home/user/.pnpm-store");
        assert_eq!(semantic_name(&path), Some("pnpm Content Store".into()));
    }

    #[test]
    fn semantic_name_virtual_store() {
        let path = PathBuf::from("/project/node_modules/.pnpm");
        assert_eq!(semantic_name(&path), Some("pnpm Virtual Store".into()));
    }

    #[test]
    fn semantic_name_store_version_v3() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3");
        assert_eq!(semantic_name(&path), Some("Store v3".into()));
    }

    #[test]
    fn semantic_name_store_version_v10() {
        let path = PathBuf::from("/Users/julien/Library/pnpm/store/v10");
        assert_eq!(semantic_name(&path), Some("Store v10".into()));
    }

    #[test]
    fn semantic_name_virtual_store_entry() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        assert_eq!(semantic_name(&path), Some("lodash 4.17.21".into()));
    }

    #[test]
    fn semantic_name_virtual_store_scoped() {
        let path = PathBuf::from("/project/node_modules/.pnpm/@babel+core@7.24.0");
        assert_eq!(semantic_name(&path), Some("@babel/core 7.24.0".into()));
    }

    #[test]
    fn semantic_name_content_files() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3/files");
        assert_eq!(semantic_name(&path), Some("Content Files".into()));
    }

    // --- Package ID ---

    #[test]
    fn package_id_virtual_store_entry() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.21");
    }

    #[test]
    fn package_id_virtual_store_scoped() {
        let path = PathBuf::from("/project/node_modules/.pnpm/@babel+core@7.24.0");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@babel/core");
        assert_eq!(id.version, "7.24.0");
    }

    #[test]
    fn package_id_content_store_returns_none() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3/files/ab/cd1234");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_pnpm_dir_returns_none() {
        let path = PathBuf::from("/project/node_modules/.pnpm");
        assert_eq!(package_id(&path), None);
    }

    // --- Index file parsing (pnpm v10) ---

    #[test]
    fn package_id_index_unscoped() {
        let path = PathBuf::from(
            "/Users/julien/Library/pnpm/store/v10/index/3e/585d15c8a594e20d7de57b362ea81754c011acb2641a19f1b72c8531ea3982-lodash@4.17.20.json",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.20");
    }

    #[test]
    fn package_id_index_scoped() {
        let path = PathBuf::from(
            "/Users/julien/Library/pnpm/store/v10/index/0e/0e8c6b62ac09d19bf960ba5290551491972f9f0c0c0ea8c8e35b8f217ffb9b-@babel+template@7.28.6.json",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@babel/template");
        assert_eq!(id.version, "7.28.6");
    }

    #[test]
    fn package_id_index_hyphenated_name() {
        let path = PathBuf::from(
            "/home/user/.pnpm-store/v3/index/ab/985c96e984d46e95603f151dedf9c0568889ff824f2e522488b9fb7cb8a6c0-is-number-object@1.1.1.json",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "is-number-object");
        assert_eq!(id.version, "1.1.1");
    }

    #[test]
    fn package_id_index_content_files_still_none() {
        let path = PathBuf::from(
            "/Users/julien/Library/pnpm/store/v10/files/61/9a372bcd920fb462ca2d04d4440fa2",
        );
        assert_eq!(package_id(&path), None);
    }

    // --- parse_index_filename rejection cases ---

    #[test]
    fn parse_index_short_hash_returns_none() {
        assert_eq!(parse_index_filename("abcd-lodash@1.0.0.json"), None);
    }

    #[test]
    fn parse_index_non_hex_hash_returns_none() {
        let bad = format!(
            "{}z-lodash@1.0.0.json",
            "g".repeat(61) // 'g' is not a hex digit
        );
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_missing_separator_returns_none() {
        // 62 hex chars followed by 'X' instead of '-'
        let bad = format!("{}Xlodash@1.0.0.json", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_non_numeric_version_returns_none() {
        let bad = format!("{}-lodash@latest.json", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_empty_name_returns_none() {
        let bad = format!("{}-@1.0.0.json", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_no_json_suffix_returns_none() {
        let bad = format!("{}-lodash@1.0.0", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_unscoped_plus_preserved() {
        // A hypothetical unscoped name with '+' should NOT have it replaced
        let filename = format!("{}-c++parser@1.0.0.json", "a".repeat(62));
        let id = parse_index_filename(&filename).unwrap();
        assert_eq!(id.name, "c++parser");
    }

    // --- semantic_name for index ---

    #[test]
    fn semantic_name_package_index_dir() {
        let path = PathBuf::from("/Users/julien/Library/pnpm/store/v10/index");
        assert_eq!(semantic_name(&path), Some("Package Index".into()));
    }

    #[test]
    fn semantic_name_index_file() {
        let path = PathBuf::from(format!(
            "/Users/julien/Library/pnpm/store/v10/index/3e/{}-lodash@4.17.20.json",
            "a".repeat(62)
        ));
        assert_eq!(semantic_name(&path), Some("lodash 4.17.20".into()));
    }

    #[test]
    fn semantic_name_store_version_non_numeric_returns_none() {
        let path = PathBuf::from("/home/user/.pnpm-store/vfoo");
        assert_eq!(semantic_name(&path), None);
    }

    // --- Metadata ---

    #[test]
    fn metadata_pnpm_store_shows_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join(".pnpm-store");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::create_dir_all(store_dir.join("v3")).unwrap();

        let fields = metadata(&store_dir);
        assert!(fields.iter().any(|f| f.label == "Entries"));
    }

    #[test]
    fn metadata_virtual_store_entry_shows_type() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Type" && f.value == "Virtual store entry")
        );
    }

    #[test]
    fn metadata_content_store_shows_type() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3/files/ab");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Type" && f.value == "Content-addressed store")
        );
    }

    // --- Peer dependency handling ---

    #[test]
    fn parse_with_peer_deps() {
        let (name, ver) = parse_virtual_store_name("react-dom@18.2.0_react@18.2.0").unwrap();
        assert_eq!(name, "react-dom");
        assert_eq!(ver, "18.2.0");
    }

    #[test]
    fn parse_scoped_with_peer_deps() {
        let (name, ver) =
            parse_virtual_store_name("@babel+core@7.24.0_@babel+preset-env@7.24.0").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn parse_with_multiple_peer_deps() {
        let (name, ver) =
            parse_virtual_store_name("eslint-plugin-react@7.35.0_eslint@9.0.0_typescript@5.0.0")
                .unwrap();
        assert_eq!(name, "eslint-plugin-react");
        assert_eq!(ver, "7.35.0");
    }

    #[test]
    fn parse_malformed_at_only() {
        // Just "@" as name — should return None
        assert!(parse_virtual_store_name("@@1.0.0").is_none());
    }

    #[test]
    fn package_id_with_non_numeric_version() {
        // pnpm can have @latest or @next in some contexts
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@latest");
        assert!(package_id(&path).is_none());
    }

    #[test]
    fn package_id_with_peer_deps() {
        let path = PathBuf::from("/project/node_modules/.pnpm/react-dom@18.2.0_react@18.2.0");
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "react-dom");
        assert_eq!(id.version, "18.2.0");
    }

    #[test]
    fn semantic_name_at_dir_outside_virtual_store() {
        // A directory with @ in name but NOT in node_modules/.pnpm
        let path = PathBuf::from("/home/user/.pnpm-store/v3/foo@1.0.0");
        assert_eq!(semantic_name(&path), None);
    }

    // =================================================================
    // Adversarial tests — designed to break the parsers
    // =================================================================

    // --- parse_virtual_store_name: degenerate inputs ---

    #[test]
    fn parse_just_at_sign() {
        assert_eq!(parse_virtual_store_name("@"), None);
    }

    #[test]
    fn parse_empty_string() {
        assert_eq!(parse_virtual_store_name(""), None);
    }

    #[test]
    fn parse_at_at_end() {
        // Name with @ at end — empty version
        assert_eq!(parse_virtual_store_name("lodash@"), None);
    }

    #[test]
    fn parse_multiple_at_signs() {
        // Extra @ in the middle — rfind finds the last one
        let result = parse_virtual_store_name("foo@bar@1.0.0");
        assert_eq!(result, Some(("foo@bar".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn parse_scoped_trailing_slash() {
        // @babel+@1.0.0 — after replace('+', '/'), name is "@babel/"
        // This is an invalid package name but the parser accepts it
        let result = parse_virtual_store_name("@babel+@1.0.0");
        assert_eq!(result, Some(("@babel/".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn parse_underscores_in_name_no_peers() {
        // Package with underscores but no peer deps
        let result = parse_virtual_store_name("my_package@1.0.0");
        assert_eq!(
            result,
            Some(("my_package".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn parse_version_with_prerelease() {
        let result = parse_virtual_store_name("typescript@5.0.0-beta.1");
        assert_eq!(
            result,
            Some(("typescript".to_string(), "5.0.0-beta.1".to_string()))
        );
    }

    #[test]
    fn parse_version_with_build_metadata() {
        let result = parse_virtual_store_name("pkg@1.0.0+build.123");
        assert_eq!(
            result,
            Some(("pkg".to_string(), "1.0.0+build.123".to_string()))
        );
    }

    // --- strip_peer_deps: adversarial ---

    #[test]
    fn strip_peers_no_at_sign() {
        // No @ at all — return as-is
        assert_eq!(strip_peer_deps("lodash"), "lodash");
    }

    #[test]
    fn strip_peers_underscore_before_at() {
        // Underscore in package name, before the version @
        assert_eq!(strip_peer_deps("my_pkg@1.0.0"), "my_pkg@1.0.0");
    }

    #[test]
    fn strip_peers_scoped_no_version() {
        // Scoped package with no version @ — should return as-is
        assert_eq!(strip_peer_deps("@scope+name"), "@scope+name");
    }

    #[test]
    fn strip_peers_double_underscore() {
        // Real pnpm output: double underscore seen in @testing-library/react peer chain
        let result = strip_peer_deps(
            "@testing-library+react@14.2.0_@types+react@18.3.28_react-dom@18.2.0_react@18.2.0__react@18.2.0",
        );
        assert_eq!(result, "@testing-library+react@14.2.0");
    }

    // --- package_id: adversarial ---

    #[test]
    fn package_id_lock_yaml_in_pnpm() {
        // pnpm puts lock.yaml inside .pnpm — should not be parsed as a package
        let path = PathBuf::from("/project/node_modules/.pnpm/lock.yaml");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_node_modules_dir_in_pnpm() {
        // .pnpm/node_modules directory — not a package
        let path = PathBuf::from("/project/node_modules/.pnpm/node_modules");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_version_zero() {
        // Version starting with 0 — should be accepted
        let path = PathBuf::from("/project/node_modules/.pnpm/pkg@0.0.1");
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "pkg");
        assert_eq!(id.version, "0.0.1");
    }

    #[test]
    fn package_id_version_is_tag() {
        // @next, @canary — not numeric, should be rejected
        let path = PathBuf::from("/project/node_modules/.pnpm/pkg@next");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_version_is_canary() {
        let path = PathBuf::from("/project/node_modules/.pnpm/pkg@canary");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_scoped_with_complex_peers() {
        // Real-world: scoped + multiple peer deps
        let path = PathBuf::from(
            "/project/node_modules/.pnpm/@testing-library+react@14.2.0_@types+react@18.3.28_react-dom@18.2.0_react@18.2.0__react@18.2.0",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "@testing-library/react");
        assert_eq!(id.version, "14.2.0");
        assert_eq!(id.ecosystem, "npm");
    }

    #[test]
    fn package_id_not_in_virtual_store() {
        // Has @ but is NOT under node_modules/.pnpm
        let path = PathBuf::from("/home/user/.pnpm-store/v3/lodash@4.17.21");
        assert_eq!(package_id(&path), None);
    }

    // --- semantic_name: adversarial ---

    #[test]
    fn semantic_name_lock_yaml() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lock.yaml");
        // No @ sign, so should not try to parse
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_node_modules_inside_pnpm() {
        let path = PathBuf::from("/project/node_modules/.pnpm/node_modules");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_store_v4_recognized() {
        let path = PathBuf::from("/home/user/.pnpm-store/v4");
        assert_eq!(semantic_name(&path), Some("Store v4".into()));
    }

    // --- metadata: adversarial ---

    #[test]
    fn metadata_empty_vec_for_unknown_path() {
        let path = PathBuf::from("/tmp/random/dir");
        let fields = metadata(&path);
        assert!(fields.is_empty());
    }

    #[test]
    fn metadata_pnpm_store_shows_correct_count() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join(".pnpm-store");
        std::fs::create_dir_all(store_dir.join("v3")).unwrap();
        std::fs::create_dir_all(store_dir.join("tmp")).unwrap();
        std::fs::write(store_dir.join("some-file"), "x").unwrap();

        let fields = metadata(&store_dir);
        let entries_field = fields.iter().find(|f| f.label == "Entries").unwrap();
        assert_eq!(entries_field.value, "3"); // v3 + tmp + some-file
    }

    // =================================================================
    // M1: byte-boundary safety on non-ASCII input
    // These inputs must not panic. They can legitimately return None.
    // =================================================================

    #[test]
    fn parse_index_filename_rejects_non_ascii_hash_without_panic() {
        // A 🔥 emoji is 4 bytes. Putting it near byte 62 means
        // `&base[..62]` lands inside the emoji — must not panic.
        let mut s = "a".repeat(60);
        s.push('🔥');
        s.push_str("xx-name@1.0.0.json");
        assert!(parse_index_filename(&s).is_none());
    }

    #[test]
    fn parse_index_filename_rejects_short_multibyte_without_panic() {
        // A filename that starts with a multi-byte char and is shorter than
        // the hash prefix: guards the byte-index at `base.as_bytes()[62]`.
        let s = "🦀-name@1.0.0.json";
        assert!(parse_index_filename(s).is_none());
    }

    #[test]
    fn parse_index_filename_rejects_multibyte_at_separator_without_panic() {
        // Exactly 62 hex chars of hash, then a multi-byte char where the
        // '-' separator is expected: must not panic on byte 62.
        let mut s = "a".repeat(62);
        s.push('🦀');
        s.push_str("name@1.0.0.json");
        assert!(parse_index_filename(&s).is_none());
    }

    #[test]
    fn strip_peer_deps_non_ascii_does_not_panic() {
        // Construct a scoped-style name with a multi-byte char in the scope
        // position; stripping peer deps must not panic even if offsets shift.
        let input = "@🦀+pkg@1.0.0_🔥-peer";
        let _ = strip_peer_deps(input);
    }

    #[test]
    fn strip_peer_deps_unscoped_non_ascii_does_not_panic() {
        let input = "🔥pkg@1.0.0_react@18";
        let _ = strip_peer_deps(input);
    }
}
