use super::MetadataField;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The path's components with each `..` resolved against the component before
/// it. Configured scan roots are only tilde-expanded, so a root like
/// `~/proj/../.m2/repository` carries `..` into every artifact path; left
/// unresolved it would end up in the group id, and rejecting it would silently
/// drop every package under that root.
///
/// Lexical resolution is only valid when the component before `..` is not a
/// symlink (`link/..` is the parent of the link's TARGET, not of the link), so
/// that case returns `None`. A component that does not exist cannot be a
/// symlink, so it still resolves lexically. Also `None` when a `..` has nothing
/// to resolve against (it would climb above the start or the filesystem root).
fn resolve_parent_dirs(path: &Path) -> Option<Vec<String>> {
    use std::path::{Component, PathBuf};
    let mut comps: Vec<String> = Vec::new();
    // The same components as a real path, to ask the filesystem about them.
    let mut prefix = PathBuf::new();
    // Index of the first component that `..` may remove: everything after a
    // root/prefix marker, so `/..` is never "resolved" away.
    let mut floor = 0;
    for c in path.components() {
        match c {
            Component::ParentDir => {
                if comps.len() <= floor {
                    return None;
                }
                let is_symlink =
                    std::fs::symlink_metadata(&prefix).is_ok_and(|m| m.file_type().is_symlink());
                if is_symlink {
                    return None;
                }
                comps.pop();
                prefix.pop();
            }
            Component::Normal(s) => {
                comps.push(s.to_string_lossy().into_owned());
                prefix.push(s);
            }
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {
                comps.push(c.as_os_str().to_string_lossy().into_owned());
                prefix.push(c.as_os_str());
                floor = comps.len();
            }
        }
    }
    Some(comps)
}

/// Parse a Maven artifact path into (group, artifact, version).
/// Expects layout `.../.m2/**/repository/<group-path>/<artifact>/<version>/<file>`.
///
/// The repository root is the FIRST `repository` component after the `.m2`
/// component, the same `.m2` relationship `providers::detect` uses to classify
/// a path as Maven. Taking the first one (not the nearest to the artifact) is
/// what keeps a group id that itself contains `repository`
/// (`com.repository.acme`) intact. Returns `None` when there is no `.m2`
/// ancestor or no `repository` directory below it, rather than guessing a group.
/// `..` components are resolved lexically first (see `resolve_parent_dirs`).
///
/// When `~/.m2/settings.xml` declares a `<localRepository>` and the path is
/// inside it, THAT directory is the root: it is Maven's own statement of where
/// the repository is, so a custom root not named `repository`
/// (`.m2/custom-repo/com/repository/acme/...`) is read correctly (#118). A path
/// outside the declared repository, or no declaration, keeps the inference
/// above, which is never worse than before.
///
/// Known limit: with no declaration, that custom root cannot be told apart from
/// a nested `.m2/work/repository` by the path alone.
fn parse_coordinates(path: &Path) -> Option<(String, String, String)> {
    parse_coordinates_with(path, declared_repository())
}

fn parse_coordinates_with(
    path: &Path,
    declared: Option<&[String]>,
) -> Option<(String, String, String)> {
    let comps = resolve_parent_dirs(path)?;
    // Components of the root itself; what follows is <group...>/<artifact>/<version>/<file>.
    let root_len = match declared.filter(|d| comps.len() > d.len() && comps[..d.len()] == **d) {
        Some(d) => d.len(),
        None => {
            let m2 = comps.iter().position(|c| c == ".m2")?;
            m2 + 1 + comps[m2 + 1..].iter().position(|c| c == "repository")? + 1
        }
    };
    // <group...> <artifact> <version> <file>, with at least one group part.
    let rest = &comps[root_len..];
    if rest.len() < 4 {
        return None;
    }
    let (group, tail) = rest.split_at(rest.len() - 3);
    Some((group.join("."), tail[0].clone(), tail[1].clone()))
}

/// The largest `settings.xml` we read.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// Components of the repository `~/.m2/settings.xml` declares, read once per
/// process (settings change rarely, and this is asked for every walked path).
fn declared_repository() -> Option<&'static [String]> {
    static DECLARED: OnceLock<Option<Vec<String>>> = OnceLock::new();
    DECLARED
        .get_or_init(|| {
            let home = directories::BaseDirs::new()?.home_dir().to_path_buf();
            declared_repository_in(&home)
        })
        .as_deref()
}

/// Components of the repository declared by `<home>/.m2/settings.xml`. `None`
/// when the file is absent, unreadable, over the size limit, or declares
/// nothing we can resolve exactly.
fn declared_repository_in(home: &Path) -> Option<Vec<String>> {
    use std::io::Read;
    let file = std::fs::File::open(home.join(".m2").join("settings.xml")).ok()?;
    let mut xml = String::new();
    file.take(MAX_SETTINGS_BYTES + 1)
        .read_to_string(&mut xml)
        .ok()?;
    if xml.len() as u64 > MAX_SETTINGS_BYTES {
        return None;
    }
    resolve_parent_dirs(&declared_repository_from_settings(&xml, home)?)
}

/// The `<localRepository>` of a `settings.xml`, as an absolute path, or `None`
/// when there is none or it cannot be resolved exactly. `${user.home}` is
/// expanded; any other placeholder, and any relative path, depends on where
/// Maven was started, so it is no declaration at all rather than a guess.
fn declared_repository_from_settings(xml: &str, home: &Path) -> Option<PathBuf> {
    // A commented-out element is not a declaration.
    let mut text = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        text.push_str(&rest[..start]);
        rest = match rest[start..].find("-->") {
            Some(end) => &rest[start + end + 3..],
            None => "",
        };
    }
    text.push_str(rest);

    let open = text.find("<localRepository>")? + "<localRepository>".len();
    let close = open + text[open..].find("</localRepository>")?;
    let value = text[open..close].trim();
    let value = match value.strip_prefix("${user.home}") {
        Some(tail) => format!("{}{}", home.to_string_lossy(), tail),
        None => value.to_string(),
    };
    if value.is_empty() || value.contains("${") {
        return None;
    }
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();
    if !name.ends_with(".jar") && !name.ends_with(".pom") {
        return None;
    }
    let (group, artifact, version) = parse_coordinates(path)?;
    Some(format!("{group}:{artifact} {version}"))
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();
    // Dedup on .jar — .pom sits alongside and would double-count.
    if !name.ends_with(".jar") {
        return None;
    }
    let (group, artifact, version) = parse_coordinates(path)?;
    Some(super::PackageId {
        ecosystem: "Maven",
        name: format!("{group}:{artifact}"),
        version,
    })
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if name == "repository" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Maven local repository (.jar, .pom, checksums)".to_string(),
        });
    }
    fields
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_declaration_is_read_from_home_m2_settings_xml() {
        let home = tempfile::tempdir().unwrap();
        // No file: nothing declared.
        assert_eq!(declared_repository_in(home.path()), None);
        let m2 = home.path().join(".m2");
        std::fs::create_dir_all(&m2).unwrap();
        // A file with a declaration, `${user.home}` expanded against THIS home.
        std::fs::write(
            m2.join("settings.xml"),
            "<settings><localRepository>${user.home}/.m2/custom-repo</localRepository></settings>",
        )
        .unwrap();
        let got = declared_repository_in(home.path()).unwrap();
        assert_eq!(got.last().map(String::as_str), Some("custom-repo"));
        assert!(got.iter().any(|c| c == ".m2"), "{got:?}");
        // A file that declares nothing.
        std::fs::write(m2.join("settings.xml"), "<settings/>").unwrap();
        assert_eq!(declared_repository_in(home.path()), None);
        // An over-size file is not read, even if it starts with a declaration.
        let mut big = String::from("<localRepository>/data/mvn</localRepository>");
        big.push_str(&" ".repeat(MAX_SETTINGS_BYTES as usize));
        std::fs::write(m2.join("settings.xml"), big).unwrap();
        assert_eq!(declared_repository_in(home.path()), None);
        // Not UTF-8.
        std::fs::write(m2.join("settings.xml"), [0xff, 0xfe]).unwrap();
        assert_eq!(declared_repository_in(home.path()), None);
    }

    #[test]
    fn an_unterminated_comment_hides_the_rest_of_the_file() {
        // `<!--` with no `-->`: everything after it is comment, so a later
        // element is not a declaration.
        let home = Path::new("/home/u");
        assert_eq!(
            declared_repository_from_settings(
                "<!-- never closed <localRepository>/data/mvn</localRepository>",
                home
            ),
            None
        );
        // An element before the comment still counts.
        assert_eq!(
            declared_repository_from_settings(
                "<localRepository>/data/mvn</localRepository><!-- tail",
                home
            ),
            Some(PathBuf::from("/data/mvn"))
        );
    }

    // --- #118: the repository root comes from settings.xml when it is declared ---

    fn declared(root: &str) -> Option<Vec<String>> {
        Some(
            Path::new(root)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect(),
        )
    }

    fn coords(path: &str, declared_root: Option<Vec<String>>) -> Option<(String, String, String)> {
        parse_coordinates_with(Path::new(path), declared_root.as_deref())
    }

    #[test]
    fn a_declared_repository_decides_where_the_group_starts() {
        // `.m2/custom-repo/com/repository/acme/...` cannot be told from a nested
        // `.m2/work/repository` by its path. Maven's own `<localRepository>`
        // can: it says which directory is the root.
        let jar = "/home/u/.m2/custom-repo/com/repository/acme/widget/1.0/widget-1.0.jar";
        assert_eq!(
            coords(jar, declared("/home/u/.m2/custom-repo")),
            Some(("com.repository.acme".into(), "widget".into(), "1.0".into()))
        );
        // Without the declaration the old inference is kept: the first
        // `repository` component is taken as the root, so the group loses
        // `com.repository` (the documented mis-parse this declaration fixes).
        assert_eq!(
            coords(jar, None),
            Some(("acme".into(), "widget".into(), "1.0".into()))
        );
    }

    #[test]
    fn a_path_outside_the_declared_repository_falls_back_to_inference() {
        let jar = "/home/u/.m2/repository/com/acme/widget/1.0/widget-1.0.jar";
        assert_eq!(
            coords(jar, declared("/home/u/.m2/custom-repo")),
            coords(jar, None)
        );
        assert_eq!(
            coords(jar, None),
            Some(("com.acme".into(), "widget".into(), "1.0".into()))
        );
    }

    #[test]
    fn a_declared_repository_needs_a_whole_component_match() {
        // `custom-repo-old` is not inside `custom-repo`.
        let jar = "/home/u/.m2/custom-repo-old/repository/com/acme/widget/1.0/widget-1.0.jar";
        assert_eq!(
            coords(jar, declared("/home/u/.m2/custom-repo")),
            Some(("com.acme".into(), "widget".into(), "1.0".into()))
        );
    }

    #[test]
    fn settings_local_repository_is_read_and_resolved() {
        let home = Path::new("/home/u");
        let read = |xml: &str| declared_repository_from_settings(xml, home);
        assert_eq!(
            read("<settings><localRepository>/data/mvn</localRepository></settings>"),
            Some(PathBuf::from("/data/mvn"))
        );
        assert_eq!(
            read(
                "<settings><localRepository>\n  ${user.home}/.m2/custom-repo\n</localRepository></settings>"
            ),
            Some(PathBuf::from("/home/u/.m2/custom-repo"))
        );
        // A commented-out element is not a declaration.
        assert_eq!(
            read("<settings><!-- <localRepository>/old</localRepository> --></settings>"),
            None
        );
        // Anything we cannot resolve exactly is no declaration: relative paths
        // and other placeholders depend on where Maven was started.
        assert_eq!(read("<localRepository>rel/path</localRepository>"), None);
        assert_eq!(read("<localRepository>${env.M2}/x</localRepository>"), None);
        // Absolute, but with a placeholder we cannot expand.
        assert_eq!(
            read("<localRepository>/data/${env.M2}/x</localRepository>"),
            None
        );
        assert_eq!(
            read("<localRepository>${user.home}/${env.X}</localRepository>"),
            None
        );
        assert_eq!(read("<localRepository></localRepository>"), None);
        assert_eq!(read("<settings/>"), None);
    }

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_jar_simple_group() {
        let path = PathBuf::from(
            "/home/user/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar",
        );
        assert_eq!(
            semantic_name(&path),
            Some("com.google.guava:guava 32.0.0-jre".into())
        );
    }

    #[test]
    fn semantic_name_jar_multi_component_group() {
        let path = PathBuf::from(
            "/home/user/.m2/repository/org/springframework/boot/spring-boot/3.2.0/spring-boot-3.2.0.jar",
        );
        assert_eq!(
            semantic_name(&path),
            Some("org.springframework.boot:spring-boot 3.2.0".into())
        );
    }

    #[test]
    fn group_containing_repository_component_keeps_full_coordinates() {
        // Issue #103: walking up and stopping at ANY component named
        // `repository` cut the group short at `com.repository.acme`, so the
        // package was attributed to the wrong coordinates (`acme:widget`) and
        // OSV findings for the real ones were missed.
        let jar = "/home/user/.m2/repository/com/repository/acme/widget/1.0/widget-1.0.jar";
        let path = PathBuf::from(jar);
        assert_eq!(
            semantic_name(&path),
            Some("com.repository.acme:widget 1.0".into())
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "com.repository.acme:widget");
        assert_eq!(id.version, "1.0");

        // `repository` as the FIRST group component, and as the last.
        let first =
            PathBuf::from("/home/user/.m2/repository/repository/acme/widget/1.0/widget-1.0.jar");
        assert_eq!(package_id(&first).unwrap().name, "repository.acme:widget");
        let last = PathBuf::from(
            "/home/user/.m2/repository/com/acme/repository/widget/1.0/widget-1.0.jar",
        );
        assert_eq!(
            package_id(&last).unwrap().name,
            "com.acme.repository:widget"
        );
    }

    #[test]
    fn repository_nested_below_m2_is_still_parsed() {
        // `detect` classifies anything under a `.m2` ancestor as Maven, so a
        // local repository configured below `.m2` (e.g. `.m2/work/repository`)
        // must keep its coordinates, including a `repository` group part.
        let plain =
            PathBuf::from("/home/user/.m2/work/repository/com/acme/widget/1.0/widget-1.0.jar");
        assert_eq!(package_id(&plain).unwrap().name, "com.acme:widget");
        let interior = PathBuf::from(
            "/home/user/.m2/work/repository/com/repository/acme/widget/1.0/widget-1.0.jar",
        );
        assert_eq!(
            package_id(&interior).unwrap().name,
            "com.repository.acme:widget"
        );
    }

    #[test]
    fn m2_without_any_repository_dir_yields_no_coordinates() {
        // No `repository` directory below `.m2`: nothing to anchor to, so no
        // guessed group (this was already `None` before #103).
        let path = PathBuf::from("/home/user/.m2/custom-repo/com/acme/widget/1.0/widget-1.0.jar");
        assert!(package_id(&path).is_none());
    }

    #[test]
    fn no_verified_m2_repository_ancestor_yields_no_coordinates() {
        // A `repository` dir that is not `.m2/repository` is not a verified
        // Maven root, so we must not guess coordinates from it.
        let path = PathBuf::from("/tmp/repository/com/acme/widget/1.0/widget-1.0.jar");
        assert_eq!(semantic_name(&path), None);
        assert!(package_id(&path).is_none());
        let no_root = PathBuf::from("/com/acme/widget/1.0/widget-1.0.jar");
        assert!(package_id(&no_root).is_none());
    }

    #[test]
    fn parent_dir_components_are_resolved_lexically() {
        // `Path::components()` keeps `..` and configured roots are only
        // tilde-expanded, so a scan root like `~/proj/../.m2/repository` carries
        // `..` into every artifact path. Left in, it leaked into the group
        // (`...repository.com.acme`) and queried OSV for the wrong package;
        // rejecting it instead silently dropped every package under that root.
        // Resolve it: the coordinates are those of the resolved location.
        let resolved = [
            // `..` in the root prefix (the realistic case).
            (
                "/home/user/proj/../.m2/repository/com/acme/widget/1.0/widget-1.0.jar",
                "com.acme:widget",
            ),
            (
                "/home/user/../user/.m2/repository/com/acme/widget/1.0/widget-1.0.jar",
                "com.acme:widget",
            ),
            // `..` after the root resolves to the real location.
            (
                "/home/user/.m2/repository/../repository/com/acme/widget/1.0/widget-1.0.jar",
                "com.acme:widget",
            ),
            (
                "/home/user/.m2/repository/com/../acme/widget/1.0/widget-1.0.jar",
                "acme:widget",
            ),
        ];
        for (p, expected) in resolved {
            let id = package_id(&PathBuf::from(p));
            assert_eq!(id.map(|i| i.name).as_deref(), Some(expected), "{p}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_after_a_symlink_is_not_resolved_lexically() {
        // `alias/..` on a real filesystem is the PARENT OF THE SYMLINK TARGET,
        // not the directory holding the link, so dropping `alias` lexically
        // would report the wrong package (`com.acme:widget` instead of the one
        // at `org/com/acme`). Where `..` cannot be resolved safely: no coordinates.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join(".m2/repository");
        std::fs::create_dir_all(repo.join("org/vendor")).unwrap();
        let widget = repo.join("org/com/acme/widget/1.0");
        std::fs::create_dir_all(&widget).unwrap();
        std::fs::write(widget.join("widget-1.0.jar"), b"").unwrap();
        std::os::unix::fs::symlink("org/vendor", repo.join("alias")).unwrap();
        std::fs::create_dir_all(repo.join("real")).unwrap();
        std::fs::create_dir_all(repo.join("com/acme/widget/1.0")).unwrap();
        std::fs::write(repo.join("com/acme/widget/1.0/widget-1.0.jar"), b"").unwrap();

        // Reached through the symlink: exists on disk, but `..` is symlink-relative.
        let via_link = repo.join("alias/../com/acme/widget/1.0/widget-1.0.jar");
        assert!(
            std::fs::metadata(&via_link).is_ok(),
            "fixture must exist: {}",
            via_link.display()
        );
        assert!(package_id(&via_link).is_none(), "{}", via_link.display());

        // Control: `..` after a real directory still resolves.
        let via_dir = repo.join("real/../com/acme/widget/1.0/widget-1.0.jar");
        assert_eq!(package_id(&via_dir).unwrap().name, "com.acme:widget");
    }

    #[test]
    fn parent_dir_climbing_above_the_start_fails_closed() {
        // Nothing to resolve `..` against: no coordinates rather than a guess.
        for p in [
            "../.m2/repository/com/acme/widget/1.0/widget-1.0.jar",
            "/../.m2/repository/com/acme/widget/1.0/widget-1.0.jar",
            "/home/../../.m2/repository/com/acme/widget/1.0/widget-1.0.jar",
        ] {
            let path = PathBuf::from(p);
            assert_eq!(semantic_name(&path), None, "{p}");
            assert!(package_id(&path).is_none(), "{p}");
        }
    }

    #[test]
    fn semantic_name_pom_file_is_also_named() {
        let path = PathBuf::from(
            "/home/user/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.pom",
        );
        assert_eq!(
            semantic_name(&path),
            Some("com.google.guava:guava 32.0.0-jre".into())
        );
    }

    #[test]
    fn semantic_name_non_maven_file_returns_none() {
        let path = PathBuf::from("/home/user/.m2/repository/com/google/guava/README.txt");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_directory_returns_none() {
        let path = PathBuf::from("/home/user/.m2/repository/com/google/guava/guava/32.0.0-jre");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn package_id_from_jar() {
        let path = PathBuf::from(
            "/home/user/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar",
        );
        let id = package_id(&path).expect("should produce PackageId");
        assert_eq!(id.ecosystem, "Maven");
        assert_eq!(id.name, "com.google.guava:guava");
        assert_eq!(id.version, "32.0.0-jre");
    }

    #[test]
    fn package_id_pom_returns_none_to_avoid_duplicates() {
        // Dedup on .jar only; .pom sits alongside and must not produce a second PackageId
        let path = PathBuf::from(
            "/home/user/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.pom",
        );
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_non_jar_returns_none() {
        let path = PathBuf::from("/home/user/.m2/repository/com/google/guava/README.txt");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn metadata_repository_dir_reports_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repository");
        std::fs::create_dir_all(&repo).unwrap();
        let fields = metadata(&repo);
        assert!(
            fields.iter().any(|f| f.label == "Contents"),
            "expected a Contents field"
        );
    }

    #[test]
    fn metadata_non_repository_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let somewhere = tmp.path().join("random");
        std::fs::create_dir_all(&somewhere).unwrap();
        assert!(metadata(&somewhere).is_empty());
    }
}
