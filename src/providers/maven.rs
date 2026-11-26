use super::MetadataField;
use std::path::Path;

/// The path's components with each `..` resolved lexically against the
/// component before it. Configured scan roots are only tilde-expanded, so a
/// root like `~/proj/../.m2/repository` carries `..` into every artifact path;
/// left unresolved it would end up in the group id, and rejecting it would
/// silently drop every package under that root. Returns `None` when a `..`
/// has nothing to resolve against (it would climb above the start or the
/// filesystem root), rather than guessing.
fn resolve_parent_dirs(path: &Path) -> Option<Vec<String>> {
    use std::path::Component;
    let mut comps: Vec<String> = Vec::new();
    // Index of the first component that `..` may remove: everything after a
    // root/prefix marker, so `/..` is never "resolved" away.
    let mut floor = 0;
    for c in path.components() {
        match c {
            Component::ParentDir => {
                if comps.len() <= floor {
                    return None;
                }
                comps.pop();
            }
            Component::Normal(s) => comps.push(s.to_string_lossy().into_owned()),
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {
                comps.push(c.as_os_str().to_string_lossy().into_owned());
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
/// Known limit: the root is inferred from the path alone, so a custom root not
/// named `repository` (e.g. `.m2/custom-repo/com/repository/acme/...`) cannot be
/// told apart from a nested `.m2/work/repository`; see #118 (needs the scan root).
fn parse_coordinates(path: &Path) -> Option<(String, String, String)> {
    let comps = resolve_parent_dirs(path)?;
    let m2 = comps.iter().position(|c| c == ".m2")?;
    let root = m2 + 1 + comps[m2 + 1..].iter().position(|c| c == "repository")?;
    // <group...> <artifact> <version> <file>, with at least one group part.
    let rest = &comps[root + 1..];
    if rest.len() < 4 {
        return None;
    }
    let (group, tail) = rest.split_at(rest.len() - 3);
    Some((group.join("."), tail[0].clone(), tail[1].clone()))
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
