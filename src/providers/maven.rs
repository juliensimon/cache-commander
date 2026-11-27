use super::MetadataField;
use std::path::Path;

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
/// Known limit, only when the scan root is NOT passed (`root` is `None`): the
/// root is inferred from the path alone, so a custom root not named
/// `repository` (e.g. `.m2/custom-repo/com/repository/acme/...`) cannot be told
/// apart from a nested `.m2/work/repository`. With the scan root the repository
/// root is known where it is unambiguous, see `scan_root_as_repository`.
fn parse_coordinates(root: Option<&Path>, path: &Path) -> Option<(String, String, String)> {
    let comps = resolve_parent_dirs(path)?;
    let m2 = comps.iter().position(|c| c == ".m2")?;
    let root = match root.and_then(|r| scan_root_as_repository(r, &comps, m2)) {
        Some(declared) => declared,
        None => m2 + 1 + comps[m2 + 1..].iter().position(|c| c == "repository")?,
    };
    // <group...> <artifact> <version> <file>, with at least one group part.
    let rest = &comps[root + 1..];
    if rest.len() < 4 {
        return None;
    }
    let (group, tail) = rest.split_at(rest.len() - 3);
    Some((group.join("."), tail[0].clone(), tail[1].clone()))
}

/// Index in `path_comps` (the resolved components of a path under `root`) of the
/// repository root when the scan root itself is that root, else `None` to fall
/// back to inference. The scan root is taken to BE the repository only when it
/// sits strictly below the `.m2` at `m2` and has no `repository` component after
/// it: then nothing at or above it could be the repository (`.m2/repository`,
/// `.m2/work/repository`, a subtree of either all keep their inferred root), so
/// the only repository the path can be in is the root itself (`.m2/custom-repo`).
/// A root that is `.m2` itself, a root the path is not under, or one with no
/// `.m2` at or above it says nothing, and also falls back.
fn scan_root_as_repository(root: &Path, path_comps: &[String], m2: usize) -> Option<usize> {
    let root_comps = resolve_parent_dirs(root)?;
    let under_root = path_comps.len() > root_comps.len() && path_comps.starts_with(&root_comps);
    let strictly_below_m2 = root_comps.len() > m2 + 1;
    let names_a_repository = root_comps.iter().skip(m2 + 1).any(|c| c == "repository");
    (under_root && strictly_below_m2 && !names_a_repository).then(|| root_comps.len() - 1)
}

#[allow(dead_code)] // path-only entry point: public library API and tests; the app passes the root
pub fn semantic_name(path: &Path) -> Option<String> {
    semantic_name_in(None, path)
}

/// Like `semantic_name`, with the configured scan root the path was found under.
pub fn semantic_name_in(root: Option<&Path>, path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();
    if !name.ends_with(".jar") && !name.ends_with(".pom") {
        return None;
    }
    let (group, artifact, version) = parse_coordinates(root, path)?;
    Some(format!("{group}:{artifact} {version}"))
}

#[allow(dead_code)] // path-only entry point: public library API and tests; the app passes the root
pub fn package_id(path: &Path) -> Option<super::PackageId> {
    package_id_in(None, path)
}

/// Like `package_id`, with the configured scan root the path was found under.
pub fn package_id_in(root: Option<&Path>, path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();
    // Dedup on .jar — .pom sits alongside and would double-count.
    if !name.ends_with(".jar") {
        return None;
    }
    let (group, artifact, version) = parse_coordinates(root, path)?;
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

    // ---- #118: the configured scan root removes the layout ambiguity ----------

    const CUSTOM_JAR: &str =
        "/home/user/.m2/custom-repo/com/repository/acme/widget/1.0/widget-1.0.jar";
    const WORK_JAR: &str = "/home/user/.m2/work/repository/com/acme/widget/1.0/widget-1.0.jar";

    #[test]
    fn a_root_that_is_itself_the_repository_anchors_coordinates() {
        // From the path alone `.m2/custom-repo/com/repository/acme/...` is read as
        // `acme:widget` (the first `repository` after `.m2`). Knowing the scan
        // root is `.m2/custom-repo` makes the repository root known, not inferred.
        let root = PathBuf::from("/home/user/.m2/custom-repo");
        let jar = PathBuf::from(CUSTOM_JAR);
        assert_eq!(
            package_id_in(Some(&root), &jar).unwrap().name,
            "com.repository.acme:widget"
        );
        assert_eq!(
            semantic_name_in(Some(&root), &jar),
            Some("com.repository.acme:widget 1.0".into())
        );
        // Without the root the limit is unchanged (documented, and never worse
        // than before): it is mis-parsed.
        assert_eq!(package_id(&jar).unwrap().name, "acme:widget");
    }

    #[test]
    fn a_custom_named_root_with_no_repository_dir_now_has_coordinates() {
        let root = PathBuf::from("/home/user/.m2/custom-repo");
        let jar = PathBuf::from("/home/user/.m2/custom-repo/com/acme/widget/1.0/widget-1.0.jar");
        assert_eq!(
            package_id_in(Some(&root), &jar).unwrap().name,
            "com.acme:widget"
        );
        assert!(package_id(&jar).is_none(), "path alone still cannot know");
    }

    #[test]
    fn the_standard_roots_are_unaffected_by_passing_them() {
        for root in [
            "/home/user/.m2/repository",
            "/home/user/.m2/work/repository",
        ] {
            let root = PathBuf::from(root);
            let jar = PathBuf::from(format!(
                "{}/com/repository/acme/widget/1.0/widget-1.0.jar",
                root.display()
            ));
            assert_eq!(
                package_id_in(Some(&root), &jar).unwrap().name,
                "com.repository.acme:widget",
                "root {}",
                root.display()
            );
        }
        let jar = PathBuf::from(WORK_JAR);
        assert_eq!(
            package_id_in(Some(Path::new("/home/user/.m2/work/repository")), &jar)
                .unwrap()
                .name,
            "com.acme:widget"
        );
    }

    #[test]
    fn a_root_inside_a_standard_repository_does_not_move_the_repository_root() {
        // Scanning a SUBTREE of the repository must not make that subtree the
        // repository: a `repository` component at or above the root wins.
        let root = PathBuf::from("/home/user/.m2/repository/com/google");
        let jar = PathBuf::from(
            "/home/user/.m2/repository/com/google/guava/guava/32.0.0/guava-32.0.0.jar",
        );
        assert_eq!(
            package_id_in(Some(&root), &jar).unwrap().name,
            "com.google.guava:guava"
        );
    }

    #[test]
    fn a_root_that_is_m2_itself_or_unrelated_falls_back_to_inference() {
        let jar = PathBuf::from(CUSTOM_JAR);
        // `.m2` is not the repository; the repository is somewhere below it.
        let m2 = PathBuf::from("/home/user/.m2");
        assert_eq!(package_id_in(Some(&m2), &jar), package_id(&jar));
        // A root the path is not under says nothing about it.
        let other = PathBuf::from("/somewhere/else/.m2/custom-repo");
        assert_eq!(package_id_in(Some(&other), &jar), package_id(&jar));
        // A root with no `.m2` at or above it cannot vouch for a Maven layout.
        let no_m2 = PathBuf::from("/data/maven");
        let no_m2_jar = PathBuf::from("/data/maven/com/acme/widget/1.0/widget-1.0.jar");
        assert!(package_id_in(Some(&no_m2), &no_m2_jar).is_none());
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
