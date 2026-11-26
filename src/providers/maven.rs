use super::MetadataField;
use std::path::Path;

/// True iff `dir` is a verified Maven local repository root, `.../.m2/repository`.
/// A bare directory named `repository` is not enough: it can be part of a
/// group id (`com.repository.acme`).
fn is_m2_repository_root(dir: &Path) -> bool {
    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned());
    name(dir).as_deref() == Some("repository")
        && dir.parent().and_then(name).as_deref() == Some(".m2")
}

/// Parse a Maven artifact path into (group, artifact, version).
/// Expects layout `.../.m2/repository/<group-path>/<artifact>/<version>/<file>`.
/// Returns `None` when no `.m2/repository` ancestor is found, rather than
/// guessing a group from an unverified directory.
fn parse_coordinates(path: &Path) -> Option<(String, String, String)> {
    let version = path.parent()?.file_name()?.to_string_lossy().to_string();
    let artifact = path
        .parent()?
        .parent()?
        .file_name()?
        .to_string_lossy()
        .to_string();

    let mut group_parts: Vec<String> = Vec::new();
    let mut current = path.parent()?.parent()?.parent()?;
    loop {
        if is_m2_repository_root(current) {
            break;
        }
        // At the filesystem root `file_name()` is `None`: no anchor was found.
        group_parts.push(current.file_name()?.to_string_lossy().to_string());
        current = current.parent()?;
    }
    if group_parts.is_empty() {
        return None;
    }
    group_parts.reverse();
    Some((group_parts.join("."), artifact, version))
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
