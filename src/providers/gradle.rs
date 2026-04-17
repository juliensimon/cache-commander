use super::MetadataField;
use std::path::Path;

/// Parse a Gradle artifact path into (group, artifact, version).
/// Expects layout `.../files-2.1/<group>/<artifact>/<version>/<hash>/<file>`.
fn parse_coordinates(path: &Path) -> Option<(String, String, String)> {
    // file → hash → version → artifact → group → files-2.1
    let version = path
        .parent()?
        .parent()?
        .file_name()?
        .to_string_lossy()
        .to_string();
    let artifact = path
        .parent()?
        .parent()?
        .parent()?
        .file_name()?
        .to_string_lossy()
        .to_string();
    let group_dir = path.parent()?.parent()?.parent()?.parent()?;
    let group = group_dir.file_name()?.to_string_lossy().to_string();
    // Anchor check: the dir above `group` must be `files-2.1`.
    let anchor = group_dir
        .parent()?
        .file_name()?
        .to_string_lossy()
        .to_string();
    if anchor != "files-2.1" {
        return None;
    }
    Some((group, artifact, version))
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
    match name.as_str() {
        "caches" => fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Gradle dependency cache (modules, build cache, transforms)".to_string(),
        }),
        "wrapper" => fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Gradle wrapper distributions (gradle-*-bin.zip)".to_string(),
        }),
        _ => {}
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_jar_in_files_2_1() {
        let path = PathBuf::from(
            "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc123def/guava-32.0.0-jre.jar",
        );
        assert_eq!(
            semantic_name(&path),
            Some("com.google.guava:guava 32.0.0-jre".into())
        );
    }

    #[test]
    fn semantic_name_pom_also_named() {
        let path = PathBuf::from(
            "/home/user/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/1.9.0/deadbeef/kotlin-stdlib-1.9.0.pom",
        );
        assert_eq!(
            semantic_name(&path),
            Some("org.jetbrains.kotlin:kotlin-stdlib 1.9.0".into())
        );
    }

    #[test]
    fn semantic_name_non_jar_returns_none() {
        let path = PathBuf::from("/home/user/.gradle/caches/modules-2/files-2.1/x/y/1.0/h/NOTES");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_path_without_files_2_1_layout_returns_none() {
        // Path too shallow to have <group>/<artifact>/<version>/<hash>/<file>
        let path = PathBuf::from("/home/user/.gradle/caches/jar-3.jar");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn package_id_from_jar_uses_maven_ecosystem() {
        // Gradle artifacts share the Maven ecosystem for OSV (same pkg:maven purl).
        let path = PathBuf::from(
            "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc/guava-32.0.0-jre.jar",
        );
        let id = package_id(&path).expect("should produce PackageId");
        assert_eq!(id.ecosystem, "Maven");
        assert_eq!(id.name, "com.google.guava:guava");
        assert_eq!(id.version, "32.0.0-jre");
    }

    #[test]
    fn package_id_pom_returns_none() {
        let path = PathBuf::from(
            "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc/guava-32.0.0-jre.pom",
        );
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_outside_layout_returns_none() {
        let path = PathBuf::from("/home/user/.gradle/caches/jar-3.jar");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn metadata_caches_dir_reports_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let caches = tmp.path().join("caches");
        std::fs::create_dir_all(&caches).unwrap();
        let fields = metadata(&caches);
        assert!(
            fields.iter().any(|f| f.label == "Contents"),
            "expected a Contents field"
        );
    }

    #[test]
    fn metadata_wrapper_dir_reports_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = tmp.path().join("wrapper");
        std::fs::create_dir_all(&wrapper).unwrap();
        let fields = metadata(&wrapper);
        assert!(
            fields.iter().any(|f| f.label == "Contents"),
            "expected a Contents field for wrapper"
        );
        assert!(
            fields
                .iter()
                .any(|f| f.value.to_lowercase().contains("distribution")),
            "wrapper Contents should mention distributions"
        );
    }

    #[test]
    fn metadata_unrelated_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert!(metadata(&other).is_empty());
    }
}
