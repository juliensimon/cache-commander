pub mod bun;
pub mod cargo;
pub mod chroma;
pub mod generic;
pub mod gh;
pub mod gradle;
pub mod homebrew;
pub mod huggingface;
pub mod maven;
pub mod npm;
pub mod pip;
pub mod pnpm;
pub mod pre_commit;
pub mod prisma;
pub mod swiftpm;
pub mod torch;
pub mod uv;
pub mod whisper;
pub mod xcode;
pub mod yarn;

use crate::tree::node::CacheKind;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MetadataField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SafetyLevel {
    Safe,
    Caution,
    Unsafe,
}

impl SafetyLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Safe => "Safe to delete (re-downloadable)",
            Self::Caution => "Caution — may cause rebuilds",
            Self::Unsafe => "Unsafe — contains config or state",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Safe => "●",
            Self::Caution => "◐",
            Self::Unsafe => "○",
        }
    }
}

/// Detect the CacheKind for a given path based on its name and parent context.
pub fn detect(path: &Path) -> CacheKind {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Direct name match
    match name.as_str() {
        "huggingface" => return CacheKind::HuggingFace,
        "pip" => return CacheKind::Pip,
        "uv" => return CacheKind::Uv,
        "Homebrew" => return CacheKind::Homebrew,
        "pre-commit" => return CacheKind::PreCommit,
        "whisper" => return CacheKind::Whisper,
        "gh" => return CacheKind::Gh,
        "torch" => return CacheKind::Torch,
        "chroma" => return CacheKind::Chroma,
        "prisma" => return CacheKind::Prisma,
        ".bun" => return CacheKind::Bun,
        ".npm" | "npm" => return CacheKind::Npm,
        ".yarn-cache" => return CacheKind::Yarn,
        ".pnpm-store" => return CacheKind::Pnpm,
        ".pnpm" => return CacheKind::Pnpm,
        ".m2" => return CacheKind::Maven,
        ".gradle" => return CacheKind::Gradle,
        "org.swift.swiftpm" => return CacheKind::SwiftPm,
        _ => {}
    }

    // Walk up the path to find a known ancestor
    for ancestor in path.ancestors().skip(1) {
        let ancestor_name = ancestor
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match ancestor_name.as_str() {
            ".pnpm-store" => return CacheKind::Pnpm,
            ".pnpm" if ancestor.to_string_lossy().contains("node_modules") => {
                return CacheKind::Pnpm;
            }
            "pnpm" if path.to_string_lossy().contains("store") => {
                return CacheKind::Pnpm;
            }
            ".m2" => return CacheKind::Maven,
            ".gradle" => return CacheKind::Gradle,
            "repository" if ancestor.to_string_lossy().contains(".m2") => {
                return CacheKind::Maven;
            }
            ".yarn-cache" | "Yarn" => return CacheKind::Yarn,
            ".yarn"
                if (path.to_string_lossy().contains(".yarn/cache")
                    || path.to_string_lossy().contains(".yarn\\cache")) =>
            {
                return CacheKind::Yarn;
            }
            "yarn" => {
                // ~/.cache/yarn/ is Classic
                if ancestor.to_string_lossy().contains(".cache") {
                    return CacheKind::Yarn;
                }
                // yarn/berry/cache is Berry global
                if path.to_string_lossy().contains("berry/cache") {
                    return CacheKind::Yarn;
                }
            }
            ".bun" => return CacheKind::Bun,
            "huggingface" => return CacheKind::HuggingFace,
            "pip" => return CacheKind::Pip,
            "uv" => return CacheKind::Uv,
            "Homebrew" => return CacheKind::Homebrew,
            "pre-commit" => return CacheKind::PreCommit,
            "whisper" => return CacheKind::Whisper,
            "gh" => return CacheKind::Gh,
            "torch" => return CacheKind::Torch,
            "chroma" => return CacheKind::Chroma,
            "prisma" => return CacheKind::Prisma,
            ".npm" | "npm" => return CacheKind::Npm,
            "registry" if ancestor.to_string_lossy().contains(".cargo") => {
                return CacheKind::Cargo;
            }
            "org.swift.swiftpm" => return CacheKind::SwiftPm,
            _ => {}
        }
    }

    // Xcode detection uses adjacent-component matching (L1-safe) rather
    // than single-component ancestor walks, because names like
    // "DerivedData" or "Caches" alone are too ambiguous to match
    // unconditionally.
    if has_adjacent_components(path, "Xcode", "DerivedData")
        || has_adjacent_components(path, "Xcode", "iOS DeviceSupport")
        || has_adjacent_components(path, "CoreSimulator", "Caches")
    {
        return CacheKind::Xcode;
    }

    CacheKind::Unknown
}

/// Get a human-readable semantic name for the path, if the provider supports it.
pub fn semantic_name(kind: CacheKind, path: &Path) -> Option<String> {
    match kind {
        CacheKind::HuggingFace => huggingface::semantic_name(path),
        CacheKind::Pip => pip::semantic_name(path),
        CacheKind::Uv => uv::semantic_name(path),
        CacheKind::Npm => npm::semantic_name(path),
        CacheKind::Homebrew => homebrew::semantic_name(path),
        CacheKind::Cargo => cargo::semantic_name(path),
        CacheKind::PreCommit => pre_commit::semantic_name(path),
        CacheKind::Whisper => whisper::semantic_name(path),
        CacheKind::Gh => gh::semantic_name(path),
        CacheKind::Torch => torch::semantic_name(path),
        CacheKind::Chroma => chroma::semantic_name(path),
        CacheKind::Prisma => prisma::semantic_name(path),
        CacheKind::Yarn => yarn::semantic_name(path),
        CacheKind::Pnpm => pnpm::semantic_name(path),
        CacheKind::Bun => bun::semantic_name(path),
        CacheKind::Maven => maven::semantic_name(path),
        CacheKind::Gradle => gradle::semantic_name(path),
        CacheKind::SwiftPm => swiftpm::semantic_name(path),
        CacheKind::Xcode => xcode::semantic_name(path),
        CacheKind::Unknown => None,
    }
}

/// Get metadata fields for the detail panel.
pub fn metadata(kind: CacheKind, path: &Path) -> Vec<MetadataField> {
    match kind {
        CacheKind::HuggingFace => huggingface::metadata(path),
        CacheKind::Pip => pip::metadata(path),
        CacheKind::Uv => uv::metadata(path),
        CacheKind::Npm => npm::metadata(path),
        CacheKind::Homebrew => homebrew::metadata(path),
        CacheKind::Cargo => cargo::metadata(path),
        CacheKind::PreCommit => pre_commit::metadata(path),
        CacheKind::Whisper => whisper::metadata(path),
        CacheKind::Gh => gh::metadata(path),
        CacheKind::Torch => torch::metadata(path),
        CacheKind::Chroma => chroma::metadata(path),
        CacheKind::Prisma => prisma::metadata(path),
        CacheKind::Yarn => yarn::metadata(path),
        CacheKind::Pnpm => pnpm::metadata(path),
        CacheKind::Bun => bun::metadata(path),
        CacheKind::Maven => maven::metadata(path),
        CacheKind::Gradle => gradle::metadata(path),
        CacheKind::SwiftPm => swiftpm::metadata(path),
        CacheKind::Xcode => xcode::metadata(path),
        CacheKind::Unknown => generic::metadata(path),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageId {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
}

pub fn package_id(kind: CacheKind, path: &Path) -> Option<PackageId> {
    match kind {
        CacheKind::Uv => uv::package_id(path),
        CacheKind::Pip => pip::package_id(path),
        CacheKind::Npm => npm::package_id(path),
        CacheKind::Cargo => cargo::package_id(path),
        CacheKind::Yarn => yarn::package_id(path),
        CacheKind::Pnpm => pnpm::package_id(path),
        CacheKind::Bun => bun::package_id(path),
        CacheKind::Maven => maven::package_id(path),
        CacheKind::Gradle => gradle::package_id(path),
        _ => None,
    }
}

/// Sanitize a string for safe use in a shell command.
/// Rejects names containing shell metacharacters.
fn is_safe_for_shell(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./@".contains(&b))
}

pub fn upgrade_command(kind: CacheKind, name: &str, version: &str) -> Option<String> {
    // Maven and Gradle take a different path: the name is `group:artifact`
    // (colon is not shell-safe) and the output is an XML / Groovy snippet
    // pasted into pom.xml or build.gradle, not a shell command. They have
    // their own safety rules in `maven_snippet` / `gradle_snippet`.
    match kind {
        CacheKind::Maven => return maven_snippet(name, version),
        CacheKind::Gradle => return gradle_snippet(name, version),
        _ => {}
    }

    if !is_safe_for_shell(name) || !is_safe_for_shell(version) {
        return None;
    }
    match kind {
        CacheKind::Pip => Some(format!("pip install '{name}>={version}'")),
        CacheKind::Uv => Some(format!("uv pip install '{name}>={version}'")),
        CacheKind::Npm => Some(format!("npm install {name}@{version}")),
        CacheKind::Cargo => Some(format!("cargo update -p {name}")),
        CacheKind::Yarn => Some(format!("yarn add {name}@{version}")),
        CacheKind::Pnpm => Some(format!("pnpm add {name}@{version}")),
        CacheKind::Bun => Some(format!("bun add {name}@{version}")),
        _ => None,
    }
}

/// True iff `s` is a plausible Maven coordinate fragment: alphanumerics plus
/// `.` `-` `_`. No angle brackets, quotes, spaces, or backslashes — those
/// would break the XML / Groovy snippet we paste into project files.
fn is_safe_for_maven_fragment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn maven_snippet(name: &str, version: &str) -> Option<String> {
    let (group, artifact) = name.split_once(':')?;
    if !is_safe_for_maven_fragment(group)
        || !is_safe_for_maven_fragment(artifact)
        || !is_safe_for_maven_fragment(version)
    {
        return None;
    }
    Some(format!(
        "<dependency><groupId>{group}</groupId>\
         <artifactId>{artifact}</artifactId>\
         <version>{version}</version></dependency>"
    ))
}

fn gradle_snippet(name: &str, version: &str) -> Option<String> {
    let (group, artifact) = name.split_once(':')?;
    if !is_safe_for_maven_fragment(group)
        || !is_safe_for_maven_fragment(artifact)
        || !is_safe_for_maven_fragment(version)
    {
        return None;
    }
    Some(format!("implementation '{group}:{artifact}:{version}'"))
}

/// Returns true if `path` contains two adjacent path components equal to `first`
/// then `second` (e.g. `install` followed by `cache`). This is stricter than a
/// substring match because it rejects `install/cache-backup` — the literal
/// component after `install` must be exactly `cache`, not merely start with it.
fn has_adjacent_components(path: &Path, first: &str, second: &str) -> bool {
    let components: Vec<&std::ffi::OsStr> = path.components().map(|c| c.as_os_str()).collect();
    components
        .windows(2)
        .any(|w| w[0] == first && w[1] == second)
}

/// Get safety level for deletion.
pub fn safety(kind: CacheKind, path: &Path) -> SafetyLevel {
    match kind {
        CacheKind::Pnpm => {
            if path.to_string_lossy().contains("node_modules/.pnpm") {
                SafetyLevel::Caution
            } else {
                SafetyLevel::Safe
            }
        }
        CacheKind::Yarn => {
            // Berry project-local caches (.yarn/cache/) may be committed to git (zero-install)
            let path_str = path.to_string_lossy();
            if path_str.contains(".yarn/cache") || path_str.contains(".yarn\\cache") {
                SafetyLevel::Caution
            } else {
                SafetyLevel::Safe
            }
        }
        CacheKind::Bun => {
            // `.bun/bin/*` is the Bun runtime binary itself — deleting it
            // breaks bun entirely, so treat as Unsafe.
            if has_adjacent_components(path, ".bun", "bin")
                || path.components().any(|c| c.as_os_str() == "bin")
                    && path
                        .ancestors()
                        .any(|a| a.file_name().is_some_and(|n| n == ".bun"))
                    && path
                        .file_name()
                        .is_some_and(|n| n == "bin" || n == "bun" || n == "bunx")
            {
                SafetyLevel::Unsafe
            } else if has_adjacent_components(path, "install", "cache") {
                // Only the install/cache subtree (package cache) is safe to delete.
                // Literal path components — substring matching leaks to siblings
                // like `install/cache-backup` (H7).
                SafetyLevel::Safe
            } else {
                SafetyLevel::Caution
            }
        }
        CacheKind::Gradle => {
            // Gradle's caches/ subdir houses a mix: dep caches (Safe) and
            // rebuild-expensive caches (Caution). Classify by subdir name.
            let path_str = path.to_string_lossy();
            if path_str.contains("/build-cache-")
                || path_str.contains("\\build-cache-")
                || path_str.contains("/transforms-")
                || path_str.contains("\\transforms-")
            {
                SafetyLevel::Caution
            } else {
                SafetyLevel::Safe
            }
        }
        CacheKind::SwiftPm => {
            // Walk the adjacent component after `org.swift.swiftpm` to decide.
            // Component-based match avoids L1 substring false positives.
            let comps: Vec<&std::ffi::OsStr> = path.components().map(|c| c.as_os_str()).collect();
            for w in comps.windows(2) {
                if w[0] == "org.swift.swiftpm" {
                    return match w[1].to_string_lossy().as_ref() {
                        "repositories" => SafetyLevel::Caution,
                        "artifacts" | "manifests" => SafetyLevel::Safe,
                        _ => SafetyLevel::Caution, // unknown future subdirs
                    };
                }
            }
            // Path is the root itself or outside the known layout.
            SafetyLevel::Caution
        }
        CacheKind::Xcode => {
            // Only DerivedData triggers Caution (rebuild cost). iOS
            // DeviceSupport and CoreSimulator caches are Safe. Component
            // matching avoids L1 substring leaks (DerivedData-backup stays
            // on the Safe fall-through).
            if has_adjacent_components(path, "Xcode", "DerivedData") {
                SafetyLevel::Caution
            } else {
                SafetyLevel::Safe
            }
        }
        CacheKind::Unknown => SafetyLevel::Caution,
        _ => SafetyLevel::Safe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- detect() ---

    #[test]
    fn detect_huggingface() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/huggingface")),
            CacheKind::HuggingFace
        );
    }

    #[test]
    fn detect_pip() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/pip")),
            CacheKind::Pip
        );
    }

    #[test]
    fn detect_uv() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/uv")),
            CacheKind::Uv
        );
    }

    #[test]
    fn detect_npm_dot() {
        assert_eq!(detect(&PathBuf::from("/home/user/.npm")), CacheKind::Npm);
    }

    #[test]
    fn detect_npm_plain() {
        assert_eq!(
            detect(&PathBuf::from("/Library/Caches/npm")),
            CacheKind::Npm
        );
    }

    #[test]
    fn detect_homebrew() {
        assert_eq!(
            detect(&PathBuf::from("/Library/Caches/Homebrew")),
            CacheKind::Homebrew
        );
    }

    #[test]
    fn detect_pre_commit() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/pre-commit")),
            CacheKind::PreCommit
        );
    }

    #[test]
    fn detect_whisper() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/whisper")),
            CacheKind::Whisper
        );
    }

    #[test]
    fn detect_cargo_registry_context() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cargo/registry/cache")),
            CacheKind::Cargo
        );
    }

    #[test]
    fn detect_huggingface_subdir_context() {
        assert_eq!(
            detect(&PathBuf::from("/cache/huggingface/hub")),
            CacheKind::HuggingFace
        );
    }

    #[test]
    fn detect_npm_subdir_context() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.npm/_cacache")),
            CacheKind::Npm
        );
    }

    #[test]
    fn detect_gh() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/gh")),
            CacheKind::Gh
        );
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.cache/something_random")),
            CacheKind::Unknown
        );
    }

    #[test]
    fn detect_maven_m2_dir() {
        assert_eq!(detect(&PathBuf::from("/home/user/.m2")), CacheKind::Maven);
    }

    #[test]
    fn detect_maven_repository_dir() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.m2/repository")),
            CacheKind::Maven
        );
    }

    #[test]
    fn detect_maven_jar_deep() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar"
            )),
            CacheKind::Maven
        );
    }

    #[test]
    fn detect_gradle_dot_dir() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.gradle")),
            CacheKind::Gradle
        );
    }

    #[test]
    fn detect_gradle_caches_subdir() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.gradle/caches")),
            CacheKind::Gradle
        );
    }

    #[test]
    fn detect_gradle_jar_deep() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc/guava-32.0.0-jre.jar"
            )),
            CacheKind::Gradle
        );
    }

    #[test]
    fn detect_yarn_classic_cache() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.yarn-cache/v6/npm-lodash-4.17.21-abc.tgz"
            )),
            CacheKind::Yarn
        );
    }

    #[test]
    fn detect_yarn_xdg_cache() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.cache/yarn/v6/npm-express-4.21.0-def.tgz"
            )),
            CacheKind::Yarn
        );
    }

    #[test]
    fn detect_yarn_berry_cache() {
        assert_eq!(
            detect(&PathBuf::from(
                "/project/.yarn/cache/lodash-npm-4.17.21-abc.zip"
            )),
            CacheKind::Yarn
        );
    }

    #[test]
    fn detect_yarn_macos_library() {
        assert_eq!(
            detect(&PathBuf::from("/Users/me/Library/Caches/Yarn/v6")),
            CacheKind::Yarn
        );
    }

    #[test]
    fn detect_yarn_releases_is_not_yarn_cache() {
        // .yarn/releases should NOT be detected as Yarn cache
        assert_eq!(
            detect(&PathBuf::from("/project/.yarn/releases/yarn-4.0.cjs")),
            CacheKind::Unknown
        );
    }

    #[test]
    fn detect_pnpm_store() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.pnpm-store/v3/files/ab/cd")),
            CacheKind::Pnpm
        );
    }

    #[test]
    fn detect_pnpm_virtual_store() {
        assert_eq!(
            detect(&PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21")),
            CacheKind::Pnpm
        );
    }

    #[test]
    fn detect_pnpm_xdg_store() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.local/share/pnpm/store/v3/files/ab"
            )),
            CacheKind::Pnpm
        );
    }

    // --- semantic_name() dispatch ---

    #[test]
    fn semantic_name_dispatches_to_huggingface() {
        let path = PathBuf::from("/cache/hub/models--org--model");
        assert_eq!(
            semantic_name(CacheKind::HuggingFace, &path),
            Some("[model] org/model".into())
        );
    }

    #[test]
    fn semantic_name_dispatches_to_whisper() {
        let path = PathBuf::from("/cache/whisper/large-v3.pt");
        assert_eq!(
            semantic_name(CacheKind::Whisper, &path),
            Some("Whisper Large V3".into())
        );
    }

    #[test]
    fn semantic_name_unknown_returns_none() {
        let path = PathBuf::from("/cache/random/dir");
        assert_eq!(semantic_name(CacheKind::Unknown, &path), None);
    }

    // --- safety() ---

    #[test]
    fn safety_known_providers_are_safe() {
        let path = PathBuf::from("/tmp");
        assert_eq!(safety(CacheKind::HuggingFace, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Pip, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Uv, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Npm, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Homebrew, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Cargo, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::PreCommit, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Whisper, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Gh, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Torch, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Chroma, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Prisma, &path), SafetyLevel::Safe);
        assert_eq!(safety(CacheKind::Yarn, &path), SafetyLevel::Safe);
        assert_eq!(
            safety(CacheKind::Pnpm, &PathBuf::from("/home/.pnpm-store/v3")),
            SafetyLevel::Safe
        );
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/.bun/install/cache")
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_pnpm_virtual_store_is_caution() {
        assert_eq!(
            safety(
                CacheKind::Pnpm,
                &PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21")
            ),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_unknown_is_caution() {
        assert_eq!(
            safety(CacheKind::Unknown, &PathBuf::from("/tmp")),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_yarn_berry_project_local_is_caution() {
        assert_eq!(
            safety(
                CacheKind::Yarn,
                &PathBuf::from("/project/.yarn/cache/lodash-npm-4.17.21-abc.zip")
            ),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_yarn_classic_global_is_safe() {
        assert_eq!(
            safety(
                CacheKind::Yarn,
                &PathBuf::from("/home/user/.cache/yarn/v6/npm-lodash-4.17.21-abc-integrity")
            ),
            SafetyLevel::Safe
        );
    }

    // --- SafetyLevel ---

    #[test]
    fn safety_level_labels() {
        assert!(SafetyLevel::Safe.label().contains("Safe"));
        assert!(SafetyLevel::Caution.label().contains("Caution"));
        assert!(SafetyLevel::Unsafe.label().contains("Unsafe"));
    }

    #[test]
    fn safety_level_icons_are_distinct() {
        let icons = [
            SafetyLevel::Safe.icon(),
            SafetyLevel::Caution.icon(),
            SafetyLevel::Unsafe.icon(),
        ];
        assert_ne!(icons[0], icons[1]);
        assert_ne!(icons[1], icons[2]);
        assert_ne!(icons[0], icons[2]);
    }

    #[test]
    fn upgrade_command_pip() {
        assert_eq!(
            upgrade_command(CacheKind::Pip, "requests", "2.32.0"),
            Some("pip install 'requests>=2.32.0'".to_string())
        );
    }

    #[test]
    fn upgrade_command_uv() {
        assert_eq!(
            upgrade_command(CacheKind::Uv, "flask", "3.1.0"),
            Some("uv pip install 'flask>=3.1.0'".to_string())
        );
    }

    #[test]
    fn upgrade_command_npm() {
        assert_eq!(
            upgrade_command(CacheKind::Npm, "express", "4.19.0"),
            Some("npm install express@4.19.0".to_string())
        );
    }

    #[test]
    fn upgrade_command_cargo() {
        assert_eq!(
            upgrade_command(CacheKind::Cargo, "serde", "1.0.200"),
            Some("cargo update -p serde".to_string())
        );
    }

    #[test]
    fn upgrade_command_unknown_returns_none() {
        assert_eq!(upgrade_command(CacheKind::Unknown, "foo", "1.0"), None);
    }

    #[test]
    fn upgrade_command_yarn() {
        assert_eq!(
            upgrade_command(CacheKind::Yarn, "lodash", "4.17.21"),
            Some("yarn add lodash@4.17.21".to_string())
        );
    }

    #[test]
    fn upgrade_command_pnpm() {
        assert_eq!(
            upgrade_command(CacheKind::Pnpm, "lodash", "4.17.21"),
            Some("pnpm add lodash@4.17.21".to_string())
        );
    }

    #[test]
    fn upgrade_command_unsupported_kinds_return_none() {
        let unsupported = [
            CacheKind::HuggingFace,
            CacheKind::Homebrew,
            CacheKind::PreCommit,
            CacheKind::Whisper,
            CacheKind::Gh,
            CacheKind::Torch,
            CacheKind::Chroma,
            CacheKind::Prisma,
        ];
        for kind in unsupported {
            assert_eq!(
                upgrade_command(kind, "pkg", "1.0"),
                None,
                "{:?} should return None for upgrade_command",
                kind
            );
        }
    }

    // --- Maven / Gradle: snippets rather than shell commands -------------
    //
    // There's no clean single-line CLI to upgrade a JVM dependency — the
    // user must edit pom.xml or build.gradle. So upgrade_command returns a
    // copy-pasteable snippet instead. This is still a `String` on the
    // clipboard; the UI layer doesn't care that it isn't a shell command.

    #[test]
    fn upgrade_command_maven_returns_xml_snippet() {
        assert_eq!(
            upgrade_command(
                CacheKind::Maven,
                "org.apache.logging.log4j:log4j-core",
                "2.26.0",
            ),
            Some(
                "<dependency><groupId>org.apache.logging.log4j</groupId>\
                 <artifactId>log4j-core</artifactId>\
                 <version>2.26.0</version></dependency>"
                    .to_string()
            )
        );
    }

    #[test]
    fn upgrade_command_gradle_returns_groovy_dsl_line() {
        assert_eq!(
            upgrade_command(CacheKind::Gradle, "com.google.guava:guava", "33.0.0-jre"),
            Some("implementation 'com.google.guava:guava:33.0.0-jre'".to_string())
        );
    }

    #[test]
    fn upgrade_command_maven_without_colon_returns_none() {
        // Name must be `group:artifact`. A bare artifact name is malformed.
        assert_eq!(
            upgrade_command(CacheKind::Maven, "log4j-core", "2.26.0"),
            None
        );
    }

    #[test]
    fn upgrade_command_gradle_without_colon_returns_none() {
        assert_eq!(
            upgrade_command(CacheKind::Gradle, "guava", "33.0.0-jre"),
            None
        );
    }

    #[test]
    fn upgrade_command_maven_rejects_xml_breaking_chars() {
        // Defense in depth: prevent the snippet from escaping XML context
        // if a malformed coordinate ever reaches here.
        for bad in &["group<x:artifact", "group:art<ifact", "group:artifact"] {
            let out = upgrade_command(CacheKind::Maven, bad, "2.26.0");
            if *bad == "group:artifact" {
                assert!(out.is_some(), "baseline should succeed");
            } else {
                assert_eq!(out, None, "{} must be rejected", bad);
            }
        }
        assert_eq!(
            upgrade_command(CacheKind::Maven, "group:artifact", "1.0<inject>"),
            None
        );
    }

    #[test]
    fn upgrade_command_gradle_rejects_quote_injection() {
        assert_eq!(
            upgrade_command(CacheKind::Gradle, "group:art'ifact", "1.0"),
            None
        );
        assert_eq!(
            upgrade_command(CacheKind::Gradle, "group:artifact", "1.0'; evil"),
            None
        );
    }

    // --- Shell safety in upgrade_command ---

    #[test]
    fn upgrade_command_rejects_shell_injection_in_name() {
        assert_eq!(
            upgrade_command(CacheKind::Pip, "foo; rm -rf /", "1.0"),
            None
        );
    }

    #[test]
    fn upgrade_command_rejects_shell_injection_in_version() {
        assert_eq!(
            upgrade_command(CacheKind::Npm, "express", "1.0 && curl evil.com"),
            None
        );
    }

    #[test]
    fn upgrade_command_rejects_backtick_substitution() {
        assert_eq!(upgrade_command(CacheKind::Pip, "`whoami`", "1.0"), None);
    }

    #[test]
    fn upgrade_command_rejects_dollar_substitution() {
        assert_eq!(upgrade_command(CacheKind::Pip, "$(whoami)", "1.0"), None);
    }

    #[test]
    fn upgrade_command_rejects_pipe() {
        assert_eq!(
            upgrade_command(CacheKind::Pip, "foo|cat /etc/passwd", "1.0"),
            None
        );
    }

    #[test]
    fn upgrade_command_rejects_empty_name() {
        assert_eq!(upgrade_command(CacheKind::Pip, "", "1.0"), None);
    }

    #[test]
    fn upgrade_command_allows_scoped_npm() {
        assert_eq!(
            upgrade_command(CacheKind::Npm, "@types/node", "22.0.0"),
            Some("npm install @types/node@22.0.0".to_string())
        );
    }

    #[test]
    fn upgrade_command_allows_dotted_names() {
        assert_eq!(
            upgrade_command(CacheKind::Pip, "python-dateutil", "2.9.0"),
            Some("pip install 'python-dateutil>=2.9.0'".to_string())
        );
    }

    #[test]
    fn upgrade_command_allows_underscored_names() {
        assert_eq!(
            upgrade_command(CacheKind::Pip, "typing_extensions", "4.12.0"),
            Some("pip install 'typing_extensions>=4.12.0'".to_string())
        );
    }

    // --- is_safe_for_shell ---

    #[test]
    fn is_safe_for_shell_allows_normal_names() {
        assert!(is_safe_for_shell("requests"));
        assert!(is_safe_for_shell("flask-restful"));
        assert!(is_safe_for_shell("@babel/core"));
        assert!(is_safe_for_shell("1.2.3"));
    }

    #[test]
    fn is_safe_for_shell_rejects_dangerous_chars() {
        assert!(!is_safe_for_shell(";"));
        assert!(!is_safe_for_shell("a b"));
        assert!(!is_safe_for_shell("$(cmd)"));
        assert!(!is_safe_for_shell("`cmd`"));
        assert!(!is_safe_for_shell("a|b"));
        assert!(!is_safe_for_shell("a&b"));
        assert!(!is_safe_for_shell("a\nb"));
        assert!(!is_safe_for_shell(""));
    }

    // =================================================================
    // Adversarial tests — detection collisions & cross-provider edge cases
    // =================================================================

    // --- Detection collisions: can a path match the wrong provider? ---

    #[test]
    fn detect_pnpm_inside_npm_cache_is_pnpm() {
        // node_modules/.pnpm inside an .npm root — pnpm should win
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.npm/node_modules/.pnpm/lodash@4.17.21"
            )),
            CacheKind::Pnpm
        );
    }

    #[test]
    fn detect_npm_node_modules_not_pnpm() {
        // Plain node_modules (no .pnpm) under .npm — should be npm, not pnpm
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.npm/_npx/abc/node_modules/lodash"
            )),
            CacheKind::Npm
        );
    }

    #[test]
    fn detect_yarn_dot_yarn_plugins_not_cache() {
        // .yarn/plugins — NOT a cache directory
        assert_eq!(
            detect(&PathBuf::from(
                "/project/.yarn/plugins/@yarnpkg/plugin-compat.cjs"
            )),
            CacheKind::Unknown
        );
    }

    #[test]
    fn detect_yarn_dot_yarn_unplugged_not_cache() {
        // .yarn/unplugged — NOT a cache directory
        assert_eq!(
            detect(&PathBuf::from(
                "/project/.yarn/unplugged/esbuild-npm-0.19.0/node_modules"
            )),
            CacheKind::Unknown
        );
    }

    #[test]
    fn detect_pnpm_dir_outside_node_modules_is_unknown() {
        // .pnpm ancestor WITHOUT node_modules → Unknown, not Pnpm
        // The ancestor walk requires "node_modules" in the path for .pnpm
        // Only the direct name ".pnpm" matches unconditionally
        assert_eq!(
            detect(&PathBuf::from("/project/.pnpm/something")),
            CacheKind::Unknown
        );
    }

    #[test]
    fn detect_pnpm_direct_name_match() {
        // When the file IS named .pnpm (not a child of it), direct match fires
        assert_eq!(
            detect(&PathBuf::from("/project/node_modules/.pnpm")),
            CacheKind::Pnpm
        );
    }

    #[test]
    fn detect_yarn_inside_pnpm_store() {
        // Unlikely: a "yarn" dir inside pnpm store — pnpm should win (earlier in walk)
        assert_eq!(
            detect(&PathBuf::from("/home/user/.pnpm-store/v3/yarn/something")),
            CacheKind::Pnpm
        );
    }

    #[test]
    fn detect_npm_named_dir_inside_yarn_cache_matches_npm() {
        // "npm" dir inside Yarn Classic cache — the ancestor walk finds "npm"
        // in the dir name before reaching "yarn" higher up. This is a known
        // quirk: the deepest matching ancestor wins. In practice this path
        // (node_modules/npm inside a Yarn cache entry) is the npm CLI package
        // itself, and detecting it as Npm is arguably correct.
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.cache/yarn/v6/npm-lodash-4.17.21-abc-integrity/node_modules/npm"
            )),
            CacheKind::Npm
        );
    }

    // --- Safety: adversarial paths ---

    #[test]
    fn safety_yarn_berry_nested_deep() {
        // Deep path inside Berry cache — still Caution
        assert_eq!(
            safety(
                CacheKind::Yarn,
                &PathBuf::from("/project/.yarn/cache/node_modules/@babel/core/index.js")
            ),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_yarn_library_caches_is_safe() {
        // macOS global cache — Safe (not project-local)
        assert_eq!(
            safety(
                CacheKind::Yarn,
                &PathBuf::from("/Users/me/Library/Caches/Yarn/v6/npm-lodash-abc-integrity")
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_pnpm_store_is_safe() {
        assert_eq!(
            safety(
                CacheKind::Pnpm,
                &PathBuf::from("/home/user/.pnpm-store/v3/files/ab/cd")
            ),
            SafetyLevel::Safe
        );
    }

    // --- upgrade_command: Yarn/pnpm with scoped packages ---

    #[test]
    fn upgrade_command_yarn_scoped() {
        assert_eq!(
            upgrade_command(CacheKind::Yarn, "@babel/core", "7.24.0"),
            Some("yarn add @babel/core@7.24.0".to_string())
        );
    }

    #[test]
    fn upgrade_command_pnpm_scoped() {
        assert_eq!(
            upgrade_command(CacheKind::Pnpm, "@types/node", "22.0.0"),
            Some("pnpm add @types/node@22.0.0".to_string())
        );
    }

    #[test]
    fn upgrade_command_yarn_rejects_injection() {
        assert_eq!(
            upgrade_command(CacheKind::Yarn, "lodash; rm -rf /", "4.17.21"),
            None
        );
    }

    #[test]
    fn upgrade_command_pnpm_rejects_injection() {
        assert_eq!(upgrade_command(CacheKind::Pnpm, "$(whoami)", "1.0.0"), None);
    }

    // --- Bun detection ---

    #[test]
    fn detect_bun_root() {
        assert_eq!(detect(&PathBuf::from("/home/user/.bun")), CacheKind::Bun);
    }

    #[test]
    fn detect_bun_install_cache() {
        assert_eq!(
            detect(&PathBuf::from("/home/user/.bun/install/cache")),
            CacheKind::Bun
        );
    }

    #[test]
    fn detect_bun_package_subdir() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.bun/install/cache/lodash@4.17.21"
            )),
            CacheKind::Bun
        );
    }

    #[test]
    fn detect_bun_scoped_package() {
        assert_eq!(
            detect(&PathBuf::from(
                "/home/user/.bun/install/cache/@babel/core@7.24.0"
            )),
            CacheKind::Bun
        );
    }

    // --- Bun safety ---

    #[test]
    fn safety_bun_cache_is_safe() {
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/.bun/install/cache")
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_bun_package_is_safe() {
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/.bun/install/cache/lodash@4.17.21")
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_bun_root_is_caution() {
        assert_eq!(
            safety(CacheKind::Bun, &PathBuf::from("/home/user/.bun")),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_bun_install_dir_is_caution() {
        assert_eq!(
            safety(CacheKind::Bun, &PathBuf::from("/home/user/.bun/install")),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_bun_bin_is_unsafe() {
        // Deleting ~/.bun/bin removes the Bun runtime itself.
        assert_eq!(
            safety(CacheKind::Bun, &PathBuf::from("/home/user/.bun/bin")),
            SafetyLevel::Unsafe
        );
    }

    #[test]
    fn safety_bun_bin_binary_is_unsafe() {
        // Deleting ~/.bun/bin/bun (the binary) breaks bun entirely.
        assert_eq!(
            safety(CacheKind::Bun, &PathBuf::from("/home/user/.bun/bin/bun")),
            SafetyLevel::Unsafe
        );
    }

    #[test]
    fn safety_bun_install_cache_is_safe() {
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/.bun/install/cache"),
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_bun_install_cache_package_is_safe() {
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/.bun/install/cache/lodash@4.17.21"),
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_gradle_modules_files_is_safe() {
        // Dependency cache — re-resolvable from Maven Central.
        assert_eq!(
            safety(
                CacheKind::Gradle,
                &PathBuf::from(
                    "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc/guava-32.0.0-jre.jar"
                )
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_gradle_build_cache_is_caution() {
        // build-cache-* stores compiled outputs — deletion triggers full rebuild.
        assert_eq!(
            safety(
                CacheKind::Gradle,
                &PathBuf::from("/home/user/.gradle/caches/build-cache-1/abc123")
            ),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_gradle_transforms_is_caution() {
        // transforms-* stores expensive dependency transformations.
        assert_eq!(
            safety(
                CacheKind::Gradle,
                &PathBuf::from("/home/user/.gradle/caches/transforms-4/abc")
            ),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_gradle_wrapper_dist_is_safe() {
        // ~/.gradle/wrapper/dists/ — re-downloadable from services.gradle.org.
        assert_eq!(
            safety(
                CacheKind::Gradle,
                &PathBuf::from("/home/user/.gradle/wrapper/dists/gradle-8.5-bin")
            ),
            SafetyLevel::Safe
        );
    }

    #[test]
    fn safety_bun_install_cache_backup_not_safe() {
        // A sibling dir like "install/cache-backup" must NOT be treated as
        // the Bun package cache (H7): substring match leaks auto-delete to
        // adjacent user directories.
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/.bun/install/cache-backup/important"),
            ),
            SafetyLevel::Caution
        );
    }

    #[test]
    fn safety_bun_random_install_path_not_safe() {
        // An "install/cache" path outside .bun that somehow got detected as Bun
        // (e.g. user-created path confusingly named) must remain Caution —
        // defence in depth.
        assert_eq!(
            safety(
                CacheKind::Bun,
                &PathBuf::from("/home/user/unrelated/install/cache-tmp/x"),
            ),
            SafetyLevel::Caution
        );
    }

    // --- Bun upgrade commands ---

    #[test]
    fn upgrade_command_bun() {
        assert_eq!(
            upgrade_command(CacheKind::Bun, "express", "4.18.2"),
            Some("bun add express@4.18.2".to_string())
        );
    }

    #[test]
    fn upgrade_command_bun_scoped() {
        assert_eq!(
            upgrade_command(CacheKind::Bun, "@types/node", "22.0.0"),
            Some("bun add @types/node@22.0.0".to_string())
        );
    }

    // --- Bun detection collisions ---

    #[test]
    fn detect_npm_inside_bun_cache_is_bun() {
        // An npm-named package inside the Bun cache — .bun ancestor wins
        assert_eq!(
            detect(&PathBuf::from("/home/user/.bun/install/cache/npm@10.0.0")),
            CacheKind::Bun
        );
    }

    #[test]
    fn upgrade_command_bun_rejects_injection() {
        assert_eq!(
            upgrade_command(CacheKind::Bun, "lodash; rm -rf /", "4.17.21"),
            None
        );
    }

    /// Dispatch every CacheKind through semantic_name/metadata/package_id with
    /// a path that won't actually match — we only want the match arms covered.
    /// Each arm must at minimum not panic.
    #[test]
    fn dispatch_all_kinds_through_semantic_metadata_package_id() {
        let dummy = PathBuf::from("/nonexistent/dummy/path");
        let all = [
            CacheKind::HuggingFace,
            CacheKind::Pip,
            CacheKind::Uv,
            CacheKind::Npm,
            CacheKind::Homebrew,
            CacheKind::Cargo,
            CacheKind::PreCommit,
            CacheKind::Whisper,
            CacheKind::Gh,
            CacheKind::Torch,
            CacheKind::Chroma,
            CacheKind::Prisma,
            CacheKind::Yarn,
            CacheKind::Pnpm,
            CacheKind::Bun,
            CacheKind::Maven,
            CacheKind::Gradle,
            CacheKind::SwiftPm,
            CacheKind::Xcode,
            CacheKind::Unknown,
        ];
        for kind in &all {
            // Just exercise the dispatch arms — the return values aren't asserted
            // because each provider has its own tests for correctness.
            let _ = semantic_name(*kind, &dummy);
            let _ = metadata(*kind, &dummy);
            let _ = package_id(*kind, &dummy);
        }
    }

    // --- SwiftPM detect ---

    #[test]
    fn detect_swiftpm_library_caches_root() {
        assert_eq!(
            detect(&PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm")),
            CacheKind::SwiftPm
        );
    }

    #[test]
    fn detect_swiftpm_linux_cache_root() {
        assert_eq!(
            detect(&PathBuf::from("/home/u/.cache/org.swift.swiftpm")),
            CacheKind::SwiftPm
        );
    }

    #[test]
    fn detect_swiftpm_repositories_subdir() {
        assert_eq!(
            detect(&PathBuf::from(
                "/Users/j/Library/Caches/org.swift.swiftpm/repositories/swift-collections-abc1234"
            )),
            CacheKind::SwiftPm
        );
    }

    #[test]
    fn detect_swiftpm_rejects_confusable_suffix() {
        // L1: substring match would accept this; component match must reject.
        assert_ne!(
            detect(&PathBuf::from(
                "/Users/j/Library/Caches/org.swift.swiftpm-backup"
            )),
            CacheKind::SwiftPm
        );
    }

    // --- Xcode detect ---

    #[test]
    fn detect_xcode_derived_data() {
        assert_eq!(
            detect(&PathBuf::from(
                "/Users/j/Library/Developer/Xcode/DerivedData"
            )),
            CacheKind::Xcode
        );
    }

    #[test]
    fn detect_xcode_derived_data_project_subdir() {
        assert_eq!(
            detect(&PathBuf::from(
                "/Users/j/Library/Developer/Xcode/DerivedData/MyApp-abc123def456"
            )),
            CacheKind::Xcode
        );
    }

    #[test]
    fn detect_xcode_ios_device_support() {
        assert_eq!(
            detect(&PathBuf::from(
                "/Users/j/Library/Developer/Xcode/iOS DeviceSupport/17.4 (21E213)"
            )),
            CacheKind::Xcode
        );
    }

    #[test]
    fn detect_xcode_core_simulator_caches() {
        assert_eq!(
            detect(&PathBuf::from(
                "/Users/j/Library/Developer/CoreSimulator/Caches/something"
            )),
            CacheKind::Xcode
        );
    }

    #[test]
    fn detect_xcode_rejects_confusable_suffix() {
        // L1: Xcode/DerivedData-backup must not match.
        assert_ne!(
            detect(&PathBuf::from(
                "/Users/j/Library/Developer/Xcode/DerivedData-backup"
            )),
            CacheKind::Xcode
        );
    }

    #[test]
    fn detect_xcode_rejects_unrelated_derived_data() {
        // A DerivedData directory not under Xcode must not match.
        assert_ne!(
            detect(&PathBuf::from("/random/path/DerivedData")),
            CacheKind::Xcode
        );
    }

    // --- SwiftPM safety ---

    #[test]
    fn safety_swiftpm_repositories_is_caution() {
        let path = PathBuf::from(
            "/Users/j/Library/Caches/org.swift.swiftpm/repositories/swift-collections-abc1234",
        );
        assert_eq!(safety(CacheKind::SwiftPm, &path), SafetyLevel::Caution);
    }

    #[test]
    fn safety_swiftpm_artifacts_is_safe() {
        let path = PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/artifacts/MyBinaryDep");
        assert_eq!(safety(CacheKind::SwiftPm, &path), SafetyLevel::Safe);
    }

    #[test]
    fn safety_swiftpm_manifests_is_safe() {
        let path = PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/manifests/deadbeef");
        assert_eq!(safety(CacheKind::SwiftPm, &path), SafetyLevel::Safe);
    }

    #[test]
    fn safety_swiftpm_unknown_subdir_is_caution() {
        // Conservative: unknown future subdir defaults to Caution.
        let path = PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/futuredir/item");
        assert_eq!(safety(CacheKind::SwiftPm, &path), SafetyLevel::Caution);
    }

    #[test]
    fn safety_swiftpm_rejects_confusable_suffix() {
        // L1: `repositories-old` must NOT be classified as repositories Caution —
        // it falls through to the unknown-subdir Caution default, which happens
        // to also be Caution, so assert the classification path via a Safe
        // companion check.
        let confusable =
            PathBuf::from("/Users/j/Library/Caches/org.swift.swiftpm/artifacts-backup/MyDep");
        // artifacts-backup must NOT be Safe (it isn't artifacts/).
        assert_eq!(
            safety(CacheKind::SwiftPm, &confusable),
            SafetyLevel::Caution
        );
    }

    // --- Xcode safety ---

    #[test]
    fn safety_xcode_derived_data_is_caution() {
        let path = PathBuf::from("/Users/j/Library/Developer/Xcode/DerivedData/MyApp-abc");
        assert_eq!(safety(CacheKind::Xcode, &path), SafetyLevel::Caution);
    }

    #[test]
    fn safety_xcode_ios_device_support_is_safe() {
        let path =
            PathBuf::from("/Users/j/Library/Developer/Xcode/iOS DeviceSupport/17.4 (21E213)");
        assert_eq!(safety(CacheKind::Xcode, &path), SafetyLevel::Safe);
    }

    #[test]
    fn safety_xcode_core_simulator_caches_is_safe() {
        let path = PathBuf::from("/Users/j/Library/Developer/CoreSimulator/Caches/something");
        assert_eq!(safety(CacheKind::Xcode, &path), SafetyLevel::Safe);
    }

    #[test]
    fn safety_xcode_rejects_confusable_suffix_derived_data() {
        // L1: DerivedData-backup must not be classified as Caution-DerivedData.
        let path = PathBuf::from("/Users/j/Library/Developer/Xcode/DerivedData-backup/junk");
        assert_eq!(safety(CacheKind::Xcode, &path), SafetyLevel::Safe);
    }
}
