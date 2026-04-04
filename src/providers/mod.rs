pub mod cargo;
pub mod chroma;
pub mod generic;
pub mod gh;
pub mod homebrew;
pub mod huggingface;
pub mod npm;
pub mod pip;
pub mod pre_commit;
pub mod prisma;
pub mod torch;
pub mod uv;
pub mod whisper;

use crate::tree::node::CacheKind;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MetadataField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        ".npm" | "npm" => return CacheKind::Npm,
        _ => {}
    }

    // Walk up the path to find a known ancestor
    for ancestor in path.ancestors().skip(1) {
        let ancestor_name = ancestor
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match ancestor_name.as_str() {
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
            "registry" => {
                if ancestor.to_string_lossy().contains(".cargo") {
                    return CacheKind::Cargo;
                }
            }
            _ => {}
        }
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
        _ => None,
    }
}

pub fn upgrade_command(kind: CacheKind, name: &str, version: &str) -> Option<String> {
    match kind {
        CacheKind::Pip | CacheKind::Uv => Some(format!("pip install {name}>={version}")),
        CacheKind::Npm => Some(format!("npm install {name}@{version}")),
        CacheKind::Cargo => Some(format!("cargo update -p {name}")),
        _ => None,
    }
}

/// Get safety level for deletion.
pub fn safety(kind: CacheKind, _path: &Path) -> SafetyLevel {
    match kind {
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
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/huggingface")), CacheKind::HuggingFace);
    }

    #[test]
    fn detect_pip() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/pip")), CacheKind::Pip);
    }

    #[test]
    fn detect_uv() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/uv")), CacheKind::Uv);
    }

    #[test]
    fn detect_npm_dot() {
        assert_eq!(detect(&PathBuf::from("/home/user/.npm")), CacheKind::Npm);
    }

    #[test]
    fn detect_npm_plain() {
        assert_eq!(detect(&PathBuf::from("/Library/Caches/npm")), CacheKind::Npm);
    }

    #[test]
    fn detect_homebrew() {
        assert_eq!(detect(&PathBuf::from("/Library/Caches/Homebrew")), CacheKind::Homebrew);
    }

    #[test]
    fn detect_pre_commit() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/pre-commit")), CacheKind::PreCommit);
    }

    #[test]
    fn detect_whisper() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/whisper")), CacheKind::Whisper);
    }

    #[test]
    fn detect_cargo_registry_context() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cargo/registry/cache")), CacheKind::Cargo);
    }

    #[test]
    fn detect_huggingface_subdir_context() {
        assert_eq!(detect(&PathBuf::from("/cache/huggingface/hub")), CacheKind::HuggingFace);
    }

    #[test]
    fn detect_npm_subdir_context() {
        assert_eq!(detect(&PathBuf::from("/home/user/.npm/_cacache")), CacheKind::Npm);
    }

    #[test]
    fn detect_gh() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/gh")), CacheKind::Gh);
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(detect(&PathBuf::from("/home/user/.cache/something_random")), CacheKind::Unknown);
    }

    // --- semantic_name() dispatch ---

    #[test]
    fn semantic_name_dispatches_to_huggingface() {
        let path = PathBuf::from("/cache/hub/models--org--model");
        assert_eq!(semantic_name(CacheKind::HuggingFace, &path), Some("[model] org/model".into()));
    }

    #[test]
    fn semantic_name_dispatches_to_whisper() {
        let path = PathBuf::from("/cache/whisper/large-v3.pt");
        assert_eq!(semantic_name(CacheKind::Whisper, &path), Some("Whisper Large V3".into()));
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
    }

    #[test]
    fn safety_unknown_is_caution() {
        assert_eq!(safety(CacheKind::Unknown, &PathBuf::from("/tmp")), SafetyLevel::Caution);
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
        let icons = [SafetyLevel::Safe.icon(), SafetyLevel::Caution.icon(), SafetyLevel::Unsafe.icon()];
        assert_ne!(icons[0], icons[1]);
        assert_ne!(icons[1], icons[2]);
        assert_ne!(icons[0], icons[2]);
    }

    #[test]
    fn upgrade_command_pip() {
        assert_eq!(
            upgrade_command(CacheKind::Pip, "requests", "2.32.0"),
            Some("pip install requests>=2.32.0".to_string())
        );
    }

    #[test]
    fn upgrade_command_uv() {
        assert_eq!(
            upgrade_command(CacheKind::Uv, "flask", "3.1.0"),
            Some("pip install flask>=3.1.0".to_string())
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
}
