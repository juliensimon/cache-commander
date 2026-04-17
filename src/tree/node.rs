use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheKind {
    HuggingFace,
    Pip,
    Uv,
    Npm,
    Homebrew,
    Cargo,
    PreCommit,
    Whisper,
    Gh,
    Torch,
    Chroma,
    Prisma,
    Yarn,
    Pnpm,
    Bun,
    Maven,
    Gradle,
    #[default]
    Unknown,
}

impl CacheKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::HuggingFace => "HuggingFace Hub",
            Self::Pip => "pip",
            Self::Uv => "uv",
            Self::Npm => "npm",
            Self::Homebrew => "Homebrew",
            Self::Cargo => "Cargo",
            Self::PreCommit => "pre-commit",
            Self::Whisper => "Whisper",
            Self::Gh => "GitHub CLI",
            Self::Torch => "PyTorch",
            Self::Chroma => "Chroma",
            Self::Prisma => "Prisma",
            Self::Yarn => "Yarn",
            Self::Pnpm => "pnpm",
            Self::Bun => "Bun",
            Self::Maven => "Maven",
            Self::Gradle => "Gradle",
            Self::Unknown => "",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HuggingFace => "ML model hub — cached models, datasets, and spaces",
            Self::Pip => "Python package installer — cached wheels and HTTP responses",
            Self::Uv => "Fast Python package manager — cached archives and built wheels",
            Self::Npm => "Node.js package manager — content-addressable package cache",
            Self::Homebrew => "macOS package manager — downloaded bottles and cask installers",
            Self::Cargo => "Rust package manager — cached crates and extracted source",
            Self::PreCommit => "Git hook framework — cached hook repositories",
            Self::Whisper => "OpenAI speech recognition — cached model weights",
            Self::Gh => "GitHub CLI — cached workflow run logs and API responses",
            Self::Torch => "PyTorch — cached model checkpoints and hub downloads",
            Self::Chroma => "Chroma vector DB — cached embedding models",
            Self::Prisma => "Prisma ORM — cached database engine binaries",
            Self::Yarn => "Yarn package manager — cached packages and metadata",
            Self::Pnpm => "pnpm package manager — content-addressed package store",
            Self::Bun => "Bun runtime — cached npm packages from global install cache",
            Self::Maven => {
                "Java/Kotlin build tool — local repository of downloaded .jar/.pom artifacts"
            }
            Self::Gradle => {
                "JVM build tool — dependency cache, wrapper distributions, and build cache"
            }
            Self::Unknown => "",
        }
    }

    pub fn url(&self) -> &'static str {
        match self {
            Self::HuggingFace => "https://huggingface.co",
            Self::Pip => "https://pip.pypa.io",
            Self::Uv => "https://github.com/astral-sh/uv",
            Self::Npm => "https://www.npmjs.com",
            Self::Homebrew => "https://brew.sh",
            Self::Cargo => "https://crates.io",
            Self::PreCommit => "https://pre-commit.com",
            Self::Whisper => "https://github.com/openai/whisper",
            Self::Gh => "https://cli.github.com",
            Self::Torch => "https://pytorch.org",
            Self::Chroma => "https://www.trychroma.com",
            Self::Prisma => "https://www.prisma.io",
            Self::Yarn => "https://yarnpkg.com",
            Self::Pnpm => "https://pnpm.io",
            Self::Bun => "https://bun.sh",
            Self::Maven => "https://maven.apache.org",
            Self::Gradle => "https://gradle.org",
            Self::Unknown => "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub depth: u16,
    pub parent: Option<usize>,
    pub has_children: bool,
    pub kind: CacheKind,
    pub last_modified: Option<SystemTime>,
    pub is_root: bool,
    pub children_loaded: bool,
}

impl TreeNode {
    pub fn new(path: PathBuf, depth: u16, parent: Option<usize>) -> Self {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());

        let has_children = path.is_dir();

        Self {
            path,
            name,
            size: 0,
            depth,
            parent,
            has_children,
            kind: CacheKind::Unknown,
            last_modified: None,
            is_root: depth == 0,
            children_loaded: false,
        }
    }

    pub fn root(path: PathBuf) -> Self {
        let display = path.to_string_lossy().replace(&dirs_home(), "~");

        Self {
            name: display,
            is_root: true,
            ..Self::new(path, 0, None)
        }
    }
}

fn dirs_home() -> String {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_extracts_filename_as_name() {
        let node = TreeNode::new(PathBuf::from("/cache/huggingface"), 1, Some(0));
        assert_eq!(node.name, "huggingface");
        assert_eq!(node.depth, 1);
        assert_eq!(node.parent, Some(0));
        assert_eq!(node.size, 0);
        assert_eq!(node.kind, CacheKind::Unknown);
        assert!(!node.is_root);
        assert!(!node.children_loaded);
    }

    #[test]
    fn new_uses_full_path_when_no_filename() {
        let node = TreeNode::new(PathBuf::from("/"), 0, None);
        assert_eq!(node.name, "/");
    }

    #[test]
    fn root_sets_tilde_display_name() {
        let home = dirs_home();
        let path = PathBuf::from(format!("{home}/.cache"));
        let node = TreeNode::root(path.clone());
        assert_eq!(node.name, "~/.cache");
        assert!(node.is_root);
        assert_eq!(node.depth, 0);
        assert_eq!(node.parent, None);
    }

    #[test]
    fn root_preserves_non_home_path() {
        let node = TreeNode::root(PathBuf::from("/tmp/test"));
        assert_eq!(node.name, "/tmp/test");
    }

    #[test]
    fn cache_kind_labels_are_non_empty_except_unknown() {
        let kinds = [
            CacheKind::HuggingFace,
            CacheKind::Pip,
            CacheKind::Uv,
            CacheKind::Npm,
            CacheKind::Homebrew,
            CacheKind::Cargo,
            CacheKind::PreCommit,
            CacheKind::Whisper,
        ];
        for kind in &kinds {
            assert!(
                !kind.label().is_empty(),
                "{:?} should have a non-empty label",
                kind
            );
        }
        assert_eq!(CacheKind::Unknown.label(), "");
    }

    #[test]
    fn cache_kind_default_is_unknown() {
        assert_eq!(CacheKind::default(), CacheKind::Unknown);
    }

    #[test]
    fn cache_kind_yarn_has_label() {
        assert_eq!(CacheKind::Yarn.label(), "Yarn");
        assert!(!CacheKind::Yarn.description().is_empty());
        assert!(!CacheKind::Yarn.url().is_empty());
    }

    #[test]
    fn cache_kind_every_variant_has_label_description_and_url() {
        // Exhaustive list — every new CacheKind variant should be added here so
        // its match arms in label/description/url are covered.
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
        ];
        for kind in &all {
            assert!(!kind.label().is_empty(), "{:?} label empty", kind);
            assert!(
                !kind.description().is_empty(),
                "{:?} description empty",
                kind
            );
            let url = kind.url();
            assert!(!url.is_empty(), "{:?} url empty", kind);
            assert!(
                url.starts_with("http"),
                "{:?} url should start with http(s), got {url}",
                kind
            );
        }
        // Unknown intentionally empty
        assert_eq!(CacheKind::Unknown.label(), "");
        assert_eq!(CacheKind::Unknown.description(), "");
        assert_eq!(CacheKind::Unknown.url(), "");
    }

    #[test]
    fn cache_kind_pnpm_has_label() {
        assert_eq!(CacheKind::Pnpm.label(), "pnpm");
        assert!(!CacheKind::Pnpm.description().is_empty());
        assert!(!CacheKind::Pnpm.url().is_empty());
    }
}
