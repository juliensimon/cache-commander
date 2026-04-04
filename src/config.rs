use clap::Parser;
use directories::ProjectDirs;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ccmd", version, about = "Cache Commander — browse and manage cache directories")]
pub struct Cli {
    /// Cache root directories to scan (can be specified multiple times)
    #[arg(long = "root", short = 'r')]
    pub roots: Vec<PathBuf>,

    /// Sort field: size, name, or modified
    #[arg(long, short)]
    pub sort: Option<String>,

    /// Skip delete confirmation
    #[arg(long)]
    pub no_confirm: bool,

    /// Enable vulnerability scanning
    #[arg(long)]
    pub vulncheck: bool,

    /// Enable version checking
    #[arg(long)]
    pub versioncheck: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortField {
    #[default]
    Size,
    Name,
    Modified,
}

impl SortField {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "size" => Some(Self::Size),
            "name" => Some(Self::Name),
            "modified" => Some(Self::Modified),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Name => "name",
            Self::Modified => "modified",
        }
    }

    pub fn cycle(&self) -> Self {
        match self {
            Self::Size => Self::Name,
            Self::Name => Self::Modified,
            Self::Modified => Self::Size,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VulncheckConfig {
    pub enabled: bool,
}

impl Default for VulncheckConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VersioncheckConfig {
    pub enabled: bool,
}

impl Default for VersioncheckConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub roots: Vec<PathBuf>,
    pub sort_by: SortField,
    pub sort_desc: bool,
    pub confirm_delete: bool,
    pub vulncheck: VulncheckConfig,
    pub versioncheck: VersioncheckConfig,
}

impl Default for Config {
    fn default() -> Self {
        let home = dirs_home();
        let mut roots = vec![home.join(".cache")];

        #[cfg(target_os = "macos")]
        roots.push(home.join("Library/Caches"));

        let npm_dir = home.join(".npm");
        if npm_dir.exists() {
            roots.push(npm_dir);
        }
        let cargo_registry = home.join(".cargo/registry");
        if cargo_registry.exists() {
            roots.push(cargo_registry);
        }

        Self {
            roots,
            sort_by: SortField::Size,
            sort_desc: true,
            confirm_delete: true,
            vulncheck: VulncheckConfig::default(),
            versioncheck: VersioncheckConfig::default(),
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let cli = Cli::parse();
        let mut config = Self::load_from_file().unwrap_or_default();

        // CLI overrides
        if !cli.roots.is_empty() {
            config.roots = cli.roots;
        }
        if let Some(sort) = cli.sort {
            if let Some(field) = SortField::from_str_opt(&sort) {
                config.sort_by = field;
            }
        }
        if cli.no_confirm {
            config.confirm_delete = false;
        }
        if cli.vulncheck {
            config.vulncheck.enabled = true;
        }
        if cli.versioncheck {
            config.versioncheck.enabled = true;
        }

        // Expand tildes
        config.roots = config
            .roots
            .into_iter()
            .map(|p| expand_tilde(&p))
            .filter(|p| p.exists())
            .collect();

        config
    }

    fn load_from_file() -> Option<Self> {
        let proj = ProjectDirs::from("", "", "ccmd")?;
        let config_path = proj.config_dir().join("config.toml");
        let content = std::fs::read_to_string(config_path).ok()?;
        toml::from_str(&content).ok()
    }
}

fn dirs_home() -> PathBuf {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn expand_tilde(path: &PathBuf) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        dirs_home().join(stripped)
    } else {
        path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SortField ---

    #[test]
    fn sort_field_from_str_valid() {
        assert_eq!(SortField::from_str_opt("size"), Some(SortField::Size));
        assert_eq!(SortField::from_str_opt("name"), Some(SortField::Name));
        assert_eq!(SortField::from_str_opt("modified"), Some(SortField::Modified));
    }

    #[test]
    fn sort_field_from_str_invalid() {
        assert_eq!(SortField::from_str_opt(""), None);
        assert_eq!(SortField::from_str_opt("date"), None);
        assert_eq!(SortField::from_str_opt("SIZE"), None);
    }

    #[test]
    fn sort_field_cycle() {
        assert_eq!(SortField::Size.cycle(), SortField::Name);
        assert_eq!(SortField::Name.cycle(), SortField::Modified);
        assert_eq!(SortField::Modified.cycle(), SortField::Size);
    }

    #[test]
    fn sort_field_cycle_is_complete_loop() {
        let start = SortField::Size;
        let result = start.cycle().cycle().cycle();
        assert_eq!(result, start);
    }

    #[test]
    fn sort_field_labels() {
        assert_eq!(SortField::Size.label(), "size");
        assert_eq!(SortField::Name.label(), "name");
        assert_eq!(SortField::Modified.label(), "modified");
    }

    #[test]
    fn sort_field_default_is_size() {
        assert_eq!(SortField::default(), SortField::Size);
    }

    // --- expand_tilde ---

    #[test]
    fn expand_tilde_with_tilde() {
        let path = PathBuf::from("~/.cache");
        let expanded = expand_tilde(&path);
        assert!(!expanded.to_string_lossy().contains('~'));
        assert!(expanded.to_string_lossy().ends_with(".cache"));
    }

    #[test]
    fn expand_tilde_without_tilde() {
        let path = PathBuf::from("/absolute/path");
        assert_eq!(expand_tilde(&path), path);
    }

    #[test]
    fn expand_tilde_just_tilde() {
        let path = PathBuf::from("~");
        let expanded = expand_tilde(&path);
        assert!(!expanded.to_string_lossy().contains('~'));
        // Should be just the home dir
        assert_eq!(expanded, dirs_home());
    }

    // --- Config TOML parsing ---

    #[test]
    fn config_deserialize_full() {
        let toml_str = r#"
            roots = ["~/.cache", "/tmp/test"]
            sort_by = "name"
            sort_desc = false
            confirm_delete = false
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.roots.len(), 2);
        assert_eq!(config.sort_by, SortField::Name);
        assert!(!config.sort_desc);
        assert!(!config.confirm_delete);
    }

    #[test]
    fn config_deserialize_partial_uses_defaults() {
        let toml_str = r#"
            roots = ["/tmp/test"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.roots.len(), 1);
        assert_eq!(config.sort_by, SortField::Size); // default
        assert!(config.sort_desc);                    // default
        assert!(config.confirm_delete);               // default
    }

    #[test]
    fn config_deserialize_empty_uses_all_defaults() {
        let toml_str = "";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.sort_by, SortField::Size);
        assert!(config.sort_desc);
        assert!(config.confirm_delete);
    }

    #[test]
    fn config_default_has_cache_root() {
        let config = Config::default();
        let has_cache = config.roots.iter().any(|r| r.to_string_lossy().contains(".cache"));
        assert!(has_cache, "Default config should include ~/.cache");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn config_default_has_library_caches_on_macos() {
        let config = Config::default();
        let has_library = config.roots.iter().any(|r| r.to_string_lossy().contains("Library/Caches"));
        assert!(has_library, "Default config should include ~/Library/Caches on macOS");
    }

    #[test]
    fn config_deserialize_vulncheck_enabled() {
        let toml_str = r#"
            [vulncheck]
            enabled = true
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.vulncheck.enabled);
        assert!(!config.versioncheck.enabled);
    }

    #[test]
    fn config_deserialize_versioncheck_enabled() {
        let toml_str = r#"
            [versioncheck]
            enabled = true
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.versioncheck.enabled);
        assert!(!config.vulncheck.enabled);
    }

    #[test]
    fn config_both_disabled_by_default() {
        let config = Config::default();
        assert!(!config.vulncheck.enabled);
        assert!(!config.versioncheck.enabled);
    }
}
