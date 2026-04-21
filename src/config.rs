use clap::Parser;
use directories::ProjectDirs;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "ccmd",
    version,
    about = "Cache Commander — browse and manage cache directories",
    after_help = "Julien Simon — https://github.com/juliensimon/cache-commander"
)]
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

    /// Disable the startup check for ccmd updates
    #[arg(long = "no-update-check")]
    pub no_update_check: bool,

    #[cfg(feature = "mcp")]
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[cfg(feature = "mcp")]
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Start MCP server (stdio transport)
    Mcp,
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct VulncheckConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct VersioncheckConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UpdaterConfig {
    pub enabled: bool,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self { enabled: true }
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
    pub updater: UpdaterConfig,
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
        let m2_repo = home.join(".m2").join("repository");
        if m2_repo.exists() {
            roots.push(m2_repo);
        }
        let gradle_caches = home.join(".gradle").join("caches");
        if gradle_caches.exists() {
            roots.push(gradle_caches);
        }

        // Xcode caches live outside ~/Library/Caches, so they need their
        // own roots. SwiftPM deliberately does NOT get its own root —
        // its cache (org.swift.swiftpm) lives under ~/Library/Caches on
        // macOS and ~/.cache on Linux, both already configured above.
        // Adding it as a duplicate root would create two TreeNodes for
        // the same path, breaking child expansion (insert_children
        // matches via first position()).
        #[cfg(target_os = "macos")]
        {
            let derived_data = home.join("Library/Developer/Xcode/DerivedData");
            if derived_data.exists() {
                roots.push(derived_data);
            }
            let device_support = home.join("Library/Developer/Xcode/iOS DeviceSupport");
            if device_support.exists() {
                roots.push(device_support);
            }
            let coresim_caches = home.join("Library/Developer/CoreSimulator/Caches");
            if coresim_caches.exists() {
                roots.push(coresim_caches);
            }
        }

        // Yarn cache paths
        for path in probe_yarn_paths() {
            if !roots.contains(&path) {
                roots.push(path);
            }
        }

        // pnpm store paths
        for path in probe_pnpm_paths() {
            if !roots.contains(&path) {
                roots.push(path);
            }
        }

        // Bun cache paths
        for path in probe_bun_paths() {
            if !roots.contains(&path) {
                roots.push(path);
            }
        }

        // Go cache paths. Only add a path if it isn't already subsumed
        // by an existing root — default $GOCACHE lives under
        // ~/Library/Caches (macOS) or ~/.cache (Linux), so probing
        // naively would duplicate TreeNodes (the SwiftPM bug).
        for path in probe_go_paths() {
            if !roots.contains(&path) && !is_ancestor_or_descendant(&path, &roots) {
                roots.push(path);
            }
        }

        Self {
            roots,
            sort_by: SortField::Size,
            sort_desc: true,
            confirm_delete: true,
            vulncheck: VulncheckConfig::default(),
            versioncheck: VersioncheckConfig::default(),
            updater: UpdaterConfig::default(),
        }
    }
}

impl Config {
    /// Tests-only default that skips subprocess probes for yarn/pnpm/bun.
    /// `Config::default()` shells out to several package-manager CLIs on
    /// every call; in a test suite that builds many configs that's both
    /// slow and coupling tests to host tool availability (L9). New
    /// callers: use this in place of `Config { ..Default::default() }`
    /// when the config's cache-root probing is not what's under test.
    #[cfg(any(test, feature = "e2e"))]
    #[allow(dead_code)] // provided for tests; not yet consumed in-tree
    pub fn default_for_test() -> Self {
        Self {
            roots: vec![],
            sort_by: SortField::Size,
            sort_desc: true,
            confirm_delete: true,
            vulncheck: VulncheckConfig::default(),
            versioncheck: VersioncheckConfig::default(),
            updater: UpdaterConfig::default(),
        }
    }

    pub fn load() -> (Self, Cli) {
        let cli = Cli::parse();
        let mut config = Self::load_from_file().unwrap_or_default();

        // CLI overrides
        if !cli.roots.is_empty() {
            config.roots = cli.roots.clone();
        }
        if let Some(ref sort) = cli.sort
            && let Some(field) = SortField::from_str_opt(sort)
        {
            config.sort_by = field;
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
        if cli.no_update_check {
            config.updater.enabled = false;
        }
        // Only a genuine "yes/1/true/on" disables the updater — a user
        // typing `CCMD_NO_UPDATE_CHECK=0` should NOT lose update checks
        // (Copilot review on PR #26).
        if std::env::var("CCMD_NO_UPDATE_CHECK")
            .ok()
            .as_deref()
            .is_some_and(env_flag_is_truthy)
        {
            config.updater.enabled = false;
        }

        // Expand tildes
        config.roots = config
            .roots
            .into_iter()
            .map(|p| expand_tilde(&p))
            .collect::<Vec<_>>();

        // Warn about non-existent roots specified via CLI
        if !cli.roots.is_empty() {
            for root in &config.roots {
                if !root.exists() {
                    eprintln!("warning: root path does not exist: {}", root.display());
                }
            }
        }

        config.roots.retain(|p| p.exists());

        (config, cli)
    }

    fn load_from_file() -> Option<Self> {
        let proj = ProjectDirs::from("", "", "ccmd")?;
        let config_path = proj.config_dir().join("config.toml");
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                eprintln!("warning: could not read {}: {}", config_path.display(), e);
                return None;
            }
        };
        match toml::from_str(&content) {
            Ok(config) => Some(config),
            Err(e) => {
                eprintln!("warning: invalid config {}: {}", config_path.display(), e);
                None
            }
        }
    }
}

/// Run a command with a 5-second timeout. Returns `None` if the tool is missing
/// or the process doesn't finish in time (e.g. corepack prompting for install).
fn run_with_timeout(program: &str, args: &[&str]) -> Option<std::process::Output> {
    use std::time::{Duration, Instant};

    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return child.wait_with_output().ok(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

fn probe_yarn_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Try CLI detection (with timeout to avoid blocking if yarn hangs)
    if let Some(output) = run_with_timeout("yarn", &["cache", "dir"])
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path = PathBuf::from(&path_str);
        if path.exists() {
            paths.push(path);
        }
    }

    // Yarn 2+ (Berry) cache folder
    if let Some(output) = run_with_timeout("yarn", &["config", "get", "cacheFolder"])
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path_str.is_empty() && path_str != "undefined" {
            let path = PathBuf::from(&path_str);
            if path.exists() && !paths.contains(&path) {
                paths.push(path);
            }
        }
    }

    // Fallback locations
    let home = dirs_home();
    let fallbacks = [
        home.join(".yarn-cache"),
        home.join(".cache/yarn"),
        home.join(".yarn/berry/cache"),
    ];
    #[cfg(target_os = "macos")]
    let macos_fallbacks = [home.join("Library/Caches/Yarn")];
    #[cfg(not(target_os = "macos"))]
    let macos_fallbacks: [PathBuf; 0] = [];

    for path in fallbacks.iter().chain(macos_fallbacks.iter()) {
        if path.exists() && !paths.contains(path) && !is_ancestor_or_descendant(path, &paths) {
            paths.push(path.clone());
        }
    }

    paths
}

fn probe_pnpm_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Try CLI detection (with timeout to avoid blocking if pnpm hangs)
    if let Some(output) = run_with_timeout("pnpm", &["store", "path"])
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path = PathBuf::from(&path_str);
        if path.exists() {
            // `pnpm store path` returns e.g. .../store/v10; go up to `store`
            // so the tree shows the full store hierarchy.
            let root = path
                .parent()
                .filter(|p| p.parent().is_some()) // reject "/" or ""
                .unwrap_or(&path);
            paths.push(root.to_path_buf());
        }
    }

    // Fallback locations
    let home = dirs_home();
    let fallbacks = [
        home.join(".pnpm-store"),
        home.join(".local/share/pnpm/store"),
    ];

    for path in &fallbacks {
        if path.exists() && !paths.contains(path) && !is_ancestor_or_descendant(path, &paths) {
            paths.push(path.clone());
        }
    }

    paths
}

fn probe_bun_paths() -> Vec<PathBuf> {
    // Note: Bun does not provide a CLI command to query cache location (unlike
    // `yarn cache dir` or `pnpm store path`). We rely on env vars and the
    // default path. If Bun adds such a command, a CLI probe should be added here.
    let mut paths = Vec::new();

    // Check BUN_INSTALL_CACHE_DIR env var first
    if let Ok(cache_dir) = std::env::var("BUN_INSTALL_CACHE_DIR") {
        let path = PathBuf::from(&cache_dir);
        if path.exists() {
            paths.push(path);
            return paths;
        }
    }

    // Check BUN_INSTALL env var (cache is at $BUN_INSTALL/install/cache)
    if let Ok(bun_install) = std::env::var("BUN_INSTALL") {
        let cache_path = PathBuf::from(&bun_install).join("install/cache");
        if cache_path.exists() {
            paths.push(cache_path);
            return paths;
        }
    }

    // Default location
    let home = dirs_home();
    let default_cache = home.join(".bun/install/cache");
    if default_cache.exists() && !paths.contains(&default_cache) {
        paths.push(default_cache);
    }

    paths
}

fn probe_go_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Prefer an explicit GOMODCACHE env override — lets tests and users
    // redirect the probe without needing a real `go` on PATH.
    if let Ok(gomc) = std::env::var("GOMODCACHE") {
        let path = PathBuf::from(&gomc);
        if path.exists() {
            paths.push(path);
        }
    } else if let Some(output) = run_with_timeout("go", &["env", "GOMODCACHE"])
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path_str.is_empty() {
            let path = PathBuf::from(&path_str);
            if path.exists() {
                paths.push(path);
            }
        }
    }

    // Fallback: ~/go/pkg/mod (the default location when GOPATH is unset).
    let fallback = dirs_home().join("go/pkg/mod");
    if fallback.exists() && !paths.contains(&fallback) {
        paths.push(fallback);
    }

    // The build cache ($GOCACHE) defaults to ~/Library/Caches/go-build on
    // macOS and ~/.cache/go-build on Linux — both subsumed by existing
    // roots, so we intentionally do NOT probe for it here. If a user
    // sets $GOCACHE to a non-default location outside those parents, the
    // caller filters via is_ancestor_or_descendant before pushing.
    if let Ok(gocache) = std::env::var("GOCACHE") {
        let path = PathBuf::from(&gocache);
        if path.exists() && !paths.contains(&path) {
            paths.push(path);
        }
    }

    paths
}

/// Returns true if `candidate` is an ancestor or descendant of any path in `existing`.
fn is_ancestor_or_descendant(candidate: &Path, existing: &[PathBuf]) -> bool {
    existing
        .iter()
        .any(|p| candidate.starts_with(p) || p.starts_with(candidate))
}

fn dirs_home() -> PathBuf {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .unwrap_or_else(|| {
            eprintln!("warning: could not determine home directory, using /");
            PathBuf::from("/")
        })
}

/// Whether an environment-variable value should be treated as "on" /
/// "enabled" for boolean-style flags. Matches common conventions
/// (1/true/yes/on, case-insensitive). Explicitly rejects 0/false/no/off
/// and the empty string so `CCMD_NO_UPDATE_CHECK=0` doesn't disable
/// updates by accident.
fn env_flag_is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        dirs_home().join(stripped)
    } else {
        path.to_path_buf()
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
        assert_eq!(
            SortField::from_str_opt("modified"),
            Some(SortField::Modified)
        );
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

    // --- env_flag_is_truthy ---

    #[test]
    fn env_flag_truthy_values() {
        for v in ["1", "true", "yes", "on", "TRUE", "Yes", "On", " 1 "] {
            assert!(env_flag_is_truthy(v), "{v:?} should be truthy");
        }
    }

    #[test]
    fn env_flag_falsy_values() {
        // Critical: "0" and "false" must NOT be treated as "please disable
        // updates" — a user typing CCMD_NO_UPDATE_CHECK=0 expects the
        // update check to stay ENABLED.
        for v in ["", "0", "false", "no", "off", "FALSE", " "] {
            assert!(!env_flag_is_truthy(v), "{v:?} should be falsy");
        }
    }

    #[test]
    fn env_flag_unknown_values_are_falsy() {
        // Conservative: unrecognized strings don't flip the flag.
        for v in ["maybe", "2", "disable", "enable"] {
            assert!(!env_flag_is_truthy(v), "{v:?} should be falsy (unknown)");
        }
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
        assert!(config.sort_desc); // default
        assert!(config.confirm_delete); // default
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
        let has_cache = config
            .roots
            .iter()
            .any(|r| r.to_string_lossy().contains(".cache"));
        assert!(has_cache, "Default config should include ~/.cache");
    }

    #[test]
    fn config_default_includes_m2_repository_when_home_has_it() {
        let m2 = dirs_home().join(".m2").join("repository");
        if !m2.exists() {
            return; // no-op on machines without Maven installed
        }
        let config = Config::default();
        assert!(
            config.roots.contains(&m2),
            "Config::default() must include ~/.m2/repository when it exists; roots: {:?}",
            config.roots
        );
    }

    #[test]
    fn config_default_includes_gradle_caches_when_home_has_it() {
        let gradle = dirs_home().join(".gradle").join("caches");
        if !gradle.exists() {
            return; // no-op on machines without Gradle installed
        }
        let config = Config::default();
        assert!(
            config.roots.contains(&gradle),
            "Config::default() must include ~/.gradle/caches when it exists; roots: {:?}",
            config.roots
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn config_default_has_library_caches_on_macos() {
        let config = Config::default();
        let has_library = config
            .roots
            .iter()
            .any(|r| r.to_string_lossy().contains("Library/Caches"));
        assert!(
            has_library,
            "Default config should include ~/Library/Caches on macOS"
        );
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

    #[test]
    fn run_with_timeout_missing_program_returns_none() {
        // Spawning a program that definitely doesn't exist should return None,
        // not panic. This covers the ok()? branch at the top of run_with_timeout.
        let out = run_with_timeout("ccmd-nonexistent-binary-xyz-9876", &["--version"]);
        assert!(out.is_none());
    }

    #[test]
    fn run_with_timeout_fast_program_returns_output() {
        // `true` exits immediately with success, exercising the Ok(Some(_)) path.
        if let Some(output) = run_with_timeout("true", &[]) {
            assert!(output.status.success());
        }
    }

    #[test]
    fn probe_bun_respects_env_var_when_dir_exists() {
        // Use a temp dir so we actually hit the early-return branch that
        // BUN_INSTALL_CACHE_DIR points at an existing dir.
        let tmp = std::env::temp_dir().join(format!("ccmd-bun-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Ensure BUN_INSTALL doesn't interfere
        // SAFETY: tests are serial within a single process for this env var usage.
        unsafe {
            std::env::set_var("BUN_INSTALL_CACHE_DIR", &tmp);
            std::env::remove_var("BUN_INSTALL");
        }
        let paths = probe_bun_paths();
        unsafe {
            std::env::remove_var("BUN_INSTALL_CACHE_DIR");
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(paths.iter().any(|p| p == &tmp));
    }

    #[test]
    fn probe_yarn_cache_handles_missing_tool() {
        // yarn may or may not be installed. Either way, every returned path
        // must be absolute so we never feed a relative path to the scanner.
        let paths = probe_yarn_paths();
        for p in &paths {
            assert!(p.is_absolute(), "probe_yarn_paths returned relative: {p:?}");
        }
    }

    #[test]
    fn probe_pnpm_cache_handles_missing_tool() {
        let paths = probe_pnpm_paths();
        for p in &paths {
            assert!(p.is_absolute(), "probe_pnpm_paths returned relative: {p:?}");
        }
    }

    #[test]
    fn probe_bun_cache_handles_missing_install() {
        let paths = probe_bun_paths();
        for p in &paths {
            assert!(p.is_absolute(), "probe_bun_paths returned relative: {p:?}");
        }
    }

    #[test]
    fn ancestor_or_descendant_child_detected() {
        let existing = vec![PathBuf::from("/home/user/Library/Caches/Yarn")];
        assert!(is_ancestor_or_descendant(
            Path::new("/home/user/Library/Caches/Yarn/v6"),
            &existing
        ));
    }

    #[test]
    fn ancestor_or_descendant_parent_detected() {
        let existing = vec![PathBuf::from("/home/user/Library/Caches/Yarn/v6")];
        assert!(is_ancestor_or_descendant(
            Path::new("/home/user/Library/Caches/Yarn"),
            &existing
        ));
    }

    #[test]
    fn ancestor_or_descendant_sibling_not_detected() {
        let existing = vec![PathBuf::from("/home/user/.npm")];
        assert!(!is_ancestor_or_descendant(
            Path::new("/home/user/.yarn"),
            &existing
        ));
    }

    #[test]
    fn ancestor_or_descendant_empty_list() {
        assert!(!is_ancestor_or_descendant(Path::new("/any/path"), &[]));
    }

    #[test]
    fn ancestor_or_descendant_exact_match() {
        let existing = vec![PathBuf::from("/home/user/.npm")];
        assert!(is_ancestor_or_descendant(
            Path::new("/home/user/.npm"),
            &existing
        ));
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn cli_no_subcommand_means_tui() {
        let cli = Cli::try_parse_from(["ccmd"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn cli_mcp_subcommand_parses() {
        let cli = Cli::try_parse_from(["ccmd", "mcp"]).unwrap();
        assert!(cli.command.is_some());
    }

    // --- SwiftPM / Xcode default roots ---

    #[test]
    fn default_for_test_is_empty_roots() {
        // Regression guard: adding new roots must not leak into the test
        // config (L6). If this fails, default_for_test() was quietly
        // extended to probe the host — don't do that.
        assert!(Config::default_for_test().roots.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn default_config_does_not_add_swiftpm_as_separate_root_on_macos() {
        // SwiftPM's cache lives at ~/Library/Caches/org.swift.swiftpm,
        // which is already under the ~/Library/Caches root. Adding it as
        // a duplicate root creates two TreeNodes with the same path —
        // insert_children picks the first one by position() and the
        // user's expand on the root-level duplicate silently does
        // nothing. Discovery via the parent root is sufficient;
        // detect() classifies org.swift.swiftpm correctly on the first
        // level-down expand.
        let swiftpm = dirs_home().join("Library/Caches/org.swift.swiftpm");
        let config = Config::default();
        assert!(
            !config.roots.iter().any(|r| r == &swiftpm),
            "SwiftPM must not be listed as its own root, got {:?}",
            config.roots
        );
    }

    #[test]
    fn default_config_does_not_add_swiftpm_as_separate_root_on_linux() {
        // Same rationale as the macOS test — ~/.cache/org.swift.swiftpm
        // lives under the ~/.cache root.
        let swiftpm = dirs_home().join(".cache/org.swift.swiftpm");
        let config = Config::default();
        assert!(
            !config.roots.iter().any(|r| r == &swiftpm),
            "SwiftPM must not be listed as its own root on Linux, got {:?}",
            config.roots
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn default_config_includes_derived_data_when_exists() {
        let dd = dirs_home().join("Library/Developer/Xcode/DerivedData");
        if !dd.exists() {
            return;
        }
        let config = Config::default();
        assert!(
            config.roots.iter().any(|r| r == &dd),
            "expected DerivedData root, got {:?}",
            config.roots
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn default_config_includes_ios_device_support_when_exists() {
        let ds = dirs_home().join("Library/Developer/Xcode/iOS DeviceSupport");
        if !ds.exists() {
            return;
        }
        let config = Config::default();
        assert!(
            config.roots.iter().any(|r| r == &ds),
            "expected iOS DeviceSupport root, got {:?}",
            config.roots
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn default_config_includes_coresimulator_caches_when_exists() {
        let sim = dirs_home().join("Library/Developer/CoreSimulator/Caches");
        if !sim.exists() {
            return;
        }
        let config = Config::default();
        assert!(
            config.roots.iter().any(|r| r == &sim),
            "expected CoreSimulator/Caches root, got {:?}",
            config.roots
        );
    }

    // --- Go probing ---

    #[test]
    fn probe_go_paths_returns_absolute_paths() {
        // Same invariant as the yarn/pnpm probes: every returned path
        // must be absolute, whether `go` is installed or not.
        let paths = probe_go_paths();
        for p in &paths {
            assert!(p.is_absolute(), "probe_go_paths returned relative: {p:?}");
        }
    }

    #[test]
    fn probe_go_paths_respects_gomodcache_env_var() {
        // Set GOMODCACHE to a fixture directory and ensure probing
        // picks it up. This is the canonical RED→GREEN for the probe
        // because it exercises the `go env GOMODCACHE` branch.
        let tmp = std::env::temp_dir().join(format!("ccmd-go-mod-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // SAFETY: tests are serial within a single process for this env var usage.
        unsafe {
            std::env::set_var("GOMODCACHE", &tmp);
        }
        let paths = probe_go_paths();
        unsafe {
            std::env::remove_var("GOMODCACHE");
        }
        let _ = std::fs::remove_dir_all(&tmp);

        // On hosts without `go` on PATH the probe returns empty; skip.
        if paths.is_empty() {
            return;
        }
        assert!(
            paths.iter().any(|p| p == &tmp),
            "expected GOMODCACHE path in probe output, got {paths:?}"
        );
    }

    #[test]
    fn default_config_includes_go_module_cache_when_exists() {
        let go_mod = dirs_home().join("go/pkg/mod");
        if !go_mod.exists() {
            return; // host without Go — skip cleanly
        }
        let config = Config::default();
        assert!(
            config.roots.iter().any(|r| r == &go_mod),
            "expected go/pkg/mod root in config, got {:?}",
            config.roots
        );
    }

    #[test]
    fn default_config_does_not_duplicate_go_build_under_existing_root() {
        // Default GOCACHE on macOS is ~/Library/Caches/go-build (under
        // the Library/Caches root); on Linux it's ~/.cache/go-build
        // (under ~/.cache). Either way the build cache is subsumed by
        // an existing root — adding it as its own root would duplicate
        // TreeNodes, same bug as SwiftPM had before we fixed it.
        let macos_gocache = dirs_home().join("Library/Caches/go-build");
        let linux_gocache = dirs_home().join(".cache/go-build");
        let config = Config::default();
        assert!(
            !config.roots.iter().any(|r| r == &macos_gocache),
            "GOCACHE must not duplicate ~/Library/Caches root, got {:?}",
            config.roots
        );
        assert!(
            !config.roots.iter().any(|r| r == &linux_gocache),
            "GOCACHE must not duplicate ~/.cache root, got {:?}",
            config.roots
        );
    }
}
