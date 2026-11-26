pub mod safety;
pub mod tools;

use crate::config::Config;
use crate::providers;
use crate::scanner;
use crate::scanner::walker;
use crate::security;
use crate::tree::node::{CacheKind, TreeNode};

use humansize::{BINARY, format_size};
use rmcp::ServerHandler;
use rmcp::ServiceExt;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::serde_json;
use rmcp::tool;
use rmcp::tool_handler;
use rmcp::tool_router;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use tools::*;

#[derive(Clone)]
pub struct CcmdMcp {
    roots: Vec<PathBuf>,
    tool_router: ToolRouter<Self>,
}

/// Check if a provider label matches a user-supplied ecosystem filter.
/// Normalize a label or filter to a canonical ecosystem tag.
/// Handles both CacheKind::label() values (e.g. "HuggingFace Hub", "Cargo")
/// and PackageId.ecosystem values (e.g. "PyPI", "crates.io", "npm").
fn canonical_ecosystem(s: &str) -> Option<&'static str> {
    match s.to_lowercase().as_str() {
        "npm" | "npx" | "node" | "nodejs" => Some("npm"),
        "pip" | "pypi" | "python" => Some("pip"),
        "uv" => Some("uv"),
        "poetry" => Some("poetry"),
        "cargo" | "crates" | "crates.io" | "rust" => Some("cargo"),
        "homebrew" | "brew" => Some("homebrew"),
        s if s.contains("huggingface") => Some("huggingface"),
        "hf" => Some("huggingface"),
        "pre-commit" | "precommit" => Some("pre-commit"),
        "whisper" => Some("whisper"),
        "torch" | "pytorch" => Some("torch"),
        "chroma" => Some("chroma"),
        "prisma" => Some("prisma"),
        s if s.contains("github") => Some("gh"),
        "gh" => Some("gh"),
        _ => None,
    }
}

/// Check if a provider label matches a user-supplied ecosystem filter.
/// Works with both CacheKind::label() and PackageId.ecosystem vocabularies.
fn matches_ecosystem(label: &str, filter: &str) -> bool {
    if label.is_empty() || filter.is_empty() {
        return false;
    }
    // Try canonical match first (handles both vocabularies)
    if let (Some(cl), Some(cf)) = (canonical_ecosystem(label), canonical_ecosystem(filter)) {
        // pip, uv, and Poetry share the PyPI ecosystem for vulnerability data.
        let python_group = |c: &str| c == "pip" || c == "uv" || c == "poetry";
        if cl == cf {
            return true;
        }
        if python_group(cl) && python_group(cf) {
            return true;
        }
        // "python"/"pypi" should match pip, uv, and Poetry caches
        if cf == "pip" && python_group(cl) {
            return true;
        }
        return false;
    }
    // Fallback: substring match for unknown ecosystems
    let label = label.to_lowercase();
    let filter = filter.to_lowercase();
    label.contains(&filter)
}

/// Check if a path is inside any of the configured cache roots (resolving symlinks).
fn is_under_roots(path: &std::path::Path, roots: &[PathBuf]) -> bool {
    canonical_under_roots(path, roots).is_some()
}

/// Canonicalize `path` and confirm it resides under a canonicalized root.
/// Returns the canonical path if so — callers performing a mutation should
/// use this canonical path, not the input, to close the TOCTOU window
/// between check and delete (H6).
fn canonical_under_roots(path: &std::path::Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let under_root = roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|cr| canonical.starts_with(cr))
            .unwrap_or(false)
    });
    if under_root { Some(canonical) } else { None }
}

const NOT_A_DISCOVERED_ENTRY: &str = "Not a discovered cache entry: configured roots, provider containers, symlinks and paths inside a package cannot be deleted via MCP";

/// The canonical paths a client may delete: exactly the entries discovery
/// lists (`walk_root_nodes`, the same set `list_caches` and `search_packages`
/// return). A path being under a root is not enough: that also covers the
/// root itself, provider containers and everything inside a package. Entries
/// that are symlinks are excluded so a link can never stand in for whatever it
/// points at (a container, another package, or a root).
///
/// Configured roots may overlap (`/cache` and `/cache/entry`), so one root can
/// be a discovered child of another. An entry that IS a configured root, or
/// CONTAINS one, is therefore excluded too: deleting it would remove a root.
fn deletable_paths(roots: &[PathBuf]) -> HashSet<PathBuf> {
    let canonical_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .collect();
    CcmdMcp::walk_root_nodes(roots, false)
        .iter()
        .filter(|n| std::fs::symlink_metadata(&n.path).is_ok_and(|m| !m.file_type().is_symlink()))
        .filter_map(|n| canonical_under_roots(&n.path, roots))
        .filter(|entry| !canonical_roots.iter().any(|root| root.starts_with(entry)))
        .collect()
}

/// Decide whether `path` may be previewed/deleted: the canonical path to act
/// on, or the reason it is refused. Scope is checked here, before and
/// independently of safety levels, so `confirm_caution` can only ever confirm
/// an item that is already in scope.
///
/// The REQUESTED path must not itself be a symlink: the allowlist holds the
/// canonical path of each package, so a link to a package would otherwise
/// canonicalize into the set and stand in for it. The path is normalized first
/// (`components()` drops trailing separators and `.`) because on Unix a
/// trailing `/` or `/.` makes the OS follow the link when stat'ing, so
/// `alias/` would look like a directory and slip past the check.
fn resolve_deletable(
    path: &Path,
    roots: &[PathBuf],
    deletable: &HashSet<PathBuf>,
) -> Result<PathBuf, &'static str> {
    let normalized: PathBuf = path.components().collect();
    if std::fs::symlink_metadata(&normalized).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(NOT_A_DISCOVERED_ENTRY);
    }
    let canonical =
        canonical_under_roots(path, roots).ok_or("Path is not inside any configured cache root")?;
    if deletable.contains(&canonical) {
        Ok(canonical)
    } else {
        Err(NOT_A_DISCOVERED_ENTRY)
    }
}

impl CcmdMcp {
    fn new(config: &Config) -> Self {
        let tool_router = Self::tool_router();
        Self {
            roots: config.roots.clone(),
            tool_router,
        }
    }

    /// Walk all roots and collect TreeNodes, recursing into provider containers
    /// to find individual packages (e.g. ~/.cache/huggingface/hub/models--org--name).
    fn walk_roots(&self) -> Vec<TreeNode> {
        Self::walk_root_nodes(&self.roots, true)
    }

    /// `walk_roots` over explicit roots. `with_sizes: false` skips the
    /// per-node directory-size walk for callers that only need the paths.
    fn walk_root_nodes(roots: &[PathBuf], with_sizes: bool) -> Vec<TreeNode> {
        let mut nodes = Vec::new();
        for root in roots {
            for child_path in walker::list_children(root) {
                Self::collect_nodes(&child_path, 1, with_sizes, &mut nodes);
            }
        }
        nodes
    }

    /// Collect package nodes from a path. Recurses into provider containers
    /// to find individual packages. A node is a "package" (leaf) if it has
    /// a package_id or a semantic name starting with '[' (typed item like
    /// [model], [npx], [dataset]). Otherwise, if it's a known provider dir,
    /// it's a container — recurse into children.
    fn collect_nodes(path: &Path, depth: u16, with_sizes: bool, nodes: &mut Vec<TreeNode>) {
        if depth > 4 {
            return;
        }
        let kind = providers::detect(path);
        let semantic_name = providers::semantic_name(kind, path);
        let has_package_id = providers::package_id(kind, path).is_some();

        // It's a real package if it has a package_id or a typed semantic name
        let is_package =
            has_package_id || semantic_name.as_ref().is_some_and(|n| n.starts_with('['));

        if is_package {
            let mut node = TreeNode::new(path.to_path_buf(), depth, None);
            node.kind = kind;
            if with_sizes {
                node.size = walker::dir_size(path);
            }
            if let Some(name) = semantic_name {
                node.name = name;
            }
            nodes.push(node);
            return;
        }

        // Known provider, not a package → check if it's a container worth recursing.
        // Recurse if: no semantic name (unnamed container like "hub/"), OR
        // has children that are themselves packages (e.g. _npx/ contains [npx] items).
        if kind != CacheKind::Unknown && path.is_dir() {
            let should_recurse = semantic_name.is_none() || {
                // Peek at children: if any child has a typed semantic name, recurse
                walker::list_children(path).iter().any(|child| {
                    let ck = providers::detect(child);
                    providers::semantic_name(ck, child).is_some_and(|n| n.starts_with('['))
                        || providers::package_id(ck, child).is_some()
                })
            };
            if should_recurse {
                for child in walker::list_children(path) {
                    Self::collect_nodes(&child, depth + 1, with_sizes, nodes);
                }
                return;
            }
        }

        // Unknown kind → leaf node (e.g. ~/Library/Caches/com.apple.something)
        let mut node = TreeNode::new(path.to_path_buf(), depth, None);
        node.kind = kind;
        if with_sizes {
            node.size = walker::dir_size(path);
        }
        nodes.push(node);
    }

    fn provider_label(node: &TreeNode) -> String {
        let label = node.kind.label();
        if !label.is_empty() {
            return label.to_string();
        }
        // Unknown provider — use parent directory to give context
        if let Some(parent) = node.path.parent()
            && parent.ends_with("Library/Caches")
        {
            return "~/Library/Caches".to_string();
        }
        "Other".to_string()
    }

    fn build_list_caches(&self) -> Vec<CacheRoot> {
        let nodes = self.walk_roots();
        let mut by_provider: HashMap<String, (u64, usize, PathBuf)> = HashMap::new();
        for node in &nodes {
            let label = Self::provider_label(node);
            let entry = by_provider.entry(label).or_insert((
                0,
                0,
                node.path.parent().unwrap_or(&node.path).to_path_buf(),
            ));
            entry.0 += node.size;
            entry.1 += 1;
        }
        let mut roots: Vec<CacheRoot> = by_provider
            .into_iter()
            .map(|(provider, (size, count, path))| CacheRoot {
                provider,
                path: path.to_string_lossy().to_string(),
                total_size: format_size(size, BINARY),
                total_size_bytes: size,
                item_count: count,
            })
            .collect();
        roots.sort_by_key(|r| std::cmp::Reverse(r.total_size_bytes));
        roots
    }

    fn build_summary(&self) -> Summary {
        let nodes = self.walk_roots();
        let mut total_size: u64 = 0;
        let mut by_provider: HashMap<String, (u64, usize)> = HashMap::new();
        let mut safe_count = 0usize;
        let mut caution_count = 0usize;
        let mut unsafe_count = 0usize;

        for node in &nodes {
            total_size += node.size;
            let label = Self::provider_label(node);
            let entry = by_provider.entry(label).or_insert((0, 0));
            entry.0 += node.size;
            entry.1 += 1;

            match providers::safety(node.kind, &node.path) {
                providers::SafetyLevel::Safe => safe_count += 1,
                providers::SafetyLevel::Caution => caution_count += 1,
                providers::SafetyLevel::Unsafe => unsafe_count += 1,
            }
        }

        let mut provider_summaries: Vec<ProviderSummary> = by_provider
            .into_iter()
            .map(|(name, (size, count))| ProviderSummary {
                name,
                size: format_size(size, BINARY),
                size_bytes: size,
                item_count: count,
            })
            .collect();
        provider_summaries.sort_by_key(|p| std::cmp::Reverse(p.size_bytes));

        Summary {
            total_size: format_size(total_size, BINARY),
            total_size_bytes: total_size,
            providers: provider_summaries,
            safety_counts: SafetyCounts {
                safe: safe_count,
                caution: caution_count,
                r#unsafe: unsafe_count,
            },
            total_items: nodes.len(),
        }
    }
}

#[tool_router]
impl CcmdMcp {
    #[tool(description = "List all cache directories with size and item count per provider")]
    async fn list_caches(&self) -> Result<String, String> {
        let server = self.clone();
        let result = tokio::task::spawn_blocking(move || server.build_list_caches())
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?;
        serde_json::to_string_pretty(&result).map_err(|e| format!("serialization failed: {e}"))
    }

    #[tool(
        description = "Get a high-level summary of all caches: total size, breakdown by provider, safety level counts"
    )]
    async fn get_summary(&self) -> Result<String, String> {
        let server = self.clone();
        let result = tokio::task::spawn_blocking(move || server.build_summary())
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?;
        serde_json::to_string_pretty(&result).map_err(|e| format!("serialization failed: {e}"))
    }

    #[tool(
        description = "Search for packages across all caches. Omit query to list all. Use ecosystem filter to scope by provider (e.g. huggingface, pip, npm). Query matches package names — for HuggingFace use '[model]' or '[dataset]' to filter by type."
    )]
    async fn search_packages(
        &self,
        input: Parameters<tools::SearchInput>,
    ) -> Result<String, String> {
        let server = self.clone();
        let input = input.0;
        let query = input
            .query
            .filter(|q| !q.is_empty())
            .map(|q| q.to_lowercase());
        let ecosystem = input.ecosystem;

        let result = tokio::task::spawn_blocking(move || {
            let nodes = server.walk_roots();
            let matches: Vec<PackageEntry> = nodes
                .into_iter()
                .filter(|node| {
                    let name_match = query
                        .as_ref()
                        .is_none_or(|q| node.name.to_lowercase().contains(q));
                    let eco_match = ecosystem
                        .as_ref()
                        .is_none_or(|eco| matches_ecosystem(node.kind.label(), eco));
                    name_match && eco_match
                })
                .map(|node| {
                    let safety = providers::safety(node.kind, &node.path);
                    PackageEntry {
                        name: node.name.clone(),
                        version: providers::package_id(node.kind, &node.path)
                            .map(|p| p.version)
                            .unwrap_or_default(),
                        ecosystem: node.kind.label().to_string(),
                        path: node.path.to_string_lossy().to_string(),
                        size: format_size(node.size, BINARY),
                        size_bytes: node.size,
                        safety_level: safety.label().to_string(),
                        safety_icon: safety.icon().to_string(),
                    }
                })
                .collect();
            matches
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        {
            let report = SearchReport {
                total_results: result.len(),
                packages: result,
            };
            serde_json::to_string_pretty(&report).map_err(|e| format!("serialization failed: {e}"))
        }
    }

    #[tool(
        description = "Get detailed metadata for a cache entry. Provide either path (absolute) or name + ecosystem (e.g. name='lodash', ecosystem='npm')."
    )]
    async fn get_package_details(
        &self,
        input: Parameters<tools::DetailsInput>,
    ) -> Result<String, String> {
        let input = input.0;

        // Resolve path: either provided directly or looked up by name+ecosystem
        let path = if let Some(ref p) = input.path {
            PathBuf::from(p)
        } else if let Some(ref name) = input.name {
            let server = self.clone();
            let name = name.to_lowercase();
            let ecosystem = input.ecosystem.clone();
            let found = tokio::task::spawn_blocking(move || {
                let nodes = server.walk_roots();
                nodes.into_iter().find(|node| {
                    let name_match = node.name.to_lowercase().contains(&name);
                    let eco_match = ecosystem
                        .as_ref()
                        .is_none_or(|eco| matches_ecosystem(node.kind.label(), eco));
                    name_match && eco_match
                })
            })
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?;
            match found {
                Some(node) => node.path,
                None => {
                    return Ok(format!(
                        "No package found matching name '{}'.",
                        input.name.unwrap()
                    ));
                }
            }
        } else {
            return Ok("Provide either 'path' or 'name' (with optional 'ecosystem').".to_string());
        };

        if !path.exists() {
            return Ok(format!("Path not found: {}", path.display()));
        }
        if !is_under_roots(&path, &self.roots) {
            return Ok("Path is not inside any configured cache root.".to_string());
        }

        let result = tokio::task::spawn_blocking(move || {
            let kind = providers::detect(&path);
            let safety = providers::safety(kind, &path);
            let size = walker::dir_size(&path);
            let last_modified = path
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Local> = t.into();
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                });

            let metadata: Vec<MetadataEntry> = providers::metadata(kind, &path)
                .into_iter()
                .map(|m| MetadataEntry {
                    label: m.label,
                    value: m.value,
                })
                .collect();

            PackageDetails {
                provider: kind.label().to_string(),
                name: providers::semantic_name(kind, &path).unwrap_or_else(|| {
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                }),
                version: providers::package_id(kind, &path)
                    .map(|p| p.version)
                    .unwrap_or_default(),
                path: path.to_string_lossy().to_string(),
                size: format_size(size, BINARY),
                size_bytes: size,
                last_modified,
                safety_level: safety.label().to_string(),
                safety_icon: safety.icon().to_string(),
                metadata,
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        serde_json::to_string_pretty(&result).map_err(|e| format!("serialization failed: {e}"))
    }

    #[tool(
        description = "Scan cached packages for known vulnerabilities (CVEs) via OSV.dev. Returns vulnerable packages with CVE details and fix versions."
    )]
    async fn scan_vulnerabilities(
        &self,
        input: Parameters<tools::EcosystemInput>,
    ) -> Result<String, String> {
        let roots = self.roots.clone();
        let ecosystem_filter = input.0.ecosystem;

        let result = tokio::task::spawn_blocking(move || {
            let mut packages = scanner::discover_packages(&roots);
            if let Some(ref eco) = ecosystem_filter {
                packages.retain(|(_, pkg)| matches_ecosystem(pkg.ecosystem, eco));
            }
            if packages.is_empty() {
                return Vec::new();
            }
            let vulns = security::scan_vulns(&packages);
            vulns
                .results
                .into_iter()
                .map(|(path, info)| {
                    let kind = providers::detect(&path);
                    let pkg_id = providers::package_id(kind, &path);
                    let (name, version, ecosystem) = pkg_id
                        .map(|p| (p.name.clone(), p.version.clone(), p.ecosystem.to_string()))
                        .unwrap_or_else(|| {
                            let name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string();
                            (name, String::new(), String::new())
                        });
                    VulnResult {
                        name: name.clone(),
                        version: version.clone(),
                        ecosystem,
                        path: path.to_string_lossy().to_string(),
                        vulnerabilities: info
                            .vulns
                            .into_iter()
                            .map(|v| VulnEntry {
                                id: v.id,
                                summary: v.summary,
                                severity: v.severity,
                                fix_version: v.fix_version.clone(),
                                upgrade_command: providers::upgrade_command(
                                    kind,
                                    &name,
                                    &v.fix_version.unwrap_or(version.clone()),
                                ),
                            })
                            .collect(),
                    }
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        {
            let total_vulns: usize = result.iter().map(|r| r.vulnerabilities.len()).sum();
            let fixable: usize = result
                .iter()
                .flat_map(|r| &r.vulnerabilities)
                .filter(|v| v.fix_version.is_some())
                .count();
            let report = VulnScanReport {
                vulnerable_packages: result.len(),
                total_vulnerabilities: total_vulns,
                fixable,
                unfixable: total_vulns - fixable,
                packages: result,
            };
            serde_json::to_string_pretty(&report).map_err(|e| format!("serialization failed: {e}"))
        }
    }

    #[tool(
        description = "Check cached packages for available version updates. Returns outdated packages with current and latest versions."
    )]
    async fn check_outdated(
        &self,
        input: Parameters<tools::EcosystemInput>,
    ) -> Result<String, String> {
        let roots = self.roots.clone();
        let ecosystem_filter = input.0.ecosystem;

        let result = tokio::task::spawn_blocking(move || {
            let mut packages = scanner::discover_packages(&roots);
            if let Some(ref eco) = ecosystem_filter {
                packages.retain(|(_, pkg)| matches_ecosystem(pkg.ecosystem, eco));
            }
            if packages.is_empty() {
                return Vec::new();
            }
            let versions = security::check_versions(&packages);
            versions
                .results
                .into_iter()
                .filter(|(_, info)| info.is_outdated)
                .map(|(path, info)| {
                    let kind = providers::detect(&path);
                    let pkg_id = providers::package_id(kind, &path);
                    let (name, ecosystem) = pkg_id
                        .map(|p| (p.name.clone(), p.ecosystem.to_string()))
                        .unwrap_or_else(|| {
                            (
                                path.file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                                String::new(),
                            )
                        });
                    OutdatedResult {
                        name: name.clone(),
                        version: info.current,
                        latest: info.latest.clone(),
                        ecosystem,
                        path: path.to_string_lossy().to_string(),
                        upgrade_command: providers::upgrade_command(kind, &name, &info.latest),
                    }
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        {
            let mut by_ecosystem: HashMap<String, usize> = HashMap::new();
            for pkg in &result {
                *by_ecosystem.entry(pkg.ecosystem.clone()).or_default() += 1;
            }
            let report = OutdatedReport {
                outdated_packages: result.len(),
                by_ecosystem,
                packages: result,
            };
            serde_json::to_string_pretty(&report).map_err(|e| format!("serialization failed: {e}"))
        }
    }

    #[tool(
        description = "Preview what would happen if cache entries were deleted. Shows size, safety level, and whether each item would be deleted. No side effects."
    )]
    async fn preview_delete(
        &self,
        input: Parameters<tools::PreviewDeleteInput>,
    ) -> Result<String, String> {
        #[allow(clippy::unnecessary_filter_map)]
        let paths: Vec<PathBuf> = input.0.paths.iter().map(PathBuf::from).collect();
        let roots = self.roots.clone();

        #[allow(clippy::unnecessary_filter_map)]
        let result = tokio::task::spawn_blocking(move || {
            let deletable = deletable_paths(&roots);
            let mut total_deletable: u64 = 0;
            let mut deletable_count = 0usize;
            let mut needs_confirmation_count = 0usize;
            let mut rejected_count = 0usize;
            let items: Vec<PreviewItem> = paths
                .iter()
                .filter_map(|path| {
                    if !path.exists() {
                        rejected_count += 1;
                        return Some(PreviewItem {
                            path: path.to_string_lossy().to_string(),
                            name: path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string(),
                            size: "0 B".to_string(),
                            size_bytes: 0,
                            safety_level: "unknown".to_string(),
                            would_delete: false,
                            reason: Some("Path not found".to_string()),
                        });
                    }
                    // H6: resolve the canonical path once, and use it for the
                    // safety check and size calculation. This closes the
                    // TOCTOU window where a racing symlink swap could escape
                    // the root between the check and the actual delete.
                    let canonical = match resolve_deletable(path, &roots, &deletable) {
                        Ok(canonical) => canonical,
                        Err(reason) => {
                            rejected_count += 1;
                            return Some(PreviewItem {
                                path: path.to_string_lossy().to_string(),
                                name: path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                                size: "0 B".to_string(),
                                size_bytes: 0,
                                safety_level: "unknown".to_string(),
                                would_delete: false,
                                reason: Some(reason.to_string()),
                            });
                        }
                    };
                    let kind = providers::detect(&canonical);
                    let safety = providers::safety(kind, &canonical);
                    let size = walker::dir_size(&canonical);
                    let name = providers::semantic_name(kind, &canonical).unwrap_or_else(|| {
                        canonical
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string()
                    });
                    let decision = safety::evaluate_delete(&safety, false);
                    let (would_delete, reason) = match decision {
                        safety::DeleteDecision::Allow => {
                            total_deletable += size;
                            deletable_count += 1;
                            (true, None)
                        }
                        safety::DeleteDecision::NeedsConfirmation { reason } => {
                            needs_confirmation_count += 1;
                            (false, Some(reason))
                        }
                        safety::DeleteDecision::Reject { reason } => {
                            rejected_count += 1;
                            (false, Some(reason))
                        }
                    };
                    Some(PreviewItem {
                        path: canonical.to_string_lossy().to_string(),
                        name,
                        size: format_size(size, BINARY),
                        size_bytes: size,
                        safety_level: safety.label().to_string(),
                        would_delete,
                        reason,
                    })
                })
                .collect();
            PreviewResult {
                deletable_count,
                needs_confirmation_count,
                rejected_count,
                total_deletable_size: format_size(total_deletable, BINARY),
                total_deletable_size_bytes: total_deletable,
                items,
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        serde_json::to_string_pretty(&result).map_err(|e| format!("serialization failed: {e}"))
    }

    #[tool(
        description = "Delete cache entries returned by list_caches/search_packages (roots, provider containers, symlinks and paths inside a package are refused). Safe items are deleted directly. Caution items require confirm_caution=true. Unsafe items are always rejected (use the TUI instead)."
    )]
    async fn delete_packages(
        &self,
        input: Parameters<tools::DeleteInput>,
    ) -> Result<String, String> {
        let input = input.0;
        let paths: Vec<PathBuf> = input.paths.iter().map(PathBuf::from).collect();
        let confirm_caution = input.confirm_caution;
        let roots = self.roots.clone();

        let result = tokio::task::spawn_blocking(move || {
            let deletable = deletable_paths(&roots);
            let mut deleted = Vec::new();
            let mut skipped = Vec::new();
            let mut space_freed: u64 = 0;

            for path in &paths {
                if !path.exists() {
                    skipped.push(SkippedItem {
                        path: path.to_string_lossy().to_string(),
                        name: path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        reason: "Path not found".to_string(),
                    });
                    continue;
                }
                // H6: resolve the canonical path once, and use it for the
                // actual deletion. This closes the TOCTOU window where a
                // racing symlink swap could escape the root between the
                // `is_under_roots` check and the `remove_dir_all` call.
                let canonical = match resolve_deletable(path, &roots, &deletable) {
                    Ok(canonical) => canonical,
                    Err(reason) => {
                        skipped.push(SkippedItem {
                            path: path.to_string_lossy().to_string(),
                            name: path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string(),
                            reason: reason.to_string(),
                        });
                        continue;
                    }
                };
                let kind = providers::detect(&canonical);
                let safety = providers::safety(kind, &canonical);
                let name = providers::semantic_name(kind, &canonical).unwrap_or_else(|| {
                    canonical
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                });
                match safety::evaluate_delete(&safety, confirm_caution) {
                    safety::DeleteDecision::Allow => {
                        let size = walker::dir_size(&canonical);
                        let ok = if canonical.is_dir() {
                            std::fs::remove_dir_all(&canonical).is_ok()
                        } else {
                            std::fs::remove_file(&canonical).is_ok()
                        };
                        if ok {
                            space_freed += size;
                            deleted.push(DeletedItem {
                                path: canonical.to_string_lossy().to_string(),
                                name,
                                size: format_size(size, BINARY),
                            });
                        } else {
                            skipped.push(SkippedItem {
                                path: canonical.to_string_lossy().to_string(),
                                name,
                                reason: "Permission denied or file in use".to_string(),
                            });
                        }
                    }
                    safety::DeleteDecision::NeedsConfirmation { reason } => {
                        skipped.push(SkippedItem {
                            path: path.to_string_lossy().to_string(),
                            name,
                            reason,
                        });
                    }
                    safety::DeleteDecision::Reject { reason } => {
                        skipped.push(SkippedItem {
                            path: path.to_string_lossy().to_string(),
                            name,
                            reason,
                        });
                    }
                }
            }
            DeleteResult {
                deleted_count: deleted.len(),
                skipped_count: skipped.len(),
                space_freed: format_size(space_freed, BINARY),
                space_freed_bytes: space_freed,
                deleted,
                skipped,
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        serde_json::to_string_pretty(&result).map_err(|e| format!("serialization failed: {e}"))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for CcmdMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("Cache Commander", env!("CARGO_PKG_VERSION"))
                    .with_title("Cache Commander")
                    .with_description(
                        "Cache Commander MCP server. Browse developer caches, scan for \
                         vulnerabilities, check for outdated packages, and safely clean up \
                         disk space.",
                    ),
            )
            .with_instructions(
                "Use list_caches or get_summary to start, then scan_vulnerabilities or \
                 check_outdated for security analysis, and delete_packages for cleanup.",
            )
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("ccmd=info".parse().unwrap()),
            )
            .try_init()
            .ok();

        let server = CcmdMcp::new(&config);
        let transport = rmcp::transport::io::stdio();
        let handle = server.serve(transport).await?;
        handle.waiting().await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::node::CacheKind;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    // --- walk_roots: Hugging Face shared blob store (#52) ---

    #[test]
    fn walk_roots_surfaces_hf_shared_blob_store() {
        // Shared blobs sit at root/huggingface/hub/blobs/<prefix>/<hash>: depth 5,
        // past collect_nodes' depth cap. Without a typed name on the store root
        // the payload was invisible to list_caches/search_packages; the
        // `[shared blobs]` label surfaces it as one sized entry.
        let dir = TempDir::new().unwrap();
        let hub = dir.path().join("huggingface/hub");
        let xet = "786820e8958abcfd7a2084c0d273f629ab8d7cbee560178f49a9cecb715b8041";
        std::fs::create_dir_all(hub.join("blobs/78")).unwrap();
        std::fs::create_dir_all(hub.join("models--org--m/blobs")).unwrap();
        std::fs::write(hub.join("blobs/.huggingface-shared-blobs"), "1\n").unwrap();
        std::fs::write(hub.join("blobs/78").join(xet), vec![0u8; 8192]).unwrap();
        symlink(
            format!("../../blobs/78/{xet}"),
            hub.join("models--org--m/blobs/951ed3fc1203e6a6"),
        )
        .unwrap();

        let mut config = Config::default_for_test();
        config.roots = vec![dir.path().to_path_buf()];
        let nodes = CcmdMcp::new(&config).walk_roots();

        let store = nodes
            .iter()
            .find(|n| n.name == "[shared blobs]")
            .expect("shared store must be listed");
        assert!(store.size >= 8192, "store size {}", store.size);
        assert!(nodes.iter().any(|n| n.name == "[model] org/m"));
    }

    // --- delete scope: only discovered cache entries are deletable (#91) ---

    /// root/huggingface/hub/models--org--m/snapshots/abc/config.json, i.e. one
    /// discovered package (`[model] org/m`) inside two provider containers,
    /// under a configured root.
    fn hf_layout() -> (TempDir, CcmdMcp) {
        let dir = TempDir::new().unwrap();
        let snap = dir
            .path()
            .join("huggingface/hub/models--org--m/snapshots/abc");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("config.json"), "{}").unwrap();
        let mut config = Config::default_for_test();
        config.roots = vec![dir.path().to_path_buf()];
        let server = CcmdMcp::new(&config);
        (dir, server)
    }

    async fn call_delete(
        server: &CcmdMcp,
        paths: &[&Path],
        confirm_caution: bool,
    ) -> serde_json::Value {
        let input = tools::DeleteInput {
            paths: paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            confirm_caution,
        };
        let out = server.delete_packages(Parameters(input)).await.unwrap();
        serde_json::from_str(&out).unwrap()
    }

    #[tokio::test]
    async fn delete_refuses_roots_containers_and_paths_inside_a_package() {
        // `confirm_caution` is the most permissive setting; it must only ever
        // confirm an in-scope item, never widen the scope itself.
        let (dir, server) = hf_layout();
        let root = dir.path();
        let hf = root.join("huggingface");
        let hub = hf.join("hub");
        let pkg = hub.join("models--org--m");
        let inner = pkg.join("snapshots/abc/config.json");

        let result = call_delete(&server, &[root, &hf, &hub, &inner], true).await;

        assert_eq!(result["deleted_count"], 0, "{result}");
        assert_eq!(result["skipped_count"], 4, "{result}");
        for p in [root, hf.as_path(), hub.as_path(), inner.as_path()] {
            assert!(p.exists(), "must not have been deleted: {}", p.display());
        }
    }

    #[tokio::test]
    async fn delete_still_removes_a_discovered_package() {
        let (dir, server) = hf_layout();
        let hub = dir.path().join("huggingface/hub");
        let pkg = hub.join("models--org--m");

        let result = call_delete(&server, &[&pkg], true).await;

        assert_eq!(result["deleted_count"], 1, "{result}");
        assert!(!pkg.exists(), "the discovered package should be gone");
        assert!(hub.exists(), "its container must be left alone");
    }

    #[tokio::test]
    async fn delete_refuses_a_symlink_that_resolves_to_the_root_or_a_container() {
        // A link inside the root canonicalizes to whatever it points at. If it
        // pointed at the root or a provider container, "deleting the link"
        // would delete that instead; symlink entries are never deletable.
        let (dir, server) = hf_layout();
        let hub = dir.path().join("huggingface/hub");
        let to_root = hub.join("models--org--to-root");
        let to_hub = hub.join("models--org--to-hub");
        symlink(dir.path(), &to_root).unwrap();
        symlink(&hub, &to_hub).unwrap();

        let result = call_delete(&server, &[&to_root, &to_hub], true).await;

        assert_eq!(result["deleted_count"], 0, "{result}");
        assert!(dir.path().join("huggingface").exists());
        assert!(hub.join("models--org--m").exists());
    }

    #[tokio::test]
    async fn delete_and_preview_refuse_a_requested_symlink_to_a_discovered_package() {
        // The allowlist holds the package's canonical path, so a link whose
        // target is that package canonicalizes into the set. The REQUESTED path
        // being a symlink must be refused too, or an unlisted link can stand in
        // for a deletable package.
        let (dir, server) = hf_layout();
        let hub = dir.path().join("huggingface/hub");
        let pkg = hub.join("models--org--m");
        let alias = dir.path().join("alias-to-pkg");
        symlink(&pkg, &alias).unwrap();
        let a = alias.to_string_lossy().to_string();

        // On Unix a trailing separator (or `/.`) makes the OS follow the link
        // when the path is stat'ed, so `alias/` would look like a directory
        // and slip past a naive symlink check. Every spelling must be refused.
        for spelling in [
            a.clone(),
            format!("{a}/"),
            format!("{a}//"),
            format!("{a}/."),
        ] {
            let preview = tools::PreviewDeleteInput {
                paths: vec![spelling.clone()],
            };
            let out = server.preview_delete(Parameters(preview)).await.unwrap();
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(
                v["items"][0]["would_delete"], false,
                "preview {spelling}: {v}"
            );

            let result = call_delete(&server, &[Path::new(&spelling)], true).await;
            assert_eq!(result["deleted_count"], 0, "delete {spelling}: {result}");
            assert!(pkg.exists(), "package must survive {spelling}");
        }
    }

    #[tokio::test]
    async fn delete_accepts_a_real_package_spelled_with_a_trailing_slash() {
        // Control for the normalization above: a trailing slash on a genuine
        // discovered package is still that package and must keep working.
        let (dir, server) = hf_layout();
        let pkg = dir.path().join("huggingface/hub/models--org--m");
        let spelled = format!("{}/", pkg.display());

        let result = call_delete(&server, &[Path::new(&spelled)], true).await;

        assert_eq!(result["deleted_count"], 1, "{result}");
        assert!(!pkg.exists());
    }

    fn server_with_roots(roots: Vec<PathBuf>) -> CcmdMcp {
        let mut config = Config::default_for_test();
        config.roots = roots;
        CcmdMcp::new(&config)
    }

    #[tokio::test]
    async fn delete_refuses_an_entry_that_is_a_configured_root() {
        // Roots may overlap (config allows it): the inner root is also a child
        // of the outer one, so discovery lists it. It must still never be
        // deletable, because it is a configured root.
        let (dir, _) = hf_layout();
        let pkg = dir.path().join("huggingface/hub/models--org--m");
        let server = server_with_roots(vec![dir.path().to_path_buf(), pkg.clone()]);

        let result = call_delete(&server, &[&pkg], true).await;

        assert_eq!(result["deleted_count"], 0, "{result}");
        assert!(pkg.exists(), "a configured root must survive");
    }

    #[tokio::test]
    async fn delete_refuses_an_entry_that_contains_a_configured_root() {
        // Deleting a discovered entry that CONTAINS another configured root
        // would remove that root with it.
        let dir = TempDir::new().unwrap();
        let plain = dir.path().join("plain");
        let inner = plain.join("inner");
        let other = dir.path().join("other");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(inner.join("f"), "x").unwrap();
        std::fs::write(other.join("f"), "x").unwrap();
        let server = server_with_roots(vec![dir.path().to_path_buf(), inner.clone()]);

        let result = call_delete(&server, &[&plain, &other], true).await;

        // `other` is an ordinary discovered entry and is deleted; `plain`
        // contains the configured root `inner` and is refused.
        assert_eq!(result["deleted_count"], 1, "{result}");
        assert!(!other.exists(), "control: an ordinary entry is deletable");
        assert!(plain.exists() && inner.exists(), "must not remove a root");
    }

    #[tokio::test]
    async fn preview_delete_agrees_with_delete_on_scope() {
        let (dir, server) = hf_layout();
        let hub = dir.path().join("huggingface/hub");
        let pkg = hub.join("models--org--m");
        let paths = [dir.path(), hub.as_path(), pkg.as_path()];
        let input = tools::PreviewDeleteInput {
            paths: paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
        };
        let out = server.preview_delete(Parameters(input)).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let would: Vec<bool> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["would_delete"].as_bool().unwrap())
            .collect();
        assert_eq!(would, [false, false, true], "root, container, package: {v}");
    }

    // --- is_under_roots ---

    #[test]
    fn is_under_roots_valid_child() {
        let dir = TempDir::new().unwrap();
        let child = dir.path().join("subdir");
        std::fs::create_dir(&child).unwrap();
        assert!(is_under_roots(&child, &[dir.path().to_path_buf()]));
    }

    #[test]
    fn is_under_roots_rejects_outside_path() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let file = outside.path().join("file.txt");
        std::fs::write(&file, "test").unwrap();
        assert!(!is_under_roots(&file, &[root.path().to_path_buf()]));
    }

    #[test]
    fn is_under_roots_rejects_nonexistent() {
        let root = TempDir::new().unwrap();
        assert!(!is_under_roots(
            &root.path().join("nope"),
            &[root.path().to_path_buf()]
        ));
    }

    #[test]
    fn is_under_roots_resolves_symlinks() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("secret");
        std::fs::write(&target, "secret data").unwrap();

        // Create symlink inside root pointing outside
        let link = root.path().join("link");
        symlink(&target, &link).unwrap();

        // String-based check would pass, but canonicalize catches it
        assert!(!is_under_roots(&link, &[root.path().to_path_buf()]));
    }

    #[test]
    fn is_under_roots_multiple_roots() {
        let root1 = TempDir::new().unwrap();
        let root2 = TempDir::new().unwrap();
        let child = root2.path().join("pkg");
        std::fs::create_dir(&child).unwrap();
        assert!(is_under_roots(
            &child,
            &[root1.path().to_path_buf(), root2.path().to_path_buf()]
        ));
    }

    // --- H6: canonical_under_roots returns the canonical path for use in
    // the actual mutation, so a later delete uses the resolved path rather
    // than a racing-swap-able input. ------------------------------------
    #[test]
    fn canonical_under_roots_returns_resolved_path_for_valid_input() {
        let dir = TempDir::new().unwrap();
        let child = dir.path().join("subdir");
        std::fs::create_dir(&child).unwrap();
        let canonical = canonical_under_roots(&child, &[dir.path().to_path_buf()]);
        assert!(canonical.is_some());
        assert_eq!(
            canonical.unwrap(),
            std::fs::canonicalize(&child).unwrap(),
            "should return the fully-resolved canonical path"
        );
    }

    #[test]
    fn canonical_under_roots_rejects_symlink_pointing_outside() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, "data").unwrap();
        let link = root.path().join("link");
        symlink(&secret, &link).unwrap();
        assert_eq!(
            canonical_under_roots(&link, &[root.path().to_path_buf()]),
            None,
            "symlink escaping the root must NOT produce a canonical-under-roots"
        );
    }

    // --- provider_label ---

    #[test]
    fn provider_label_known_kind() {
        let mut node = TreeNode::new(PathBuf::from("/tmp/test"), 1, None);
        node.kind = CacheKind::Pip;
        assert_eq!(CcmdMcp::provider_label(&node), "pip");
    }

    #[test]
    fn provider_label_unknown_under_library_caches() {
        let mut node = TreeNode::new(
            PathBuf::from("/Users/test/Library/Caches/com.apple.something"),
            1,
            None,
        );
        node.kind = CacheKind::Unknown;
        assert_eq!(CcmdMcp::provider_label(&node), "~/Library/Caches");
    }

    #[test]
    fn provider_label_unknown_elsewhere() {
        let mut node = TreeNode::new(PathBuf::from("/home/user/.cache/something"), 1, None);
        node.kind = CacheKind::Unknown;
        assert_eq!(CcmdMcp::provider_label(&node), "Other");
    }

    // --- VulnScanReport aggregation ---

    #[test]
    fn vuln_report_counts() {
        let packages = vec![
            VulnResult {
                name: "pkg1".into(),
                version: "1.0".into(),
                ecosystem: "pip".into(),
                path: "/a".into(),
                vulnerabilities: vec![
                    VulnEntry {
                        id: "CVE-1".into(),
                        summary: "bad".into(),
                        severity: None,
                        fix_version: Some("1.1".into()),
                        upgrade_command: None,
                    },
                    VulnEntry {
                        id: "CVE-2".into(),
                        summary: "worse".into(),
                        severity: None,
                        fix_version: None,
                        upgrade_command: None,
                    },
                ],
            },
            VulnResult {
                name: "pkg2".into(),
                version: "2.0".into(),
                ecosystem: "npm".into(),
                path: "/b".into(),
                vulnerabilities: vec![VulnEntry {
                    id: "CVE-3".into(),
                    summary: "also bad".into(),
                    severity: None,
                    fix_version: Some("2.1".into()),
                    upgrade_command: None,
                }],
            },
        ];

        let total_vulns: usize = packages.iter().map(|r| r.vulnerabilities.len()).sum();
        let fixable: usize = packages
            .iter()
            .flat_map(|r| &r.vulnerabilities)
            .filter(|v| v.fix_version.is_some())
            .count();

        let report = VulnScanReport {
            vulnerable_packages: packages.len(),
            total_vulnerabilities: total_vulns,
            fixable,
            unfixable: total_vulns - fixable,
            packages,
        };

        assert_eq!(report.vulnerable_packages, 2);
        assert_eq!(report.total_vulnerabilities, 3);
        assert_eq!(report.fixable, 2);
        assert_eq!(report.unfixable, 1);
    }

    // --- OutdatedReport aggregation ---

    #[test]
    fn outdated_report_by_ecosystem() {
        let packages = vec![
            OutdatedResult {
                name: "a".into(),
                version: "1.0".into(),
                latest: "2.0".into(),
                ecosystem: "pip".into(),
                path: "/a".into(),
                upgrade_command: None,
            },
            OutdatedResult {
                name: "b".into(),
                version: "1.0".into(),
                latest: "3.0".into(),
                ecosystem: "pip".into(),
                path: "/b".into(),
                upgrade_command: None,
            },
            OutdatedResult {
                name: "c".into(),
                version: "1.0".into(),
                latest: "2.0".into(),
                ecosystem: "npm".into(),
                path: "/c".into(),
                upgrade_command: None,
            },
        ];

        let mut by_ecosystem: HashMap<String, usize> = HashMap::new();
        for pkg in &packages {
            *by_ecosystem.entry(pkg.ecosystem.clone()).or_default() += 1;
        }

        let report = OutdatedReport {
            outdated_packages: packages.len(),
            by_ecosystem,
            packages,
        };

        assert_eq!(report.outdated_packages, 3);
        assert_eq!(report.by_ecosystem["pip"], 2);
        assert_eq!(report.by_ecosystem["npm"], 1);
    }

    // --- PreviewResult counts ---

    #[test]
    fn preview_result_counts() {
        let result = PreviewResult {
            deletable_count: 5,
            needs_confirmation_count: 2,
            rejected_count: 1,
            total_deletable_size: "100 MiB".into(),
            total_deletable_size_bytes: 100 * 1024 * 1024,
            items: vec![],
        };
        assert_eq!(
            result.deletable_count + result.needs_confirmation_count + result.rejected_count,
            8
        );
    }

    // --- DeleteResult counts ---

    #[test]
    fn delete_result_counts_match_arrays() {
        let result = DeleteResult {
            deleted_count: 2,
            skipped_count: 1,
            space_freed: "50 MiB".into(),
            space_freed_bytes: 50 * 1024 * 1024,
            deleted: vec![
                DeletedItem {
                    path: "/a".into(),
                    name: "a".into(),
                    size: "25 MiB".into(),
                },
                DeletedItem {
                    path: "/b".into(),
                    name: "b".into(),
                    size: "25 MiB".into(),
                },
            ],
            skipped: vec![SkippedItem {
                path: "/c".into(),
                name: "c".into(),
                reason: "unsafe".into(),
            }],
        };
        assert_eq!(result.deleted_count, result.deleted.len());
        assert_eq!(result.skipped_count, result.skipped.len());
    }

    // --- SearchReport count ---

    #[test]
    fn search_report_count_matches() {
        let packages = vec![PackageEntry {
            name: "torch".into(),
            version: "2.0".into(),
            ecosystem: "pip".into(),
            path: "/a".into(),
            size: "1 GiB".into(),
            size_bytes: 1024 * 1024 * 1024,
            safety_level: "Safe".into(),
            safety_icon: "●".into(),
        }];
        let report = SearchReport {
            total_results: packages.len(),
            packages,
        };
        assert_eq!(report.total_results, 1);
    }

    // --- JSON serialization round-trip ---

    #[test]
    fn vuln_report_serializes_with_counts_at_top() {
        let report = VulnScanReport {
            vulnerable_packages: 1,
            total_vulnerabilities: 2,
            fixable: 1,
            unfixable: 1,
            packages: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        // Counts should appear before packages array in JSON
        let count_pos = json.find("vulnerable_packages").unwrap();
        let packages_pos = json.find("\"packages\"").unwrap();
        assert!(
            count_pos < packages_pos,
            "Counts should appear before packages array"
        );
    }

    // --- matches_ecosystem ---

    #[test]
    fn ecosystem_exact_match() {
        assert!(matches_ecosystem("npm", "npm"));
        assert!(matches_ecosystem("pip", "pip"));
        assert!(matches_ecosystem("Cargo", "cargo"));
    }

    #[test]
    fn ecosystem_case_insensitive() {
        assert!(matches_ecosystem("HuggingFace Hub", "huggingface"));
        assert!(matches_ecosystem("npm", "NPM"));
    }

    #[test]
    fn ecosystem_aliases_for_labels() {
        // CacheKind::label() vocabulary
        assert!(matches_ecosystem("npm", "npx"));
        assert!(matches_ecosystem("npm", "node"));
        assert!(matches_ecosystem("npm", "nodejs"));
        assert!(matches_ecosystem("pip", "python"));
        assert!(matches_ecosystem("pip", "pypi"));
        assert!(matches_ecosystem("uv", "python"));
        assert!(matches_ecosystem("uv", "pypi"));
        assert!(matches_ecosystem("Poetry", "poetry"));
        assert!(matches_ecosystem("Poetry", "pypi"));
        assert!(matches_ecosystem("Cargo", "rust"));
        assert!(matches_ecosystem("Cargo", "crates"));
        assert!(matches_ecosystem("Homebrew", "brew"));
        assert!(matches_ecosystem("HuggingFace Hub", "hf"));
    }

    #[test]
    fn ecosystem_aliases_for_package_id() {
        // PackageId.ecosystem vocabulary (the I-1 bug)
        assert!(matches_ecosystem("crates.io", "cargo"));
        assert!(matches_ecosystem("crates.io", "rust"));
        assert!(matches_ecosystem("crates.io", "crates"));
        assert!(matches_ecosystem("PyPI", "pip"));
        assert!(matches_ecosystem("PyPI", "python"));
        assert!(matches_ecosystem("npm", "npx"));
    }

    #[test]
    fn ecosystem_empty_never_matches() {
        assert!(!matches_ecosystem("", "npm"));
        assert!(!matches_ecosystem("npm", ""));
        assert!(!matches_ecosystem("", ""));
    }

    #[test]
    fn ecosystem_unrelated_no_match() {
        assert!(!matches_ecosystem("npm", "pip"));
        assert!(!matches_ecosystem("Cargo", "npm"));
        assert!(!matches_ecosystem("HuggingFace Hub", "cargo"));
    }

    #[test]
    fn delete_result_serializes_with_counts_at_top() {
        let result = DeleteResult {
            deleted_count: 0,
            skipped_count: 0,
            space_freed: "0 B".into(),
            space_freed_bytes: 0,
            deleted: vec![],
            skipped: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let count_pos = json.find("deleted_count").unwrap();
        let array_pos = json.find("\"deleted\"").unwrap();
        assert!(count_pos < array_pos, "Counts should appear before arrays");
    }
}
