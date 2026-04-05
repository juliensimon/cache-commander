pub mod safety;
pub mod tools;

use crate::config::Config;
use crate::providers;
use crate::scanner;
use crate::scanner::walker;
use crate::security;
use crate::tree::node::{CacheKind, TreeNode};

use humansize::{format_size, BINARY};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::serde_json;
use rmcp::tool;
use rmcp::tool_handler;
use rmcp::tool_router;
use rmcp::ServerHandler;
use rmcp::ServiceExt;
use std::collections::HashMap;
use std::path::PathBuf;

use tools::*;

#[derive(Clone)]
pub struct CcmdMcp {
    roots: Vec<PathBuf>,
    tool_router: ToolRouter<Self>,
}

/// Check if a provider label matches a user-supplied ecosystem filter.
/// Handles aliases (e.g. "npx" matches "npm") and fuzzy matching.
fn matches_ecosystem(label: &str, filter: &str) -> bool {
    if label.is_empty() || filter.is_empty() {
        return false;
    }
    let label = label.to_lowercase();
    let filter = filter.to_lowercase();
    // Exact or substring match
    if label.contains(&filter) || filter.contains(&label) {
        return true;
    }
    // Known aliases
    match filter.as_str() {
        "npx" => label.contains("npm"),
        "node" | "nodejs" => label.contains("npm"),
        "python" | "pypi" => label.contains("pip") || label.contains("uv"),
        "rust" | "crates" => label.contains("cargo"),
        "brew" => label.contains("homebrew"),
        "hf" => label.contains("huggingface"),
        _ => false,
    }
}

/// Check if a path is inside any of the configured cache roots (resolving symlinks).
fn is_under_roots(path: &std::path::Path, roots: &[PathBuf]) -> bool {
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|cr| canonical.starts_with(cr))
            .unwrap_or(false)
    })
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
        let mut nodes = Vec::new();
        for root in &self.roots {
            for child_path in walker::list_children(root) {
                Self::collect_nodes(&child_path, 1, &mut nodes);
            }
        }
        nodes
    }

    /// Collect package nodes from a path. Recurses into provider containers
    /// to find individual packages. A node is a "package" (leaf) if it has
    /// a package_id or a semantic name starting with '[' (typed item like
    /// [model], [npx], [dataset]). Otherwise, if it's a known provider dir,
    /// it's a container — recurse into children.
    fn collect_nodes(path: &PathBuf, depth: u16, nodes: &mut Vec<TreeNode>) {
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
            let mut node = TreeNode::new(path.clone(), depth, None);
            node.kind = kind;
            node.size = walker::dir_size(path);
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
                    Self::collect_nodes(&child, depth + 1, nodes);
                }
                return;
            }
        }

        // Unknown kind → leaf node (e.g. ~/Library/Caches/com.apple.something)
        let mut node = TreeNode::new(path.clone(), depth, None);
        node.kind = kind;
        node.size = walker::dir_size(path);
        nodes.push(node);
    }

    fn provider_label(node: &TreeNode) -> String {
        let label = node.kind.label();
        if !label.is_empty() {
            return label.to_string();
        }
        // Unknown provider — use parent directory to give context
        if let Some(parent) = node.path.parent() {
            if parent.ends_with("Library/Caches") {
                return "~/Library/Caches".to_string();
            }
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
        roots.sort_by(|a, b| b.total_size_bytes.cmp(&a.total_size_bytes));
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
        provider_summaries.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

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

        if result.is_empty() {
            Ok("No packages found matching query.".to_string())
        } else {
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
                    ))
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

        if result.is_empty() {
            Ok("No vulnerabilities found.".to_string())
        } else {
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

        if result.is_empty() {
            Ok("All packages are up to date.".to_string())
        } else {
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
        let paths: Vec<PathBuf> = input.0.paths.iter().map(PathBuf::from).collect();
        let roots = self.roots.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut total_deletable: u64 = 0;
            let mut deletable_count = 0usize;
            let mut needs_confirmation_count = 0usize;
            let mut rejected_count = 0usize;
            let items: Vec<PreviewItem> = paths
                .iter()
                .map(|path| {
                    if !path.exists() {
                        rejected_count += 1;
                        return PreviewItem {
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
                        };
                    }
                    if !is_under_roots(path, &roots) {
                        rejected_count += 1;
                        return PreviewItem {
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
                            reason: Some(
                                "Path is not inside any configured cache root".to_string(),
                            ),
                        };
                    }
                    let kind = providers::detect(path);
                    let safety = providers::safety(kind, path);
                    let size = walker::dir_size(path);
                    let name = providers::semantic_name(kind, path).unwrap_or_else(|| {
                        path.file_name()
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
                    PreviewItem {
                        path: path.to_string_lossy().to_string(),
                        name,
                        size: format_size(size, BINARY),
                        size_bytes: size,
                        safety_level: safety.label().to_string(),
                        would_delete,
                        reason,
                    }
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
        description = "Delete cache entries. Safe items are deleted directly. Caution items require confirm_caution=true. Unsafe items are always rejected (use the TUI instead)."
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
                if !is_under_roots(path, &roots) {
                    skipped.push(SkippedItem {
                        path: path.to_string_lossy().to_string(),
                        name: path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        reason: "Path is not inside any configured cache root".to_string(),
                    });
                    continue;
                }
                let kind = providers::detect(path);
                let safety = providers::safety(kind, path);
                let name = providers::semantic_name(kind, path).unwrap_or_else(|| {
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                });
                match safety::evaluate_delete(&safety, confirm_caution) {
                    safety::DeleteDecision::Allow => {
                        let size = walker::dir_size(path);
                        let ok = if path.is_dir() {
                            std::fs::remove_dir_all(path).is_ok()
                        } else {
                            std::fs::remove_file(path).is_ok()
                        };
                        if ok {
                            space_freed += size;
                            deleted.push(DeletedItem {
                                path: path.to_string_lossy().to_string(),
                                name,
                                size: format_size(size, BINARY),
                            });
                        } else {
                            skipped.push(SkippedItem {
                                path: path.to_string_lossy().to_string(),
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

#[tool_handler]
impl ServerHandler for CcmdMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities {
                tools: Some(Default::default()),
                ..Default::default()
            },
            server_info: Implementation {
                name: "Cache Commander".to_string(),
                title: Some("Cache Commander".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some(
                    "Cache Commander MCP server. Browse developer caches, scan for \
                     vulnerabilities, check for outdated packages, and safely clean up \
                     disk space."
                        .to_string(),
                ),
                ..Default::default()
            },
            instructions: Some(
                "Use list_caches or get_summary to start, then scan_vulnerabilities or \
                 check_outdated for security analysis, and delete_packages for cleanup."
                    .to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::node::CacheKind;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

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

pub fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("ccmd=info".parse().unwrap()),
            )
            .init();

        let server = CcmdMcp::new(&config);
        let transport = rmcp::transport::io::stdio();
        let handle = server.serve(transport).await?;
        handle.waiting().await?;
        Ok(())
    })
}
