use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Shared response types ---

#[derive(Debug, Clone, Serialize)]
pub struct CacheRoot {
    pub provider: String,
    pub path: String,
    pub total_size: String,
    pub total_size_bytes: u64,
    pub item_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchReport {
    pub total_results: usize,
    pub packages: Vec<PackageEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub path: String,
    pub size: String,
    pub size_bytes: u64,
    pub safety_level: String,
    pub safety_icon: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageDetails {
    pub provider: String,
    pub name: String,
    pub version: String,
    pub path: String,
    pub size: String,
    pub size_bytes: u64,
    pub last_modified: Option<String>,
    pub safety_level: String,
    pub safety_icon: String,
    pub metadata: Vec<MetadataEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataEntry {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnScanReport {
    pub vulnerable_packages: usize,
    pub total_vulnerabilities: usize,
    pub fixable: usize,
    pub unfixable: usize,
    pub packages: Vec<VulnResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnResult {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub path: String,
    pub vulnerabilities: Vec<VulnEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnEntry {
    pub id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub fix_version: Option<String>,
    pub upgrade_command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutdatedReport {
    pub outdated_packages: usize,
    pub by_ecosystem: HashMap<String, usize>,
    pub packages: Vec<OutdatedResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutdatedResult {
    pub name: String,
    pub version: String,
    pub latest: String,
    pub ecosystem: String,
    pub path: String,
    pub upgrade_command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total_size: String,
    pub total_size_bytes: u64,
    pub providers: Vec<ProviderSummary>,
    pub safety_counts: SafetyCounts,
    pub total_items: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderSummary {
    pub name: String,
    pub size: String,
    pub size_bytes: u64,
    pub item_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafetyCounts {
    pub safe: usize,
    pub caution: usize,
    pub r#unsafe: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeleteResult {
    pub deleted_count: usize,
    pub skipped_count: usize,
    pub space_freed: String,
    pub space_freed_bytes: u64,
    pub deleted: Vec<DeletedItem>,
    pub skipped: Vec<SkippedItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeletedItem {
    pub path: String,
    pub name: String,
    pub size: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedItem {
    pub path: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewItem {
    pub path: String,
    pub name: String,
    pub size: String,
    pub size_bytes: u64,
    pub safety_level: String,
    pub would_delete: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewResult {
    pub deletable_count: usize,
    pub needs_confirmation_count: usize,
    pub rejected_count: usize,
    pub total_deletable_size: String,
    pub total_deletable_size_bytes: u64,
    pub items: Vec<PreviewItem>,
}

// --- Tool input types (need JsonSchema for MCP discovery) ---

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInput {
    /// Package name to search for (case-insensitive substring match). Omit or leave empty to list all packages.
    #[serde(default)]
    pub query: Option<String>,
    /// Optional ecosystem filter: npm, pip, cargo, uv, huggingface, homebrew, etc.
    pub ecosystem: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DetailsInput {
    /// Absolute path to a cache entry. If omitted, use name + ecosystem instead.
    pub path: Option<String>,
    /// Package name to look up (used when path is omitted)
    pub name: Option<String>,
    /// Ecosystem to search in (used with name, e.g. npm, pip, huggingface)
    pub ecosystem: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EcosystemInput {
    /// Optional ecosystem filter: npm, pip, cargo, uv, huggingface, homebrew, etc.
    pub ecosystem: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteInput {
    /// Absolute paths to cache entries to delete
    pub paths: Vec<String>,
    /// Set to true to confirm deletion of Caution-level items (may cause rebuilds)
    #[serde(default)]
    pub confirm_caution: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PreviewDeleteInput {
    /// Absolute paths to cache entries to preview deletion for
    pub paths: Vec<String>,
}
