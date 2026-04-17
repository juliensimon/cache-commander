//! On-disk cache for vulnerability and version-check results.
//!
//! Keyed by `(ecosystem, name, version)` — a specific release is
//! immutable, so its scan result is reusable across runs. A TTL
//! bounds staleness (e.g. newly disclosed CVEs on an old version).
//!
//! Time is passed in as a parameter rather than read from the clock
//! internally so tests can exercise expiry without sleeping.

use crate::providers::PackageId;
use crate::security::{SecurityInfo, VersionInfo, Vulnerability};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

fn key(pkg: &PackageId) -> String {
    format!("{}|{}|{}", pkg.ecosystem, pkg.name, pkg.version)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredVuln {
    id: String,
    summary: String,
    severity: Option<String>,
    fix_version: Option<String>,
}

impl From<&Vulnerability> for StoredVuln {
    fn from(v: &Vulnerability) -> Self {
        Self {
            id: v.id.clone(),
            summary: v.summary.clone(),
            severity: v.severity.clone(),
            fix_version: v.fix_version.clone(),
        }
    }
}

impl From<StoredVuln> for Vulnerability {
    fn from(s: StoredVuln) -> Self {
        Self {
            id: s.id,
            summary: s.summary,
            severity: s.severity,
            fix_version: s.fix_version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VulnEntry {
    cached_at: u64,
    vulns: Vec<StoredVuln>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionEntry {
    cached_at: u64,
    current: String,
    latest: String,
    is_outdated: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VulnCacheFile {
    #[serde(default)]
    entries: HashMap<String, VulnEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VersionCacheFile {
    #[serde(default)]
    entries: HashMap<String, VersionEntry>,
}

#[derive(Debug, Default)]
pub struct VulnCache {
    entries: HashMap<String, VulnEntry>,
    ttl_secs: u64,
}

impl VulnCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    #[allow(dead_code)]
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_TTL_SECS)
    }

    /// Look up a package at the given wall-clock time. Returns `None`
    /// if missing or if the entry has aged past the TTL.
    pub fn get_at(&self, pkg: &PackageId, now: u64) -> Option<SecurityInfo> {
        let entry = self.entries.get(&key(pkg))?;
        if now.saturating_sub(entry.cached_at) > self.ttl_secs {
            return None;
        }
        Some(SecurityInfo {
            vulns: entry.vulns.iter().cloned().map(Into::into).collect(),
        })
    }

    pub fn get(&self, pkg: &PackageId) -> Option<SecurityInfo> {
        self.get_at(pkg, now_secs())
    }

    pub fn insert_at(&mut self, pkg: &PackageId, info: &SecurityInfo, now: u64) {
        self.entries.insert(
            key(pkg),
            VulnEntry {
                cached_at: now,
                vulns: info.vulns.iter().map(StoredVuln::from).collect(),
            },
        );
    }

    pub fn insert(&mut self, pkg: &PackageId, info: &SecurityInfo) {
        self.insert_at(pkg, info, now_secs());
    }

    pub fn load(path: &Path) -> Self {
        Self::load_with_ttl(path, DEFAULT_TTL_SECS)
    }

    pub fn load_with_ttl(path: &Path, ttl_secs: u64) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::new(ttl_secs),
        };
        let file: VulnCacheFile = serde_json::from_str(&content).unwrap_or_default();
        Self {
            entries: file.entries,
            ttl_secs,
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = VulnCacheFile {
            entries: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct VersionCache {
    entries: HashMap<String, VersionEntry>,
    ttl_secs: u64,
}

impl VersionCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    #[allow(dead_code)]
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_TTL_SECS)
    }

    pub fn get_at(&self, pkg: &PackageId, now: u64) -> Option<VersionInfo> {
        let entry = self.entries.get(&key(pkg))?;
        if now.saturating_sub(entry.cached_at) > self.ttl_secs {
            return None;
        }
        Some(VersionInfo {
            current: entry.current.clone(),
            latest: entry.latest.clone(),
            is_outdated: entry.is_outdated,
        })
    }

    pub fn get(&self, pkg: &PackageId) -> Option<VersionInfo> {
        self.get_at(pkg, now_secs())
    }

    pub fn insert_at(&mut self, pkg: &PackageId, info: &VersionInfo, now: u64) {
        self.entries.insert(
            key(pkg),
            VersionEntry {
                cached_at: now,
                current: info.current.clone(),
                latest: info.latest.clone(),
                is_outdated: info.is_outdated,
            },
        );
    }

    pub fn insert(&mut self, pkg: &PackageId, info: &VersionInfo) {
        self.insert_at(pkg, info, now_secs());
    }

    pub fn load(path: &Path) -> Self {
        Self::load_with_ttl(path, DEFAULT_TTL_SECS)
    }

    pub fn load_with_ttl(path: &Path, ttl_secs: u64) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::new(ttl_secs),
        };
        let file: VersionCacheFile = serde_json::from_str(&content).unwrap_or_default();
        Self {
            entries: file.entries,
            ttl_secs,
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = VersionCacheFile {
            entries: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }
}

/// Resolve on-disk paths for the two cache files. Returns `None` if the
/// platform-standard cache directory is unavailable (rare; falls back to
/// no-cache behavior at call sites).
pub fn default_paths() -> Option<(PathBuf, PathBuf)> {
    let proj = directories::ProjectDirs::from("", "", "ccmd")?;
    let dir = proj.cache_dir().to_path_buf();
    Some((dir.join("vuln_cache.json"), dir.join("version_cache.json")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: &str) -> PackageId {
        PackageId {
            ecosystem: "PyPI",
            name: name.into(),
            version: version.into(),
        }
    }

    #[test]
    fn vuln_cache_get_missing_returns_none() {
        let cache = VulnCache::new(100);
        assert!(cache.get(&pkg("requests", "2.31.0")).is_none());
    }

    #[test]
    fn vuln_cache_insert_then_get_within_ttl() {
        let mut cache = VulnCache::new(100);
        let p = pkg("requests", "2.31.0");
        let info = SecurityInfo {
            vulns: vec![Vulnerability {
                id: "CVE-1".into(),
                summary: "bad".into(),
                severity: Some("HIGH".into()),
                fix_version: Some("2.32.0".into()),
            }],
        };
        cache.insert_at(&p, &info, 1000);
        let hit = cache.get_at(&p, 1050).expect("should be cached");
        assert_eq!(hit.vulns.len(), 1);
        assert_eq!(hit.vulns[0].id, "CVE-1");
        assert_eq!(hit.vulns[0].fix_version.as_deref(), Some("2.32.0"));
    }

    #[test]
    fn vuln_cache_expired_entry_returns_none() {
        let mut cache = VulnCache::new(100);
        let p = pkg("requests", "2.31.0");
        cache.insert_at(&p, &SecurityInfo { vulns: vec![] }, 1000);
        // 1000 + 100 = 1100 is still fresh; 1101 is one second past TTL.
        assert!(cache.get_at(&p, 1101).is_none());
    }

    #[test]
    fn vuln_cache_caches_empty_vulns_as_negative_result() {
        // If OSV reported no vulns, we still want to avoid re-querying.
        let mut cache = VulnCache::new(100);
        let p = pkg("clean-pkg", "1.0.0");
        cache.insert_at(&p, &SecurityInfo { vulns: vec![] }, 500);
        let hit = cache.get_at(&p, 500).expect("negative result cached");
        assert!(hit.vulns.is_empty());
    }

    #[test]
    fn vuln_cache_roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("vuln.json");
        let mut cache = VulnCache::new(100);
        let p = pkg("requests", "2.31.0");
        cache.insert_at(
            &p,
            &SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-X".into(),
                    summary: "s".into(),
                    severity: None,
                    fix_version: None,
                }],
            },
            2000,
        );
        cache.save(&path).unwrap();

        let loaded = VulnCache::load_with_ttl(&path, 100);
        let hit = loaded.get_at(&p, 2050).expect("loaded from disk");
        assert_eq!(hit.vulns[0].id, "CVE-X");
    }

    #[test]
    fn vuln_cache_load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let cache = VulnCache::load(&path);
        assert!(cache.is_empty());
    }

    #[test]
    fn vuln_cache_load_corrupted_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "{not valid json").unwrap();
        let cache = VulnCache::load(&path);
        assert!(cache.is_empty());
    }

    #[test]
    fn version_cache_insert_get_and_ttl() {
        let mut cache = VersionCache::new(100);
        let p = pkg("requests", "2.31.0");
        let info = VersionInfo {
            current: "2.31.0".into(),
            latest: "2.32.0".into(),
            is_outdated: true,
        };
        cache.insert_at(&p, &info, 1000);
        let hit = cache.get_at(&p, 1050).expect("fresh");
        assert_eq!(hit.latest, "2.32.0");
        assert!(hit.is_outdated);
        assert!(cache.get_at(&p, 1200).is_none(), "past TTL");
    }

    #[test]
    fn version_cache_roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut cache = VersionCache::new(100);
        let p = pkg("x", "1.0.0");
        cache.insert_at(
            &p,
            &VersionInfo {
                current: "1.0.0".into(),
                latest: "1.0.0".into(),
                is_outdated: false,
            },
            500,
        );
        cache.save(&path).unwrap();
        let loaded = VersionCache::load_with_ttl(&path, 100);
        let hit = loaded.get_at(&p, 500).expect("roundtripped");
        assert!(!hit.is_outdated);
    }

    #[test]
    fn key_differs_across_versions() {
        let p1 = pkg("requests", "2.31.0");
        let p2 = pkg("requests", "2.32.0");
        assert_ne!(key(&p1), key(&p2));
    }
}
