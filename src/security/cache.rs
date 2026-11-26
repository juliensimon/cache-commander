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

/// Version of the filtering logic whose OUTPUT the vulnerability cache stores.
/// The cache holds post-filter results, so when what counts as "fixed" changes,
/// older entries (including cached "clean" results for advisories that used to
/// be filtered out wrongly) must not be served. Bump this whenever the
/// OSV extraction/filtering semantics change; a cache file with a different
/// (or no) schema is discarded on load and rebuilt by a fresh scan.
pub const VULN_CACHE_SCHEMA: u32 = 4;

/// Version of the ordering semantics behind the version cache. Unlike the
/// vulnerability cache it does not hold OSV filtering output, but each entry
/// stores a COMPUTED `is_outdated`, derived with `osv::compare_versions`; when
/// that comparator changes, entries computed with the old one (e.g. installed
/// `v2.0.0` vs latest `1.9.9`) must not be replayed for the rest of the TTL. Bump
/// this whenever `compare_versions`/`normalize_version` change; a file with a
/// different (or no) schema is discarded on load.
pub const VERSION_CACHE_SCHEMA: u32 = 1;

fn key(pkg: &PackageId) -> String {
    format!("{}|{}|{}", pkg.ecosystem, pkg.name, pkg.version)
}

fn now_secs() -> u64 {
    // If the clock is set before 1970 we can't compute age correctly.
    // Returning u64::MAX makes every entry appear expired instead of
    // the opposite (falling back to 0 would make everything look fresh
    // forever on a misconfigured host).
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
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
    schema: u32,
    #[serde(default)]
    entries: HashMap<String, VulnEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VersionCacheFile {
    #[serde(default)]
    schema: u32,
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
        if file.schema != VULN_CACHE_SCHEMA {
            return Self::new(ttl_secs);
        }
        Self {
            entries: file.entries,
            ttl_secs,
        }
    }

    /// Drop entries older than the TTL at the given wall-clock time. The
    /// scanner calls this before `save()` so the disk file doesn't grow
    /// unbounded as packages get upgraded (stale `(name, version)` tuples
    /// would otherwise linger, just ignored on read).
    pub fn prune_expired(&mut self, now: u64) {
        let ttl = self.ttl_secs;
        self.entries
            .retain(|_, e| now.saturating_sub(e.cached_at) <= ttl);
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = VulnCacheFile {
            schema: VULN_CACHE_SCHEMA,
            entries: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        atomic_write(path, json.as_bytes())
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
        if file.schema != VERSION_CACHE_SCHEMA {
            return Self::new(ttl_secs);
        }
        Self {
            entries: file.entries,
            ttl_secs,
        }
    }

    pub fn prune_expired(&mut self, now: u64) {
        let ttl = self.ttl_secs;
        self.entries
            .retain(|_, e| now.saturating_sub(e.cached_at) <= ttl);
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = VersionCacheFile {
            schema: VERSION_CACHE_SCHEMA,
            entries: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        atomic_write(path, json.as_bytes())
    }
}

/// Write `bytes` to `path` atomically: write to a sibling temp file, then
/// rename it into place. A crash mid-write leaves either the prior file
/// (pre-rename) or the complete new file, never a truncated blob.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Same directory as the final path so rename stays on the same
    // filesystem (cross-fs rename would silently degrade to copy+remove
    // and lose the atomicity guarantee).
    let tmp = match path.file_name() {
        Some(name) => {
            let mut tmp_name = std::ffi::OsString::from(".");
            tmp_name.push(name);
            tmp_name.push(".tmp");
            path.with_file_name(tmp_name)
        }
        None => return std::fs::write(path, bytes),
    };
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
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
    fn vuln_cache_from_older_filtering_logic_is_discarded_on_load() {
        // The cache stores POST-filter results. An entry written by code that
        // wrongly filtered an advisory out (e.g. a GIT-range hash read as a
        // fix) is a cached "clean" result that would hide it for up to the TTL
        // after upgrading. A file with no/old schema version must not be reused.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vuln-cache.json");
        let fresh = now_secs();
        std::fs::write(
            &path,
            format!(
                r#"{{"entries":{{"PyPI|requests|2.31.0":{{"cached_at":{fresh},"vulns":[]}}}}}}"#
            ),
        )
        .unwrap();
        let cache = VulnCache::load(&path);
        assert!(
            cache.get(&pkg("requests", "2.31.0")).is_none(),
            "a pre-versioning negative entry must not be served"
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn version_cache_from_an_older_comparator_is_discarded_on_load() {
        // The version cache stores a COMPUTED `is_outdated`, derived with
        // `compare_versions`. After the comparator changed (Go's `v` prefix),
        // an entry such as installed v2.0.0 vs latest 1.9.9 cached as outdated
        // would be replayed for up to the TTL. A file with no/old schema must
        // not be reused.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("version-cache.json");
        let fresh = now_secs();
        std::fs::write(
            &path,
            format!(
                r#"{{"entries":{{"PyPI|requests|2.31.0":{{"cached_at":{fresh},"current":"v2.0.0","latest":"1.9.9","is_outdated":true}}}}}}"#
            ),
        )
        .unwrap();
        let cache = VersionCache::load(&path);
        assert!(
            cache.get(&pkg("requests", "2.31.0")).is_none(),
            "a pre-versioning computed result must not be served"
        );
    }

    #[test]
    fn version_cache_current_schema_round_trips_and_other_schemas_are_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("version-cache.json");
        let p = pkg("requests", "2.31.0");
        let info = VersionInfo {
            current: "2.31.0".into(),
            latest: "2.32.0".into(),
            is_outdated: true,
        };
        let mut cache = VersionCache::new(DEFAULT_TTL_SECS);
        cache.insert(&p, &info);
        cache.save(&path).unwrap();
        assert!(
            VersionCache::load(&path).get(&p).is_some(),
            "same schema is reused"
        );

        let fresh = now_secs();
        std::fs::write(
            &path,
            format!(
                r#"{{"schema":{},"entries":{{"PyPI|requests|2.31.0":{{"cached_at":{fresh},"current":"2.31.0","latest":"2.32.0","is_outdated":true}}}}}}"#,
                VERSION_CACHE_SCHEMA + 1
            ),
        )
        .unwrap();
        assert!(VersionCache::load(&path).get(&p).is_none());
    }

    #[test]
    fn vuln_cache_current_schema_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vuln-cache.json");
        let p = pkg("requests", "2.31.0");
        let mut cache = VulnCache::new(DEFAULT_TTL_SECS);
        cache.insert(&p, &SecurityInfo { vulns: vec![] });
        cache.save(&path).unwrap();

        let loaded = VulnCache::load(&path);
        assert!(loaded.get(&p).is_some(), "same-schema entries are reused");
    }

    #[test]
    fn vuln_cache_with_a_different_schema_version_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vuln-cache.json");
        let fresh = now_secs();
        std::fs::write(
            &path,
            format!(
                r#"{{"schema":{},"entries":{{"PyPI|requests|2.31.0":{{"cached_at":{fresh},"vulns":[]}}}}}}"#,
                VULN_CACHE_SCHEMA + 1
            ),
        )
        .unwrap();
        assert!(VulnCache::load(&path).is_empty());
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
    fn prune_expired_drops_stale_entries() {
        let mut cache = VulnCache::new(60);
        let fresh = PackageId {
            ecosystem: "PyPI",
            name: "fresh".into(),
            version: "1.0.0".into(),
        };
        let ancient = PackageId {
            ecosystem: "PyPI",
            name: "ancient".into(),
            version: "1.0.0".into(),
        };
        cache.insert_at(&ancient, &SecurityInfo { vulns: vec![] }, 1_000);
        cache.insert_at(&fresh, &SecurityInfo { vulns: vec![] }, 10_000);

        cache.prune_expired(10_050); // 50s past the fresh insert
        assert!(cache.get_at(&fresh, 10_050).is_some(), "fresh retained");
        assert!(
            cache.get_at(&ancient, 10_050).is_none(),
            "ancient (9050s old) pruned"
        );
        // Direct entry count to prove the HashMap itself shrank.
        assert_eq!(cache.entries.len(), 1, "in-memory entries shrank");
    }

    #[test]
    fn atomic_save_leaves_no_temp_file_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vuln.json");
        let mut c = VulnCache::new(100);
        c.insert_at(
            &PackageId {
                ecosystem: "PyPI",
                name: "p".into(),
                version: "1.0".into(),
            },
            &SecurityInfo { vulns: vec![] },
            1000,
        );
        c.save(&path).unwrap();
        assert!(path.exists());
        // The temp file should not linger after a successful rename.
        let tmp = dir.path().join(".vuln.json.tmp");
        assert!(!tmp.exists(), "temp file cleaned up after rename");
    }

    #[test]
    fn atomic_save_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vuln.json");
        std::fs::write(&path, "old garbage").unwrap();
        let c = VulnCache::new(100);
        c.save(&path).unwrap();
        // Rename atomically replaces the old contents; no "old garbage" remains.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with("{"), "expected JSON, got: {raw:?}");
    }

    #[test]
    fn key_differs_across_versions() {
        let p1 = pkg("requests", "2.31.0");
        let p2 = pkg("requests", "2.32.0");
        assert_ne!(key(&p1), key(&p2));
    }
}
