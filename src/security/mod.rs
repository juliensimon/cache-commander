pub mod cache;
pub mod osv;
pub mod registry;

use crate::providers::PackageId;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub fix_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityInfo {
    pub vulns: Vec<Vulnerability>,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub current: String,
    pub latest: String,
    pub is_outdated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NodeStatus {
    pub has_vuln: bool,
    pub has_outdated: bool,
}

/// Outcome of a vulnerability scan. Tracks both successful results and the
/// number of packages whose OSV query failed — callers must distinguish
/// "empty because clean" from "empty because scan was incomplete" (H5).
///
/// `cached_hits` counts packages whose result was served from the on-disk
/// cache instead of a network call; the UI surfaces this so users can see
/// the cache is doing its job.
#[derive(Debug, Clone, Default)]
pub struct VulnScanOutcome {
    pub results: HashMap<PathBuf, SecurityInfo>,
    pub unscanned_packages: usize,
    pub cached_hits: usize,
}

/// Outcome of a version check. Tracks successful results and the number of
/// packages whose registry query failed. `cached_hits` counts packages
/// answered from the disk cache.
#[derive(Debug, Clone, Default)]
pub struct VersionCheckOutcome {
    pub results: HashMap<PathBuf, VersionInfo>,
    pub unchecked_packages: usize,
    pub cached_hits: usize,
}

/// Returns true if a vulnerability is still active (not fixed) for the given package version.
fn is_vuln_active(fix_version: &Option<String>, pkg_version: &str) -> bool {
    match fix_version {
        Some(fix) if !fix.is_empty() => !osv::version_lte(fix, pkg_version),
        _ => true, // unknown or empty fix = assume still affected
    }
}

/// Convert a single OSV batch response chunk into SecurityInfo entries, returning
/// the entries and the set of vuln IDs whose details still need fetching.
///
/// Pure function — no I/O. Extracted so scan_vulns' non-network logic is testable.
fn process_osv_response(
    chunk: &[(PathBuf, PackageId)],
    response: &osv::OsvResponse,
    vuln_ids_to_fetch: &mut Vec<String>,
) -> Vec<(PathBuf, SecurityInfo)> {
    let mut out = Vec::new();
    for (i, query_result) in response.results.iter().enumerate() {
        if i >= chunk.len() {
            break;
        }
        if query_result.vulns.is_empty() {
            continue;
        }
        let vulns: Vec<Vulnerability> = query_result
            .vulns
            .iter()
            .map(|v| {
                if !vuln_ids_to_fetch.contains(&v.id) {
                    vuln_ids_to_fetch.push(v.id.clone());
                }
                Vulnerability {
                    id: v.id.clone(),
                    summary: v.summary.clone().unwrap_or_default(),
                    severity: v.severity.first().map(|s| s.score.clone()),
                    fix_version: None,
                }
            })
            .collect();
        out.push((chunk[i].0.clone(), SecurityInfo { vulns }));
    }
    out
}

/// Backfill fix versions from the detail cache and drop vulns whose fix is
/// already <= installed version. Mutates `results` in place and removes
/// entries whose vulns are all filtered out.
///
/// Pure function — no I/O.
fn backfill_and_filter_vulns(
    results: &mut HashMap<PathBuf, SecurityInfo>,
    packages: &[(PathBuf, PackageId)],
    detail_cache: &HashMap<String, osv::OsvVulnDetail>,
) {
    for (path, info) in results.iter_mut() {
        let pkg = packages.iter().find(|(p, _)| p == path).map(|(_, id)| id);
        if let Some(pkg) = pkg {
            for vuln in &mut info.vulns {
                if let Some(detail) = detail_cache.get(&vuln.id) {
                    vuln.fix_version =
                        osv::extract_fix_version(detail, &pkg.name, pkg.ecosystem, &pkg.version);
                }
            }
            info.vulns
                .retain(|vuln| is_vuln_active(&vuln.fix_version, &pkg.version));
        }
    }
    results.retain(|_, info| !info.vulns.is_empty());
}

pub fn scan_vulns(packages: &[(PathBuf, PackageId)]) -> VulnScanOutcome {
    scan_vulns_with_querier(packages, osv::query_osv)
}

/// Run a vuln scan, consulting `cache` for hits and writing misses back into
/// it. Packages present in the cache never reach the network.
pub fn scan_vulns_with_cache(
    packages: &[(PathBuf, PackageId)],
    cache: &mut cache::VulnCache,
) -> VulnScanOutcome {
    scan_vulns_with_querier_and_cache(packages, osv::query_osv, Some(cache))
}

/// Testable core of `scan_vulns`: accepts an OSV querier closure. Tracks
/// failed-chunk packages in the returned outcome so the caller can
/// distinguish "no vulns" from "partial scan" (H5).
fn scan_vulns_with_querier<Q>(packages: &[(PathBuf, PackageId)], querier: Q) -> VulnScanOutcome
where
    Q: FnMut(&[PackageId]) -> Result<osv::OsvResponse, String>,
{
    scan_vulns_with_querier_and_cache(packages, querier, None)
}

/// Cache-aware core. Splits `packages` into cache hits and misses, queries
/// only the misses, records fresh results into the cache, and merges.
///
/// Invariants:
/// - Cache hits never count toward `unscanned_packages`.
/// - On querier error for a miss chunk, those packages count as unscanned
///   and the cache is not updated for them.
/// - Negative results (no vulns) are cached too, so clean packages stop
///   being re-queried on every run.
fn scan_vulns_with_querier_and_cache<Q>(
    packages: &[(PathBuf, PackageId)],
    mut querier: Q,
    mut cache: Option<&mut cache::VulnCache>,
) -> VulnScanOutcome
where
    Q: FnMut(&[PackageId]) -> Result<osv::OsvResponse, String>,
{
    let mut results = HashMap::new();
    let mut unscanned = 0usize;
    let mut cached_hits = 0usize;
    if packages.is_empty() {
        return VulnScanOutcome::default();
    }

    // Split hits from misses. Hits' active vulns go straight into results;
    // misses fall through to the network path below. Both positive and
    // negative (no-vulns) hits count toward `cached_hits`.
    let mut misses: Vec<(PathBuf, PackageId)> = Vec::new();
    for (path, pkg) in packages {
        let hit = cache.as_ref().and_then(|c| c.get(pkg));
        match hit {
            Some(info) if !info.vulns.is_empty() => {
                cached_hits += 1;
                results.insert(path.clone(), info);
            }
            Some(_) => {
                cached_hits += 1;
            }
            None => misses.push((path.clone(), pkg.clone())),
        }
    }

    if misses.is_empty() {
        return VulnScanOutcome {
            results,
            unscanned_packages: 0,
            cached_hits,
        };
    }

    let mut vuln_ids_to_fetch: Vec<String> = Vec::new();
    let mut fresh_results: HashMap<PathBuf, SecurityInfo> = HashMap::new();
    // Paths from chunks whose OSV query succeeded. Packages not listed here
    // either failed outright (contributing to `unscanned`) and must not be
    // cached, so writeback consults this set instead of re-scanning misses.
    let mut succeeded_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for chunk in misses.chunks(100) {
        let ids: Vec<PackageId> = chunk.iter().map(|(_, id)| id.clone()).collect();
        let response = match querier(&ids) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("OSV batch query failed for chunk: {e}");
                unscanned += chunk.len();
                continue;
            }
        };
        for (path, _) in chunk {
            succeeded_paths.insert(path.clone());
        }
        for (path, info) in process_osv_response(chunk, &response, &mut vuln_ids_to_fetch) {
            fresh_results.insert(path, info);
        }
    }

    let detail_cache = fetch_fix_versions(&vuln_ids_to_fetch);
    backfill_and_filter_vulns(&mut fresh_results, &misses, &detail_cache);

    // One linear pass over misses: cache only the ones whose query succeeded.
    // Entries absent from fresh_results had no active vulns → cache as negative.
    if let Some(c) = cache.as_mut() {
        let empty = SecurityInfo { vulns: vec![] };
        for (path, pkg) in &misses {
            if !succeeded_paths.contains(path) {
                continue;
            }
            let info = fresh_results.get(path).unwrap_or(&empty);
            c.insert(pkg, info);
        }
    }

    for (path, info) in fresh_results {
        results.insert(path, info);
    }

    VulnScanOutcome {
        results,
        unscanned_packages: unscanned,
        cached_hits,
    }
}

fn fetch_fix_versions(vuln_ids: &[String]) -> HashMap<String, osv::OsvVulnDetail> {
    use std::sync::{Arc, Mutex};

    let cache = Arc::new(Mutex::new(HashMap::new()));

    for chunk in vuln_ids.chunks(20) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|id| {
                let id = id.clone();
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    if let Ok(detail) = osv::fetch_vuln_detail(&id)
                        && let Ok(mut map) = cache.lock()
                    {
                        map.insert(id, detail);
                    }
                })
            })
            .collect();
        for handle in handles {
            let _ = handle.join();
        }
    }

    match Arc::try_unwrap(cache) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().map(|g| g.clone()).unwrap_or_default(),
    }
}

pub fn check_versions(packages: &[(PathBuf, PackageId)]) -> VersionCheckOutcome {
    check_versions_inner(packages, registry::check_latest)
}

/// Run a version check, consulting `cache` for hits and writing misses back.
/// Packages present in the cache never reach the registry.
pub fn check_versions_with_cache(
    packages: &[(PathBuf, PackageId)],
    cache: &mut cache::VersionCache,
) -> VersionCheckOutcome {
    check_versions_with_cache_inner(packages, registry::check_latest, Some(cache))
}

/// Cache-aware split/merge wrapper. Tested via an injectable `checker` so we
/// don't need network. The heavy threaded path is reused for misses.
fn check_versions_with_cache_inner<F>(
    packages: &[(PathBuf, PackageId)],
    checker: F,
    mut cache: Option<&mut cache::VersionCache>,
) -> VersionCheckOutcome
where
    F: Fn(&PackageId) -> Result<Option<String>, String> + Send + Sync + 'static + Copy,
{
    let mut results = HashMap::new();
    let mut misses: Vec<(PathBuf, PackageId)> = Vec::new();
    let mut cached_hits = 0usize;
    for (path, pkg) in packages {
        match cache.as_ref().and_then(|c| c.get(pkg)) {
            Some(info) => {
                // Replay stored result verbatim. Inner check_versions returns
                // every successful lookup (outdated or not); the UI filters
                // on is_outdated, so cache hits must surface the same shape.
                cached_hits += 1;
                results.insert(path.clone(), info);
            }
            None => misses.push((path.clone(), pkg.clone())),
        }
    }

    if misses.is_empty() {
        return VersionCheckOutcome {
            results,
            unchecked_packages: 0,
            cached_hits,
        };
    }

    let fresh = check_versions_inner(&misses, checker);

    // Only cache successful lookups. A miss that produced an entry in
    // fresh.results succeeded; a miss absent from fresh.results failed
    // (counted in unchecked_packages) and must not pollute the cache.
    if let Some(c) = cache.as_mut() {
        for (path, pkg) in &misses {
            if let Some(info) = fresh.results.get(path) {
                c.insert(pkg, info);
            }
        }
    }

    for (path, info) in fresh.results {
        results.insert(path, info);
    }
    VersionCheckOutcome {
        results,
        unchecked_packages: fresh.unchecked_packages,
        cached_hits,
    }
}

fn check_versions_inner<F>(packages: &[(PathBuf, PackageId)], checker: F) -> VersionCheckOutcome
where
    F: Fn(&PackageId) -> Result<Option<String>, String> + Send + Sync + 'static + Copy,
{
    use std::sync::{Arc, Mutex};

    // Track failed lookups so an unreachable registry never appears as
    // "all up to date" to the user (H5).
    let results = Arc::new(Mutex::new(HashMap::new()));
    let unchecked = Arc::new(Mutex::new(0usize));

    for chunk in packages.chunks(8) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|(path, pkg)| {
                let path = path.clone();
                let pkg = pkg.clone();
                let results = Arc::clone(&results);
                let unchecked = Arc::clone(&unchecked);
                std::thread::spawn(move || match checker(&pkg) {
                    Ok(Some(latest)) => {
                        let is_outdated = osv::compare_versions(&pkg.version, &latest)
                            == std::cmp::Ordering::Less;
                        if let Ok(mut map) = results.lock() {
                            map.insert(
                                path,
                                VersionInfo {
                                    current: pkg.version.clone(),
                                    latest,
                                    is_outdated,
                                },
                            );
                        }
                    }
                    Ok(None) => {
                        // No latest known — treat as unchecked so the UI
                        // doesn't silently elide the package.
                        if let Ok(mut n) = unchecked.lock() {
                            *n += 1;
                        }
                    }
                    Err(_) => {
                        if let Ok(mut n) = unchecked.lock() {
                            *n += 1;
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }
    let results = match Arc::try_unwrap(results) {
        Ok(m) => m.into_inner().unwrap_or_default(),
        Err(arc) => arc.lock().map(|g| g.clone()).unwrap_or_default(),
    };
    let unchecked_packages = match Arc::try_unwrap(unchecked) {
        Ok(m) => m.into_inner().unwrap_or(0),
        Err(arc) => arc.lock().map(|g| *g).unwrap_or(0),
    };
    VersionCheckOutcome {
        results,
        unchecked_packages,
        cached_hits: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_vuln_active_fix_greater_than_installed() {
        assert!(is_vuln_active(&Some("2.0.0".into()), "1.0.0"));
    }

    #[test]
    fn is_vuln_active_fix_equal_to_installed() {
        // fix == installed means the installed version has the fix
        assert!(!is_vuln_active(&Some("1.0.0".into()), "1.0.0"));
    }

    #[test]
    fn is_vuln_active_fix_less_than_installed() {
        assert!(!is_vuln_active(&Some("1.0.0".into()), "2.0.0"));
    }

    #[test]
    fn is_vuln_active_no_fix_version() {
        assert!(is_vuln_active(&None, "1.0.0"));
    }

    #[test]
    fn is_vuln_active_empty_fix_version() {
        // Empty fix string should be treated as unknown = still active
        assert!(is_vuln_active(&Some("".into()), "1.0.0"));
    }

    #[test]
    fn filter_removes_all_vulns_clears_entry() {
        let mut results = HashMap::new();
        results.insert(
            PathBuf::from("/test/pkg"),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-1".into(),
                    summary: "fixed".into(),
                    severity: None,
                    fix_version: Some("1.0.0".into()),
                }],
            },
        );

        // Simulate the retain + remove logic from scan_vulns
        for info in results.values_mut() {
            info.vulns
                .retain(|v| is_vuln_active(&v.fix_version, "2.0.0"));
        }
        results.retain(|_, info| !info.vulns.is_empty());

        assert!(
            results.is_empty(),
            "Entry should be removed when all vulns filtered"
        );
    }

    #[test]
    fn scan_vulns_empty_input_returns_empty_outcome_without_network() {
        // Early-return path — must not attempt any network call.
        let out = scan_vulns(&[]);
        assert!(out.results.is_empty());
        assert_eq!(out.unscanned_packages, 0);
    }

    #[test]
    fn check_versions_empty_input_returns_empty_outcome_without_network() {
        let out = check_versions(&[]);
        assert!(out.results.is_empty());
        assert_eq!(out.unchecked_packages, 0);
    }

    // --- H5: querier-based unit tests for unscanned tracking --------------

    #[test]
    fn scan_vulns_with_querier_tracks_failed_chunks() {
        let pkgs: Vec<(PathBuf, PackageId)> = (0..3)
            .map(|i| {
                (
                    PathBuf::from(format!("/test/pkg{i}")),
                    PackageId {
                        ecosystem: "npm",
                        name: format!("pkg{i}"),
                        version: "1.0.0".into(),
                    },
                )
            })
            .collect();
        // Querier always errors — simulates OSV being unreachable.
        let out = scan_vulns_with_querier(&pkgs, |_ids| Err("simulated network failure".into()));
        assert!(out.results.is_empty());
        assert_eq!(
            out.unscanned_packages, 3,
            "all 3 packages should be counted as unscanned"
        );
    }

    #[test]
    fn scan_vulns_with_querier_succeeds_returns_zero_unscanned() {
        let pkgs = vec![(
            PathBuf::from("/test/ok"),
            PackageId {
                ecosystem: "npm",
                name: "ok".into(),
                version: "1.0.0".into(),
            },
        )];
        let out = scan_vulns_with_querier(&pkgs, |_ids| {
            Ok(osv::OsvResponse {
                results: vec![osv::OsvQueryResult { vulns: vec![] }],
            })
        });
        assert!(out.results.is_empty());
        assert_eq!(out.unscanned_packages, 0);
    }

    #[test]
    fn fetch_fix_versions_empty_ids_returns_empty_map_without_network() {
        let out = fetch_fix_versions(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn vulnerability_struct_clone_roundtrip() {
        // Exercises #[derive(Clone)] on the public types so they count toward
        // line coverage (they're currently only built at call sites that the
        // offline test suite doesn't reach).
        let v = Vulnerability {
            id: "CVE-1".into(),
            summary: "s".into(),
            severity: Some("HIGH".into()),
            fix_version: Some("1.0.0".into()),
        };
        let cloned = v.clone();
        assert_eq!(cloned.id, "CVE-1");
        let info = SecurityInfo {
            vulns: vec![cloned],
        };
        assert_eq!(info.clone().vulns.len(), 1);
        let ver = VersionInfo {
            current: "1".into(),
            latest: "2".into(),
            is_outdated: true,
        };
        assert!(ver.clone().is_outdated);
        let st = NodeStatus::default();
        let _ = st.clone();
    }

    fn pkg(name: &str, version: &str) -> PackageId {
        PackageId {
            ecosystem: "PyPI",
            name: name.to_string(),
            version: version.to_string(),
        }
    }

    #[test]
    fn process_osv_response_populates_results_and_ids() {
        let chunk = vec![
            (PathBuf::from("/a"), pkg("requests", "2.31.0")),
            (PathBuf::from("/b"), pkg("flask", "2.0.0")),
        ];
        let json = r#"{"results":[
            {"vulns":[{"id":"CVE-1","summary":"bad","severity":[{"type":"CVSS_V3","score":"7.5"}]}]},
            {"vulns":[]}
        ]}"#;
        let response = osv::parse_response(json).unwrap();
        let mut ids = Vec::new();
        let out = process_osv_response(&chunk, &response, &mut ids);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, PathBuf::from("/a"));
        assert_eq!(out[0].1.vulns.len(), 1);
        assert_eq!(out[0].1.vulns[0].id, "CVE-1");
        assert_eq!(out[0].1.vulns[0].summary, "bad");
        assert_eq!(out[0].1.vulns[0].severity.as_deref(), Some("7.5"));
        assert!(out[0].1.vulns[0].fix_version.is_none());
        assert_eq!(ids, vec!["CVE-1".to_string()]);
    }

    #[test]
    fn process_osv_response_dedups_vuln_ids() {
        let chunk = vec![
            (PathBuf::from("/a"), pkg("p1", "1.0")),
            (PathBuf::from("/b"), pkg("p2", "1.0")),
        ];
        // Both packages have the same CVE — ID should only appear once
        let json = r#"{"results":[
            {"vulns":[{"id":"CVE-shared"}]},
            {"vulns":[{"id":"CVE-shared"}]}
        ]}"#;
        let response = osv::parse_response(json).unwrap();
        let mut ids = Vec::new();
        let out = process_osv_response(&chunk, &response, &mut ids);
        assert_eq!(out.len(), 2);
        assert_eq!(ids, vec!["CVE-shared".to_string()]);
    }

    #[test]
    fn process_osv_response_stops_at_chunk_length() {
        // Defensive: if OSV returns more results than we sent, extra results are dropped.
        let chunk = vec![(PathBuf::from("/a"), pkg("p", "1.0"))];
        let json = r#"{"results":[
            {"vulns":[{"id":"CVE-1"}]},
            {"vulns":[{"id":"CVE-2"}]}
        ]}"#;
        let response = osv::parse_response(json).unwrap();
        let mut ids = Vec::new();
        let out = process_osv_response(&chunk, &response, &mut ids);
        assert_eq!(out.len(), 1);
        assert_eq!(ids, vec!["CVE-1".to_string()]);
    }

    #[test]
    fn process_osv_response_handles_missing_summary() {
        let chunk = vec![(PathBuf::from("/a"), pkg("p", "1.0"))];
        let json = r#"{"results":[{"vulns":[{"id":"CVE-1"}]}]}"#;
        let response = osv::parse_response(json).unwrap();
        let mut ids = Vec::new();
        let out = process_osv_response(&chunk, &response, &mut ids);
        assert_eq!(out[0].1.vulns[0].summary, "");
        assert!(out[0].1.vulns[0].severity.is_none());
    }

    #[test]
    fn backfill_and_filter_extracts_fix_and_retains_active() {
        let mut results = HashMap::new();
        results.insert(
            PathBuf::from("/a"),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-1".into(),
                    summary: "x".into(),
                    severity: None,
                    fix_version: None,
                }],
            },
        );
        let packages = vec![(PathBuf::from("/a"), pkg("requests", "2.31.0"))];

        let detail_json = r#"{
            "id": "CVE-1",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.32.0"}]}]
            }]
        }"#;
        let mut detail_cache = HashMap::new();
        detail_cache.insert(
            "CVE-1".to_string(),
            osv::parse_vuln_detail(detail_json).unwrap(),
        );

        backfill_and_filter_vulns(&mut results, &packages, &detail_cache);

        assert_eq!(results.len(), 1);
        let info = results.get(&PathBuf::from("/a")).unwrap();
        assert_eq!(info.vulns[0].fix_version.as_deref(), Some("2.32.0"));
    }

    #[test]
    fn backfill_and_filter_drops_entry_when_installed_already_fixed() {
        let mut results = HashMap::new();
        results.insert(
            PathBuf::from("/a"),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-1".into(),
                    summary: "x".into(),
                    severity: None,
                    fix_version: None,
                }],
            },
        );
        // Installed version 2.32.5 is past the fix 2.32.0 → entry should be removed
        let packages = vec![(PathBuf::from("/a"), pkg("requests", "2.32.5"))];

        let detail_json = r#"{
            "id": "CVE-1",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.32.0"}]}]
            }]
        }"#;
        let mut detail_cache = HashMap::new();
        detail_cache.insert(
            "CVE-1".to_string(),
            osv::parse_vuln_detail(detail_json).unwrap(),
        );

        backfill_and_filter_vulns(&mut results, &packages, &detail_cache);
        assert!(results.is_empty(), "fixed vuln should remove entry");
    }

    #[test]
    fn backfill_and_filter_keeps_vuln_when_no_detail_available() {
        // When detail_cache has no entry for a vuln ID, we leave fix_version None
        // and is_vuln_active returns true (assume still affected).
        let mut results = HashMap::new();
        results.insert(
            PathBuf::from("/a"),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-unknown".into(),
                    summary: "".into(),
                    severity: None,
                    fix_version: None,
                }],
            },
        );
        let packages = vec![(PathBuf::from("/a"), pkg("p", "1.0"))];
        let detail_cache: HashMap<String, osv::OsvVulnDetail> = HashMap::new();
        backfill_and_filter_vulns(&mut results, &packages, &detail_cache);
        assert_eq!(results.len(), 1);
        assert!(
            results.get(&PathBuf::from("/a")).unwrap().vulns[0]
                .fix_version
                .is_none()
        );
    }

    #[test]
    fn backfill_and_filter_skips_entries_without_matching_package() {
        // If an entry's path doesn't appear in `packages`, we leave it alone.
        let mut results = HashMap::new();
        results.insert(
            PathBuf::from("/orphan"),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-1".into(),
                    summary: "".into(),
                    severity: None,
                    fix_version: None,
                }],
            },
        );
        let packages: Vec<(PathBuf, PackageId)> = vec![];
        let detail_cache: HashMap<String, osv::OsvVulnDetail> = HashMap::new();
        backfill_and_filter_vulns(&mut results, &packages, &detail_cache);
        // Orphan entry retained (not in packages → loop body skipped, retain preserves)
        assert_eq!(results.len(), 1);
    }

    // --- Cache integration ----------------------------------------------

    #[test]
    fn scan_vulns_with_cache_skips_cached_packages() {
        use std::cell::RefCell;
        let pkgs: Vec<(PathBuf, PackageId)> = vec![
            (PathBuf::from("/a"), pkg("requests", "2.31.0")),
            (PathBuf::from("/b"), pkg("flask", "2.0.0")),
            (PathBuf::from("/c"), pkg("django", "4.0.0")),
        ];
        let mut cache = cache::VulnCache::with_default_ttl();
        // Pre-populate cache for two of the three.
        cache.insert(
            &pkgs[0].1,
            &SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-CACHED".into(),
                    summary: "from cache".into(),
                    severity: None,
                    fix_version: None,
                }],
            },
        );
        cache.insert(&pkgs[1].1, &SecurityInfo { vulns: vec![] });

        let saw_ids: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        let out = scan_vulns_with_querier_and_cache(
            &pkgs,
            |ids| {
                saw_ids
                    .borrow_mut()
                    .push(ids.iter().map(|i| i.name.clone()).collect());
                Ok(osv::OsvResponse {
                    results: ids
                        .iter()
                        .map(|_| osv::OsvQueryResult { vulns: vec![] })
                        .collect(),
                })
            },
            Some(&mut cache),
        );

        let calls = saw_ids.borrow();
        assert_eq!(calls.len(), 1, "exactly one chunk for the misses");
        assert_eq!(
            calls[0],
            vec!["django".to_string()],
            "only the uncached pkg"
        );
        assert_eq!(out.unscanned_packages, 0);
        // Cached vulnerable package must show up in results.
        let cached_hit = out
            .results
            .get(&PathBuf::from("/a"))
            .expect("cache hit surfaced");
        assert_eq!(cached_hit.vulns[0].id, "CVE-CACHED");
        // Negative cache hit for /b → absent from results.
        assert!(!out.results.contains_key(&PathBuf::from("/b")));
    }

    #[test]
    fn scan_vulns_with_cache_all_hits_skips_network() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pkgs = vec![(PathBuf::from("/a"), pkg("x", "1.0"))];
        let mut cache = cache::VulnCache::with_default_ttl();
        cache.insert(&pkgs[0].1, &SecurityInfo { vulns: vec![] });

        let calls = AtomicUsize::new(0);
        let out = scan_vulns_with_querier_and_cache(
            &pkgs,
            |_ids| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(osv::OsvResponse { results: vec![] })
            },
            Some(&mut cache),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "querier never invoked");
        assert_eq!(out.unscanned_packages, 0);
        assert!(out.results.is_empty());
    }

    #[test]
    fn scan_vulns_with_cache_records_misses_into_cache() {
        let pkgs = vec![(PathBuf::from("/a"), pkg("clean-pkg", "1.0"))];
        let mut cache = cache::VulnCache::with_default_ttl();
        let out = scan_vulns_with_querier_and_cache(
            &pkgs,
            |_ids| {
                Ok(osv::OsvResponse {
                    results: vec![osv::OsvQueryResult { vulns: vec![] }],
                })
            },
            Some(&mut cache),
        );
        assert!(out.results.is_empty());
        assert!(
            cache.get(&pkgs[0].1).is_some(),
            "negative result must be cached"
        );
    }

    #[test]
    fn check_versions_with_cache_skips_cached_packages() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pkgs: Vec<(PathBuf, PackageId)> = vec![
            (PathBuf::from("/a"), pkg("requests", "2.31.0")),
            (PathBuf::from("/b"), pkg("flask", "2.0.0")),
        ];
        let mut cache = cache::VersionCache::with_default_ttl();
        // Pre-cache /a as outdated — should surface without hitting registry.
        cache.insert(
            &pkgs[0].1,
            &VersionInfo {
                current: "2.31.0".into(),
                latest: "2.32.0".into(),
                is_outdated: true,
            },
        );
        // Counter captured by the checker closure.
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);

        fn fake_checker(_pkg: &PackageId) -> Result<Option<String>, String> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(Some("2.1.0".into()))
        }

        let out = check_versions_with_cache_inner(&pkgs, fake_checker, Some(&mut cache));
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "checker called only for miss"
        );
        // Cached outdated entry present in results.
        let a = out.results.get(&PathBuf::from("/a")).expect("cache hit");
        assert_eq!(a.latest, "2.32.0");
        // /b got fresh check → now cached + present (2.0.0 < 2.1.0 => outdated).
        assert!(out.results.contains_key(&PathBuf::from("/b")));
        assert!(cache.get(&pkgs[1].1).is_some(), "miss got cached");
    }

    #[test]
    fn check_versions_with_cache_caches_up_to_date_as_negative() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.store(0, Ordering::SeqCst);
        fn up_to_date(pkg: &PackageId) -> Result<Option<String>, String> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(Some(pkg.version.clone()))
        }
        let pkgs = vec![(PathBuf::from("/a"), pkg("x", "1.0.0"))];
        let mut cache = cache::VersionCache::with_default_ttl();

        let out = check_versions_with_cache_inner(&pkgs, up_to_date, Some(&mut cache));
        let entry = out.results.get(&PathBuf::from("/a")).expect("present");
        assert!(!entry.is_outdated, "up-to-date flagged as current");
        assert!(cache.get(&pkgs[0].1).is_some(), "up-to-date cached");

        // Second call should skip the network entirely and replay the cache.
        let out2 = check_versions_with_cache_inner(&pkgs, up_to_date, Some(&mut cache));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "second call reuses cache");
        let entry2 = out2.results.get(&PathBuf::from("/a")).expect("cache hit");
        assert!(!entry2.is_outdated);
    }

    #[test]
    fn check_versions_with_cache_does_not_cache_when_unchecked_present() {
        // Failed lookups are absent from fresh.results, so they never get
        // cached — next run will retry. Verifies that invariant.
        fn fails(_pkg: &PackageId) -> Result<Option<String>, String> {
            Err("nope".into())
        }
        let pkgs = vec![(PathBuf::from("/a"), pkg("x", "1.0.0"))];
        let mut cache = cache::VersionCache::with_default_ttl();
        let out = check_versions_with_cache_inner(&pkgs, fails, Some(&mut cache));
        assert_eq!(out.unchecked_packages, 1);
        assert!(cache.get(&pkgs[0].1).is_none(), "no cache on failure");
    }

    #[test]
    fn scan_vulns_with_cache_failed_chunk_does_not_poison_cache() {
        let pkgs = vec![(PathBuf::from("/a"), pkg("p", "1.0"))];
        let mut cache = cache::VulnCache::with_default_ttl();
        let out = scan_vulns_with_querier_and_cache(
            &pkgs,
            |_ids| Err("network down".into()),
            Some(&mut cache),
        );
        assert_eq!(out.unscanned_packages, 1);
        assert!(
            cache.get(&pkgs[0].1).is_none(),
            "failed fetches must not cache"
        );
    }

    #[test]
    fn filter_keeps_active_vulns_removes_fixed() {
        let mut results = HashMap::new();
        results.insert(
            PathBuf::from("/test/pkg"),
            SecurityInfo {
                vulns: vec![
                    Vulnerability {
                        id: "CVE-fixed".into(),
                        summary: "already fixed".into(),
                        severity: None,
                        fix_version: Some("1.0.0".into()),
                    },
                    Vulnerability {
                        id: "CVE-active".into(),
                        summary: "still active".into(),
                        severity: None,
                        fix_version: Some("3.0.0".into()),
                    },
                ],
            },
        );

        let pkg_version = "2.0.0";
        for info in results.values_mut() {
            info.vulns
                .retain(|v| is_vuln_active(&v.fix_version, pkg_version));
        }
        results.retain(|_, info| !info.vulns.is_empty());

        assert_eq!(results.len(), 1);
        let info = results.get(&PathBuf::from("/test/pkg")).unwrap();
        assert_eq!(info.vulns.len(), 1);
        assert_eq!(info.vulns[0].id, "CVE-active");
    }

    #[test]
    fn is_vuln_active_with_go_v_prefixed_fix() {
        // Go proxy returns "v1.0.0" as fix version; normalize_version now strips leading 'v'.
        assert!(
            !is_vuln_active(&Some("v1.0.0".into()), "v1.0.0"),
            "same version is not vulnerable"
        );
        assert!(
            is_vuln_active(&Some("v2.0.0".into()), "v1.0.0"),
            "fix > installed means still vulnerable"
        );
    }
}
