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

/// Returns true if a vulnerability is still active (not fixed) for the given package version.
fn is_vuln_active(fix_version: &Option<String>, pkg_version: &str) -> bool {
    match fix_version {
        Some(fix) if !fix.is_empty() => !osv::version_lte(fix, pkg_version),
        _ => true, // unknown or empty fix = assume still affected
    }
}

pub fn scan_vulns(packages: &[(PathBuf, PackageId)]) -> HashMap<PathBuf, SecurityInfo> {
    let mut results = HashMap::new();
    if packages.is_empty() {
        return results;
    }

    // OSV batch API works best with chunks of ~100 packages
    let mut vuln_ids_to_fetch: Vec<String> = Vec::new();

    for chunk in packages.chunks(100) {
        let ids: Vec<PackageId> = chunk.iter().map(|(_, id)| id.clone()).collect();
        let response = match osv::query_osv(&ids) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("OSV batch query failed for chunk: {e}");
                continue;
            }
        };

        for (i, query_result) in response.results.iter().enumerate() {
            if i >= chunk.len() {
                break;
            }
            if !query_result.vulns.is_empty() {
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
                results.insert(chunk[i].0.clone(), SecurityInfo { vulns });
            }
        }
    }

    // Fetch fix versions from detail endpoint
    let detail_cache = fetch_fix_versions(&vuln_ids_to_fetch);

    // Backfill fix_version and filter out vulns already fixed by installed version
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

    results
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
                    if let Ok(detail) = osv::fetch_vuln_detail(&id) {
                        cache.lock().unwrap().insert(id, detail);
                    }
                })
            })
            .collect();
        for handle in handles {
            let _ = handle.join();
        }
    }

    Arc::try_unwrap(cache).unwrap().into_inner().unwrap()
}

pub fn check_versions(packages: &[(PathBuf, PackageId)]) -> HashMap<PathBuf, VersionInfo> {
    use std::sync::{Arc, Mutex};

    let results = Arc::new(Mutex::new(HashMap::new()));

    // Process in chunks of 8 for bounded parallelism
    for chunk in packages.chunks(8) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|(path, pkg)| {
                let path = path.clone();
                let pkg = pkg.clone();
                let results = Arc::clone(&results);
                std::thread::spawn(move || {
                    if let Ok(Some(latest)) = registry::check_latest(&pkg) {
                        let is_outdated = osv::compare_versions(&pkg.version, &latest)
                            == std::cmp::Ordering::Less;
                        results.lock().unwrap().insert(
                            path,
                            VersionInfo {
                                current: pkg.version.clone(),
                                latest,
                                is_outdated,
                            },
                        );
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }
    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
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
}
