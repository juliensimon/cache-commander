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

pub fn scan_vulns(packages: &[(PathBuf, PackageId)]) -> HashMap<PathBuf, SecurityInfo> {
    let mut results = HashMap::new();
    if packages.is_empty() {
        return results;
    }

    let ids: Vec<PackageId> = packages.iter().map(|(_, id)| id.clone()).collect();
    match osv::query_osv(&ids) {
        Ok(response) => {
            for (i, query_result) in response.results.iter().enumerate() {
                if i >= packages.len() {
                    break;
                }
                if !query_result.vulns.is_empty() {
                    let vulns = query_result
                        .vulns
                        .iter()
                        .map(|v| Vulnerability {
                            id: v.id.clone(),
                            summary: v.summary.clone().unwrap_or_default(),
                            severity: v.severity.first().map(|s| s.score.clone()),
                        })
                        .collect();
                    results.insert(packages[i].0.clone(), SecurityInfo { vulns });
                }
            }
        }
        Err(_) => {}
    }
    results
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
                        let is_outdated = latest != pkg.version;
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
