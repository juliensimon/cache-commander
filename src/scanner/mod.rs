pub mod walker;

use crate::providers;
use crate::tree::node::TreeNode;
use std::path::PathBuf;
use std::sync::mpsc;

pub enum ScanRequest {
    ScanRoots(Vec<PathBuf>),
    ExpandNode(PathBuf),
    /// Walk given paths to discover packages, then query OSV.dev
    ScanVulns(Vec<PathBuf>),
    /// Walk given paths to discover packages, then query registries
    CheckVersions(Vec<PathBuf>),
}

pub enum ScanResult {
    RootsScanned(Vec<TreeNode>),
    ChildrenScanned(PathBuf, Vec<TreeNode>),
    SizeUpdated(PathBuf, u64),
    /// (packages_scanned, results)
    VulnsScanned(usize, std::collections::HashMap<PathBuf, crate::security::SecurityInfo>),
    /// (packages_checked, results)
    VersionsChecked(usize, std::collections::HashMap<PathBuf, crate::security::VersionInfo>),
}

/// Walk a set of root paths to find all identifiable packages.
/// Deduplicates by (ecosystem, name, version) — each unique package is returned once.
pub fn discover_packages(roots: &[PathBuf]) -> Vec<(PathBuf, crate::providers::PackageId)> {
    let mut seen = std::collections::HashSet::new();
    let mut packages = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        let walk = jwalk::WalkDir::new(root)
            .skip_hidden(false)
            .max_depth(6);
        for entry in walk.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            let kind = crate::providers::detect(&path);
            if let Some(id) = crate::providers::package_id(kind, &path) {
                let key = (id.ecosystem, id.name.clone(), id.version.clone());
                if seen.insert(key) {
                    packages.push((path.to_path_buf(), id));
                }
            }
        }
    }
    packages
}

pub fn start(
    result_tx: mpsc::Sender<ScanResult>,
) -> mpsc::Sender<ScanRequest> {
    let (request_tx, request_rx) = mpsc::channel::<ScanRequest>();

    std::thread::spawn(move || {
        while let Ok(request) = request_rx.recv() {
            match request {
                ScanRequest::ScanRoots(roots) => {
                    let mut nodes = Vec::new();
                    for root in &roots {
                        if !root.exists() {
                            continue;
                        }
                        let mut node = TreeNode::root(root.clone());
                        node.last_modified = root
                            .metadata()
                            .ok()
                            .and_then(|m| m.modified().ok());
                        nodes.push(node);
                    }
                    let _ = result_tx.send(ScanResult::RootsScanned(nodes));

                    for root in roots {
                        if !root.exists() {
                            continue;
                        }
                        let tx = result_tx.clone();
                        std::thread::spawn(move || {
                            let size = walker::dir_size(&root);
                            let _ = tx.send(ScanResult::SizeUpdated(root, size));
                        });
                    }
                }
                ScanRequest::ScanVulns(roots) => {
                    let tx = result_tx.clone();
                    std::thread::spawn(move || {
                        let packages = discover_packages(&roots);
                        let count = packages.len();
                        let results = crate::security::scan_vulns(&packages);
                        let _ = tx.send(ScanResult::VulnsScanned(count, results));
                    });
                }
                ScanRequest::CheckVersions(roots) => {
                    let tx = result_tx.clone();
                    std::thread::spawn(move || {
                        let packages = discover_packages(&roots);
                        let count = packages.len();
                        let results = crate::security::check_versions(&packages);
                        let _ = tx.send(ScanResult::VersionsChecked(count, results));
                    });
                }
                ScanRequest::ExpandNode(path) => {
                    let children_paths = walker::list_children(&path);
                    let mut children: Vec<TreeNode> = children_paths
                        .iter()
                        .map(|child_path| {
                            let mut node =
                                TreeNode::new(child_path.clone(), 0, None);
                            node.last_modified = child_path
                                .metadata()
                                .ok()
                                .and_then(|m| m.modified().ok());
                            node.kind = providers::detect(child_path);
                            if let Some(semantic) =
                                providers::semantic_name(node.kind, child_path)
                            {
                                node.name = semantic;
                            }
                            node
                        })
                        .collect();

                    let mut deferred: Vec<PathBuf> = Vec::new();
                    for (i, child_path) in children_paths.iter().enumerate() {
                        if let Some(size) = walker::quick_size(child_path) {
                            children[i].size = size;
                        } else {
                            deferred.push(child_path.clone());
                        }
                    }

                    let _ = result_tx
                        .send(ScanResult::ChildrenScanned(path.clone(), children));

                    for child_path in deferred {
                        let tx = result_tx.clone();
                        std::thread::spawn(move || {
                            let size = walker::dir_size(&child_path);
                            let _ = tx.send(ScanResult::SizeUpdated(child_path, size));
                        });
                    }
                }
            }
        }
    });

    request_tx
}
