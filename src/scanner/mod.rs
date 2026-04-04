pub mod walker;

use crate::providers;
use crate::tree::node::TreeNode;
use std::path::PathBuf;
use std::sync::mpsc;

pub enum ScanRequest {
    ScanRoots(Vec<PathBuf>),
    ExpandNode(PathBuf),
}

pub enum ScanResult {
    RootsScanned(Vec<TreeNode>),
    /// Children identified by parent path (not index — indices shift)
    ChildrenScanned(PathBuf, Vec<TreeNode>),
    /// Size update identified by path (safe even after tree mutations)
    SizeUpdated(PathBuf, u64),
}

pub fn start(
    result_tx: mpsc::Sender<ScanResult>,
) -> mpsc::Sender<ScanRequest> {
    let (request_tx, request_rx) = mpsc::channel::<ScanRequest>();

    std::thread::spawn(move || {
        while let Ok(request) = request_rx.recv() {
            match request {
                ScanRequest::ScanRoots(roots) => {
                    // Send roots immediately with size=0
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

                    // Spawn a background thread for each root's size computation
                    // so the scanner stays responsive to ExpandNode requests
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
                ScanRequest::ExpandNode(path) => {
                    // Send children immediately with metadata but size=0
                    let children_paths = walker::list_children(&path);
                    let children: Vec<TreeNode> = children_paths
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

                    let _ = result_tx
                        .send(ScanResult::ChildrenScanned(path.clone(), children));

                    // Spawn size computation for each child in background
                    for child_path in children_paths {
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
