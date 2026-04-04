use std::sync::mpsc;
use std::time::Duration;

/// Helper to create a fake HuggingFace cache structure.
fn create_hf_cache(root: &std::path::Path) {
    let hf = root.join("huggingface");
    let hub = hf.join("hub");
    let model = hub.join("models--meta-llama--Llama-3.1-8B");
    std::fs::create_dir_all(model.join("snapshots/rev1")).unwrap();
    std::fs::create_dir_all(model.join("blobs")).unwrap();
    std::fs::write(model.join("blobs/sha256abc"), "fake model data").unwrap();

    let dataset = hub.join("datasets--squad--squad");
    std::fs::create_dir_all(&dataset).unwrap();

    let xet = hf.join("xet");
    std::fs::create_dir_all(&xet).unwrap();
    std::fs::write(xet.join("data.bin"), "xet data here").unwrap();
}

/// Helper to create a fake uv cache structure.
fn create_uv_cache(root: &std::path::Path) {
    let uv = root.join("uv");
    let archive = uv.join("archive-v0");
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::write(archive.join("requests-2.31.0.tar.gz"), "pkg").unwrap();
    std::fs::write(archive.join("flask-3.0.0.tar.gz"), "pkg").unwrap();

    let simple = uv.join("simple-v20");
    std::fs::create_dir_all(&simple).unwrap();
}

/// Helper to create a fake whisper cache structure.
fn create_whisper_cache(root: &std::path::Path) {
    let whisper = root.join("whisper");
    std::fs::create_dir_all(&whisper).unwrap();
    std::fs::write(whisper.join("large-v3.pt"), "model weights").unwrap();
    std::fs::write(whisper.join("tiny.pt"), "small model").unwrap();
}

#[test]
fn scanner_discovers_roots_and_computes_sizes() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());
    create_uv_cache(tmp.path());

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ScanRoots(vec![
            tmp.path().to_path_buf(),
        ]))
        .unwrap();

    // First message: roots with size=0 (immediate)
    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        cache_explorer::scanner::ScanResult::RootsScanned(nodes) => {
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].has_children);
        }
        _ => panic!("Expected RootsScanned"),
    }

    // Second message: size update
    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        cache_explorer::scanner::ScanResult::SizeUpdated(path, size) => {
            assert_eq!(path, tmp.path().to_path_buf());
            assert!(size > 0, "Root should have non-zero size");
        }
        _ => panic!("Expected SizeUpdated"),
    }
}

#[test]
fn scanner_expand_discovers_children_with_providers() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());
    create_uv_cache(tmp.path());
    create_whisper_cache(tmp.path());

    let cache_dir = tmp.path().to_path_buf();

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ExpandNode(cache_dir.clone()))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        cache_explorer::scanner::ScanResult::ChildrenScanned(parent_path, children) => {
            assert_eq!(parent_path, cache_dir);
            assert_eq!(children.len(), 3); // huggingface, uv, whisper

            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(names.contains(&"huggingface"), "Should find huggingface: {:?}", names);
            assert!(names.contains(&"uv"), "Should find uv: {:?}", names);
            assert!(names.contains(&"whisper"), "Should find whisper: {:?}", names);

            // Check kinds
            let hf = children.iter().find(|n| n.name == "huggingface").unwrap();
            assert_eq!(hf.kind, cache_explorer::tree::node::CacheKind::HuggingFace);
            let uv = children.iter().find(|n| n.name == "uv").unwrap();
            assert_eq!(uv.kind, cache_explorer::tree::node::CacheKind::Uv);
            let wh = children.iter().find(|n| n.name == "whisper").unwrap();
            assert_eq!(wh.kind, cache_explorer::tree::node::CacheKind::Whisper);

            // Children arrive with size=0 (async)
            for child in &children {
                assert_eq!(child.size, 0, "{} should start with size=0 (async)", child.name);
            }
        }
        _ => panic!("Expected ChildrenScanned"),
    }

    // Size updates arrive separately
    let mut sizes_received = 0;
    while let Ok(result) = result_rx.recv_timeout(Duration::from_secs(5)) {
        if let cache_explorer::scanner::ScanResult::SizeUpdated(_, size) = result {
            assert!(size > 0);
            sizes_received += 1;
            if sizes_received == 3 {
                break;
            }
        }
    }
    assert_eq!(sizes_received, 3, "Should receive 3 size updates");
}

#[test]
fn scanner_expand_huggingface_hub_shows_semantic_names() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());

    let hub_path = tmp.path().join("huggingface").join("hub");

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ExpandNode(hub_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        cache_explorer::scanner::ScanResult::ChildrenScanned(_, children) => {
            assert_eq!(children.len(), 2); // model + dataset

            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names.iter().any(|n| n.contains("meta-llama")),
                "Should show semantic model name: {:?}", names
            );
            assert!(
                names.iter().any(|n| n.contains("squad")),
                "Should show semantic dataset name: {:?}", names
            );
            assert!(
                !names.iter().any(|n| n.starts_with("models--")),
                "Should not show raw dir names: {:?}", names
            );
        }
        _ => panic!("Expected ChildrenScanned"),
    }
}

#[test]
fn scanner_expand_whisper_shows_model_names() {
    let tmp = tempfile::tempdir().unwrap();
    create_whisper_cache(tmp.path());

    let whisper_path = tmp.path().join("whisper");

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ExpandNode(whisper_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        cache_explorer::scanner::ScanResult::ChildrenScanned(_, children) => {
            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names.iter().any(|n| n.contains("Whisper") && n.contains("Large")),
                "Should show 'Whisper Large V3': {:?}", names
            );
            assert!(
                names.iter().any(|n| n.contains("Whisper") && n.contains("Tiny")),
                "Should show 'Whisper Tiny': {:?}", names
            );
        }
        _ => panic!("Expected ChildrenScanned"),
    }
}

#[test]
fn full_tree_workflow_expand_navigate_mark_delete() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());
    create_whisper_cache(tmp.path());

    let mut tree = cache_explorer::tree::state::TreeState::new(
        cache_explorer::config::SortField::Size,
        true,
    );

    let root = cache_explorer::tree::node::TreeNode::root(tmp.path().to_path_buf());
    tree.set_roots(vec![root]);
    assert_eq!(tree.visible.len(), 1);

    // Expand root
    let needs_load = tree.toggle_expand();
    assert!(needs_load.is_some());

    // Use scanner to get children
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ExpandNode(
            tmp.path().to_path_buf(),
        ))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    if let cache_explorer::scanner::ScanResult::ChildrenScanned(parent_path, children) = result {
        // Resolve parent by path (like the real app does)
        let parent_idx = tree.nodes.iter().position(|n| n.path == parent_path).unwrap();
        tree.insert_children(parent_idx, children);
    }

    assert!(tree.visible.len() >= 3, "Should have root + 2 children, got {}", tree.visible.len());

    tree.move_down();
    assert_eq!(tree.selected, 1);

    let selected_idx = tree.selected_node_index().unwrap();
    tree.toggle_mark();
    assert!(tree.marked.contains(&selected_idx));

    let selected_idx2 = tree.selected_node_index().unwrap();
    tree.toggle_mark();
    assert!(tree.marked.contains(&selected_idx2));
    assert_eq!(tree.marked.len(), 2);
}

// === Duplicate insertion guard tests ===

#[test]
fn insert_children_twice_does_not_duplicate() {
    let mut tree = cache_explorer::tree::state::TreeState::new(
        cache_explorer::config::SortField::Size,
        true,
    );

    let root = make_test_node("root", 0, None, true);
    tree.set_roots(vec![root]);
    tree.expanded.insert(0);

    tree.insert_children(0, vec![
        make_test_node("child-a", 1, Some(0), true),
        make_test_node("child-b", 1, Some(0), true),
    ]);
    assert_eq!(tree.nodes.len(), 3);

    // Second insert should be ignored
    tree.insert_children(0, vec![
        make_test_node("child-c", 1, Some(0), true),
    ]);
    assert_eq!(tree.nodes.len(), 3, "Should NOT duplicate children");
}

#[test]
fn size_update_by_path_finds_correct_node_after_tree_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let child_a_path = tmp.path().join("aaa");
    let child_b_path = tmp.path().join("bbb");
    std::fs::create_dir_all(&child_a_path).unwrap();
    std::fs::create_dir_all(&child_b_path).unwrap();

    let mut tree = cache_explorer::tree::state::TreeState::new(
        cache_explorer::config::SortField::Size,
        true,
    );

    tree.set_roots(vec![make_test_node_with_path("root", tmp.path().to_path_buf(), 0, None)]);
    tree.expanded.insert(0);
    tree.insert_children(0, vec![
        make_test_node_with_path("aaa", child_a_path.clone(), 1, Some(0)),
        make_test_node_with_path("bbb", child_b_path.clone(), 1, Some(0)),
    ]);

    assert_eq!(tree.nodes[1].size, 0);
    assert_eq!(tree.nodes[2].size, 0);

    if let Some(node) = tree.nodes.iter_mut().find(|n| n.path == child_b_path) {
        node.size = 5000;
    }
    if let Some(node) = tree.nodes.iter_mut().find(|n| n.path == child_a_path) {
        node.size = 3000;
    }

    let aaa = tree.nodes.iter().find(|n| n.path == child_a_path).unwrap();
    assert_eq!(aaa.size, 3000);
    let bbb = tree.nodes.iter().find(|n| n.path == child_b_path).unwrap();
    assert_eq!(bbb.size, 5000);
}

#[test]
fn size_update_after_removing_node_doesnt_corrupt() {
    let tmp = tempfile::tempdir().unwrap();
    let child_a = tmp.path().join("aaa");
    let child_b = tmp.path().join("bbb");
    let child_c = tmp.path().join("ccc");
    std::fs::create_dir_all(&child_a).unwrap();
    std::fs::create_dir_all(&child_b).unwrap();
    std::fs::create_dir_all(&child_c).unwrap();

    let mut tree = cache_explorer::tree::state::TreeState::new(
        cache_explorer::config::SortField::Size,
        true,
    );

    tree.set_roots(vec![make_test_node_with_path("root", tmp.path().to_path_buf(), 0, None)]);
    tree.expanded.insert(0);
    tree.insert_children(0, vec![
        make_test_node_with_path("aaa", child_a.clone(), 1, Some(0)),
        make_test_node_with_path("bbb", child_b.clone(), 1, Some(0)),
        make_test_node_with_path("ccc", child_c.clone(), 1, Some(0)),
    ]);

    tree.remove_nodes(&[2]);
    assert_eq!(tree.nodes.len(), 3);

    let found = tree.nodes.iter_mut().find(|n| n.path == child_b);
    assert!(found.is_none(), "Removed node should not be found");

    if let Some(node) = tree.nodes.iter_mut().find(|n| n.path == child_c) {
        node.size = 9999;
    }
    let ccc = tree.nodes.iter().find(|n| n.path == child_c).unwrap();
    assert_eq!(ccc.size, 9999);
}

#[test]
fn async_expand_returns_children_with_zero_size() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("sub1")).unwrap();
    std::fs::write(tmp.path().join("sub1/file.txt"), "some data here").unwrap();
    std::fs::create_dir_all(tmp.path().join("sub2")).unwrap();

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ExpandNode(tmp.path().to_path_buf()))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        cache_explorer::scanner::ScanResult::ChildrenScanned(_, children) => {
            assert_eq!(children.len(), 2);
            for child in &children {
                assert_eq!(child.size, 0, "Children should arrive with size=0");
            }
        }
        _ => panic!("Expected ChildrenScanned first"),
    }

    let mut sizes = std::collections::HashMap::new();
    while let Ok(result) = result_rx.recv_timeout(Duration::from_secs(5)) {
        if let cache_explorer::scanner::ScanResult::SizeUpdated(path, size) = result {
            sizes.insert(path, size);
            if sizes.len() == 2 {
                break;
            }
        }
    }
    assert_eq!(sizes.len(), 2, "Should get 2 size updates");

    let sub1_size = sizes.get(&tmp.path().join("sub1")).unwrap();
    assert!(*sub1_size > 0, "sub1 should have non-zero size");
}

#[test]
fn scanner_expand_and_size_update_full_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());

    let mut tree = cache_explorer::tree::state::TreeState::new(
        cache_explorer::config::SortField::Size,
        true,
    );
    tree.set_roots(vec![cache_explorer::tree::node::TreeNode::root(
        tmp.path().to_path_buf(),
    )]);
    tree.expanded.insert(0);

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = cache_explorer::scanner::start(result_tx);

    scan_tx
        .send(cache_explorer::scanner::ScanRequest::ExpandNode(tmp.path().to_path_buf()))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    if let cache_explorer::scanner::ScanResult::ChildrenScanned(parent_path, children) = result {
        let count = children.len();
        let parent_idx = tree.nodes.iter().position(|n| n.path == parent_path).unwrap();
        tree.insert_children(parent_idx, children);
        assert!(tree.nodes.len() > 1);

        for i in 1..=count {
            assert_eq!(tree.nodes[i].size, 0);
        }

        let mut updates = 0;
        while let Ok(result) = result_rx.recv_timeout(Duration::from_secs(5)) {
            if let cache_explorer::scanner::ScanResult::SizeUpdated(path, size) = result {
                if let Some(node) = tree.nodes.iter_mut().find(|n| n.path == path) {
                    node.size = size;
                }
                updates += 1;
                if updates == count {
                    break;
                }
            }
        }
        assert_eq!(updates, count);

        let hf = tree.nodes.iter().find(|n| n.name == "huggingface").unwrap();
        assert!(hf.size > 0, "huggingface should have size after update");
    }
}

/// Test that expanding a node while sort-triggered reorders are happening
/// still inserts children under the correct parent (path-based, not index-based).
#[test]
fn expand_is_correct_after_sort_reorder() {
    let tmp = tempfile::tempdir().unwrap();
    let root_path = tmp.path().to_path_buf();
    let child_a = tmp.path().join("aaa");
    let child_b = tmp.path().join("bbb");
    std::fs::create_dir_all(&child_a).unwrap();
    std::fs::create_dir_all(&child_b).unwrap();
    std::fs::create_dir_all(child_a.join("nested")).unwrap();

    let mut tree = cache_explorer::tree::state::TreeState::new(
        cache_explorer::config::SortField::Size,
        true, // desc
    );
    tree.set_roots(vec![make_test_node_with_path("root", root_path.clone(), 0, None)]);
    tree.expanded.insert(0);
    tree.insert_children(0, vec![
        make_test_node_with_path("aaa", child_a.clone(), 1, Some(0)),
        make_test_node_with_path("bbb", child_b.clone(), 1, Some(0)),
    ]);

    // aaa is at index 1, bbb at index 2
    assert_eq!(tree.nodes[1].name, "aaa");
    assert_eq!(tree.nodes[2].name, "bbb");

    // Simulate size update that triggers re-sort: bbb becomes larger
    tree.nodes[2].size = 9000; // bbb
    tree.nodes[1].size = 1000; // aaa
    tree.sort_children(0);

    // After sort (desc by size), bbb should come first
    assert_eq!(tree.nodes[1].name, "bbb", "bbb should be first after sort");
    assert_eq!(tree.nodes[2].name, "aaa", "aaa should be second after sort");

    // Now expand "aaa" — find it by PATH not by stale index
    let aaa_idx = tree.nodes.iter().position(|n| n.path == child_a).unwrap();
    assert_eq!(aaa_idx, 2, "aaa is now at index 2 after sort");
    tree.expanded.insert(aaa_idx);

    // Simulate ChildrenScanned arriving with parent_path
    let nested_children = vec![
        make_test_node_with_path("nested", child_a.join("nested"), 2, None),
    ];
    // App resolves parent by path:
    let parent_idx = tree.nodes.iter().position(|n| n.path == child_a).unwrap();
    tree.nodes[parent_idx].children_loaded = false; // allow insertion
    tree.insert_children(parent_idx, nested_children);

    // Verify nested is under aaa, not bbb
    let nested_node = tree.nodes.iter().find(|n| n.name == "nested").unwrap();
    assert_eq!(nested_node.parent, Some(aaa_idx), "nested should be child of aaa");
}

// === Test helpers ===

fn make_test_node(
    name: &str,
    depth: u16,
    parent: Option<usize>,
    has_children: bool,
) -> cache_explorer::tree::node::TreeNode {
    cache_explorer::tree::node::TreeNode {
        path: std::path::PathBuf::from(format!("/test/{name}")),
        name: name.to_string(),
        size: 0,
        depth,
        parent,
        has_children,
        kind: cache_explorer::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: depth == 0,
        children_loaded: false,
    }
}

fn make_test_node_with_path(
    name: &str,
    path: std::path::PathBuf,
    depth: u16,
    parent: Option<usize>,
) -> cache_explorer::tree::node::TreeNode {
    cache_explorer::tree::node::TreeNode {
        path,
        name: name.to_string(),
        size: 0,
        depth,
        parent,
        has_children: true,
        kind: cache_explorer::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: depth == 0,
        children_loaded: false,
    }
}
