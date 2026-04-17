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
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ScanRoots(vec![
            tmp.path().to_path_buf(),
        ]))
        .unwrap();

    // First message: roots with size=0 (immediate)
    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::RootsScanned(nodes) => {
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].has_children);
        }
        _ => panic!("Expected RootsScanned"),
    }

    // Second message: size update
    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::SizeUpdated(path, size) => {
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
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(cache_dir.clone()))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(parent_path, children) => {
            assert_eq!(parent_path, cache_dir);
            assert_eq!(children.len(), 3); // huggingface, uv, whisper

            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names.contains(&"huggingface"),
                "Should find huggingface: {:?}",
                names
            );
            assert!(names.contains(&"uv"), "Should find uv: {:?}", names);
            assert!(
                names.contains(&"whisper"),
                "Should find whisper: {:?}",
                names
            );

            // Check kinds
            let hf = children.iter().find(|n| n.name == "huggingface").unwrap();
            assert_eq!(hf.kind, ccmd::tree::node::CacheKind::HuggingFace);
            let uv = children.iter().find(|n| n.name == "uv").unwrap();
            assert_eq!(uv.kind, ccmd::tree::node::CacheKind::Uv);
            let wh = children.iter().find(|n| n.name == "whisper").unwrap();
            assert_eq!(wh.kind, ccmd::tree::node::CacheKind::Whisper);

            // Small children get instant sizes via quick_size;
            // large ones arrive with size=0 and get async updates
        }
        _ => panic!("Expected ChildrenScanned"),
    }

    // Small test fixtures get instant sizes via quick_size,
    // so no SizeUpdated messages expected for this test
}

#[test]
fn scanner_expand_huggingface_hub_shows_semantic_names() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());

    let hub_path = tmp.path().join("huggingface").join("hub");

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(hub_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(_, children) => {
            assert_eq!(children.len(), 2); // model + dataset

            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names.iter().any(|n| n.contains("meta-llama")),
                "Should show semantic model name: {:?}",
                names
            );
            assert!(
                names.iter().any(|n| n.contains("squad")),
                "Should show semantic dataset name: {:?}",
                names
            );
            assert!(
                !names.iter().any(|n| n.starts_with("models--")),
                "Should not show raw dir names: {:?}",
                names
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
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(whisper_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(_, children) => {
            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names
                    .iter()
                    .any(|n| n.contains("Whisper") && n.contains("Large")),
                "Should show 'Whisper Large V3': {:?}",
                names
            );
            assert!(
                names
                    .iter()
                    .any(|n| n.contains("Whisper") && n.contains("Tiny")),
                "Should show 'Whisper Tiny': {:?}",
                names
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

    let mut tree = ccmd::tree::state::TreeState::new(ccmd::config::SortField::Size, true);

    let root = ccmd::tree::node::TreeNode::root(tmp.path().to_path_buf());
    tree.set_roots(vec![root]);
    assert_eq!(tree.visible.len(), 1);

    // Expand root
    let needs_load = tree.toggle_expand();
    assert!(needs_load.is_some());

    // Use scanner to get children
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(
            tmp.path().to_path_buf(),
        ))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    if let ccmd::scanner::ScanResult::ChildrenScanned(parent_path, children) = result {
        // Resolve parent by path (like the real app does)
        let parent_idx = tree
            .nodes
            .iter()
            .position(|n| n.path == parent_path)
            .unwrap();
        tree.insert_children(parent_idx, children);
    }

    assert!(
        tree.visible.len() >= 3,
        "Should have root + 2 children, got {}",
        tree.visible.len()
    );

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
    let mut tree = ccmd::tree::state::TreeState::new(ccmd::config::SortField::Size, true);

    let root = make_test_node("root", 0, None, true);
    tree.set_roots(vec![root]);
    tree.expanded.insert(0);

    tree.insert_children(
        0,
        vec![
            make_test_node("child-a", 1, Some(0), true),
            make_test_node("child-b", 1, Some(0), true),
        ],
    );
    assert_eq!(tree.nodes.len(), 3);

    // Second insert should be ignored
    tree.insert_children(0, vec![make_test_node("child-c", 1, Some(0), true)]);
    assert_eq!(tree.nodes.len(), 3, "Should NOT duplicate children");
}

#[test]
fn size_update_by_path_finds_correct_node_after_tree_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let child_a_path = tmp.path().join("aaa");
    let child_b_path = tmp.path().join("bbb");
    std::fs::create_dir_all(&child_a_path).unwrap();
    std::fs::create_dir_all(&child_b_path).unwrap();

    let mut tree = ccmd::tree::state::TreeState::new(ccmd::config::SortField::Size, true);

    tree.set_roots(vec![make_test_node_with_path(
        "root",
        tmp.path().to_path_buf(),
        0,
        None,
    )]);
    tree.expanded.insert(0);
    tree.insert_children(
        0,
        vec![
            make_test_node_with_path("aaa", child_a_path.clone(), 1, Some(0)),
            make_test_node_with_path("bbb", child_b_path.clone(), 1, Some(0)),
        ],
    );

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

    let mut tree = ccmd::tree::state::TreeState::new(ccmd::config::SortField::Size, true);

    tree.set_roots(vec![make_test_node_with_path(
        "root",
        tmp.path().to_path_buf(),
        0,
        None,
    )]);
    tree.expanded.insert(0);
    tree.insert_children(
        0,
        vec![
            make_test_node_with_path("aaa", child_a.clone(), 1, Some(0)),
            make_test_node_with_path("bbb", child_b.clone(), 1, Some(0)),
            make_test_node_with_path("ccc", child_c.clone(), 1, Some(0)),
        ],
    );

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
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(
            tmp.path().to_path_buf(),
        ))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(_, children) => {
            assert_eq!(children.len(), 2);
            // Small dirs get instant sizes via quick_size
            let sub1 = children
                .iter()
                .find(|c| c.path == tmp.path().join("sub1"))
                .unwrap();
            assert!(
                sub1.size > 0,
                "sub1 should have instant size via quick_size"
            );
        }
        _ => panic!("Expected ChildrenScanned first"),
    }
}

#[test]
fn scanner_expand_and_size_update_full_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    create_hf_cache(tmp.path());

    let mut tree = ccmd::tree::state::TreeState::new(ccmd::config::SortField::Size, true);
    tree.set_roots(vec![ccmd::tree::node::TreeNode::root(
        tmp.path().to_path_buf(),
    )]);
    tree.expanded.insert(0);

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(
            tmp.path().to_path_buf(),
        ))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    if let ccmd::scanner::ScanResult::ChildrenScanned(parent_path, children) = result {
        let parent_idx = tree
            .nodes
            .iter()
            .position(|n| n.path == parent_path)
            .unwrap();
        tree.insert_children(parent_idx, children);
        assert!(tree.nodes.len() > 1);

        // Small dirs get instant sizes via quick_size, large ones come via SizeUpdated
        // Drain any remaining size updates
        while let Ok(result) = result_rx.recv_timeout(Duration::from_secs(2)) {
            if let ccmd::scanner::ScanResult::SizeUpdated(path, size) = result
                && let Some(node) = tree.nodes.iter_mut().find(|n| n.path == path)
            {
                node.size = size;
            }
        }

        let hf = tree.nodes.iter().find(|n| n.name == "huggingface").unwrap();
        assert!(hf.size > 0, "huggingface should have size");
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

    let mut tree = ccmd::tree::state::TreeState::new(
        ccmd::config::SortField::Size,
        true, // desc
    );
    tree.set_roots(vec![make_test_node_with_path(
        "root",
        root_path.clone(),
        0,
        None,
    )]);
    tree.expanded.insert(0);
    tree.insert_children(
        0,
        vec![
            make_test_node_with_path("aaa", child_a.clone(), 1, Some(0)),
            make_test_node_with_path("bbb", child_b.clone(), 1, Some(0)),
        ],
    );

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
    let nested_children = vec![make_test_node_with_path(
        "nested",
        child_a.join("nested"),
        2,
        None,
    )];
    // App resolves parent by path:
    let parent_idx = tree.nodes.iter().position(|n| n.path == child_a).unwrap();
    tree.nodes[parent_idx].children_loaded = false; // allow insertion
    tree.insert_children(parent_idx, nested_children);

    // Verify nested is under aaa, not bbb
    let nested_node = tree.nodes.iter().find(|n| n.name == "nested").unwrap();
    assert_eq!(
        nested_node.parent,
        Some(aaa_idx),
        "nested should be child of aaa"
    );
}

// === Test helpers ===

fn make_test_node(
    name: &str,
    depth: u16,
    parent: Option<usize>,
    has_children: bool,
) -> ccmd::tree::node::TreeNode {
    ccmd::tree::node::TreeNode {
        path: std::path::PathBuf::from(format!("/test/{name}")),
        name: name.to_string(),
        size: 0,
        depth,
        parent,
        has_children,
        kind: ccmd::tree::node::CacheKind::Unknown,
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
) -> ccmd::tree::node::TreeNode {
    ccmd::tree::node::TreeNode {
        path,
        name: name.to_string(),
        size: 0,
        depth,
        parent,
        has_children: true,
        kind: ccmd::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: depth == 0,
        children_loaded: false,
    }
}

#[test]
fn discover_packages_finds_uv_dist_info() {
    let tmp = tempfile::tempdir().unwrap();
    // Each hash dir is a separate venv with one primary package
    let hash1 = tmp.path().join("uv/archive-v0/hash1");
    let hash2 = tmp.path().join("uv/archive-v0/hash2");
    std::fs::create_dir_all(hash1.join("urllib3-1.26.5.dist-info")).unwrap();
    std::fs::create_dir_all(hash2.join("requests-2.25.0.dist-info")).unwrap();

    let packages = ccmd::scanner::discover_packages(&[tmp.path().to_path_buf()]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"urllib3"),
        "Should find urllib3: {:?}",
        names
    );
    assert!(
        names.contains(&"requests"),
        "Should find requests: {:?}",
        names
    );
    assert_eq!(packages.len(), 2);
}

#[cfg(feature = "e2e")]
#[test]
fn osv_query_finds_urllib3_vulns() {
    // Hits the real OSV.dev API — gated behind the `e2e` feature so the
    // default test suite stays deterministic and offline-safe.
    let packages = vec![ccmd::providers::PackageId {
        ecosystem: "PyPI",
        name: "urllib3".to_string(),
        version: "1.26.5".to_string(),
    }];

    let resp = ccmd::security::osv::query_osv(&packages)
        .expect("OSV query failed — network required for e2e test");
    assert_eq!(resp.results.len(), 1);
    let vulns = &resp.results[0].vulns;
    assert!(
        !vulns.is_empty(),
        "urllib3 1.26.5 should have known vulns, got 0"
    );
}

/// Helper to create a fake Yarn Berry cache structure.
fn create_yarn_berry_cache(root: &std::path::Path) {
    let yarn_cache = root.join(".yarn/cache");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    std::fs::write(
        yarn_cache.join("lodash-npm-4.17.21-6382d821f21d.zip"),
        "fake zip contents",
    )
    .unwrap();
    std::fs::write(
        yarn_cache.join("@babel-core-npm-7.24.0-abc123def456.zip"),
        "fake zip contents",
    )
    .unwrap();
}

/// Helper to create a fake Yarn Classic cache structure.
fn create_yarn_classic_cache(root: &std::path::Path) {
    let yarn_cache = root.join(".yarn-cache/v6");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    // Real Yarn Classic format: directories named npm-<name>-<version>-<hash>-integrity
    std::fs::create_dir_all(
        yarn_cache.join("npm-express-4.21.0-abcdef123456abcdef123456abcdef123456abcd-integrity"),
    )
    .unwrap();
}

/// Helper to create a fake pnpm cache structure.
fn create_pnpm_cache(root: &std::path::Path) {
    // Virtual store
    let pnpm_vs = root.join("node_modules/.pnpm");
    let lodash = pnpm_vs.join("lodash@4.17.21/node_modules/lodash");
    std::fs::create_dir_all(&lodash).unwrap();
    std::fs::write(lodash.join("index.js"), "module.exports = {}").unwrap();

    let babel = pnpm_vs.join("@babel+core@7.24.0/node_modules/@babel/core");
    std::fs::create_dir_all(&babel).unwrap();
    std::fs::write(babel.join("index.js"), "module.exports = {}").unwrap();

    // Content store
    let store = root.join(".pnpm-store/v3/files/ab");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("cd1234abcdef"), "blob content").unwrap();
}

/// Create a fake npx cache with node_modules for npm scanning tests.
fn create_npx_cache(root: &std::path::Path) {
    // Root must be named .npm for detect() to identify children as CacheKind::Npm
    let npx = root.join(".npm/_npx/abc123");
    std::fs::create_dir_all(&npx).unwrap();
    std::fs::write(
        npx.join("package.json"),
        r#"{"dependencies":{"express":"^4"},"_npx":{"packages":["express"]}}"#,
    )
    .unwrap();

    // Direct dependency
    let express = npx.join("node_modules/express");
    std::fs::create_dir_all(&express).unwrap();
    std::fs::write(
        express.join("package.json"),
        r#"{"name":"express","version":"4.21.0","scripts":{"test":"mocha"}}"#,
    )
    .unwrap();

    // Transitive dependency with install script
    let native = npx.join("node_modules/express/node_modules/native-addon");
    std::fs::create_dir_all(&native).unwrap();
    std::fs::write(
        native.join("package.json"),
        r#"{"name":"native-addon","version":"1.0.0","scripts":{"postinstall":"node-gyp rebuild"}}"#,
    )
    .unwrap();

    // Transitive dependency without install script
    let qs = npx.join("node_modules/qs");
    std::fs::create_dir_all(&qs).unwrap();
    std::fs::write(
        qs.join("package.json"),
        r#"{"name":"qs","version":"6.11.0","scripts":{"test":"tape"}}"#,
    )
    .unwrap();
}

#[test]
fn npm_discover_packages_finds_node_modules() {
    let tmp = tempfile::tempdir().unwrap();
    create_npx_cache(tmp.path());

    let packages = ccmd::scanner::discover_packages(&[tmp.path().join(".npm")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"express"),
        "Should find express: {:?}",
        names
    );
    assert!(names.contains(&"qs"), "Should find qs: {:?}", names);
    assert!(
        names.contains(&"native-addon"),
        "Should find native-addon: {:?}",
        names
    );
    assert_eq!(
        packages
            .iter()
            .filter(|(_, id)| id.ecosystem == "npm")
            .count(),
        3
    );
}

#[test]
fn npm_install_script_detection() {
    let tmp = tempfile::tempdir().unwrap();
    create_npx_cache(tmp.path());

    let native = tmp
        .path()
        .join(".npm/_npx/abc123/node_modules/express/node_modules/native-addon");
    let meta = ccmd::providers::metadata(ccmd::tree::node::CacheKind::Npm, &native);

    let scripts_field = meta.iter().find(|f| f.label.contains("Scripts"));
    assert!(
        scripts_field.is_some(),
        "Should detect install scripts: {:?}",
        meta
    );
    assert!(scripts_field.unwrap().value.contains("postinstall"));
}

#[test]
fn npm_dep_depth_in_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    create_npx_cache(tmp.path());

    // Direct dep
    let express = tmp.path().join(".npm/_npx/abc123/node_modules/express");
    let meta = ccmd::providers::metadata(ccmd::tree::node::CacheKind::Npm, &express);
    let depth_field = meta.iter().find(|f| f.label == "Dep depth");
    assert!(depth_field.is_some(), "Should show dep depth: {:?}", meta);
    assert_eq!(depth_field.unwrap().value, "direct");

    // Transitive dep
    let native = tmp
        .path()
        .join(".npm/_npx/abc123/node_modules/express/node_modules/native-addon");
    let meta = ccmd::providers::metadata(ccmd::tree::node::CacheKind::Npm, &native);
    let depth_field = meta.iter().find(|f| f.label == "Dep depth");
    assert!(depth_field.is_some());
    assert!(depth_field.unwrap().value.contains("transitive"));
}

#[test]
fn yarn_discover_packages_finds_berry_zips() {
    let tmp = tempfile::tempdir().unwrap();
    create_yarn_berry_cache(tmp.path());

    let packages = ccmd::scanner::discover_packages(&[tmp.path().join(".yarn")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(names.contains(&"lodash"), "Should find lodash: {:?}", names);
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {:?}",
        names
    );
    assert_eq!(
        packages
            .iter()
            .filter(|(_, id)| id.ecosystem == "npm")
            .count(),
        2
    );
}

#[test]
fn yarn_discover_packages_finds_classic_cache() {
    let tmp = tempfile::tempdir().unwrap();
    create_yarn_classic_cache(tmp.path());

    let packages = ccmd::scanner::discover_packages(&[tmp.path().join(".yarn-cache")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"express"),
        "Should find express: {:?}",
        names
    );
}

#[test]
fn pnpm_discover_packages_finds_virtual_store() {
    let tmp = tempfile::tempdir().unwrap();
    create_pnpm_cache(tmp.path());

    let packages = ccmd::scanner::discover_packages(&[tmp.path().join("node_modules/.pnpm")]);

    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(names.contains(&"lodash"), "Should find lodash: {:?}", names);
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {:?}",
        names
    );
}

#[test]
fn pnpm_content_store_returns_no_packages() {
    let tmp = tempfile::tempdir().unwrap();
    create_pnpm_cache(tmp.path());

    let packages = ccmd::scanner::discover_packages(&[tmp.path().join(".pnpm-store")]);

    assert_eq!(packages.len(), 0, "Store blobs should not yield packages");
}

#[test]
fn scanner_expand_yarn_berry_shows_semantic_names() {
    let tmp = tempfile::tempdir().unwrap();
    create_yarn_berry_cache(tmp.path());

    let cache_path = tmp.path().join(".yarn/cache");

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(cache_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(_, children) => {
            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names
                    .iter()
                    .any(|n| n.contains("lodash") && n.contains("4.17.21")),
                "Should show 'lodash 4.17.21': {:?}",
                names
            );
            assert!(
                names.iter().any(|n| n.contains("@babel/core")),
                "Should show '@babel/core 7.24.0': {:?}",
                names
            );
            for child in &children {
                assert_eq!(
                    child.kind,
                    ccmd::tree::node::CacheKind::Yarn,
                    "All children should be detected as Yarn: {:?}",
                    child.name
                );
            }
        }
        _ => panic!("Expected ChildrenScanned"),
    }
}

#[test]
fn scanner_expand_pnpm_virtual_store_shows_semantic_names() {
    let tmp = tempfile::tempdir().unwrap();
    create_pnpm_cache(tmp.path());

    let pnpm_path = tmp.path().join("node_modules/.pnpm");

    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx);

    scan_tx
        .send(ccmd::scanner::ScanRequest::ExpandNode(pnpm_path))
        .unwrap();

    let result = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match result {
        ccmd::scanner::ScanResult::ChildrenScanned(_, children) => {
            let names: Vec<&str> = children.iter().map(|n| n.name.as_str()).collect();
            assert!(
                names
                    .iter()
                    .any(|n| n.contains("lodash") && n.contains("4.17.21")),
                "Should show 'lodash 4.17.21': {:?}",
                names
            );
            assert!(
                names.iter().any(|n| n.contains("@babel/core")),
                "Should show '@babel/core 7.24.0': {:?}",
                names
            );
            for child in &children {
                assert_eq!(
                    child.kind,
                    ccmd::tree::node::CacheKind::Pnpm,
                    "All children should be detected as Pnpm: {:?}",
                    child.name
                );
            }
        }
        _ => panic!("Expected ChildrenScanned"),
    }
}

#[test]
fn dedup_across_npm_and_yarn_caches() {
    let tmp = tempfile::tempdir().unwrap();

    // npm: express via node_modules
    let npm_dir = tmp.path().join(".npm/_npx/abc/node_modules/express");
    std::fs::create_dir_all(&npm_dir).unwrap();
    std::fs::write(
        npm_dir.join("package.json"),
        r#"{"name":"express","version":"4.21.0"}"#,
    )
    .unwrap();

    // yarn: express via berry zip
    let yarn_cache = tmp.path().join(".yarn/cache");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    std::fs::write(yarn_cache.join("express-npm-4.21.0-abcdef123456.zip"), "z").unwrap();

    let packages = ccmd::scanner::discover_packages(&[tmp.path().to_path_buf()]);

    let express_count = packages
        .iter()
        .filter(|(_, id)| id.name == "express" && id.version == "4.21.0")
        .count();
    assert_eq!(
        express_count, 1,
        "express@4.21.0 should be deduplicated across npm and yarn"
    );
}
