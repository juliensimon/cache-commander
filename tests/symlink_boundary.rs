//! Symlinks below a cache root are never entered, sized or read through
//! (#92, #93).
//!
//! A cache is data other tools wrote. A link in it can point anywhere, so
//! following one discloses what is outside the root (package coordinates that
//! are then sent to OSV, sizes, listings) and, through links back at the
//! root, can walk the same tree again and again. The rule: a link is a leaf. A
//! root that is itself a link is still followed, because relocating a cache
//! behind one is common and the user named that root.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ccmd::scanner::{ScanRequest, ScanResult};
use ccmd::tree::node::TreeNode;

/// An npm package directory with a `package.json`, under a path `detect`
/// recognises (`.npm/_npx/<hash>/node_modules/<name>`).
fn npm_package(dir: &Path, name: &str, version: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
}

fn names(packages: &[(PathBuf, ccmd::providers::PackageId)]) -> Vec<String> {
    packages.iter().map(|(_, id)| id.name.clone()).collect()
}

#[test]
fn discovery_does_not_report_a_package_reached_through_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    let outside = tmp.join("outside");
    npm_package(&outside.join("secret-internal"), "secret-internal", "9.9.9");

    let modules = tmp.join("home/.npm/_npx/abc/node_modules");
    npm_package(&modules.join("real-pkg"), "real-pkg", "1.0.0");
    symlink(
        outside.join("secret-internal"),
        modules.join("secret-internal"),
    )
    .unwrap();

    let found = names(&ccmd::scanner::discover_packages(&[tmp.join("home/.npm")]));

    assert!(
        found.contains(&"real-pkg".to_string()),
        "a package inside the root is still found: {found:?}"
    );
    assert!(
        !found.contains(&"secret-internal".to_string()),
        "a package behind a symlink must not be read, and its name must not be sent to OSV: {found:?}"
    );
}

#[test]
fn discovery_still_walks_a_root_that_is_itself_a_symlink() {
    // Control: relocating a cache behind a link is common, and the user named
    // the root. Rejecting every link would make that cache invisible.
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    let real = tmp.join("elsewhere/.npm");
    npm_package(
        &real.join("_npx/abc/node_modules/real-pkg"),
        "real-pkg",
        "1.0.0",
    );
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    symlink(&real, tmp.join("home/.npm")).unwrap();

    let found = names(&ccmd::scanner::discover_packages(&[tmp.join("home/.npm")]));
    assert_eq!(found, vec!["real-pkg".to_string()]);
}

/// Expand `dir` through the real scanner thread and collect what comes back,
/// including any later size updates.
fn expand(dir: &Path) -> (Vec<TreeNode>, Vec<(PathBuf, u64)>) {
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = ccmd::scanner::start(result_tx, None);
    scan_tx
        .send(ScanRequest::ExpandNode(dir.to_path_buf()))
        .unwrap();
    let mut children = Vec::new();
    let mut sizes = Vec::new();
    // The children arrive first; later messages are size updates for large
    // children. A quiet second is enough to know none are coming.
    while let Ok(msg) = result_rx.recv_timeout(Duration::from_secs(1)) {
        match msg {
            ScanResult::ChildrenScanned(_, nodes) => children = nodes,
            ScanResult::SizeUpdated(path, size) => sizes.push((path, size)),
            _ => {}
        }
    }
    (children, sizes)
}

#[test]
fn expanding_a_node_shows_a_symlink_as_a_leaf_without_measuring_its_target() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    let outside = tmp.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("big.bin"), vec![0u8; 64 * 1024]).unwrap();
    let root = tmp.join("root");
    std::fs::create_dir_all(root.join("real")).unwrap();
    std::fs::write(root.join("real/a.bin"), vec![0u8; 100]).unwrap();
    symlink(&outside, root.join("huggingface")).unwrap();

    let (children, sizes) = expand(&root);

    let link = children
        .iter()
        .find(|n| n.name == "huggingface")
        .expect("the link is still listed, so the user can see it");
    assert!(
        !link.has_children,
        "a symlink must not be expandable: expanding it would list what is outside the root"
    );
    assert_eq!(
        link.size, 0,
        "a symlink must not be sized by what it points at"
    );
    assert_eq!(
        link.kind,
        ccmd::tree::node::CacheKind::Unknown,
        "and not classified by its name: that would read through it"
    );
    assert!(
        sizes.iter().all(|(p, _)| *p != root.join("huggingface")),
        "no later size update may measure the link target: {sizes:?}"
    );

    let real = children.iter().find(|n| n.name == "real").unwrap();
    assert!(real.has_children, "control: a real directory expands");
    assert_eq!(real.size, 100, "control: and is sized");
}

#[test]
fn a_symlinked_root_is_still_expandable() {
    // Control for the rule above: only roots are exempt.
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    let real = tmp.join("real_root");
    std::fs::create_dir_all(real.join("child")).unwrap();
    symlink(&real, tmp.join("linked_root")).unwrap();

    assert!(
        TreeNode::root(tmp.join("linked_root")).has_children,
        "a root behind a link must still open"
    );
    let (children, _) = expand(&tmp.join("linked_root"));
    assert_eq!(children.len(), 1, "and its children are listed");
}
