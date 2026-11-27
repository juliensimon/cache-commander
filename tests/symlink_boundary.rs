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

use ccmd::tree::node::TreeNode;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

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

#[test]
fn expanding_a_node_shows_a_symlink_as_a_leaf_without_measuring_its_target() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    // Enough entries that `quick_size` gives up and the size would be queued
    // for a background walk, which is where a followed link used to be
    // measured. No timing involved: the queue is returned.
    let outside = tmp.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    for i in 0..60 {
        std::fs::write(outside.join(format!("f{i}.bin")), vec![0u8; 1024]).unwrap();
    }
    let root = tmp.join("root");
    std::fs::create_dir_all(root.join("real")).unwrap();
    std::fs::write(root.join("real/a.bin"), vec![0u8; 100]).unwrap();
    symlink(&outside, root.join("huggingface")).unwrap();

    let (children, deferred) = ccmd::scanner::expand(&root);

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
        !deferred.contains(&root.join("huggingface")),
        "and must not be queued for a background size walk: {deferred:?}"
    );

    let real = children.iter().find(|n| n.name == "real").unwrap();
    assert!(real.has_children, "control: a real directory expands");
    assert_eq!(real.size, 100, "control: and is sized");
}

#[test]
fn a_symlink_to_a_file_is_a_leaf_of_size_zero_too() {
    // Hugging Face snapshots hold links to blobs. Their size is the blob's,
    // counted where the blob lives; showing it again under the link would
    // double-count, and deleting a link frees nothing. The parent directory
    // already treats them as 0 (`dir_size` does not follow links).
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    let snapshot = tmp.join("snapshot");
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::write(tmp.join("blob"), vec![0u8; 4096]).unwrap();
    symlink(tmp.join("blob"), snapshot.join("model.safetensors")).unwrap();

    let (children, _) = ccmd::scanner::expand(&snapshot);
    let file = &children[0];
    assert_eq!(file.name, "model.safetensors");
    assert_eq!(file.size, 0);
    assert!(!file.has_children);
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
    let (children, _) = ccmd::scanner::expand(&tmp.join("linked_root"));
    assert_eq!(children.len(), 1, "and its children are listed");
}

#[test]
fn a_root_that_is_itself_a_link_to_a_package_is_still_discovered() {
    // `discover_packages` skips link entries below the root. The root is the
    // walk's own depth-0 entry and is exempt, like every other root.
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path().canonicalize().unwrap();
    let real = tmp.join("elsewhere/real-pkg");
    npm_package(&real, "real-pkg", "1.0.0");
    let modules = tmp.join("home/.npm/_npx/abc/node_modules");
    std::fs::create_dir_all(&modules).unwrap();
    symlink(&real, modules.join("real-pkg")).unwrap();

    let found = names(&ccmd::scanner::discover_packages(&[
        modules.join("real-pkg")
    ]));
    assert_eq!(found, vec!["real-pkg".to_string()]);
}
