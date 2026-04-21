// Integration test: synthetic Go module + build cache fixtures
// exercise the full detect → semantic_name → metadata → safety →
// package_id pipeline.
//
// Tier-3 E2E (install real go, download a vulnerable module, verify
// OSV + version-check fire) lives in tests/e2e_go_provider.rs and is
// feature-gated on `e2e`.

use ccmd::providers::{self, SafetyLevel};
use ccmd::tree::node::CacheKind;
use std::fs;

#[test]
fn go_module_cache_pipeline() {
    let tmp = tempfile::tempdir().unwrap();
    let download = tmp
        .path()
        .join("go/pkg/mod/cache/download/github.com/stretchr/testify/@v");
    fs::create_dir_all(&download).unwrap();
    let zip = download.join("v1.8.4.zip");
    fs::write(&zip, b"fake zip").unwrap();
    fs::write(download.join("v1.8.4.info"), b"{}").unwrap();
    fs::write(
        download.join("v1.8.4.mod"),
        b"module github.com/stretchr/testify\n",
    )
    .unwrap();

    // detect
    assert_eq!(providers::detect(&zip), CacheKind::Go);
    assert_eq!(providers::detect(&download), CacheKind::Go);

    // semantic_name decodes bang-escapes and joins module path
    assert_eq!(
        providers::semantic_name(CacheKind::Go, &zip),
        Some("github.com/stretchr/testify v1.8.4".into())
    );

    // package_id only on .zip (dedup) — .info and .mod return None
    let id = providers::package_id(CacheKind::Go, &zip).expect("expected PackageId");
    assert_eq!(id.ecosystem, "Go");
    assert_eq!(id.name, "github.com/stretchr/testify");
    assert_eq!(id.version, "v1.8.4");
    assert_eq!(
        providers::package_id(CacheKind::Go, &download.join("v1.8.4.info")),
        None
    );
    assert_eq!(
        providers::package_id(CacheKind::Go, &download.join("v1.8.4.mod")),
        None
    );

    // safety: module cache is Safe
    assert_eq!(providers::safety(CacheKind::Go, &zip), SafetyLevel::Safe);
}

#[test]
fn go_module_cache_bang_decoding_pipeline() {
    let tmp = tempfile::tempdir().unwrap();
    // !uber-go is the on-disk form of Uber-go.
    let download = tmp
        .path()
        .join("go/pkg/mod/cache/download/github.com/!uber-go/zap/@v");
    fs::create_dir_all(&download).unwrap();
    let zip = download.join("v1.27.0.zip");
    fs::write(&zip, b"fake zip").unwrap();

    assert_eq!(providers::detect(&zip), CacheKind::Go);
    assert_eq!(
        providers::semantic_name(CacheKind::Go, &zip),
        Some("github.com/Uber-go/zap v1.27.0".into())
    );
    let id = providers::package_id(CacheKind::Go, &zip).expect("expected PackageId");
    assert_eq!(
        id.name, "github.com/Uber-go/zap",
        "package_id.name must be bang-decoded so OSV sees the real module path"
    );
}

#[test]
fn go_build_cache_pipeline() {
    let tmp = tempfile::tempdir().unwrap();
    let build = tmp.path().join("Library/Caches/go-build/ab");
    fs::create_dir_all(&build).unwrap();
    let blob = build.join("abcdef123456-d");
    fs::write(&blob, b"build artifact").unwrap();

    assert_eq!(providers::detect(&blob), CacheKind::Go);
    // Content-addressed blobs have no semantic name.
    assert_eq!(providers::semantic_name(CacheKind::Go, &blob), None);
    // Not a package — no identity.
    assert_eq!(providers::package_id(CacheKind::Go, &blob), None);
    // Build cache is Caution (cold rebuild cost).
    assert_eq!(
        providers::safety(CacheKind::Go, &blob),
        SafetyLevel::Caution
    );
}

#[test]
fn go_extracted_module_dir_is_safe_and_named_but_not_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let extracted = tmp
        .path()
        .join("go/pkg/mod/github.com/stretchr/testify@v1.8.4");
    fs::create_dir_all(&extracted).unwrap();

    assert_eq!(providers::detect(&extracted), CacheKind::Go);
    assert_eq!(
        providers::semantic_name(CacheKind::Go, &extracted),
        Some("github.com/stretchr/testify v1.8.4".into())
    );
    // Dedup guard: extracted dir must NOT produce a PackageId
    // (otherwise the zip + the extracted dir would double-count).
    assert_eq!(providers::package_id(CacheKind::Go, &extracted), None);
    assert_eq!(
        providers::safety(CacheKind::Go, &extracted),
        SafetyLevel::Safe
    );
}

#[cfg(unix)]
#[test]
fn go_pre_delete_unblocks_remove_dir_all_on_read_only_module() {
    // pre_delete's job: after Go has chmod -R -w'd the extracted
    // module tree, remove_dir_all must still succeed. We don't test
    // the "without pre_delete it would fail" sanity path because its
    // outcome varies by filesystem (APFS sometimes tolerates it) —
    // the positive assertion below is what matters.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let module = tmp
        .path()
        .join("go/pkg/mod/github.com/stretchr/testify@v1.8.4");
    fs::create_dir_all(&module).unwrap();
    let readme = module.join("README.md");
    fs::write(&readme, "docs").unwrap();

    // Simulate Go's chmod -R -w.
    fs::set_permissions(&readme, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&module, fs::Permissions::from_mode(0o555)).unwrap();

    // Run the hook, then remove.
    providers::pre_delete(CacheKind::Go, &module).expect("pre_delete should succeed");
    fs::remove_dir_all(&module).expect("remove_dir_all should succeed after pre_delete");
}
