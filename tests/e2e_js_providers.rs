//! End-to-end tests for Yarn and pnpm providers using real tools.
//!
//! These tests install real packages into real caches, then verify the parsers
//! extract correct names, versions, and ecosystems from actual on-disk formats.
//!
//! Requires: npm, yarn (classic), corepack (for berry), pnpm
//! Run with: cargo test --features e2e --test e2e_js_providers -- --test-threads=1
#![cfg(feature = "e2e")]

use std::path::{Path, PathBuf};
use std::process::Command;

// ============================================================
// Helpers
// ============================================================

/// Check if a command is available on PATH.
fn is_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command in a directory and assert success.
fn run_in(dir: &Path, cmd: &str, args: &[&str]) {
    run_in_with_env(dir, cmd, args, &[]);
}

/// Run pnpm with an isolated content-addressed store so tests never pollute the
/// host's global pnpm store (`~/Library/pnpm`, `~/.local/share/pnpm`, etc.).
/// The `--store-dir` flag is inserted after `pnpm` and before the subcommand.
fn run_pnpm(dir: &Path, store_dir: &Path, args: &[&str]) {
    let store_str = store_dir.to_string_lossy().to_string();
    let mut full_args: Vec<&str> = vec!["--store-dir", &store_str];
    full_args.extend_from_slice(args);
    run_in(dir, "pnpm", &full_args);
}

/// Run a command in a directory with extra env vars and assert success.
fn run_in_with_env(dir: &Path, cmd: &str, args: &[&str], env: &[(&str, &str)]) {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(dir)
        .env("npm_config_fund", "false")
        .env("npm_config_audit", "false");
    for (k, v) in env {
        command.env(k, v);
    }
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("Failed to run {cmd} {args:?}: {e}"));
    assert!(
        output.status.success(),
        "{cmd} {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run a command and return stdout, or None on failure.
fn run_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Collect discovered packages as (name, version, ecosystem) tuples.
fn discovered_packages(roots: &[PathBuf]) -> Vec<(String, String, &'static str)> {
    ccmd::scanner::discover_packages(roots)
        .into_iter()
        .map(|(_, id)| (id.name, id.version, id.ecosystem))
        .collect()
}

/// List filenames in a directory (non-recursive).
fn list_dir(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Create a minimal npm project in the given directory.
fn init_npm_project(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"test-project","version":"1.0.0","private":true}"#,
    )
    .unwrap();
}

// ============================================================
// Yarn Classic (1.x)
// ============================================================

/// Yarn Classic: simple package, scoped package, hyphenated name
/// Validates actual .tgz filenames match our `parse_classic_filename` assumptions.
#[test]
fn e2e_yarn_classic_realistic_packages() {
    if !is_available("yarn") {
        eprintln!("SKIP: yarn not installed");
        return;
    }
    let version = run_stdout("yarn", &["--version"]).unwrap_or_default();
    if !version.starts_with('1') {
        eprintln!("SKIP: yarn is not Classic (1.x), got {version}");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("classic");
    let cache = tmp.path().join(".yarn-cache");
    std::fs::create_dir_all(&cache).unwrap();
    init_npm_project(&project);

    let cache_str = cache.to_string_lossy().to_string();
    let env = [("YARN_CACHE_FOLDER", cache_str.as_str())];

    // Install a mix of package types that stress the parser:
    // - simple name: lodash
    // - scoped package: @babel/core
    // - hyphenated name: is-even
    // - name containing digits: base64-js
    run_in_with_env(
        &project,
        "yarn",
        &[
            "add",
            "lodash@4.17.21",
            "@babel/core@7.24.0",
            "is-even@1.0.0",
            "base64-js@1.5.1",
        ],
        &env,
    );

    let cache_path = cache.join("v6");
    assert!(
        cache_path.exists(),
        "Yarn cache dir missing: {cache_path:?}"
    );

    // Verify the actual filenames on disk are what we expect
    let files = list_dir(&cache_path);
    eprintln!(
        "Yarn Classic cache files (sample): {:?}",
        &files[..files.len().min(10)]
    );

    // Yarn Classic uses directories named npm-<name>-<version>-<hash>-integrity
    let integrity_dirs: Vec<&String> = files.iter().filter(|f| f.ends_with("-integrity")).collect();
    assert!(
        !integrity_dirs.is_empty(),
        "Expected -integrity directories in Yarn Classic cache, got: {files:?}"
    );
    for f in &integrity_dirs {
        assert!(
            f.starts_with("npm-"),
            "Yarn Classic entries should start with 'npm-': {f}"
        );
    }

    // Now verify the scanner discovers all packages correctly
    let packages = discovered_packages(std::slice::from_ref(&cache_path));
    let names: Vec<&str> = packages.iter().map(|(n, _, _)| n.as_str()).collect();

    assert!(names.contains(&"lodash"), "Should find lodash: {names:?}");
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {names:?}"
    );
    assert!(names.contains(&"is-even"), "Should find is-even: {names:?}");
    assert!(
        names.contains(&"base64-js"),
        "Should find base64-js: {names:?}"
    );

    // Verify versions are correct
    let lodash = packages.iter().find(|(n, _, _)| n == "lodash").unwrap();
    assert_eq!(lodash.1, "4.17.21", "lodash version mismatch");
    assert_eq!(lodash.2, "npm", "lodash ecosystem should be npm");

    let babel = packages
        .iter()
        .find(|(n, _, _)| n == "@babel/core")
        .unwrap();
    assert_eq!(babel.1, "7.24.0", "babel version mismatch");

    let is_even = packages.iter().find(|(n, _, _)| n == "is-even").unwrap();
    assert_eq!(is_even.1, "1.0.0");

    let base64 = packages.iter().find(|(n, _, _)| n == "base64-js").unwrap();
    assert_eq!(base64.1, "1.5.1");

    // tempdir cleanup handles the isolated cache — no global cache was touched
}

// ============================================================
// Yarn Berry (2+)
// ============================================================

/// Yarn Berry: simple, scoped, and hyphenated packages
/// Validates actual .zip filenames match our `parse_berry_filename` assumptions.
#[test]
fn e2e_yarn_berry_realistic_packages() {
    if !is_available("corepack") {
        eprintln!("SKIP: corepack not available");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("berry");
    init_npm_project(&project);

    // Set up Berry
    run_in(&project, "corepack", &["enable"]);
    run_in(&project, "yarn", &["set", "version", "berry"]);

    // Disable PnP to avoid node resolution issues, use node_modules
    std::fs::write(
        project.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();

    // Install packages that stress the parser
    run_in(
        &project,
        "yarn",
        &[
            "add",
            "lodash@4.17.21",
            "@babel/core@7.24.0",
            "is-even@1.0.0",
            "base64-js@1.5.1",
        ],
    );

    // Berry cache is per-project
    let cache_path = project.join(".yarn/cache");
    assert!(cache_path.exists(), ".yarn/cache should exist");

    // Verify the actual filenames on disk
    let files = list_dir(&cache_path);
    eprintln!(
        "Yarn Berry cache files (sample): {:?}",
        &files[..files.len().min(10)]
    );

    let zip_files: Vec<&String> = files.iter().filter(|f| f.ends_with(".zip")).collect();
    assert!(
        !zip_files.is_empty(),
        "Expected .zip files in Berry cache, got: {files:?}"
    );

    // Verify the -npm- marker is present in zip filenames
    for f in &zip_files {
        assert!(
            f.contains("-npm-"),
            "Berry .zip should contain '-npm-': {f}"
        );
    }

    // Verify scanner discovers packages
    let packages = discovered_packages(&[project.join(".yarn")]);
    let names: Vec<&str> = packages.iter().map(|(n, _, _)| n.as_str()).collect();

    assert!(names.contains(&"lodash"), "Should find lodash: {names:?}");
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {names:?}"
    );
    assert!(names.contains(&"is-even"), "Should find is-even: {names:?}");
    assert!(
        names.contains(&"base64-js"),
        "Should find base64-js: {names:?}"
    );

    // Verify versions
    let lodash = packages.iter().find(|(n, _, _)| n == "lodash").unwrap();
    assert_eq!(lodash.1, "4.17.21");
    assert_eq!(lodash.2, "npm");

    let babel = packages
        .iter()
        .find(|(n, _, _)| n == "@babel/core")
        .unwrap();
    assert_eq!(babel.1, "7.24.0");
}

/// Yarn Berry: package with `-npm-` in the name (the bug we fixed)
#[test]
fn e2e_yarn_berry_npm_in_package_name() {
    if !is_available("corepack") {
        eprintln!("SKIP: corepack not available");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("berry-npm-name");
    init_npm_project(&project);

    run_in(&project, "corepack", &["enable"]);
    run_in(&project, "yarn", &["set", "version", "berry"]);
    std::fs::write(
        project.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();

    // npm-run-all has "npm" in its name — this is the exact bug we fixed
    run_in(&project, "yarn", &["add", "npm-run-all@4.1.5"]);

    let cache_path = project.join(".yarn/cache");
    let files = list_dir(&cache_path);
    eprintln!("Berry cache with npm-run-all: {files:?}");

    let packages = discovered_packages(&[project.join(".yarn")]);
    let names: Vec<&str> = packages.iter().map(|(n, _, _)| n.as_str()).collect();

    assert!(
        names.contains(&"npm-run-all"),
        "Should find npm-run-all despite '-npm-' in name: {names:?}"
    );

    let pkg = packages
        .iter()
        .find(|(n, _, _)| n == "npm-run-all")
        .unwrap();
    assert_eq!(pkg.1, "4.1.5");
}

// ============================================================
// pnpm
// ============================================================

/// pnpm: simple, scoped, and hyphenated packages in virtual store
/// Validates actual directory names match our `parse_virtual_store_name` assumptions.
#[test]
fn e2e_pnpm_realistic_packages() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("pnpm-basic");
    let store = tmp.path().join(".pnpm-store");
    init_npm_project(&project);

    run_pnpm(
        &project,
        &store,
        &[
            "add",
            "lodash@4.17.21",
            "@babel/core@7.24.0",
            "is-even@1.0.0",
            "base64-js@1.5.1",
        ],
    );

    let pnpm_dir = project.join("node_modules/.pnpm");
    assert!(pnpm_dir.exists(), "node_modules/.pnpm should exist");

    // Verify actual directory naming convention
    let entries = list_dir(&pnpm_dir);
    eprintln!(
        "pnpm virtual store entries (sample): {:?}",
        &entries[..entries.len().min(15)]
    );

    // Verify @ naming convention
    let at_entries: Vec<&String> = entries.iter().filter(|e| e.contains('@')).collect();
    assert!(
        !at_entries.is_empty(),
        "Expected @-named entries in .pnpm: {entries:?}"
    );

    // Verify scoped packages use + separator
    let scoped: Vec<&&String> = at_entries.iter().filter(|e| e.starts_with('@')).collect();
    assert!(
        !scoped.is_empty(),
        "Expected scoped packages in .pnpm: {entries:?}"
    );
    for s in &scoped {
        assert!(
            s.contains('+'),
            "Scoped pnpm entries should use '+' separator: {s}"
        );
    }

    // Verify scanner finds all packages
    let packages = discovered_packages(std::slice::from_ref(&pnpm_dir));
    let names: Vec<&str> = packages.iter().map(|(n, _, _)| n.as_str()).collect();

    assert!(names.contains(&"lodash"), "Should find lodash: {names:?}");
    assert!(
        names.contains(&"@babel/core"),
        "Should find @babel/core: {names:?}"
    );
    assert!(names.contains(&"is-even"), "Should find is-even: {names:?}");
    assert!(
        names.contains(&"base64-js"),
        "Should find base64-js: {names:?}"
    );

    // Verify versions
    let lodash = packages.iter().find(|(n, _, _)| n == "lodash").unwrap();
    assert_eq!(lodash.1, "4.17.21");
    assert_eq!(lodash.2, "npm");

    let babel = packages
        .iter()
        .find(|(n, _, _)| n == "@babel/core")
        .unwrap();
    assert_eq!(babel.1, "7.24.0");
}

/// pnpm: peer dependency suffixes (the bug we fixed)
/// Installs packages with peer deps to verify strip_peer_deps works on real dirs.
#[test]
fn e2e_pnpm_peer_dependencies() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("pnpm-peers");
    let store = tmp.path().join(".pnpm-store");
    init_npm_project(&project);

    // react-dom has a peer dep on react — pnpm encodes this in the directory name
    run_pnpm(
        &project,
        &store,
        &["add", "react@18.2.0", "react-dom@18.2.0"],
    );

    let pnpm_dir = project.join("node_modules/.pnpm");
    let entries = list_dir(&pnpm_dir);
    eprintln!(
        "pnpm entries with peer deps: {:?}",
        &entries[..entries.len().min(20)]
    );

    // Find the react-dom entry — it should have a peer dep suffix with '_'
    let react_dom_entries: Vec<&String> = entries
        .iter()
        .filter(|e| e.starts_with("react-dom@"))
        .collect();
    assert!(
        !react_dom_entries.is_empty(),
        "Should find react-dom@ entry: {entries:?}"
    );

    // Log the actual format for debugging
    for entry in &react_dom_entries {
        eprintln!("react-dom entry: {entry}");
    }

    // Verify scanner correctly parses react-dom despite peer dep suffix
    let packages = discovered_packages(&[pnpm_dir]);
    let names: Vec<&str> = packages.iter().map(|(n, _, _)| n.as_str()).collect();

    assert!(
        names.contains(&"react-dom"),
        "Should find react-dom after stripping peer deps: {names:?}"
    );
    assert!(names.contains(&"react"), "Should find react: {names:?}");

    // Verify version is correct (not polluted by peer dep suffix)
    let react_dom = packages.iter().find(|(n, _, _)| n == "react-dom").unwrap();
    assert_eq!(
        react_dom.1, "18.2.0",
        "react-dom version should be 18.2.0, not include peer dep suffix"
    );
}

/// pnpm: scoped packages with peer deps
#[test]
fn e2e_pnpm_scoped_with_peers() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("pnpm-scoped-peers");
    let store = tmp.path().join(".pnpm-store");
    init_npm_project(&project);

    // @testing-library/react has peer deps on react and react-dom
    run_pnpm(
        &project,
        &store,
        &[
            "add",
            "react@18.2.0",
            "react-dom@18.2.0",
            "@testing-library/react@14.2.0",
        ],
    );

    let pnpm_dir = project.join("node_modules/.pnpm");
    let entries = list_dir(&pnpm_dir);

    // Find the scoped entry with peer deps
    let tl_entries: Vec<&String> = entries
        .iter()
        .filter(|e| e.starts_with("@testing-library+react@"))
        .collect();
    assert!(
        !tl_entries.is_empty(),
        "Should find @testing-library+react@ entry: {entries:?}"
    );
    for entry in &tl_entries {
        eprintln!("@testing-library/react entry: {entry}");
    }

    let packages = discovered_packages(&[pnpm_dir]);
    let names: Vec<&str> = packages.iter().map(|(n, _, _)| n.as_str()).collect();

    assert!(
        names.contains(&"@testing-library/react"),
        "Should find @testing-library/react: {names:?}"
    );

    let pkg = packages
        .iter()
        .find(|(n, _, _)| n == "@testing-library/react")
        .unwrap();
    assert_eq!(pkg.1, "14.2.0");
    assert_eq!(pkg.2, "npm");
}

// ============================================================
// Cross-provider deduplication with real tools
// ============================================================

/// Verify that the same package installed via npm and yarn is deduplicated.
#[test]
fn e2e_dedup_across_npm_and_yarn() {
    if !is_available("yarn") || !is_available("npm") {
        eprintln!("SKIP: yarn or npm not installed");
        return;
    }
    let version = run_stdout("yarn", &["--version"]).unwrap_or_default();
    if !version.starts_with('1') {
        eprintln!("SKIP: need Yarn Classic for this test, got {version}");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let yarn_cache = tmp.path().join(".yarn-cache");
    std::fs::create_dir_all(&yarn_cache).unwrap();
    let yarn_cache_str = yarn_cache.to_string_lossy().to_string();
    let yarn_env = [("YARN_CACHE_FOLDER", yarn_cache_str.as_str())];

    // Install lodash via Yarn Classic into an isolated cache dir
    let yarn_project = tmp.path().join("yarn-dedup");
    init_npm_project(&yarn_project);
    run_in_with_env(&yarn_project, "yarn", &["add", "lodash@4.17.21"], &yarn_env);

    // Install lodash via npm — into the project's local node_modules (already under tempdir)
    let npm_project = tmp.path().join("npm-dedup");
    init_npm_project(&npm_project);
    run_in(&npm_project, "npm", &["install", "lodash@4.17.21"]);

    let npm_modules = npm_project.join("node_modules");

    // Scan both caches together — yarn cache is the isolated tempdir cache
    let packages = ccmd::scanner::discover_packages(&[yarn_cache, npm_modules]);

    let lodash_count = packages
        .iter()
        .filter(|(_, id)| id.name == "lodash" && id.version == "4.17.21")
        .count();

    assert_eq!(
        lodash_count, 1,
        "lodash@4.17.21 should be deduplicated across npm and yarn, got {lodash_count}"
    );
    // No `yarn cache clean` — tempdir drop cleans up our isolated cache.
}
