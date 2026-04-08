//! End-to-end tests for Yarn and pnpm providers using real tools.
//! Requires Yarn and pnpm to be installed.
//! Run with: cargo test --features e2e --test e2e_js_providers
#![cfg(feature = "e2e")]

use std::process::Command;

/// Check if a command is available on PATH.
fn is_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command in a directory and assert success.
fn run_in(dir: &std::path::Path, cmd: &str, args: &[&str]) {
    let output = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("Failed to run {} {:?}: {}", cmd, args, e));
    assert!(
        output.status.success(),
        "{} {:?} failed:\nstdout: {}\nstderr: {}",
        cmd,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- Yarn Classic E2E ---

#[test]
fn e2e_yarn_classic_cache_detection() {
    if !is_available("yarn") {
        eprintln!("SKIP: yarn not installed");
        return;
    }

    // Check if this is Yarn Classic (1.x)
    let output = Command::new("yarn").arg("--version").output().unwrap();
    let version = String::from_utf8_lossy(&output.stdout);
    if !version.starts_with('1') {
        eprintln!("SKIP: yarn is not Classic (1.x), got {}", version.trim());
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("classic-project");
    std::fs::create_dir_all(&project).unwrap();

    // Initialize project and install a package
    run_in(&project, "npm", &["init", "-y"]);
    run_in(&project, "yarn", &["add", "is-even@1.0.0"]);

    // Find yarn cache dir
    let output = Command::new("yarn")
        .args(["cache", "dir"])
        .output()
        .unwrap();
    let cache_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let cache_path = std::path::PathBuf::from(&cache_dir);

    assert!(
        cache_path.exists(),
        "Yarn cache dir should exist: {}",
        cache_dir
    );

    // Scan for packages
    let packages = ccmd::scanner::discover_packages(&[cache_path]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"is-even"),
        "Should find is-even in Yarn Classic cache: {:?}",
        names
    );

    // Clean up: remove the cached package
    let _ = Command::new("yarn")
        .args(["cache", "clean", "is-even"])
        .output();
}

// --- Yarn Berry E2E ---

#[test]
fn e2e_yarn_berry_cache_detection() {
    if !is_available("corepack") {
        eprintln!("SKIP: corepack not available");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("berry-project");
    std::fs::create_dir_all(&project).unwrap();

    // Initialize Berry project
    run_in(&project, "npm", &["init", "-y"]);
    run_in(&project, "corepack", &["enable"]);
    run_in(&project, "yarn", &["set", "version", "berry"]);
    run_in(&project, "yarn", &["add", "is-even@1.0.0"]);

    // Berry cache is per-project at .yarn/cache/
    let cache_path = project.join(".yarn/cache");
    assert!(cache_path.exists(), ".yarn/cache should exist");

    // Scan for packages
    let packages = ccmd::scanner::discover_packages(&[project.join(".yarn")]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"is-even"),
        "Should find is-even in Berry cache: {:?}",
        names
    );
}

// --- pnpm E2E ---

#[test]
fn e2e_pnpm_virtual_store_detection() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("pnpm-project");
    std::fs::create_dir_all(&project).unwrap();

    // Initialize and install
    run_in(&project, "pnpm", &["init"]);
    run_in(&project, "pnpm", &["add", "is-even@1.0.0"]);

    // pnpm creates node_modules/.pnpm/
    let pnpm_dir = project.join("node_modules/.pnpm");
    assert!(pnpm_dir.exists(), "node_modules/.pnpm should exist");

    // Scan for packages
    let packages = ccmd::scanner::discover_packages(&[project.join("node_modules/.pnpm")]);
    let names: Vec<&str> = packages.iter().map(|(_, id)| id.name.as_str()).collect();
    assert!(
        names.contains(&"is-even"),
        "Should find is-even in pnpm virtual store: {:?}",
        names
    );
}

#[test]
fn e2e_pnpm_store_path_detection() {
    if !is_available("pnpm") {
        eprintln!("SKIP: pnpm not installed");
        return;
    }

    let output = Command::new("pnpm")
        .args(["store", "path"])
        .output()
        .unwrap();
    if output.status.success() {
        let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path = std::path::PathBuf::from(&store_path);
        assert!(
            path.exists(),
            "pnpm store path should exist: {}",
            store_path
        );
    }
}
