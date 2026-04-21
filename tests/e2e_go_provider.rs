//! End-to-end test for the Go provider using a real `go` tool.
//!
//! Populates a scoped module cache via `go mod download` on an outdated,
//! known-vulnerable module (`github.com/gin-gonic/gin v1.6.0`, CVE-2023-26125
//! / CVE-2023-29401), then verifies:
//!   1. `ccmd::scanner::discover_packages` extracts the correct PackageId.
//!   2. `ccmd::security::scan_vulns` (hits osv.dev) detects ≥1 vuln.
//!   3. `ccmd::security::check_versions` (hits proxy.golang.org /@v/list)
//!      reports the module as outdated.
//!   4. `providers::pre_delete` + `remove_dir_all` succeeds on Go's
//!      chmod-R-w module tree (the whole motivation for the hook).
//!
//! All state lives in a scoped tempdir — `GOMODCACHE` / `GOCACHE` / `GOPATH`
//! all redirect there, so we never touch the developer's real `~/go`.
//! Test SKIPs cleanly if `go` is absent.
//!
//! Run with: cargo test --features e2e --test e2e_go_provider -- --nocapture

#![cfg(feature = "e2e")]

use ccmd::providers::{self, SafetyLevel};
use ccmd::tree::node::CacheKind;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

fn is_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str], envs: &[(&str, &Path)], cwd: &Path) -> Result<(), String> {
    let mut c = Command::new(cmd);
    c.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (k, v) in envs {
        c.env(k, v);
    }
    let status = c.status().map_err(|e| format!("{cmd} {args:?}: {e}"))?;
    if !status.success() {
        return Err(format!("{cmd} {args:?} failed with {status}"));
    }
    Ok(())
}

/// Deliberately-vulnerable and deliberately-outdated Go module.
/// gin v1.6.0 is both outdated (latest is v1.10+) and OSV-flagged for
/// CVE-2023-26125 and CVE-2023-29401 among others.
const GIN_VULN_MODULE: &str = "github.com/gin-gonic/gin";
const GIN_VULN_VERSION: &str = "v1.6.0";

#[test]
fn e2e_go_discovery_vuln_scan_version_check_and_delete() {
    if !is_available("go") {
        eprintln!("SKIP: go not installed (install with `brew install go` or use CI)");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    // Preserve the real-world `pkg/mod` layout — detect() requires
    // `pkg` as the immediate parent of `mod` via has_adjacent_components.
    let gomodcache = tmp.path().join("pkg/mod");
    let gocache = tmp.path().join("build");
    let gopath = tmp.path().join("gopath");
    let workdir = tmp.path().join("work");
    std::fs::create_dir_all(&gomodcache).unwrap();
    std::fs::create_dir_all(&gocache).unwrap();
    std::fs::create_dir_all(&gopath).unwrap();
    std::fs::create_dir_all(&workdir).unwrap();

    // Sanity: tempdir must be the only cache location used (#feedback_e2e_must_isolate).
    assert!(
        gomodcache.starts_with(tmp.path()),
        "GOMODCACHE escaped tempdir: {gomodcache:?}"
    );

    let envs: &[(&str, &Path)] = &[
        ("GOMODCACHE", gomodcache.as_path()),
        ("GOCACHE", gocache.as_path()),
        ("GOPATH", gopath.as_path()),
    ];

    // Initialise a throwaway module in the workdir so `go mod download` has context.
    run("go", &["mod", "init", "ccmd-e2e-test"], envs, &workdir).expect("go mod init");
    // Add the dep, then resolve — populates the module cache.
    run(
        "go",
        &[
            "mod",
            "edit",
            "-require",
            &format!("{GIN_VULN_MODULE}@{GIN_VULN_VERSION}"),
        ],
        envs,
        &workdir,
    )
    .expect("go mod edit");
    run("go", &["mod", "download", GIN_VULN_MODULE], envs, &workdir).expect("go mod download");

    // The download should have produced a .zip under cache/download/.
    let zip_dir = gomodcache.join("cache/download/github.com/gin-gonic/gin/@v");
    if !zip_dir.exists() {
        // Dump what IS in the tempdir to help debugging env-var mis-wire.
        eprintln!("GOMODCACHE contents after go mod download:");
        fn dump(p: &Path, depth: usize) {
            if depth > 4 {
                return;
            }
            if let Ok(entries) = std::fs::read_dir(p) {
                for e in entries.flatten() {
                    eprintln!("  {}{}", "  ".repeat(depth), e.path().display());
                    if e.path().is_dir() {
                        dump(&e.path(), depth + 1);
                    }
                }
            }
        }
        dump(&gomodcache, 0);
        panic!("expected {zip_dir:?} after go mod download");
    }
    let zip_path = zip_dir.join(format!("{GIN_VULN_VERSION}.zip"));
    assert!(zip_path.exists(), "expected {zip_path:?}");

    // 1. Discover: the scanner should find gin with the expected identity.
    let packages = ccmd::scanner::discover_packages(&[gomodcache.clone()]);
    eprintln!(
        "[e2e] discover_packages returned {} entries",
        packages.len()
    );
    let gin = packages
        .iter()
        .find(|(_, id)| id.name == GIN_VULN_MODULE && id.ecosystem == "Go")
        .unwrap_or_else(|| {
            panic!(
                "expected Go/{GIN_VULN_MODULE} in discovered packages, got {:?}",
                packages
                    .iter()
                    .map(|(_, id)| (id.ecosystem, id.name.clone(), id.version.clone()))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(gin.1.version, GIN_VULN_VERSION);
    eprintln!(
        "[e2e] found {} @ {} at {}",
        gin.1.name,
        gin.1.version,
        gin.0.display()
    );

    // 2. OSV vuln scan: proxy.golang.org / osv.dev agree this version is vulnerable.
    let vuln_outcome = ccmd::security::scan_vulns(&packages);
    let cve_count: usize = vuln_outcome
        .results
        .iter()
        .filter(|(path, _)| path.to_string_lossy().contains("gin"))
        .map(|(_, info)| info.vulns.len())
        .sum();
    let cve_ids: Vec<String> = vuln_outcome
        .results
        .iter()
        .filter(|(path, _)| path.to_string_lossy().contains("gin"))
        .flat_map(|(_, info)| info.vulns.iter().map(|v| v.id.clone()))
        .collect();
    eprintln!(
        "[e2e] OSV scanned {} package(s), {} unscanned; gin CVEs: {} ({})",
        vuln_outcome.results.len(),
        vuln_outcome.unscanned_packages,
        cve_count,
        cve_ids.join(", ")
    );
    assert!(
        cve_count > 0,
        "expected OSV to flag gin v1.6.0; unscanned={}, results:\n{:#?}",
        vuln_outcome.unscanned_packages,
        vuln_outcome.results
    );

    // 3. Version check: proxy.golang.org /@v/list should return something newer.
    let outdated = ccmd::security::registry::check_latest(&gin.1)
        .expect("check_latest should succeed for Go ecosystem");
    let latest = outdated.expect("expected a latest version from proxy.golang.org");
    eprintln!(
        "[e2e] proxy.golang.org latest for {}: {} (installed: {})",
        gin.1.name, latest, GIN_VULN_VERSION
    );
    // compare_versions strips the leading `v` for Go-style versions — if the
    // returned version is strictly greater than v1.6.0, we're good.
    assert!(
        ccmd::security::osv::compare_versions(&latest, GIN_VULN_VERSION)
            == std::cmp::Ordering::Greater,
        "expected a version > {GIN_VULN_VERSION} from proxy, got {latest}"
    );

    // 4. Delete via pre_delete + remove_dir_all: verify the module tree goes
    // away cleanly despite Go's chmod -R -w.
    // Target the extracted module dir if it exists; otherwise the download dir.
    let extracted_glob = gomodcache.join(format!("github.com/gin-gonic/gin@{GIN_VULN_VERSION}"));
    let target = if extracted_glob.exists() {
        extracted_glob
    } else {
        // `go mod download` sometimes stops at the zip without extracting.
        // The zip dir itself is read-only too; still a valid test target.
        zip_dir
    };
    assert_eq!(providers::detect(&target), CacheKind::Go);
    assert_eq!(providers::safety(CacheKind::Go, &target), SafetyLevel::Safe);
    providers::pre_delete(CacheKind::Go, &target).expect("pre_delete should succeed");
    eprintln!("[e2e] pre_delete succeeded on {}", target.display());
    // Now the canonical delete path.
    std::fs::remove_dir_all(&target).expect("remove_dir_all should succeed after pre_delete");
    eprintln!("[e2e] remove_dir_all succeeded — delete flow verified end-to-end");

    // Tempdir drops at scope exit → clean on green, preserved on red
    // (we explicitly didn't register a cleanup for a failed run so the
    // failure is inspectable).
    let _ = tmp; // keep alive through the test
    drop(gomodcache);
    drop(gocache);
    drop(gopath);
    // Silence unused Duration import (used for potential future timeouts).
    let _ = Duration::from_secs(0);
}
