//! End-to-end tests for Maven and Gradle providers using real tools.
//!
//! These tests populate real on-disk caches via `mvn` and `gradle`, then verify:
//!   1. `ccmd::scanner::discover_packages` extracts correct PackageIds.
//!   2. `ccmd::security::scan_vulns` (which hits osv.dev) detects known CVEs
//!      in deliberately-vulnerable versions (Log4Shell, Text4Shell).
//!
//! All state lives in `tempfile::tempdir()` scoped caches — nothing touches the
//! user's real `~/.m2` or `~/.gradle`. Tests SKIP cleanly if tools are absent.
//!
//! Run with: cargo test --features e2e --test e2e_jvm_providers -- --test-threads=1 --nocapture
#![cfg(feature = "e2e")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ============================================================
// Helpers
// ============================================================

fn is_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// How long any single `mvn` / `gradle` invocation is allowed to run before we
/// kill it. A stalled Maven Central download or a paused Gradle daemon should
/// not hang the whole CI job indefinitely.
const RUN_TIMEOUT: Duration = Duration::from_secs(180);

/// Run a command with a bounded timeout. Kills the child on timeout so we
/// surface a clean test failure instead of letting CI hang.
fn run(cmd: &mut Command, label: &str) {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{label}: failed to spawn: {e}"));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > RUN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{label}: exceeded {}s timeout", RUN_TIMEOUT.as_secs());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("{label}: wait failed: {e}"),
        }
    };

    if !status.success() {
        let output = child.wait_with_output().ok();
        let (stdout, stderr) = match output {
            Some(o) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            ),
            None => (String::new(), String::new()),
        };
        panic!("{label} failed:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }
}

fn list_jars(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    for entry in walkdir_all(root) {
        if entry.extension().and_then(|e| e.to_str()) == Some("jar") {
            out.push(entry);
        }
    }
    out
}

fn walkdir_all(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&p) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
    }
    out
}

// Deliberately-vulnerable and deliberately-outdated artifacts used across tests.
const LOG4J_VULN: (&str, &str, &str) = ("org.apache.logging.log4j", "log4j-core", "2.14.1"); // Log4Shell CVE-2021-44228
const COMMONS_TEXT_VULN: (&str, &str, &str) = ("org.apache.commons", "commons-text", "1.9"); // Text4Shell CVE-2022-42889
const GUAVA_OUTDATED: (&str, &str, &str) = ("com.google.guava", "guava", "20.0"); // outdated (current ~33.x)
const GUAVA_CLEAN: (&str, &str, &str) = ("com.google.guava", "guava", "32.0.0-jre"); // baseline, not known-vulnerable

fn coord(p: &(&str, &str, &str)) -> String {
    format!("{}:{}:{}", p.0, p.1, p.2)
}

/// Assert that `scan_vulns` reported at least one vulnerability for a package
/// whose name matches `group:artifact`. Panics with the full result map on miss.
fn assert_vuln_reported(
    outcome: &ccmd::security::VulnScanOutcome,
    group_artifact: &str,
    label: &str,
) {
    let hit = outcome.results.iter().any(|(path, info)| {
        path.to_string_lossy().contains(group_artifact) && !info.vulns.is_empty()
    });
    assert!(
        hit,
        "expected OSV to report vulns for {label} ({group_artifact}); unscanned={}, results:\n{:#?}",
        outcome.unscanned_packages, outcome.results
    );
}

/// Assert that `check_versions` reported a package as outdated.
fn assert_outdated_reported(
    outcome: &ccmd::security::VersionCheckOutcome,
    group_artifact: &str,
    label: &str,
) {
    let hit = outcome
        .results
        .iter()
        .any(|(path, info)| path.to_string_lossy().contains(group_artifact) && info.is_outdated);
    assert!(
        hit,
        "expected Maven Central to mark {label} ({group_artifact}) outdated; unchecked={}, results:\n{:#?}",
        outcome.unchecked_packages, outcome.results
    );
}

// ============================================================
// Maven
// ============================================================

/// Populate a scoped local Maven repository with one vulnerable, one extra
/// vulnerable, and one clean artifact, then verify discovery + OSV pipeline.
#[test]
fn e2e_maven_discovery_and_vuln_scan() {
    if !is_available("mvn") {
        eprintln!("SKIP: mvn not installed (install with `brew install maven` or use CI)");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    // Nest under `.m2/repository` so provider `detect()` classifies paths as Maven.
    let m2 = tmp.path().join(".m2");
    let repo = m2.join("repository");
    std::fs::create_dir_all(&repo).unwrap();

    // `mvn dependency:get` resolves an artifact into the specified local repo.
    // Using `-Dtransitive=false` keeps the download small and deterministic.
    for artifact in [LOG4J_VULN, COMMONS_TEXT_VULN, GUAVA_OUTDATED, GUAVA_CLEAN] {
        let mut cmd = Command::new("mvn");
        cmd.args([
            "-B",
            "-q",
            "dependency:get",
            &format!("-Dmaven.repo.local={}", repo.display()),
            &format!("-Dartifact={}", coord(&artifact)),
            "-Dtransitive=false",
        ]);
        run(
            &mut cmd,
            &format!("mvn dependency:get {}", coord(&artifact)),
        );
    }

    // Verify the cache actually got populated as we expect.
    let jars = list_jars(&repo);
    assert!(
        jars.iter()
            .any(|p| p.to_string_lossy().contains("log4j-core")),
        "log4j-core jar not found under {}; jars: {:?}",
        repo.display(),
        jars
    );
    assert!(
        jars.iter()
            .any(|p| p.to_string_lossy().contains("commons-text")),
        "commons-text jar not found"
    );
    assert!(
        jars.iter().any(|p| p.to_string_lossy().contains("guava")),
        "guava jar not found"
    );

    // --- Discovery ---
    // Start the walk from .m2 so ancestor-based `.m2` detection fires.
    let packages = ccmd::scanner::discover_packages(&[m2.clone()]);
    let names: Vec<_> = packages
        .iter()
        .map(|(_, id)| (id.ecosystem, id.name.clone(), id.version.clone()))
        .collect();

    assert!(
        names.iter().any(|(eco, n, v)| *eco == "Maven"
            && n == "org.apache.logging.log4j:log4j-core"
            && v == "2.14.1"),
        "expected Log4Shell PackageId; got: {:?}",
        names
    );
    assert!(
        names.iter().any(|(eco, n, v)| *eco == "Maven"
            && n == "org.apache.commons:commons-text"
            && v == "1.9"),
        "expected Text4Shell PackageId; got: {:?}",
        names
    );
    assert!(
        names.iter().any(|(eco, n, v)| *eco == "Maven"
            && n == "com.google.guava:guava"
            && v == "32.0.0-jre"),
        "expected Guava PackageId; got: {:?}",
        names
    );

    // --- OSV vulnerability scan (network call to osv.dev) ---
    let vuln_results = ccmd::security::scan_vulns(&packages);
    assert_vuln_reported(&vuln_results, "log4j-core", "Log4Shell");
    assert_vuln_reported(&vuln_results, "commons-text", "Text4Shell");

    // --- Version check (network call to repo1.maven.org) ---
    let version_results = ccmd::security::check_versions(&packages);
    assert_outdated_reported(&version_results, "guava/20.0", "Guava 20.0");
}

// ============================================================
// Gradle
// ============================================================

fn write_gradle_project(project_dir: &Path) {
    std::fs::create_dir_all(project_dir).unwrap();
    // Declare Maven Central inline in build.gradle (no init script needed).
    let settings = r#"rootProject.name = 'e2e'"#;
    std::fs::write(project_dir.join("settings.gradle"), settings).unwrap();

    // Use pre-Gradle-4.9 `task name { ... }` syntax — supported by every
    // Gradle version we might encounter (Ubuntu's apt still ships 4.4.1).
    // `tasks.register(...)` would break on older Gradles.
    let build = format!(
        r#"
apply plugin: 'java'
repositories {{ mavenCentral() }}
dependencies {{
    implementation '{log4j}'
    implementation '{commons_text}'
    implementation '{guava}'
}}
task resolveAll {{
    doLast {{
        configurations.runtimeClasspath.resolve()
    }}
}}
"#,
        log4j = coord(&LOG4J_VULN),
        commons_text = coord(&COMMONS_TEXT_VULN),
        guava = coord(&GUAVA_CLEAN),
    );
    std::fs::write(project_dir.join("build.gradle"), build).unwrap();
}

#[test]
fn e2e_gradle_discovery_and_vuln_scan() {
    if !is_available("gradle") {
        eprintln!("SKIP: gradle not installed (install with `brew install gradle` or use CI)");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    // Name the Gradle home `.gradle` so the provider detects it.
    let gradle_home = tmp.path().join(".gradle");
    std::fs::create_dir_all(&gradle_home).unwrap();

    write_gradle_project(&project);

    // Use scoped GRADLE_USER_HOME so we never touch ~/.gradle.
    // --no-daemon avoids leaving a daemon running after the test.
    let mut cmd = Command::new("gradle");
    cmd.current_dir(&project)
        .args(["-q", "--no-daemon", "--console=plain", "resolveAll"])
        .env("GRADLE_USER_HOME", &gradle_home);
    run(&mut cmd, "gradle resolveAll");

    // The cache lives under <gradle-home>/caches/modules-2/files-2.1/...
    let files_21 = gradle_home
        .join("caches")
        .join("modules-2")
        .join("files-2.1");
    assert!(
        files_21.exists(),
        "expected files-2.1 cache under {}",
        gradle_home.display()
    );

    // --- Discovery ---
    let packages = ccmd::scanner::discover_packages(&[gradle_home.clone()]);
    let names: Vec<_> = packages
        .iter()
        .map(|(_, id)| (id.ecosystem, id.name.clone(), id.version.clone()))
        .collect();

    assert!(
        names.iter().any(|(eco, n, v)| *eco == "Maven"
            && n == "org.apache.logging.log4j:log4j-core"
            && v == "2.14.1"),
        "expected Log4Shell PackageId from Gradle cache; got: {:?}",
        names
    );
    assert!(
        names.iter().any(|(eco, n, v)| *eco == "Maven"
            && n == "org.apache.commons:commons-text"
            && v == "1.9"),
        "expected Text4Shell PackageId from Gradle cache; got: {:?}",
        names
    );

    // --- OSV vulnerability scan ---
    // (Maven Central registry-based version-check is covered by the Maven test;
    // the Gradle test focuses on cache format + OSV pipeline.)
    let vuln_results = ccmd::security::scan_vulns(&packages);
    assert_vuln_reported(&vuln_results, "log4j-core", "Log4Shell");
    assert_vuln_reported(&vuln_results, "commons-text", "Text4Shell");
}
