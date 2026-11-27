pub mod walker;

use crate::providers;
use crate::security::privacy::PrivacyPolicy;
use crate::tree::node::TreeNode;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

pub enum ScanRequest {
    ScanRoots(Vec<PathBuf>),
    ExpandNode(PathBuf),
    /// Walk given paths to discover packages, then query OSV.dev
    ScanVulns(Vec<PathBuf>),
    /// Walk given paths to discover packages, then query registries
    CheckVersions(Vec<PathBuf>),
    /// Run `brew outdated --json=v2` in the background
    BrewOutdated,
}

pub enum ScanResult {
    RootsScanned(Vec<TreeNode>),
    ChildrenScanned(PathBuf, Vec<TreeNode>),
    SizeUpdated(PathBuf, u64),
    /// (packages_attempted, outcome) — outcome includes unscanned count so
    /// transient OSV errors aren't masked as "clean" (H5).
    VulnsScanned(usize, crate::security::VulnScanOutcome),
    /// (packages_attempted, outcome) — outcome includes unchecked count.
    VersionsChecked(usize, crate::security::VersionCheckOutcome),
    /// formula name → outdated info
    BrewOutdatedCompleted(
        std::collections::HashMap<String, crate::providers::homebrew::BrewOutdatedEntry>,
    ),
    /// How many package directories discovery found but could not turn into a
    /// package (#117). They are not scanned, so the UI must say so.
    ManifestsUnidentified(usize),
}

/// Something discovery found but could not turn into scannable packages: an npm
/// package directory whose manifest is unusable, or entries of a pnpm
/// `index.db` (#117, #39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnidentifiedManifest {
    pub path: PathBuf,
    pub reason: String,
    /// How many packages this entry stands for: 1 for a directory, the number
    /// of unusable rows for an `index.db`, so the count a scan reports is not
    /// understated.
    pub count: usize,
}

/// The number of packages the entries stand for.
pub fn unidentified_total(all: &[UnidentifiedManifest]) -> usize {
    all.iter().map(|u| u.count).sum()
}

/// What discovery found: the identified packages, and what it had to skip.
#[derive(Debug, Default)]
pub struct Discovery {
    pub packages: Vec<(PathBuf, crate::providers::PackageId)>,
    pub unidentified: Vec<UnidentifiedManifest>,
}

/// Walk a set of root paths to find all identifiable packages.
/// Deduplicates by (ecosystem, name, version) — each unique package is returned once.
/// Use [`discover`] to also learn what could not be identified.
#[allow(dead_code)] // the binary uses `discover`; tests and library callers use this
pub fn discover_packages(roots: &[PathBuf]) -> Vec<(PathBuf, crate::providers::PackageId)> {
    discover(roots).packages
}

/// [`discover_packages`], plus the npm package directories whose manifest could
/// not be turned into a package (#117): missing, malformed, oversized, or with
/// an invalid name or version. Also the entries of a pnpm 11 `index.db` that are
/// not scannable or could not be read (#39). Without this they vanish from the
/// scan and the package looks absent or clean. Both are npm-ecosystem; other
/// providers decide identity from paths or file names.
pub fn discover(roots: &[PathBuf]) -> Discovery {
    let mut seen = std::collections::HashSet::new();
    let mut packages = Vec::new();
    let mut unidentified = Vec::new();
    // Overlapping roots walk the same directory twice; a path is reported once.
    let mut unidentified_paths = std::collections::HashSet::new();
    // Likewise an index.db is read once.
    let mut index_dbs = std::collections::HashSet::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        // Depth 12 accommodates the deepest layouts: Maven's `~/.m2/repository/<group-path>/<artifact>/<version>/<file>`
        // where the group path alone can be 4-5 segments (e.g. `org/apache/logging/log4j`), and Gradle's
        // `~/.gradle/caches/modules-2/files-2.1/<group>/<artifact>/<version>/<hash>/<file>`.
        let walk = jwalk::WalkDir::new(root).skip_hidden(false).max_depth(12);
        for entry in walk.into_iter().filter_map(|e| e.ok()) {
            // A link below the root can point anywhere: reading a package
            // through it would send names from outside the root to OSV and the
            // registries (#92). Its target, if inside the root, is found by
            // its own path.
            if entry.depth() > 0 && entry.file_type().is_symlink() {
                continue;
            }
            let path = entry.path();
            let kind = crate::providers::detect(&path);
            // pnpm 11 keeps its package index in one SQLite file (#39): its
            // packages are read from there, under virtual paths below it.
            if kind == crate::tree::node::CacheKind::Pnpm
                && path.file_name().is_some_and(|n| n == "index.db")
                && entry.file_type().is_file()
            {
                if !index_dbs.insert(path.to_path_buf()) {
                    continue;
                }
                let report = |reason: String, count: usize| UnidentifiedManifest {
                    path: path.to_path_buf(),
                    reason,
                    count,
                };
                match crate::providers::pnpm::read_index_db(&path) {
                    Ok(db) => {
                        for id in db.packages {
                            let key = (id.ecosystem, id.name.clone(), id.version.clone());
                            if seen.insert(key) {
                                let virtual_path =
                                    crate::providers::pnpm::index_entry_path(&path, &id);
                                packages.push((virtual_path, id));
                            }
                        }
                        if db.unusable_keys > 0 {
                            unidentified.push(report(
                                format!(
                                    "pnpm index.db has {} entries without a registry name and version",
                                    db.unusable_keys
                                ),
                                db.unusable_keys,
                            ));
                        }
                        if db.incomplete {
                            unidentified.push(report(
                                "pnpm index.db was only partly read (row or time limit); the rest was not scanned".to_string(),
                                1,
                            ));
                        }
                        if db.wal_unread {
                            unidentified.push(report(
                                "pnpm index.db has write-ahead-log or journal entries that could not be read; recently installed packages may be missing".to_string(),
                                1,
                            ));
                        }
                    }
                    Err(reason) => unidentified.push(report(reason.to_string(), 1)),
                }
                continue;
            }
            if let Some(id) = crate::providers::package_id(kind, &path) {
                let key = (id.ecosystem, id.name.clone(), id.version.clone());
                if seen.insert(key) {
                    packages.push((path.to_path_buf(), id));
                }
            } else if kind == crate::tree::node::CacheKind::Npm
                && let Some(reason) = crate::providers::npm::unidentified_reason(&path)
                && unidentified_paths.insert(path.to_path_buf())
            {
                unidentified.push(UnidentifiedManifest {
                    path: path.to_path_buf(),
                    reason: reason.describe().to_string(),
                    count: 1,
                });
            }
        }
    }
    Discovery {
        packages,
        unidentified,
    }
}

/// Discover packages for a scan and tell the UI at once what was skipped, plus
/// that count, for the caller to put in the scan's own outcome. The early
/// message is feedback while the network answers; the outcome's copy is what the
/// final summary uses, so overlapping scans cannot swap their counts.
fn discover_for_scan(
    roots: &[PathBuf],
    tx: &mpsc::Sender<ScanResult>,
) -> (Vec<(PathBuf, crate::providers::PackageId)>, usize) {
    let found = discover(roots);
    let skipped = unidentified_total(&found.unidentified);
    if skipped > 0 {
        send_result(tx, ScanResult::ManifestsUnidentified(skipped));
    }
    (found.packages, skipped)
}

/// Build a rayon-based thread pool with bounded parallelism.
fn build_pool(max_threads: usize) -> rayon::ThreadPool {
    ThreadPoolBuilder::new()
        .num_threads(max_threads)
        .thread_name(|i| format!("ccmd-scan-{i}"))
        .build()
        .expect("rayon pool build should not fail")
}

/// Helper: send a result, logging instead of silently dropping.
fn send_result<T>(tx: &mpsc::Sender<T>, result: T) {
    if tx.send(result).is_err() {
        eprintln!("scanner: result channel closed, receiver dropped");
    }
}

/// Start the scanner worker thread.
/// `shutdown` is an optional externally-controlled flag; when set to true, the
/// worker stops processing new requests and exits cleanly.
/// If `None`, the scanner runs indefinitely (no shutdown signal).
/// Returns the request tx handle.
///
/// `policy` is the outbound privacy policy (#95): packages it marks private are
/// never sent to OSV or a registry. It is a required argument so no caller can
/// start a scanner that discloses everything by omission; pass
/// `PrivacyPolicy::default()` to say that on purpose.
pub fn start_with_policy(
    result_tx: mpsc::Sender<ScanResult>,
    shutdown: Option<Arc<AtomicBool>>,
    policy: PrivacyPolicy,
) -> mpsc::Sender<ScanRequest> {
    let (request_tx, request_rx) = mpsc::channel::<ScanRequest>();

    // Bounded pool: 8 threads max.
    // This prevents thread explosion when the UI sends rapid requests.
    let pool = build_pool(8);

    std::thread::spawn(move || {
        worker_loop(
            request_rx,
            result_tx,
            Some(pool),
            shutdown.clone(),
            Arc::new(policy),
        );
    });

    request_tx
}

fn worker_loop(
    request_rx: mpsc::Receiver<ScanRequest>,
    result_tx: mpsc::Sender<ScanResult>,
    pool: Option<ThreadPool>,
    shutdown: Option<Arc<AtomicBool>>,
    policy: Arc<PrivacyPolicy>,
) {
    while let Ok(request) = request_rx.recv() {
        // Check shutdown flag before processing each request.
        if let Some(ref flag) = shutdown
            && flag.load(Ordering::Relaxed)
        {
            break;
        }
        match request {
            ScanRequest::ScanRoots(roots) => {
                let mut nodes = Vec::new();
                for root in &roots {
                    if !root.exists() {
                        continue;
                    }
                    let mut node = TreeNode::root(root.clone());
                    node.last_modified = root.metadata().ok().and_then(|m| m.modified().ok());
                    nodes.push(node);
                }
                send_result(&result_tx, ScanResult::RootsScanned(nodes));

                if let Some(ref pool) = pool {
                    for root in roots {
                        if !root.exists() {
                            continue;
                        }
                        let tx = result_tx.clone();
                        pool.spawn(move || {
                            let size = walker::dir_size(&root);
                            send_result(&tx, ScanResult::SizeUpdated(root, size));
                        });
                    }
                } else {
                    for root in roots {
                        if !root.exists() {
                            continue;
                        }
                        let tx = result_tx.clone();
                        std::thread::spawn(move || {
                            let size = walker::dir_size(&root);
                            send_result(&tx, ScanResult::SizeUpdated(root, size));
                        });
                    }
                }
            }
            ScanRequest::ScanVulns(roots) => {
                let tx = result_tx.clone();
                let policy = Arc::clone(&policy);
                if let Some(ref pool) = pool {
                    pool.spawn(move || {
                        let cache = crate::security::cache::default_paths().map(|(v, _)| v);
                        run_vuln_scan(&roots, &tx, &policy, cache.as_deref());
                    });
                } else {
                    std::thread::spawn(move || {
                        let cache = crate::security::cache::default_paths().map(|(v, _)| v);
                        run_vuln_scan(&roots, &tx, &policy, cache.as_deref());
                    });
                }
            }
            ScanRequest::CheckVersions(roots) => {
                let tx = result_tx.clone();
                let policy = Arc::clone(&policy);
                if let Some(ref pool) = pool {
                    pool.spawn(move || {
                        let cache = crate::security::cache::default_paths().map(|(_, v)| v);
                        run_version_check(&roots, &tx, &policy, cache.as_deref());
                    });
                } else {
                    std::thread::spawn(move || {
                        let cache = crate::security::cache::default_paths().map(|(_, v)| v);
                        run_version_check(&roots, &tx, &policy, cache.as_deref());
                    });
                }
            }
            ScanRequest::BrewOutdated => {
                let tx = result_tx.clone();
                if let Some(ref pool) = pool {
                    pool.spawn(move || {
                        let results = run_brew_outdated();
                        send_result(&tx, ScanResult::BrewOutdatedCompleted(results));
                    });
                } else {
                    std::thread::spawn(move || {
                        let results = run_brew_outdated();
                        send_result(&tx, ScanResult::BrewOutdatedCompleted(results));
                    });
                }
            }
            ScanRequest::ExpandNode(path) => {
                let (children, deferred) = expand(&path);

                send_result(
                    &result_tx,
                    ScanResult::ChildrenScanned(path.clone(), children),
                );

                if let Some(ref pool) = pool {
                    for child_path in deferred {
                        let tx = result_tx.clone();
                        pool.spawn(move || {
                            let size = walker::dir_size(&child_path);
                            send_result(&tx, ScanResult::SizeUpdated(child_path, size));
                        });
                    }
                } else {
                    for child_path in deferred {
                        let tx = result_tx.clone();
                        std::thread::spawn(move || {
                            let size = walker::dir_size(&child_path);
                            send_result(&tx, ScanResult::SizeUpdated(child_path, size));
                        });
                    }
                }
            }
        }
    }
}

/// The children of `path` as tree nodes, and the children whose size was too
/// large for `quick_size` and must be measured in the background.
///
/// A child that is a symlink is a leaf (#93): listed so the user sees it, but
/// never classified, named or sized through its target, and never queued for a
/// size walk. `path` itself may be a link (a root the user named).
pub fn expand(path: &std::path::Path) -> (Vec<TreeNode>, Vec<PathBuf>) {
    let children_paths = walker::list_children(path);
    let mut children: Vec<TreeNode> = children_paths
        .iter()
        .map(|child_path| {
            let mut node = TreeNode::new(child_path.clone(), 0, None);
            if walker::is_symlink(child_path) {
                node.last_modified = std::fs::symlink_metadata(child_path)
                    .ok()
                    .and_then(|m| m.modified().ok());
                return node;
            }
            node.last_modified = child_path.metadata().ok().and_then(|m| m.modified().ok());
            node.kind = providers::detect(child_path);
            if let Some(semantic) = providers::semantic_name(node.kind, child_path) {
                node.name = semantic;
            }
            node
        })
        .collect();

    let mut deferred: Vec<PathBuf> = Vec::new();
    for (i, child_path) in children_paths.iter().enumerate() {
        if walker::is_symlink(child_path) {
            continue; // size stays 0: a link is not its target's bytes
        }
        if let Some(size) = walker::quick_size(child_path) {
            children[i].size = size;
        } else {
            deferred.push(child_path.clone());
        }
    }
    (children, deferred)
}

/// One vulnerability scan: discover, tell the UI what discovery skipped, query
/// OSV (through the cache at `cache_path`, if any) and send the outcome.
fn run_vuln_scan(
    roots: &[PathBuf],
    tx: &mpsc::Sender<ScanResult>,
    policy: &PrivacyPolicy,
    cache_path: Option<&std::path::Path>,
) {
    let (packages, unidentified) = discover_for_scan(roots, tx);
    let count = packages.len();
    let outcome = match cache_path {
        Some(p) => {
            let mut c = crate::security::cache::VulnCache::load(p);
            let out = crate::security::scan_vulns_with_cache(&packages, &mut c, policy);
            c.prune_expired(now_secs());
            if let Err(e) = c.save(p) {
                eprintln!("warning: could not save vuln cache: {e}");
            }
            out
        }
        None => crate::security::scan_vulns(&packages, policy),
    };
    let mut outcome = outcome;
    outcome.unidentified_manifests = unidentified;
    send_result(tx, ScanResult::VulnsScanned(count, outcome));
}

/// One version check; see [`run_vuln_scan`].
fn run_version_check(
    roots: &[PathBuf],
    tx: &mpsc::Sender<ScanResult>,
    policy: &PrivacyPolicy,
    cache_path: Option<&std::path::Path>,
) {
    let (packages, unidentified) = discover_for_scan(roots, tx);
    let count = packages.len();
    let outcome = match cache_path {
        Some(p) => {
            let mut c = crate::security::cache::VersionCache::load(p);
            let out = crate::security::check_versions_with_cache(&packages, &mut c, policy);
            c.prune_expired(now_secs());
            if let Err(e) = c.save(p) {
                eprintln!("warning: could not save version cache: {e}");
            }
            out
        }
        None => crate::security::check_versions(&packages, policy),
    };
    let mut outcome = outcome;
    outcome.unidentified_manifests = unidentified;
    send_result(tx, ScanResult::VersionsChecked(count, outcome));
}

fn run_brew_outdated()
-> std::collections::HashMap<String, crate::providers::homebrew::BrewOutdatedEntry> {
    let output = match std::process::Command::new("brew")
        .args(["outdated", "--json=v2"])
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output()
    {
        Ok(o) => o,
        Err(_) => return std::collections::HashMap::new(),
    };
    if !output.status.success() {
        return std::collections::HashMap::new();
    }
    // L1: brew's JSON output is always UTF-8; if it isn't, we have a locale
    // or brew-version problem and should return empty rather than
    // silently replacing bytes with U+FFFD (which then fails JSON parse
    // and masquerades as "no outdated packages").
    let Ok(stdout) = std::str::from_utf8(&output.stdout) else {
        return std::collections::HashMap::new();
    };
    crate::providers::homebrew::parse_brew_outdated(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_result_logs_on_dropped_receiver() {
        let (tx, rx) = mpsc::channel::<ScanResult>();
        drop(rx); // drop receiver
        // Should log, not panic
        send_result(&tx, ScanResult::RootsScanned(vec![]));
    }

    fn npx_modules(tmp: &std::path::Path) -> PathBuf {
        let m = tmp.join(".npm/_npx/abc/node_modules");
        std::fs::create_dir_all(&m).unwrap();
        m
    }

    #[test]
    fn discover_reports_npm_package_dirs_it_could_not_identify() {
        // #117: these used to vanish, so the package looked absent or clean.
        let tmp = tempfile::tempdir().unwrap();
        let m = npx_modules(tmp.path());
        let write = |rel: &str, json: Option<&str>| {
            std::fs::create_dir_all(m.join(rel)).unwrap();
            if let Some(j) = json {
                std::fs::write(m.join(rel).join("package.json"), j).unwrap();
            }
        };
        write("good", Some(r#"{"name":"good","version":"1.0.0"}"#));
        write("malformed", Some("{oops"));
        write("nomanifest", None);
        write("badname", Some(r#"{"name":"../x","version":"1.0.0"}"#));
        write("@acme/scoped", Some("{"));
        write(".bin", None); // not a package

        let found = discover(&[tmp.path().join(".npm")]);

        let ids: Vec<_> = found
            .packages
            .iter()
            .map(|(_, id)| id.name.as_str())
            .collect();
        assert_eq!(ids, vec!["good"]);
        let mut got: Vec<_> = found
            .unidentified
            .iter()
            .map(|u| {
                (
                    u.path.file_name().unwrap().to_str().unwrap().to_string(),
                    u.reason.as_str(),
                )
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                (
                    "badname".to_string(),
                    "package.json name is not a valid npm name"
                ),
                ("malformed".to_string(), "package.json is not valid JSON"),
                ("nomanifest".to_string(), "no package.json"),
                ("scoped".to_string(), "package.json is not valid JSON"),
            ]
        );
    }

    #[test]
    fn overlapping_roots_do_not_count_a_broken_package_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let m = npx_modules(tmp.path());
        std::fs::create_dir_all(m.join("bad")).unwrap();
        // `.npm` and `.npm/_npx` contain the same directory.
        let found = discover(&[tmp.path().join(".npm"), tmp.path().join(".npm/_npx")]);
        assert_eq!(found.unidentified.len(), 1, "{:?}", found.unidentified);
    }

    #[test]
    fn discover_packages_is_discover_without_the_report() {
        let tmp = tempfile::tempdir().unwrap();
        let m = npx_modules(tmp.path());
        std::fs::create_dir_all(m.join("bad")).unwrap();
        let roots = [tmp.path().join(".npm")];
        assert_eq!(
            discover_packages(&roots).len(),
            discover(&roots).packages.len()
        );
    }

    #[test]
    fn a_scan_tells_the_ui_how_many_manifests_it_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let m = npx_modules(tmp.path());
        std::fs::create_dir_all(m.join("bad")).unwrap();
        let (tx, rx) = mpsc::channel();
        let (packages, skipped) = discover_for_scan(&[tmp.path().join(".npm")], &tx);
        assert!(packages.is_empty());
        assert_eq!(skipped, 1, "the caller needs the count for the outcome");
        assert!(matches!(
            rx.try_recv(),
            Ok(ScanResult::ManifestsUnidentified(1))
        ));
        // Nothing skipped: nothing to say early.
        let empty = tempfile::tempdir().unwrap();
        discover_for_scan(&[empty.path().to_path_buf()], &tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_vuln_scan_reports_skipped_manifests_before_its_outcome() {
        // The wiring that matters for #117: a scan must say what discovery
        // skipped. Only a broken manifest exists, so no request is made.
        let tmp = tempfile::tempdir().unwrap();
        let m = npx_modules(tmp.path());
        std::fs::create_dir_all(m.join("bad")).unwrap();
        let (tx, rx) = mpsc::channel();
        run_vuln_scan(
            &[tmp.path().join(".npm")],
            &tx,
            &PrivacyPolicy::default(),
            None,
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(ScanResult::ManifestsUnidentified(1))
        ));
        // The outcome carries the same count, for the summary that follows.
        match rx.try_recv() {
            Ok(ScanResult::VulnsScanned(0, outcome)) => {
                assert_eq!(outcome.unidentified_manifests, 1)
            }
            _ => panic!("expected the vuln outcome"),
        }
    }

    #[test]
    fn a_version_check_reports_skipped_manifests_too() {
        let tmp = tempfile::tempdir().unwrap();
        let m = npx_modules(tmp.path());
        std::fs::create_dir_all(m.join("bad")).unwrap();
        let (tx, rx) = mpsc::channel();
        run_version_check(
            &[tmp.path().join(".npm")],
            &tx,
            &PrivacyPolicy::default(),
            None,
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(ScanResult::ManifestsUnidentified(1))
        ));
        match rx.try_recv() {
            Ok(ScanResult::VersionsChecked(0, outcome)) => {
                assert_eq!(outcome.unidentified_manifests, 1)
            }
            _ => panic!("expected the version outcome"),
        }
    }

    const REAL_INDEX_DB: &[u8] = include_bytes!("../providers/testdata/pnpm11-index.db");

    /// `<tmp>/pnpm/store/v11/index.db`, a layout `detect` classifies as pnpm.
    fn pnpm11_store(tmp: &std::path::Path, db: &[u8]) -> PathBuf {
        let v11 = tmp.join("pnpm/store/v11");
        std::fs::create_dir_all(v11.join("files")).unwrap();
        std::fs::write(v11.join("index.db"), db).unwrap();
        v11.join("index.db")
    }

    #[test]
    fn discover_finds_packages_in_a_pnpm_11_index_db() {
        // #39: with the JSON index gone, global-store packages were no longer
        // identified, so they were never scanned for vulnerabilities.
        let tmp = tempfile::tempdir().unwrap();
        let db = pnpm11_store(tmp.path(), REAL_INDEX_DB);
        let found = discover(&[tmp.path().join("pnpm")]);
        let mut ids: Vec<_> = found
            .packages
            .iter()
            .map(|(_, id)| format!("{}@{}", id.name, id.version))
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["@babel/helper-string-parser@7.25.9", "left-pad@1.3.0"]
        );
        assert!(found.unidentified.is_empty());
        // They are addressed under the index.db node, so a result for one rolls
        // up to it and to every folder above.
        assert!(
            found
                .packages
                .iter()
                .all(|(p, _)| p.parent() == Some(db.as_path()))
        );
    }

    #[test]
    fn an_unreadable_pnpm_index_db_is_reported_not_silently_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        pnpm11_store(tmp.path(), b"not a database");
        let found = discover(&[tmp.path().join("pnpm")]);
        assert!(found.packages.is_empty());
        assert_eq!(found.unidentified.len(), 1, "{:?}", found.unidentified);
        assert!(found.unidentified[0].reason.contains("index.db"));
    }

    #[test]
    fn an_index_db_with_unusable_rows_is_reported_once() {
        let tmp = tempfile::tempdir().unwrap();
        let db = pnpm11_store(tmp.path(), b"");
        std::fs::remove_file(&db).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             INSERT INTO package_index VALUES ('sha512-a\tleft-pad@1.3.0', x'00');
             INSERT INTO package_index VALUES ('sha512-b\thttps://codeload.github.com/a/b/tar.gz/c', x'00');
             INSERT INTO package_index VALUES ('sha512-c\tgit+ssh://x/y', x'00');",
        )
        .unwrap();
        drop(conn);
        let found = discover(&[tmp.path().join("pnpm")]);
        assert_eq!(found.packages.len(), 1);
        assert_eq!(found.unidentified.len(), 1, "one entry per database");
        assert!(
            found.unidentified[0]
                .reason
                .contains("2 entries without a registry name")
        );
        // ...but it stands for every row it could not use, so the count a scan
        // reports is not understated.
        assert_eq!(unidentified_total(&found.unidentified), 2);
        // Walked twice through overlapping roots: still once.
        let twice = discover(&[tmp.path().join("pnpm"), tmp.path().join("pnpm/store")]);
        assert_eq!(twice.unidentified.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn unread_write_ahead_log_entries_are_reported_by_discover() {
        // The reader flags them; the scan must pass that on, or the packages
        // installed since the last checkpoint look clean.
        use std::os::unix::fs::PermissionsExt;
        let live = tempfile::tempdir().unwrap();
        let db = live.path().join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;",
        )
        .unwrap();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        conn.execute(
            "INSERT INTO package_index VALUES ('sha512-a\tleft-pad@1.3.0', x'00')",
            [],
        )
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let v11 = tmp.path().join("pnpm/store/v11");
        std::fs::create_dir_all(&v11).unwrap();
        for f in ["index.db", "index.db-wal"] {
            std::fs::copy(live.path().join(f), v11.join(f)).unwrap();
        }
        std::fs::set_permissions(&v11, std::fs::Permissions::from_mode(0o555)).unwrap();
        let found = discover(&[tmp.path().join("pnpm")]);
        std::fs::set_permissions(&v11, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(found.packages.is_empty(), "the row is only in the log");
        assert_eq!(found.unidentified.len(), 1, "{:?}", found.unidentified);
        assert!(found.unidentified[0].reason.contains("write-ahead-log"));
    }

    #[test]
    fn a_store_over_the_row_cap_is_scanned_in_part_and_says_so() {
        // A valid store a little over the cap must not read as an empty, clean
        // one: the packages read are scanned, and the rest is reported.
        let cap = crate::providers::pnpm::MAX_INDEX_ROWS;
        let tmp = tempfile::tempdir().unwrap();
        let db = pnpm11_store(tmp.path(), b"");
        std::fs::remove_file(&db).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < {})
             INSERT INTO package_index SELECT 'sha512-x\tp' || i || '@1.0.0', x'00' FROM n;",
            cap + 1
        ))
        .unwrap();
        drop(conn);
        let found = discover(&[tmp.path().join("pnpm")]);
        assert_eq!(found.packages.len(), cap, "the prefix is scanned");
        assert_eq!(found.unidentified.len(), 1, "{:?}", found.unidentified);
        assert!(found.unidentified[0].reason.contains("only partly read"));
    }

    #[test]
    fn a_pnpm_store_in_a_custom_location_is_recognised_by_its_layout() {
        // `pnpm store path` can be anywhere (`/tmp/pkg-cache/v11`), so the
        // directory names say nothing. The layout does: `v<N>/index.db` with a
        // `files/` directory beside it.
        let tmp = tempfile::tempdir().unwrap();
        let v11 = tmp.path().join("pkg-cache/v11");
        std::fs::create_dir_all(v11.join("files/ab")).unwrap();
        std::fs::write(v11.join("index.db"), REAL_INDEX_DB).unwrap();
        let found = discover(&[tmp.path().join("pkg-cache")]);
        assert_eq!(found.packages.len(), 2, "{:?}", found.unidentified);
        // Their virtual paths classify as pnpm too, so MCP can name them.
        let (path, id) = &found.packages[0];
        assert_eq!(
            crate::providers::package_id(crate::providers::detect(path), path).as_ref(),
            Some(id)
        );
    }

    #[test]
    fn a_v_directory_without_the_pnpm_layout_is_not_a_store() {
        let tmp = tempfile::tempdir().unwrap();
        let v11 = tmp.path().join("app/v11");
        std::fs::create_dir_all(&v11).unwrap();
        std::fs::write(v11.join("index.db"), REAL_INDEX_DB).unwrap(); // no files/
        let found = discover(&[tmp.path().to_path_buf()]);
        assert!(found.packages.is_empty() && found.unidentified.is_empty());
    }

    #[test]
    fn an_index_db_outside_a_pnpm_store_is_not_read() {
        // Plenty of tools have a file called index.db.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("some-app/cache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.db"), REAL_INDEX_DB).unwrap();
        let found = discover(&[tmp.path().to_path_buf()]);
        assert!(found.packages.is_empty() && found.unidentified.is_empty());
    }

    #[test]
    fn the_same_package_in_two_overlapping_roots_is_found_once() {
        let tmp = tempfile::tempdir().unwrap();
        pnpm11_store(tmp.path(), REAL_INDEX_DB);
        let found = discover(&[tmp.path().join("pnpm"), tmp.path().join("pnpm/store")]);
        assert_eq!(found.packages.len(), 2);
    }

    #[test]
    fn discover_packages_dedup_poetry_same_wheel_two_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("pypoetry").join("artifacts");
        let p1 = base.join("aa").join("11");
        let p2 = base.join("bb").join("22");
        std::fs::create_dir_all(&p1).unwrap();
        std::fs::create_dir_all(&p2).unwrap();
        let w = "requests-2.31.0-py3-none-any.whl";
        std::fs::write(p1.join(w), "").unwrap();
        std::fs::write(p2.join(w), "").unwrap();
        let roots = vec![tmp.path().to_path_buf()];
        let packs = discover_packages(&roots);
        assert_eq!(
            packs.len(),
            1,
            "same PyPI (name, version) from two artifact paths should dedup: {packs:?}"
        );
    }
}
