use super::MetadataField;
use std::path::Path;

/// Returns true if the path is within a known pnpm cache/store location.
#[allow(dead_code)]
pub fn is_pnpm_cache(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".pnpm-store")
        || path_str.contains("pnpm/store")
        || path_str.contains("node_modules/.pnpm")
}

/// Returns true if the path is within the pnpm virtual store (node_modules/.pnpm).
pub fn is_pnpm_virtual_store(path: &Path) -> bool {
    path.to_string_lossy().contains("node_modules/.pnpm")
}

/// Parse a pnpm virtual store directory name into (name, version).
///
/// Examples:
/// - `"lodash@4.17.21"` → `("lodash", "4.17.21")`
/// - `"@babel+core@7.24.0"` → `("@babel/core", "7.24.0")`
/// - `"@types+node@22.0.0"` → `("@types/node", "22.0.0")`
/// - `"react-dom@18.2.0_react@18.2.0"` → `("react-dom", "18.2.0")`
pub fn parse_virtual_store_name(dir_name: &str) -> Option<(String, String)> {
    // pnpm v9+ appends peer dependency info after '_':
    // e.g., "react-dom@18.2.0_react@18.2.0"
    // Strip everything after the first '_' that follows a version.
    let base = strip_peer_deps(dir_name);

    // Find the last '@' which separates name from version
    let at_pos = base.rfind('@')?;
    let version = &base[at_pos + 1..];

    if version.is_empty() {
        return None;
    }

    let raw_name = &base[..at_pos];
    if raw_name.is_empty() {
        return None;
    }

    // Convert '+' back to '/' for scoped packages: @babel+core → @babel/core
    let name = raw_name.replace('+', "/");

    // Reject degenerate names like bare "@"
    if name == "@" {
        return None;
    }

    Some((name, version.to_string()))
}

/// Strip peer dependency suffix from a pnpm virtual store directory name.
/// pnpm uses '_' to separate the base package from peer deps:
/// `react-dom@18.2.0_react@18.2.0` → `react-dom@18.2.0`
/// But scoped packages use '+' not '_' for the scope separator,
/// so `_` always indicates peer deps in practice.
fn strip_peer_deps(dir_name: &str) -> &str {
    // Find the version '@': for scoped packages, skip the leading '@'
    let search_start = if let Some(after_at) = dir_name.strip_prefix('@') {
        // Find the second '@' (version delimiter)
        match after_at.find('@') {
            Some(pos) => pos + 1, // position in dir_name
            None => return dir_name,
        }
    } else {
        match dir_name.find('@') {
            Some(pos) => pos,
            None => return dir_name,
        }
    };

    // Now look for '_' after the version '@'
    match dir_name[search_start..].find('_') {
        Some(pos) => &dir_name[..search_start + pos],
        None => dir_name,
    }
}

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let path_str = path.to_string_lossy();

    // Top-level store directories
    if name == ".pnpm-store" {
        return Some("pnpm Content Store".to_string());
    }

    if name == ".pnpm" {
        return Some("pnpm Virtual Store".to_string());
    }

    // Subdirectories inside the content store
    if path_str.contains(".pnpm-store") || path_str.contains("pnpm/store") {
        if let Some(version) = name.strip_prefix('v')
            && version.chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("Store v{version}"));
        }
        if name == "files" {
            return Some("Content Files".to_string());
        }
        if name == "index" {
            return Some("Package Index".to_string());
        }
        // pnpm 11 (store v11): the JSON index dir was replaced by a single
        // SQLite database plus its WAL/SHM sidecars. Its packages are read by
        // `read_index_db` (#39).
        if matches!(name.as_str(), "index.db" | "index.db-wal" | "index.db-shm") {
            return Some("Package Index (SQLite)".to_string());
        }
    }

    // Index files: {hash}-name@version.json → "name version"
    if name.ends_with(".json")
        && path_str.contains("/index/")
        && let Some(id) = parse_index_filename(&name)
    {
        return Some(format!("{} {}", id.name, id.version));
    }

    // Virtual store entries: name@version directories
    if name.contains('@')
        && is_pnpm_virtual_store(path)
        && let Some((pkg, ver)) = parse_virtual_store_name(&name)
    {
        return Some(format!("{} {}", pkg, ver));
    }

    None
}

pub fn package_id(path: &Path) -> Option<super::PackageId> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // pnpm 11: a package recorded inside `index.db`, addressed as the virtual
    // path `<store>/index.db/<name>@<version>` (see `index_entry_path`).
    // The parent must be the database FILE, not just something named `index.db`.
    if path
        .parent()
        .is_some_and(|p| p.file_name().is_some_and(|n| n == "index.db") && p.is_file())
    {
        return parse_index_entry_name(&name);
    }

    // pnpm v10 index files: {hash}-{name}@{version}.json
    if name.ends_with(".json") {
        let path_str = path.to_string_lossy();
        if path_str.contains("/index/") {
            return parse_index_filename(&name);
        }
    }

    // Virtual store entries: name@version directories
    if is_pnpm_virtual_store(path) && name.contains('@') {
        let (pkg, ver) = parse_virtual_store_name(&name)?;
        if ver.starts_with(|c: char| c.is_ascii_digit()) {
            return Some(super::PackageId {
                ecosystem: "npm",
                name: pkg,
                version: ver,
            });
        }
    }

    None
}

/// Parse a pnpm v10 index filename into a PackageId.
///
/// Format: `{62-hex-chars}-{name}@{version}.json`
/// Scoped: `{62-hex-chars}-@{scope}+{name}@{version}.json`
///
/// The filename hash is 62 hex chars (the parent directory has the first 2,
/// making 64 total = SHA-256).
fn parse_index_filename(filename: &str) -> Option<super::PackageId> {
    let base = filename.strip_suffix(".json")?;

    // The hash is 62 hex chars, followed by '-', then the package spec.
    // Validate and skip the hash prefix. The byte-indexed slicing below is
    // safe only if the first 63 bytes are ASCII — guard against multi-byte
    // chars landing on byte 62 (would otherwise panic at the slice).
    if base.len() < 64 || !base.is_char_boundary(62) || !base.is_char_boundary(63) {
        return None;
    }
    let hash_part = &base[..62];
    if !hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if base.as_bytes()[62] != b'-' {
        return None;
    }
    let spec = &base[63..]; // "name@version" or "@scope+name@version"

    // Find the last '@' which separates name from version
    let at_pos = spec.rfind('@')?;
    let version = &spec[at_pos + 1..];
    if version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }

    let raw_name = &spec[..at_pos];
    if raw_name.is_empty() {
        return None;
    }

    // Only replace '+' with '/' for scoped packages (@scope+name → @scope/name)
    let name = if raw_name.starts_with('@') {
        if let Some(pos) = raw_name.find('+') {
            format!("{}/{}", &raw_name[..pos], &raw_name[pos + 1..])
        } else {
            raw_name.to_string()
        }
    } else {
        raw_name.to_string()
    };

    Some(super::PackageId {
        ecosystem: "npm",
        name,
        version: version.to_string(),
    })
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let path_str = path.to_string_lossy();

    // Top-level store and virtual store dirs: count entries
    if name == ".pnpm-store" || name == ".pnpm" {
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.filter_map(|e| e.ok()).count();
            fields.push(MetadataField {
                label: "Entries".to_string(),
                value: count.to_string(),
            });
        }
        return fields;
    }

    // Inside content store
    if path_str.contains(".pnpm-store") || path_str.contains("pnpm/store") {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Content-addressed store".to_string(),
        });
        return fields;
    }

    // Virtual store entries with @
    if name.contains('@') && is_pnpm_virtual_store(path) {
        fields.push(MetadataField {
            label: "Type".to_string(),
            value: "Virtual store entry".to_string(),
        });
        return fields;
    }

    fields
}

/// What `read_index_db` found in a pnpm 11 `index.db`.
#[derive(Debug, Default)]
pub struct IndexDb {
    pub packages: Vec<super::PackageId>,
    /// Rows whose key is not a registry `name@version` (git or tarball URL
    /// dependencies, or a key shape this reader does not know). They are not
    /// scanned, so the caller must say so.
    pub unusable_keys: usize,
    /// A write-ahead log with content sits beside the database but could not be
    /// read, so packages pnpm installed recently may be missing. The caller must
    /// say so: they would otherwise look clean.
    pub wal_unread: bool,
    /// Reading stopped at the row or time limit. The packages read are kept; the
    /// rest were not scanned, which the caller must say, so a valid store just
    /// over the limit does not read as an empty one.
    pub incomplete: bool,
}

/// How much of an `index.db` we are willing to read. The file comes from a
/// cache directory, so a crafted one must not be able to hang or exhaust a scan.
#[derive(Debug, Clone, Copy)]
struct IndexLimits {
    max_rows: usize,
    max_time: std::time::Duration,
}

/// Rows read from an `index.db` before the rest is left unscanned.
pub const MAX_INDEX_ROWS: usize = 250_000;

const INDEX_LIMITS: IndexLimits = IndexLimits {
    // pnpm stores hold tens of thousands of packages at most.
    max_rows: MAX_INDEX_ROWS,
    max_time: std::time::Duration::from_secs(20),
};

/// The packages recorded in a pnpm 11 store's `index.db` (#39).
///
/// pnpm 11 replaced the JSON index directory with one SQLite database. Each row
/// of `package_index` is keyed `<integrity>\t<name>@<version>`, so the identity
/// is in the key and the MessagePack blob is never decoded. Every name and
/// version is validated as npm coordinates, as for a `package.json`: the file is
/// cache content anyone can write.
///
/// The file is untrusted, so reading is bounded (rows and time), `package_index`
/// must be a real table (not a view that runs a query of its choosing), and
/// `trusted_schema` is off.
///
/// Opening never writes into the store when it can be avoided. With no
/// write-ahead log beside the database it is opened `immutable`, which touches
/// nothing and is complete. With one, a plain read-only open is used so its
/// rows are seen; if that is refused (it may need to create `-shm`), the
/// `immutable` open reads the main file only and `wal_unread` is set.
///
/// The error is a short reason for the report of what could not be scanned.
pub fn read_index_db(db: &Path) -> Result<IndexDb, &'static str> {
    read_index_db_with(db, INDEX_LIMITS)
}

fn read_index_db_with(db: &Path, limits: IndexLimits) -> Result<IndexDb, &'static str> {
    use rusqlite::{Connection, OpenFlags};

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    // Opening is lazy: reading the schema is what touches the `-shm` file, so
    // that is the probe for "this open works".
    let probe = |c: Connection| -> rusqlite::Result<Connection> {
        c.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        Ok(c)
    };
    let open_immutable = || {
        // `immutable=1` needs a URI; percent-encode what a path can hold.
        let mut uri = String::from("file:");
        for b in db.to_string_lossy().bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                    uri.push(b as char)
                }
                _ => uri.push_str(&format!("%{b:02X}")),
            }
        }
        uri.push_str("?immutable=1");
        Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI).and_then(probe)
    };

    let mut wal = db.as_os_str().to_os_string();
    wal.push("-wal");
    let wal_len = std::fs::metadata(std::path::PathBuf::from(wal)).map_or(0, |m| m.len());

    let (mut conn, immutable) = if wal_len == 0 {
        (open_immutable(), true)
    } else {
        match Connection::open_with_flags(db, flags).and_then(probe) {
            Ok(c) => (Ok(c), false),
            Err(_) => (open_immutable(), true),
        }
    };
    let conn = conn
        .as_mut()
        .map_err(|_| "pnpm index.db could not be opened")?;
    let wal_unread = immutable && wal_len > 0;

    // Untrusted file: no schema-defined functions, and an upper bound on time.
    conn.pragma_update(None, "trusted_schema", false)
        .map_err(|_| "pnpm index.db could not be opened")?;
    let started = std::time::Instant::now();
    let max_time = limits.max_time;
    conn.progress_handler(10_000, Some(move || started.elapsed() > max_time))
        .map_err(|_| "pnpm index.db could not be opened")?;
    let unreadable = |started: std::time::Instant| {
        if started.elapsed() > max_time {
            "pnpm index.db took too long to read"
        } else {
            "pnpm index.db could not be read"
        }
    };

    // A view named package_index would run a query of the file's choosing.
    let kind: Option<String> = conn
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = 'package_index'",
            [],
            |row| row.get(0),
        )
        .ok();
    if kind.as_deref() != Some("table") {
        // With an unread log the table may simply be in it, which is not the
        // same finding as a database that lacks one.
        return Err(if wal_unread {
            "pnpm index.db has write-ahead-log entries that could not be read"
        } else {
            "pnpm index.db has no package_index table"
        });
    }
    let mut stmt = conn
        .prepare("SELECT key FROM package_index")
        .map_err(|_| "pnpm index.db has no package_index table")?;
    let keys = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| unreadable(started))?;

    let mut out = IndexDb {
        wal_unread,
        ..IndexDb::default()
    };
    let mut rows = 0usize;
    for key in keys {
        let key = match key {
            Ok(k) => k,
            // Out of time: keep what was read and say the rest was not.
            Err(_) if started.elapsed() > max_time => {
                out.incomplete = true;
                break;
            }
            Err(_) => return Err("pnpm index.db could not be read"),
        };
        rows += 1;
        if rows > limits.max_rows {
            out.incomplete = true;
            break;
        }
        match parse_index_key(&key) {
            Some(id) => out.packages.push(id),
            None => out.unusable_keys += 1,
        }
    }
    Ok(out)
}

/// `<integrity>\t<name>@<version>` to a package, or `None`.
fn parse_index_key(key: &str) -> Option<super::PackageId> {
    let (_integrity, name_version) = key.split_once('\t')?;
    let (name, version) = name_version.rsplit_once('@')?;
    if !super::npm::is_valid_npm_name(name) || !super::npm::is_valid_npm_version(version) {
        return None;
    }
    Some(super::PackageId {
        ecosystem: "npm",
        name: name.to_string(),
        version: version.to_string(),
    })
}

/// The virtual path a package inside `index.db` is reported under:
/// `<index.db>/<name>@<version>`, with `/` in a scoped name written `%2F`.
/// Results are keyed by path and rolled up through a path's ancestors, so this
/// lights up the `index.db` node and every folder above it, with no node of
/// its own. It does not exist on disk.
pub fn index_entry_path(db: &Path, id: &super::PackageId) -> std::path::PathBuf {
    db.join(format!("{}@{}", id.name.replace('/', "%2F"), id.version))
}

/// Inverse of the last component of [`index_entry_path`].
fn parse_index_entry_name(file_name: &str) -> Option<super::PackageId> {
    let (name, version) = file_name.rsplit_once('@')?;
    let name = name.replace("%2F", "/");
    if !super::npm::is_valid_npm_name(&name) || !super::npm::is_valid_npm_version(version) {
        return None;
    }
    Some(super::PackageId {
        ecosystem: "npm",
        name,
        version: version.to_string(),
    })
}

#[cfg(test)]
mod tests {
    // --- #39: pnpm 11 index.db ---

    /// A store written by pnpm 12.23.0 (`pnpm add left-pad@1.3.0
    /// @babel/helper-string-parser@7.25.9`), so the reader is checked against
    /// the real format and not against one assumed from it.
    const REAL_INDEX_DB: &[u8] = include_bytes!("testdata/pnpm11-index.db");

    fn real_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.db");
        std::fs::write(&db, REAL_INDEX_DB).unwrap();
        (tmp, db)
    }

    fn sorted(db: &IndexDb) -> Vec<(String, String)> {
        let mut v: Vec<_> = db
            .packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn reads_packages_from_a_real_pnpm_11_index_db() {
        let (_t, db) = real_db();
        let found = read_index_db(&db).unwrap();
        assert_eq!(
            sorted(&found),
            vec![
                (
                    "@babel/helper-string-parser".to_string(),
                    "7.25.9".to_string()
                ),
                ("left-pad".to_string(), "1.3.0".to_string()),
            ]
        );
        assert_eq!(found.unusable_keys, 0);
        assert!(found.packages.iter().all(|p| p.ecosystem == "npm"));
    }

    #[cfg(unix)]
    #[test]
    fn reads_a_wal_mode_store_in_a_read_only_directory() {
        // pnpm leaves the database in WAL mode. A plain read-only open needs to
        // create `index.db-shm`, which a read-only directory refuses; the
        // reader must still get the packages.
        use std::os::unix::fs::PermissionsExt;
        let (tmp, db) = real_db();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = read_index_db(&db);
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(sorted(&result.unwrap()).len(), 2);
    }

    #[test]
    fn rows_without_a_registry_name_and_version_are_counted_not_guessed() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;",
        )
        .unwrap();
        let keys = [
            "sha512-aaa\tleft-pad@1.3.0",
            "sha512-bbb\t@scope/pkg@2.0.0-beta.1",
            "sha512-ccc\thttps://codeload.github.com/acme/x/tar.gz/abc", // URL dependency
            "no-tab-at-all@1.0.0",
            "sha512-ddd\t../evil@1.0.0", // not an npm name
            "sha512-eee\tgood@latest",   // not a concrete version
            "sha512-fff\tnoversion",
        ];
        for k in keys {
            conn.execute("INSERT INTO package_index VALUES (?1, x'00')", [k])
                .unwrap();
        }
        drop(conn);
        let found = read_index_db(&db).unwrap();
        assert_eq!(
            sorted(&found),
            vec![
                ("@scope/pkg".to_string(), "2.0.0-beta.1".to_string()),
                ("left-pad".to_string(), "1.3.0".to_string()),
            ]
        );
        assert_eq!(found.unusable_keys, 5);
    }

    #[test]
    fn an_unreadable_index_db_says_why_instead_of_reading_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let not_sqlite = tmp.path().join("index.db");
        std::fs::write(&not_sqlite, b"this is not a database at all").unwrap();
        assert!(read_index_db(&not_sqlite).is_err());
        assert!(read_index_db(&tmp.path().join("missing.db")).is_err());
        // A database from some other format: no package_index table.
        let other = tmp.path().join("other.db");
        let conn = rusqlite::Connection::open(&other).unwrap();
        conn.execute_batch("CREATE TABLE unrelated (x INTEGER);")
            .unwrap();
        drop(conn);
        assert_eq!(
            read_index_db(&other).unwrap_err(),
            "pnpm index.db has no package_index table"
        );
    }

    #[test]
    fn reading_a_clean_store_writes_nothing_into_it() {
        // A scan is read-only. Opening a WAL-mode database the ordinary way
        // creates `-shm` beside it, so with no write-ahead log the file is
        // opened immutable, which touches nothing.
        let (tmp, db) = real_db();
        let listing = |dir: &Path| {
            let mut v: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        let before = listing(tmp.path());
        let found = read_index_db(&db).unwrap();
        assert_eq!(found.packages.len(), 2);
        assert!(!found.wal_unread);
        assert_eq!(listing(tmp.path()), before, "the store gained files");
        assert_eq!(
            std::fs::read(&db).unwrap(),
            REAL_INDEX_DB,
            "and the db changed"
        );
    }

    /// A WAL-mode database with `keys` still in its write-ahead log, held open
    /// by the returned connection (as pnpm would while it runs).
    fn db_with_live_wal(tmp: &Path, keys: &[&str]) -> (std::path::PathBuf, rusqlite::Connection) {
        let db = tmp.join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;",
        )
        .unwrap();
        // The schema is in the main file; only the rows are in the log.
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        for k in keys {
            conn.execute("INSERT INTO package_index VALUES (?1, x'00')", [k])
                .unwrap();
        }
        let wal_len = std::fs::metadata(tmp.join("index.db-wal")).unwrap().len();
        assert!(
            wal_len > 0,
            "the fixture needs rows that exist only in the WAL"
        );
        (db, conn)
    }

    #[test]
    fn rows_that_exist_only_in_the_write_ahead_log_are_read() {
        let tmp = tempfile::tempdir().unwrap();
        let (db, _writer) = db_with_live_wal(tmp.path(), &["sha512-a\tleft-pad@1.3.0"]);
        let found = read_index_db(&db).unwrap();
        assert_eq!(
            sorted(&found),
            vec![("left-pad".to_string(), "1.3.0".to_string())]
        );
        assert!(!found.wal_unread);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_write_ahead_log_is_flagged_not_silently_dropped() {
        // A snapshot of a store pnpm was writing to: the database and its
        // write-ahead log, no `-shm`, in a directory that cannot be written. The
        // plain open must create `-shm`, so it is refused and the immutable
        // fallback reads the main file only. The rows in the WAL are then
        // missing; that must be said, not read as "clean".
        use std::os::unix::fs::PermissionsExt;
        let live = tempfile::tempdir().unwrap();
        let (_db, _writer) = db_with_live_wal(live.path(), &["sha512-a\tleft-pad@1.3.0"]);
        let snap = tempfile::tempdir().unwrap();
        for f in ["index.db", "index.db-wal"] {
            std::fs::copy(live.path().join(f), snap.path().join(f)).unwrap();
        }
        std::fs::set_permissions(snap.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = read_index_db(&snap.path().join("index.db"));
        std::fs::set_permissions(snap.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let found = result.unwrap();
        assert!(found.wal_unread, "unread WAL content must be flagged");
        assert!(found.packages.is_empty(), "the row lives only in the WAL");
    }

    #[cfg(unix)]
    #[test]
    fn a_schema_that_only_exists_in_an_unread_log_is_not_called_missing() {
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
        let snap = tempfile::tempdir().unwrap();
        for f in ["index.db", "index.db-wal"] {
            std::fs::copy(live.path().join(f), snap.path().join(f)).unwrap();
        }
        std::fs::set_permissions(snap.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = read_index_db(&snap.path().join("index.db"));
        std::fs::set_permissions(snap.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            result.unwrap_err(),
            "pnpm index.db has write-ahead-log entries that could not be read"
        );
    }

    #[test]
    fn a_view_named_package_index_is_refused() {
        // A view would run a query of the file's choosing.
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE VIEW package_index AS SELECT 'sha512-a\tleft-pad@1.3.0' AS key;",
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            read_index_db(&db).unwrap_err(),
            "pnpm index.db has no package_index table"
        );
    }

    fn three_row_db(tmp: &Path) -> std::path::PathBuf {
        let db = tmp.join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             INSERT INTO package_index VALUES ('sha512-a\ta@1.0.0', x'00');
             INSERT INTO package_index VALUES ('sha512-b\tb@1.0.0', x'00');
             INSERT INTO package_index VALUES ('sha512-c\tc@1.0.0', x'00');",
        )
        .unwrap();
        db
    }

    #[test]
    fn reading_stops_at_the_row_cap_but_keeps_what_it_read() {
        // A valid store just over the cap must not read as an empty scan: the
        // packages read are kept, and the rest is reported as not scanned.
        let tmp = tempfile::tempdir().unwrap();
        let db = three_row_db(tmp.path());
        let limits = IndexLimits {
            max_rows: 3,
            max_time: INDEX_LIMITS.max_time,
        };
        let all = read_index_db_with(&db, limits).unwrap();
        assert_eq!(all.packages.len(), 3);
        assert!(!all.incomplete, "exactly at the cap is complete");
        let limits = IndexLimits {
            max_rows: 2,
            max_time: INDEX_LIMITS.max_time,
        };
        let part = read_index_db_with(&db, limits).unwrap();
        assert_eq!(part.packages.len(), 2, "the prefix is kept");
        assert!(part.incomplete, "and the rest is flagged as not read");
    }

    #[test]
    fn reading_stops_at_the_time_limit() {
        // The progress handler interrupts a read that runs past its budget.
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 200000)
             INSERT INTO package_index SELECT 'sha512-x\tp' || i || '@1.0.0', x'00' FROM n;",
        )
        .unwrap();
        drop(conn);
        let limits = IndexLimits {
            max_rows: usize::MAX,
            max_time: std::time::Duration::ZERO,
        };
        let part = read_index_db_with(&db, limits).unwrap();
        assert!(part.incomplete, "an interrupted read is flagged");
        assert!(part.packages.len() < 200_000, "and did not read everything");
    }

    #[test]
    fn an_oversized_key_is_unusable() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE package_index (key TEXT PRIMARY KEY, data BLOB NOT NULL) WITHOUT ROWID;",
        )
        .unwrap();
        let huge = format!("sha512-a\t{}@1.0.0", "a".repeat(2048));
        conn.execute("INSERT INTO package_index VALUES (?1, x'00')", [huge])
            .unwrap();
        drop(conn);
        let found = read_index_db(&db).unwrap();
        assert!(found.packages.is_empty());
        assert_eq!(found.unusable_keys, 1);
    }

    #[test]
    fn only_a_real_index_db_file_makes_its_children_packages() {
        // The parent merely being NAMED `index.db` is not enough: a directory
        // of that name, or a path that is not under any such file, must not
        // turn `<name>@<version>` children into packages sent to OSV.
        let tmp = tempfile::tempdir().unwrap();
        let as_dir = tmp.path().join("pnpm/store/v11/index.db");
        std::fs::create_dir_all(&as_dir).unwrap();
        assert_eq!(package_id(&as_dir.join("left-pad@1.3.0")), None);
        std::fs::remove_dir(&as_dir).unwrap();
        std::fs::write(&as_dir, b"").unwrap();
        assert!(package_id(&as_dir.join("left-pad@1.3.0")).is_some());
    }

    #[test]
    fn index_entry_paths_round_trip_through_package_id() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.db");
        std::fs::write(&db, b"").unwrap();
        let db = db.as_path();
        for (name, version) in [("left-pad", "1.3.0"), ("@babel/code-frame", "7.0.0-rc.1")] {
            let id = super::super::PackageId {
                ecosystem: "npm",
                name: name.into(),
                version: version.into(),
            };
            let path = index_entry_path(db, &id);
            assert_eq!(path.parent(), Some(db), "a child of the index.db node");
            assert_eq!(package_id(&path), Some(id));
        }
        // Only children of an `index.db` are read this way.
        assert_eq!(package_id(Path::new("/x/other/left-pad@1.3.0")), None);
        // And what they carry is validated like everything else.
        assert_eq!(package_id(&db.join("..%2Fevil@1.0.0")), None);
        assert_eq!(package_id(&db.join("left-pad@latest")), None);
    }

    use super::*;
    use std::path::PathBuf;

    // --- pnpm 11 SQLite index ---

    #[test]
    fn semantic_name_v11_sqlite_index() {
        for f in ["index.db", "index.db-wal", "index.db-shm"] {
            let path = PathBuf::from(format!("/home/u/.local/share/pnpm/store/v11/{f}"));
            assert_eq!(
                semantic_name(&path),
                Some("Package Index (SQLite)".into()),
                "{f}"
            );
        }
    }

    // --- Detection ---

    #[test]
    fn detects_pnpm_store() {
        assert!(is_pnpm_cache(&PathBuf::from("/home/user/.pnpm-store/v3")));
    }

    #[test]
    fn detects_pnpm_virtual_store() {
        assert!(is_pnpm_cache(&PathBuf::from(
            "/project/node_modules/.pnpm/lodash@4.17.21"
        )));
    }

    #[test]
    fn detects_xdg_pnpm_store() {
        assert!(is_pnpm_cache(&PathBuf::from(
            "/home/user/.local/share/pnpm/store/v3"
        )));
    }

    #[test]
    fn does_not_detect_unrelated_path() {
        assert!(!is_pnpm_cache(&PathBuf::from("/home/user/.npm/_cacache")));
    }

    // --- Parsing ---

    #[test]
    fn parse_unscoped_package() {
        assert_eq!(
            parse_virtual_store_name("lodash@4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
    }

    #[test]
    fn parse_scoped_package() {
        assert_eq!(
            parse_virtual_store_name("@babel+core@7.24.0"),
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
    }

    #[test]
    fn parse_scoped_types() {
        assert_eq!(
            parse_virtual_store_name("@types+node@22.0.0"),
            Some(("@types/node".to_string(), "22.0.0".to_string()))
        );
    }

    #[test]
    fn parse_empty_version_returns_none() {
        assert_eq!(parse_virtual_store_name("lodash@"), None);
    }

    #[test]
    fn parse_no_at_returns_none() {
        assert_eq!(parse_virtual_store_name("lodash"), None);
    }

    // --- Semantic name ---

    #[test]
    fn semantic_name_pnpm_store() {
        let path = PathBuf::from("/home/user/.pnpm-store");
        assert_eq!(semantic_name(&path), Some("pnpm Content Store".into()));
    }

    #[test]
    fn semantic_name_virtual_store() {
        let path = PathBuf::from("/project/node_modules/.pnpm");
        assert_eq!(semantic_name(&path), Some("pnpm Virtual Store".into()));
    }

    #[test]
    fn semantic_name_store_version_v3() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3");
        assert_eq!(semantic_name(&path), Some("Store v3".into()));
    }

    #[test]
    fn semantic_name_store_version_v10() {
        let path = PathBuf::from("/Users/julien/Library/pnpm/store/v10");
        assert_eq!(semantic_name(&path), Some("Store v10".into()));
    }

    #[test]
    fn semantic_name_virtual_store_entry() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        assert_eq!(semantic_name(&path), Some("lodash 4.17.21".into()));
    }

    #[test]
    fn semantic_name_virtual_store_scoped() {
        let path = PathBuf::from("/project/node_modules/.pnpm/@babel+core@7.24.0");
        assert_eq!(semantic_name(&path), Some("@babel/core 7.24.0".into()));
    }

    #[test]
    fn semantic_name_content_files() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3/files");
        assert_eq!(semantic_name(&path), Some("Content Files".into()));
    }

    // --- Package ID ---

    #[test]
    fn package_id_virtual_store_entry() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.21");
    }

    #[test]
    fn package_id_virtual_store_scoped() {
        let path = PathBuf::from("/project/node_modules/.pnpm/@babel+core@7.24.0");
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@babel/core");
        assert_eq!(id.version, "7.24.0");
    }

    #[test]
    fn package_id_content_store_returns_none() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3/files/ab/cd1234");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_pnpm_dir_returns_none() {
        let path = PathBuf::from("/project/node_modules/.pnpm");
        assert_eq!(package_id(&path), None);
    }

    // --- Index file parsing (pnpm v10) ---

    #[test]
    fn package_id_index_unscoped() {
        let path = PathBuf::from(
            "/Users/julien/Library/pnpm/store/v10/index/3e/585d15c8a594e20d7de57b362ea81754c011acb2641a19f1b72c8531ea3982-lodash@4.17.20.json",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "lodash");
        assert_eq!(id.version, "4.17.20");
    }

    #[test]
    fn package_id_index_scoped() {
        let path = PathBuf::from(
            "/Users/julien/Library/pnpm/store/v10/index/0e/0e8c6b62ac09d19bf960ba5290551491972f9f0c0c0ea8c8e35b8f217ffb9b-@babel+template@7.28.6.json",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "@babel/template");
        assert_eq!(id.version, "7.28.6");
    }

    #[test]
    fn package_id_index_hyphenated_name() {
        let path = PathBuf::from(
            "/home/user/.pnpm-store/v3/index/ab/985c96e984d46e95603f151dedf9c0568889ff824f2e522488b9fb7cb8a6c0-is-number-object@1.1.1.json",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.ecosystem, "npm");
        assert_eq!(id.name, "is-number-object");
        assert_eq!(id.version, "1.1.1");
    }

    #[test]
    fn package_id_index_content_files_still_none() {
        let path = PathBuf::from(
            "/Users/julien/Library/pnpm/store/v10/files/61/9a372bcd920fb462ca2d04d4440fa2",
        );
        assert_eq!(package_id(&path), None);
    }

    // --- parse_index_filename rejection cases ---

    #[test]
    fn parse_index_short_hash_returns_none() {
        assert_eq!(parse_index_filename("abcd-lodash@1.0.0.json"), None);
    }

    #[test]
    fn parse_index_non_hex_hash_returns_none() {
        let bad = format!(
            "{}z-lodash@1.0.0.json",
            "g".repeat(61) // 'g' is not a hex digit
        );
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_missing_separator_returns_none() {
        // 62 hex chars followed by 'X' instead of '-'
        let bad = format!("{}Xlodash@1.0.0.json", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_non_numeric_version_returns_none() {
        let bad = format!("{}-lodash@latest.json", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_empty_name_returns_none() {
        let bad = format!("{}-@1.0.0.json", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_no_json_suffix_returns_none() {
        let bad = format!("{}-lodash@1.0.0", "a".repeat(62));
        assert_eq!(parse_index_filename(&bad), None);
    }

    #[test]
    fn parse_index_unscoped_plus_preserved() {
        // A hypothetical unscoped name with '+' should NOT have it replaced
        let filename = format!("{}-c++parser@1.0.0.json", "a".repeat(62));
        let id = parse_index_filename(&filename).unwrap();
        assert_eq!(id.name, "c++parser");
    }

    // --- semantic_name for index ---

    #[test]
    fn semantic_name_package_index_dir() {
        let path = PathBuf::from("/Users/julien/Library/pnpm/store/v10/index");
        assert_eq!(semantic_name(&path), Some("Package Index".into()));
    }

    #[test]
    fn semantic_name_index_file() {
        let path = PathBuf::from(format!(
            "/Users/julien/Library/pnpm/store/v10/index/3e/{}-lodash@4.17.20.json",
            "a".repeat(62)
        ));
        assert_eq!(semantic_name(&path), Some("lodash 4.17.20".into()));
    }

    #[test]
    fn semantic_name_store_version_non_numeric_returns_none() {
        let path = PathBuf::from("/home/user/.pnpm-store/vfoo");
        assert_eq!(semantic_name(&path), None);
    }

    // --- Metadata ---

    #[test]
    fn metadata_pnpm_store_shows_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join(".pnpm-store");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::create_dir_all(store_dir.join("v3")).unwrap();

        let fields = metadata(&store_dir);
        assert!(fields.iter().any(|f| f.label == "Entries"));
    }

    #[test]
    fn metadata_virtual_store_entry_shows_type() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@4.17.21");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Type" && f.value == "Virtual store entry")
        );
    }

    #[test]
    fn metadata_content_store_shows_type() {
        let path = PathBuf::from("/home/user/.pnpm-store/v3/files/ab");
        let fields = metadata(&path);
        assert!(
            fields
                .iter()
                .any(|f| f.label == "Type" && f.value == "Content-addressed store")
        );
    }

    // --- Peer dependency handling ---

    #[test]
    fn parse_with_peer_deps() {
        let (name, ver) = parse_virtual_store_name("react-dom@18.2.0_react@18.2.0").unwrap();
        assert_eq!(name, "react-dom");
        assert_eq!(ver, "18.2.0");
    }

    #[test]
    fn parse_scoped_with_peer_deps() {
        let (name, ver) =
            parse_virtual_store_name("@babel+core@7.24.0_@babel+preset-env@7.24.0").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn parse_with_multiple_peer_deps() {
        let (name, ver) =
            parse_virtual_store_name("eslint-plugin-react@7.35.0_eslint@9.0.0_typescript@5.0.0")
                .unwrap();
        assert_eq!(name, "eslint-plugin-react");
        assert_eq!(ver, "7.35.0");
    }

    #[test]
    fn parse_malformed_at_only() {
        // Just "@" as name — should return None
        assert!(parse_virtual_store_name("@@1.0.0").is_none());
    }

    #[test]
    fn package_id_with_non_numeric_version() {
        // pnpm can have @latest or @next in some contexts
        let path = PathBuf::from("/project/node_modules/.pnpm/lodash@latest");
        assert!(package_id(&path).is_none());
    }

    #[test]
    fn package_id_with_peer_deps() {
        let path = PathBuf::from("/project/node_modules/.pnpm/react-dom@18.2.0_react@18.2.0");
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "react-dom");
        assert_eq!(id.version, "18.2.0");
    }

    #[test]
    fn semantic_name_at_dir_outside_virtual_store() {
        // A directory with @ in name but NOT in node_modules/.pnpm
        let path = PathBuf::from("/home/user/.pnpm-store/v3/foo@1.0.0");
        assert_eq!(semantic_name(&path), None);
    }

    // =================================================================
    // Adversarial tests — designed to break the parsers
    // =================================================================

    // --- parse_virtual_store_name: degenerate inputs ---

    #[test]
    fn parse_just_at_sign() {
        assert_eq!(parse_virtual_store_name("@"), None);
    }

    #[test]
    fn parse_empty_string() {
        assert_eq!(parse_virtual_store_name(""), None);
    }

    #[test]
    fn parse_at_at_end() {
        // Name with @ at end — empty version
        assert_eq!(parse_virtual_store_name("lodash@"), None);
    }

    #[test]
    fn parse_multiple_at_signs() {
        // Extra @ in the middle — rfind finds the last one
        let result = parse_virtual_store_name("foo@bar@1.0.0");
        assert_eq!(result, Some(("foo@bar".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn parse_scoped_trailing_slash() {
        // @babel+@1.0.0 — after replace('+', '/'), name is "@babel/"
        // This is an invalid package name but the parser accepts it
        let result = parse_virtual_store_name("@babel+@1.0.0");
        assert_eq!(result, Some(("@babel/".to_string(), "1.0.0".to_string())));
    }

    #[test]
    fn parse_underscores_in_name_no_peers() {
        // Package with underscores but no peer deps
        let result = parse_virtual_store_name("my_package@1.0.0");
        assert_eq!(
            result,
            Some(("my_package".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn parse_version_with_prerelease() {
        let result = parse_virtual_store_name("typescript@5.0.0-beta.1");
        assert_eq!(
            result,
            Some(("typescript".to_string(), "5.0.0-beta.1".to_string()))
        );
    }

    #[test]
    fn parse_version_with_build_metadata() {
        let result = parse_virtual_store_name("pkg@1.0.0+build.123");
        assert_eq!(
            result,
            Some(("pkg".to_string(), "1.0.0+build.123".to_string()))
        );
    }

    // --- strip_peer_deps: adversarial ---

    #[test]
    fn strip_peers_no_at_sign() {
        // No @ at all — return as-is
        assert_eq!(strip_peer_deps("lodash"), "lodash");
    }

    #[test]
    fn strip_peers_underscore_before_at() {
        // Underscore in package name, before the version @
        assert_eq!(strip_peer_deps("my_pkg@1.0.0"), "my_pkg@1.0.0");
    }

    #[test]
    fn strip_peers_scoped_no_version() {
        // Scoped package with no version @ — should return as-is
        assert_eq!(strip_peer_deps("@scope+name"), "@scope+name");
    }

    #[test]
    fn strip_peers_double_underscore() {
        // Real pnpm output: double underscore seen in @testing-library/react peer chain
        let result = strip_peer_deps(
            "@testing-library+react@14.2.0_@types+react@18.3.28_react-dom@18.2.0_react@18.2.0__react@18.2.0",
        );
        assert_eq!(result, "@testing-library+react@14.2.0");
    }

    // --- package_id: adversarial ---

    #[test]
    fn package_id_lock_yaml_in_pnpm() {
        // pnpm puts lock.yaml inside .pnpm — should not be parsed as a package
        let path = PathBuf::from("/project/node_modules/.pnpm/lock.yaml");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_node_modules_dir_in_pnpm() {
        // .pnpm/node_modules directory — not a package
        let path = PathBuf::from("/project/node_modules/.pnpm/node_modules");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_version_zero() {
        // Version starting with 0 — should be accepted
        let path = PathBuf::from("/project/node_modules/.pnpm/pkg@0.0.1");
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "pkg");
        assert_eq!(id.version, "0.0.1");
    }

    #[test]
    fn package_id_version_is_tag() {
        // @next, @canary — not numeric, should be rejected
        let path = PathBuf::from("/project/node_modules/.pnpm/pkg@next");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_version_is_canary() {
        let path = PathBuf::from("/project/node_modules/.pnpm/pkg@canary");
        assert_eq!(package_id(&path), None);
    }

    #[test]
    fn package_id_scoped_with_complex_peers() {
        // Real-world: scoped + multiple peer deps
        let path = PathBuf::from(
            "/project/node_modules/.pnpm/@testing-library+react@14.2.0_@types+react@18.3.28_react-dom@18.2.0_react@18.2.0__react@18.2.0",
        );
        let id = package_id(&path).unwrap();
        assert_eq!(id.name, "@testing-library/react");
        assert_eq!(id.version, "14.2.0");
        assert_eq!(id.ecosystem, "npm");
    }

    #[test]
    fn package_id_not_in_virtual_store() {
        // Has @ but is NOT under node_modules/.pnpm
        let path = PathBuf::from("/home/user/.pnpm-store/v3/lodash@4.17.21");
        assert_eq!(package_id(&path), None);
    }

    // --- semantic_name: adversarial ---

    #[test]
    fn semantic_name_lock_yaml() {
        let path = PathBuf::from("/project/node_modules/.pnpm/lock.yaml");
        // No @ sign, so should not try to parse
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_node_modules_inside_pnpm() {
        let path = PathBuf::from("/project/node_modules/.pnpm/node_modules");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_store_v4_recognized() {
        let path = PathBuf::from("/home/user/.pnpm-store/v4");
        assert_eq!(semantic_name(&path), Some("Store v4".into()));
    }

    // --- metadata: adversarial ---

    #[test]
    fn metadata_empty_vec_for_unknown_path() {
        let path = PathBuf::from("/tmp/random/dir");
        let fields = metadata(&path);
        assert!(fields.is_empty());
    }

    #[test]
    fn metadata_pnpm_store_shows_correct_count() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join(".pnpm-store");
        std::fs::create_dir_all(store_dir.join("v3")).unwrap();
        std::fs::create_dir_all(store_dir.join("tmp")).unwrap();
        std::fs::write(store_dir.join("some-file"), "x").unwrap();

        let fields = metadata(&store_dir);
        let entries_field = fields.iter().find(|f| f.label == "Entries").unwrap();
        assert_eq!(entries_field.value, "3"); // v3 + tmp + some-file
    }

    // =================================================================
    // M1: byte-boundary safety on non-ASCII input
    // These inputs must not panic. They can legitimately return None.
    // =================================================================

    #[test]
    fn parse_index_filename_rejects_non_ascii_hash_without_panic() {
        // A 🔥 emoji is 4 bytes. Putting it near byte 62 means
        // `&base[..62]` lands inside the emoji — must not panic.
        let mut s = "a".repeat(60);
        s.push('🔥');
        s.push_str("xx-name@1.0.0.json");
        assert!(parse_index_filename(&s).is_none());
    }

    #[test]
    fn parse_index_filename_rejects_short_multibyte_without_panic() {
        // A filename that starts with a multi-byte char and is shorter than
        // the hash prefix: guards the byte-index at `base.as_bytes()[62]`.
        let s = "🦀-name@1.0.0.json";
        assert!(parse_index_filename(s).is_none());
    }

    #[test]
    fn parse_index_filename_rejects_multibyte_at_separator_without_panic() {
        // Exactly 62 hex chars of hash, then a multi-byte char where the
        // '-' separator is expected: must not panic on byte 62.
        let mut s = "a".repeat(62);
        s.push('🦀');
        s.push_str("name@1.0.0.json");
        assert!(parse_index_filename(&s).is_none());
    }

    #[test]
    fn strip_peer_deps_non_ascii_does_not_panic() {
        // Construct a scoped-style name with a multi-byte char in the scope
        // position; stripping peer deps must not panic even if offsets shift.
        let input = "@🦀+pkg@1.0.0_🔥-peer";
        let _ = strip_peer_deps(input);
    }

    #[test]
    fn strip_peer_deps_unscoped_non_ascii_does_not_panic() {
        let input = "🔥pkg@1.0.0_react@18";
        let _ = strip_peer_deps(input);
    }
}
