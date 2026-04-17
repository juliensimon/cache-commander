pub mod cache;
pub mod http;
pub mod version;

use chrono::{DateTime, Utc};
use std::path::Path;
use std::sync::mpsc;

use http::HttpClient;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // fields consumed by `App` render code in Task 8
pub struct UpdateInfo {
    pub latest: String,
    pub url: String,
}

#[derive(Debug)]
#[allow(dead_code)] // variant matched on in Task 8
pub enum UpdateMsg {
    Available(UpdateInfo),
}

pub const CACHE_TTL_HOURS: i64 = 24;

/// Pure orchestration: given a current version, a cache file path, an HTTP
/// client, and a clock, return `Some(UpdateInfo)` iff a strictly-newer
/// non-pre-release upgrade is available. Silent on all errors.
#[allow(dead_code)] // wired into `start()` in Task 7
pub fn check(
    current: &str,
    cache_path: &Path,
    http: &dyn HttpClient,
    now: DateTime<Utc>,
) -> Option<UpdateInfo> {
    if version::is_prerelease(current) {
        return None;
    }

    if let Some(entry) = cache::read_cache(cache_path)
        && let Ok(last) = DateTime::parse_from_rfc3339(&entry.last_checked)
        && (now - last.with_timezone(&Utc)) < chrono::Duration::hours(CACHE_TTL_HOURS)
    {
        return if version::is_newer(current, &entry.latest_seen) {
            Some(UpdateInfo {
                latest: entry.latest_seen,
                url: entry.html_url,
            })
        } else {
            None
        };
    }

    let fetched = match http.get_latest_release() {
        Ok(r) => r,
        Err(_) => return None,
    };

    let tag = fetched
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&fetched.tag_name);
    let _ = cache::write_cache(
        cache_path,
        &cache::CacheEntry {
            last_checked: now.to_rfc3339(),
            latest_seen: tag.to_string(),
            html_url: fetched.html_url.clone(),
        },
    );

    if version::is_newer(current, tag) {
        Some(UpdateInfo {
            latest: tag.to_string(),
            url: fetched.html_url,
        })
    } else {
        None
    }
}

/// Spawns a background thread that checks GitHub for a newer `ccmd` release.
/// Returns a receiver that yields at most one `UpdateMsg::Available` if a
/// newer version exists. Silent on all errors.
#[allow(dead_code)] // called from main.rs in Task 9
pub fn start(config: &crate::config::Config) -> mpsc::Receiver<UpdateMsg> {
    let (tx, rx) = mpsc::channel();
    if !config.updater.enabled {
        return rx;
    }
    std::thread::spawn(move || {
        let cache_path = match cache_file_path() {
            Some(p) => p,
            None => return,
        };
        let http = http::UreqClient::for_ccmd();
        if let Some(info) = check(env!("CARGO_PKG_VERSION"), &cache_path, &http, Utc::now()) {
            let _ = tx.send(UpdateMsg::Available(info));
        }
    });
    rx
}

fn cache_file_path() -> Option<std::path::PathBuf> {
    let proj = directories::ProjectDirs::from("", "", "ccmd")?;
    Some(proj.cache_dir().join("update-check.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache::CacheEntry;
    use chrono::Duration;
    use http::{LatestRelease, UpdaterError};
    use std::cell::Cell;
    use tempfile::tempdir;

    struct FakeClient {
        response: Result<LatestRelease, UpdaterError>,
        calls: Cell<usize>,
    }

    impl FakeClient {
        fn ok(tag: &str) -> Self {
            Self {
                response: Ok(LatestRelease {
                    tag_name: tag.to_string(),
                    html_url: format!(
                        "https://github.com/juliensimon/cache-commander/releases/tag/{tag}"
                    ),
                }),
                calls: Cell::new(0),
            }
        }
        fn err() -> Self {
            Self {
                response: Err(UpdaterError::Network),
                calls: Cell::new(0),
            }
        }
    }

    impl HttpClient for FakeClient {
        fn get_latest_release(&self) -> Result<LatestRelease, UpdaterError> {
            self.calls.set(self.calls.get() + 1);
            match &self.response {
                Ok(r) => Ok(r.clone()),
                Err(_) => Err(UpdaterError::Network),
            }
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-04-17T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn returns_info_when_remote_is_newer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        let http = FakeClient::ok("v0.3.1");
        let info = check("0.3.0", &path, &http, now());
        assert_eq!(info.as_ref().map(|i| i.latest.as_str()), Some("0.3.1"));
        assert!(info.unwrap().url.contains("v0.3.1"));
        assert_eq!(http.calls.get(), 1);
    }

    #[test]
    fn returns_none_when_up_to_date() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        let http = FakeClient::ok("v0.3.0");
        assert_eq!(check("0.3.0", &path, &http, now()), None);
    }

    #[test]
    fn returns_none_on_network_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        let http = FakeClient::err();
        assert_eq!(check("0.3.0", &path, &http, now()), None);
    }

    #[test]
    fn returns_none_when_current_is_prerelease() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        let http = FakeClient::ok("v0.3.0");
        assert_eq!(check("0.4.0-dev", &path, &http, now()), None);
        assert_eq!(http.calls.get(), 0, "must not call HTTP for pre-release");
    }

    #[test]
    fn fresh_cache_hit_skips_http_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        cache::write_cache(
            &path,
            &CacheEntry {
                last_checked: now().to_rfc3339(),
                latest_seen: "0.3.1".into(),
                html_url: "https://example.com/0.3.1".into(),
            },
        );
        let http = FakeClient::ok("v9.9.9");
        let info = check("0.3.0", &path, &http, now());
        assert_eq!(info.unwrap().latest, "0.3.1");
        assert_eq!(http.calls.get(), 0, "cache hit must skip HTTP");
    }

    #[test]
    fn stale_cache_triggers_refresh() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        let old = now() - Duration::hours(25);
        cache::write_cache(
            &path,
            &CacheEntry {
                last_checked: old.to_rfc3339(),
                latest_seen: "0.3.1".into(),
                html_url: "https://example.com/0.3.1".into(),
            },
        );
        let http = FakeClient::ok("v0.3.2");
        let info = check("0.3.0", &path, &http, now());
        assert_eq!(info.unwrap().latest, "0.3.2");
        assert_eq!(http.calls.get(), 1);
    }

    #[test]
    fn http_call_updates_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.json");
        let http = FakeClient::ok("v0.3.1");
        let _ = check("0.3.0", &path, &http, now());
        let entry = cache::read_cache(&path).expect("cache written");
        assert_eq!(entry.latest_seen, "0.3.1");
        assert_eq!(entry.last_checked, now().to_rfc3339());
    }
}
