// `allow(dead_code)` until consumed by `check()` in Task 5 and `start()` in Task 7.
#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct LatestRelease {
    pub tag_name: String,
    pub html_url: String,
}

#[derive(Debug)]
pub enum UpdaterError {
    Network,
    Parse,
}

pub trait HttpClient {
    fn get_latest_release(&self) -> Result<LatestRelease, UpdaterError>;
}

pub struct UreqClient {
    pub url: String,
    pub user_agent: String,
}

impl UreqClient {
    pub fn for_ccmd() -> Self {
        Self {
            url: "https://api.github.com/repos/juliensimon/cache-commander/releases/latest"
                .to_string(),
            user_agent: format!("ccmd/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl HttpClient for UreqClient {
    fn get_latest_release(&self) -> Result<LatestRelease, UpdaterError> {
        // Mirrors the pattern in `src/security/registry.rs` — `ureq::agent()`
        // plus a per-request timeout, with User-Agent + Accept headers.
        let resp = ureq::agent()
            .get(&self.url)
            .timeout(std::time::Duration::from_secs(10))
            .set("User-Agent", &self.user_agent)
            .set("Accept", "application/vnd.github+json")
            .call()
            .map_err(|_| UpdaterError::Network)?;
        let body = resp.into_string().map_err(|_| UpdaterError::Network)?;
        serde_json::from_str(&body).map_err(|_| UpdaterError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn for_ccmd_has_expected_url_and_ua() {
        let c = UreqClient::for_ccmd();
        assert!(c.url.contains("juliensimon/cache-commander"));
        assert!(c.user_agent.starts_with("ccmd/"));
    }

    /// Spawns a one-shot HTTP server on 127.0.0.1 that returns `body` with
    /// `Content-Type: application/json` once, then exits. Returns the URL
    /// the client should hit.
    fn spawn_one_shot_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain request bytes so the client's write() doesn't block.
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/latest")
    }

    #[test]
    fn get_latest_release_parses_github_response() {
        let url = spawn_one_shot_server(
            r#"{"tag_name":"v0.3.1","html_url":"https://example.com/v0.3.1","ignored":"field"}"#,
        );
        let client = UreqClient {
            url,
            user_agent: "ccmd-test/0.0.0".into(),
        };
        let release = client.get_latest_release().expect("should succeed");
        assert_eq!(release.tag_name, "v0.3.1");
        assert_eq!(release.html_url, "https://example.com/v0.3.1");
    }

    #[test]
    fn get_latest_release_returns_parse_error_on_malformed_json() {
        let url = spawn_one_shot_server("not json");
        let client = UreqClient {
            url,
            user_agent: "ccmd-test/0.0.0".into(),
        };
        match client.get_latest_release() {
            Err(UpdaterError::Parse) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }
}
