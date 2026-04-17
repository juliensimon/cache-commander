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

    #[test]
    fn for_ccmd_has_expected_url_and_ua() {
        let c = UreqClient::for_ccmd();
        assert!(c.url.contains("juliensimon/cache-commander"));
        assert!(c.user_agent.starts_with("ccmd/"));
    }
}
