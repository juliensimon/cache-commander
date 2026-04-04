pub fn parse_pypi_latest(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    val["info"]["version"].as_str().map(|s| s.to_string())
}

pub fn parse_crates_io_latest(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    val["crate"]["max_version"].as_str().map(|s| s.to_string())
}

pub fn parse_npm_latest(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    val["version"].as_str().map(|s| s.to_string())
}

pub fn check_latest(pkg: &crate::providers::PackageId) -> Result<Option<String>, String> {
    let url = match pkg.ecosystem {
        "PyPI" => format!("https://pypi.org/pypi/{}/json", pkg.name),
        "crates.io" => format!("https://crates.io/api/v1/crates/{}", pkg.name),
        "npm" => format!("https://registry.npmjs.org/{}/latest", pkg.name),
        _ => return Ok(None),
    };

    let resp = ureq::agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .set("User-Agent", "ccmd/0.1 (https://github.com/ccmd)")
        .call()
        .map_err(|e| format!("Registry request failed: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("Registry read failed: {e}"))?;

    let latest = match pkg.ecosystem {
        "PyPI" => parse_pypi_latest(&text),
        "crates.io" => parse_crates_io_latest(&text),
        "npm" => parse_npm_latest(&text),
        _ => None,
    };
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pypi_response() {
        let json = r#"{"info":{"version":"2.32.3"}}"#;
        assert_eq!(parse_pypi_latest(json), Some("2.32.3".into()));
    }

    #[test]
    fn parse_crates_io_response() {
        let json = r#"{"crate":{"max_version":"1.0.200"}}"#;
        assert_eq!(parse_crates_io_latest(json), Some("1.0.200".into()));
    }

    #[test]
    fn parse_npm_response() {
        let json = r#"{"version":"10.8.1"}"#;
        assert_eq!(parse_npm_latest(json), Some("10.8.1".into()));
    }

    #[test]
    fn parse_invalid_json_returns_none() {
        assert_eq!(parse_pypi_latest("not json"), None);
    }
}
