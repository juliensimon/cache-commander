pub fn parse_pypi_latest(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    val["info"]["version"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub fn parse_crates_io_latest(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    val["crate"]["max_version"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub fn parse_npm_latest(json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json).ok()?;
    val["version"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Extract the content between `<tag>` and `</tag>` from XML-like text.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    let value = xml[start..start + end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parse Maven Central's maven-metadata.xml. Prefers `<release>` over `<latest>`
/// because `<latest>` may include snapshot versions that users shouldn't be pushed to.
pub fn parse_maven_latest(xml: &str) -> Option<String> {
    extract_tag(xml, "release").or_else(|| extract_tag(xml, "latest"))
}

/// Build the registry URL for a given package, or `None` if the ecosystem is unsupported.
pub fn build_registry_url(pkg: &crate::providers::PackageId) -> Option<String> {
    match pkg.ecosystem {
        "PyPI" => Some(format!("https://pypi.org/pypi/{}/json", pkg.name)),
        "crates.io" => Some(format!("https://crates.io/api/v1/crates/{}", pkg.name)),
        "npm" => Some(format!("https://registry.npmjs.org/{}/latest", pkg.name)),
        "Maven" => {
            // pkg.name is `group:artifact`; group dots become path slashes.
            let (group, artifact) = pkg.name.split_once(':')?;
            let group_path = group.replace('.', "/");
            Some(format!(
                "https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml"
            ))
        }
        _ => None,
    }
}

/// Parse the registry JSON response for the given ecosystem.
pub fn parse_registry_response(ecosystem: &str, body: &str) -> Option<String> {
    match ecosystem {
        "PyPI" => parse_pypi_latest(body),
        "crates.io" => parse_crates_io_latest(body),
        "npm" => parse_npm_latest(body),
        "Maven" => parse_maven_latest(body),
        _ => None,
    }
}

pub fn check_latest(pkg: &crate::providers::PackageId) -> Result<Option<String>, String> {
    let url = match build_registry_url(pkg) {
        Some(u) => u,
        None => return Ok(None),
    };
    check_latest_at(&url, pkg.ecosystem)
}

/// Issue a registry request to a specific URL (mockable for M2 tests).
pub fn check_latest_at(url: &str, ecosystem: &str) -> Result<Option<String>, String> {
    let resp = ureq::agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .set(
            "User-Agent",
            &format!(
                "ccmd/{} (https://github.com/juliensimon/cache-commander)",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .call()
        .map_err(|e| format!("Registry request failed: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("Registry read failed: {e}"))?;

    Ok(parse_registry_response(ecosystem, &text))
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

    #[test]
    fn parse_pypi_missing_info_key() {
        assert_eq!(parse_pypi_latest(r#"{"other": "data"}"#), None);
    }

    #[test]
    fn parse_pypi_null_version() {
        assert_eq!(parse_pypi_latest(r#"{"info": {"version": null}}"#), None);
    }

    #[test]
    fn parse_crates_io_missing_crate_key() {
        assert_eq!(parse_crates_io_latest(r#"{"other": "data"}"#), None);
    }

    #[test]
    fn parse_npm_empty_version() {
        assert_eq!(parse_npm_latest(r#"{"version": ""}"#), None);
    }

    #[test]
    fn parse_npm_whitespace_only_version() {
        // Whitespace-only version is technically non-empty but would be useless;
        // current impl returns Some(" ") which is acceptable — the version comparison
        // will handle it by treating it as no numeric parts.
        let result = parse_npm_latest(r#"{"version": " "}"#);
        assert_eq!(result, Some(" ".to_string()));
    }

    #[test]
    fn parse_pypi_empty_version() {
        assert_eq!(parse_pypi_latest(r#"{"info": {"version": ""}}"#), None);
    }

    fn pkg(ecosystem: &'static str, name: &str) -> crate::providers::PackageId {
        crate::providers::PackageId {
            ecosystem,
            name: name.to_string(),
            version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn build_registry_url_pypi() {
        assert_eq!(
            build_registry_url(&pkg("PyPI", "requests")),
            Some("https://pypi.org/pypi/requests/json".to_string())
        );
    }

    #[test]
    fn build_registry_url_crates_io() {
        assert_eq!(
            build_registry_url(&pkg("crates.io", "serde")),
            Some("https://crates.io/api/v1/crates/serde".to_string())
        );
    }

    #[test]
    fn build_registry_url_npm() {
        assert_eq!(
            build_registry_url(&pkg("npm", "lodash")),
            Some("https://registry.npmjs.org/lodash/latest".to_string())
        );
    }

    #[test]
    fn build_registry_url_unknown_ecosystem_returns_none() {
        assert_eq!(build_registry_url(&pkg("Homebrew", "whatever")), None);
        assert_eq!(build_registry_url(&pkg("", "whatever")), None);
    }

    #[test]
    fn parse_registry_response_dispatches_by_ecosystem() {
        assert_eq!(
            parse_registry_response("PyPI", r#"{"info":{"version":"1.2.3"}}"#),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            parse_registry_response("crates.io", r#"{"crate":{"max_version":"0.5.0"}}"#),
            Some("0.5.0".to_string())
        );
        assert_eq!(
            parse_registry_response("npm", r#"{"version":"9.9.9"}"#),
            Some("9.9.9".to_string())
        );
        assert_eq!(parse_registry_response("unknown", r#"{}"#), None);
    }

    #[test]
    fn parse_crates_io_empty_version() {
        assert_eq!(
            parse_crates_io_latest(r#"{"crate": {"max_version": ""}}"#),
            None
        );
    }

    // ------------------------------------------------------------------
    // Maven Central (pkg.ecosystem == "Maven", pkg.name == "group:artifact")
    // ------------------------------------------------------------------

    #[test]
    fn build_registry_url_maven_simple_group() {
        // group `com.google.guava`, artifact `guava`
        // → https://repo1.maven.org/maven2/com/google/guava/guava/maven-metadata.xml
        let p = pkg("Maven", "com.google.guava:guava");
        assert_eq!(
            build_registry_url(&p),
            Some(
                "https://repo1.maven.org/maven2/com/google/guava/guava/maven-metadata.xml"
                    .to_string()
            )
        );
    }

    #[test]
    fn build_registry_url_maven_multi_segment_group() {
        let p = pkg("Maven", "org.apache.logging.log4j:log4j-core");
        assert_eq!(
            build_registry_url(&p),
            Some(
                "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/maven-metadata.xml"
                    .to_string()
            )
        );
    }

    #[test]
    fn build_registry_url_maven_missing_colon_returns_none() {
        // Malformed Maven coord (no `:`) — can't be used to build a URL.
        let p = pkg("Maven", "guava");
        assert_eq!(build_registry_url(&p), None);
    }

    #[test]
    fn parse_maven_latest_prefers_release_over_latest() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>34.0.0-SNAPSHOT</latest>
    <release>33.6.0-jre</release>
  </versioning>
</metadata>"#;
        assert_eq!(parse_maven_latest(xml), Some("33.6.0-jre".to_string()));
    }

    #[test]
    fn parse_maven_latest_falls_back_to_latest_when_no_release() {
        let xml = r#"<metadata><versioning><latest>1.2.3</latest></versioning></metadata>"#;
        assert_eq!(parse_maven_latest(xml), Some("1.2.3".to_string()));
    }

    #[test]
    fn parse_maven_latest_returns_none_when_empty() {
        assert_eq!(parse_maven_latest(""), None);
        assert_eq!(parse_maven_latest("<metadata></metadata>"), None);
    }

    #[test]
    fn parse_registry_response_dispatches_to_maven() {
        let xml = r#"<metadata><versioning><release>2.0.0</release></versioning></metadata>"#;
        assert_eq!(
            parse_registry_response("Maven", xml),
            Some("2.0.0".to_string())
        );
    }
}
