use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OsvResponse {
    pub results: Vec<OsvQueryResult>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvQueryResult {
    #[serde(default)]
    pub vulns: Vec<OsvVuln>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

pub fn parse_response(json: &str) -> Result<OsvResponse, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn build_query(packages: &[crate::providers::PackageId]) -> String {
    let queries: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| {
            serde_json::json!({
                "package": {
                    "name": p.name,
                    "version": p.version,
                    "ecosystem": p.ecosystem,
                }
            })
        })
        .collect();
    serde_json::json!({ "queries": queries }).to_string()
}

pub fn query_osv(packages: &[crate::providers::PackageId]) -> Result<OsvResponse, String> {
    let body = build_query(packages);
    let resp = ureq::agent()
        .post("https://api.osv.dev/v1/querybatch")
        .timeout(std::time::Duration::from_secs(30))
        .set("Content-Type", "application/json")
        .set("User-Agent", "ccmd/0.1 (https://github.com/ccmd)")
        .send_string(&body)
        .map_err(|e| format!("OSV request failed: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("OSV read failed: {e}"))?;
    parse_response(&text).map_err(|e| format!("OSV parse failed: {e}"))
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvVulnDetail {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub fixed: Option<String>,
}

pub fn parse_vuln_detail(json: &str) -> Result<OsvVulnDetail, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn extract_fix_version(detail: &OsvVulnDetail, package_name: &str, ecosystem: &str) -> Option<String> {
    for affected in &detail.affected {
        if let Some(pkg) = &affected.package {
            if pkg.name == package_name && pkg.ecosystem == ecosystem {
                for range in &affected.ranges {
                    for event in &range.events {
                        if let Some(fixed) = &event.fixed {
                            return Some(fixed.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn fetch_vuln_detail(vuln_id: &str) -> Result<OsvVulnDetail, String> {
    let url = format!("https://api.osv.dev/v1/vulns/{}", vuln_id);
    let resp = ureq::agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .set("User-Agent", "ccmd/0.1 (https://github.com/ccmd)")
        .call()
        .map_err(|e| format!("OSV detail request failed: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("OSV detail read failed: {e}"))?;
    parse_vuln_detail(&text).map_err(|e| format!("OSV detail parse failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_response() {
        let json = r#"{"results":[{"vulns":[]},{"vulns":[]}]}"#;
        let resp = parse_response(json).unwrap();
        assert_eq!(resp.results.len(), 2);
        assert!(resp.results[0].vulns.is_empty());
    }

    #[test]
    fn parse_response_with_vulns() {
        let json = r#"{"results":[{"vulns":[{"id":"CVE-2023-1234","summary":"Bad thing","severity":[{"type":"CVSS_V3","score":"7.5"}]}]}]}"#;
        let resp = parse_response(json).unwrap();
        assert_eq!(resp.results[0].vulns.len(), 1);
        assert_eq!(resp.results[0].vulns[0].id, "CVE-2023-1234");
        assert_eq!(resp.results[0].vulns[0].summary.as_deref(), Some("Bad thing"));
    }

    #[test]
    fn build_query_format() {
        let packages = vec![crate::providers::PackageId {
            ecosystem: "PyPI",
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
        }];
        let query = build_query(&packages);
        assert!(query.contains("\"name\":\"requests\""));
        assert!(query.contains("\"ecosystem\":\"PyPI\""));
    }

    #[test]
    fn parse_vuln_detail_extracts_fix_version() {
        let json = r#"{
            "id": "CVE-2023-32681",
            "summary": "Unintended leak",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.32.0"}
                    ]
                }]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(detail.id, "CVE-2023-32681");
        let fix = extract_fix_version(&detail, "requests", "PyPI");
        assert_eq!(fix, Some("2.32.0".to_string()));
    }

    #[test]
    fn extract_fix_version_no_match_for_different_package() {
        let json = r#"{
            "id": "CVE-2023-32681",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]
                }]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        let fix = extract_fix_version(&detail, "urllib3", "PyPI");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_no_affected_field() {
        let json = r#"{"id": "CVE-2024-0001", "summary": "No affected"}"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(detail.id, "CVE-2024-0001");
        assert!(detail.affected.is_empty());
        let fix = extract_fix_version(&detail, "anything", "PyPI");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_empty_ranges() {
        let json = r#"{
            "id": "CVE-2024-0002",
            "affected": [{
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": []
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        let fix = extract_fix_version(&detail, "flask", "PyPI");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_empty_events() {
        let json = r#"{
            "id": "CVE-2024-0003",
            "affected": [{
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": []}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        let fix = extract_fix_version(&detail, "flask", "PyPI");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_only_introduced_no_fixed() {
        let json = r#"{
            "id": "CVE-2024-0004",
            "affected": [{
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        let fix = extract_fix_version(&detail, "flask", "PyPI");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_multiple_affected_packages() {
        let json = r#"{
            "id": "CVE-2024-0005",
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.32.0"}]}]
                },
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.26.18"}]}]
                }
            ]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(detail.affected.len(), 2);
        assert_eq!(extract_fix_version(&detail, "requests", "PyPI"), Some("2.32.0".to_string()));
        assert_eq!(extract_fix_version(&detail, "urllib3", "PyPI"), Some("1.26.18".to_string()));
        assert_eq!(extract_fix_version(&detail, "flask", "PyPI"), None);
    }

    #[test]
    fn extract_fix_version_wrong_ecosystem() {
        let json = r#"{
            "id": "CVE-2024-0006",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.32.0"}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        // Right name, wrong ecosystem
        assert_eq!(extract_fix_version(&detail, "requests", "npm"), None);
    }

    #[test]
    fn parse_vuln_detail_affected_no_package() {
        let json = r#"{
            "id": "CVE-2024-0007",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}]}]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert!(detail.affected[0].package.is_none());
        let fix = extract_fix_version(&detail, "anything", "PyPI");
        assert_eq!(fix, None);
    }
}
