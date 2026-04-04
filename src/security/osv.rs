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
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

pub fn parse_vuln_detail(json: &str) -> Result<OsvVulnDetail, serde_json::Error> {
    serde_json::from_str(json)
}

/// Extract the fix version for a specific package version from OSV detail.
///
/// OSV `affected` entries can have multiple ranges (e.g., 0.35.x, 0.38.x, 1.x).
/// We find the range whose `introduced` version best matches `pkg_version` by
/// comparing version prefixes, then return that range's `fixed` value.
pub fn extract_fix_version(
    detail: &OsvVulnDetail,
    package_name: &str,
    ecosystem: &str,
    pkg_version: &str,
) -> Option<String> {
    for affected in &detail.affected {
        if let Some(pkg) = &affected.package {
            if pkg.name == package_name && pkg.ecosystem == ecosystem {
                // Collect all (introduced, fixed) pairs from ranges
                let mut candidates: Vec<(&str, &str)> = Vec::new();
                for range in &affected.ranges {
                    let mut intro: Option<&str> = None;
                    let mut fix: Option<&str> = None;
                    for event in &range.events {
                        if let Some(i) = &event.introduced {
                            intro = Some(i);
                        }
                        if let Some(f) = &event.fixed {
                            fix = Some(f);
                        }
                    }
                    if let (Some(i), Some(f)) = (intro, fix) {
                        candidates.push((i, f));
                    }
                }

                if candidates.is_empty() {
                    return None;
                }

                // Find the best matching range: the one whose introduced version
                // is <= pkg_version with the highest introduced version.
                // This picks the most specific range that covers our version.
                let best = candidates.iter()
                    .filter(|(intro, _)| version_lte(intro, pkg_version))
                    .max_by(|(a, _), (b, _)| compare_versions(a, b));

                if let Some((_, fix)) = best {
                    return Some(fix.to_string());
                }

                // Fallback: return the last fix if no range matched
                return candidates.last().map(|(_, f)| f.to_string());
            }
        }
    }
    None
}

/// Compare two version strings numerically component by component.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<u64> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u64> = b.split('.').filter_map(|s| s.parse().ok()).collect();
    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let a_val = a_parts.get(i).copied().unwrap_or(0);
        let b_val = b_parts.get(i).copied().unwrap_or(0);
        match a_val.cmp(&b_val) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

/// Check if version a <= version b.
fn version_lte(a: &str, b: &str) -> bool {
    compare_versions(a, b) != std::cmp::Ordering::Greater
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
        let fix = extract_fix_version(&detail, "requests", "PyPI", "2.31.0");
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
        let fix = extract_fix_version(&detail, "urllib3", "PyPI", "1.0.0");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_no_affected_field() {
        let json = r#"{"id": "CVE-2024-0001", "summary": "No affected"}"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(detail.id, "CVE-2024-0001");
        assert!(detail.affected.is_empty());
        let fix = extract_fix_version(&detail, "anything", "PyPI", "1.0.0");
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
        let fix = extract_fix_version(&detail, "flask", "PyPI", "2.0.0");
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
        let fix = extract_fix_version(&detail, "flask", "PyPI", "2.0.0");
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
        let fix = extract_fix_version(&detail, "flask", "PyPI", "2.0.0");
        assert_eq!(fix, None);
    }

    #[test]
    fn parse_vuln_detail_multiple_affected_packages() {
        let json = r#"{
            "id": "CVE-2024-0005",
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]
                },
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.18"}]}]
                }
            ]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(detail.affected.len(), 2);
        assert_eq!(extract_fix_version(&detail, "requests", "PyPI", "2.31.0"), Some("2.32.0".to_string()));
        assert_eq!(extract_fix_version(&detail, "urllib3", "PyPI", "1.26.5"), Some("1.26.18".to_string()));
        assert_eq!(extract_fix_version(&detail, "flask", "PyPI", "3.0.0"), None);
    }

    #[test]
    fn extract_fix_version_wrong_ecosystem() {
        let json = r#"{
            "id": "CVE-2024-0006",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(extract_fix_version(&detail, "requests", "npm", "2.31.0"), None);
    }

    #[test]
    fn parse_vuln_detail_affected_no_package() {
        let json = r#"{
            "id": "CVE-2024-0007",
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert!(detail.affected[0].package.is_none());
        let fix = extract_fix_version(&detail, "anything", "PyPI", "0.5.0");
        assert_eq!(fix, None);
    }

    #[test]
    fn extract_fix_version_multi_range_picks_correct_major() {
        // Simulates the rustix case: vuln affects both 0.x and 1.x lines
        let json = r#"{
            "id": "GHSA-c827-hfw6-qwvm",
            "affected": [{
                "package": {"name": "rustix", "ecosystem": "crates.io"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "0.35.15"}
                        ]
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0.36.0"},
                            {"fixed": "0.36.16"}
                        ]
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0.37.0"},
                            {"fixed": "0.37.27"}
                        ]
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0.38.0"},
                            {"fixed": "0.38.37"}
                        ]
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.0.5"}
                        ]
                    }
                ]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();

        // Version 1.1.4 should match the 1.x range → fix 1.0.5
        assert_eq!(
            extract_fix_version(&detail, "rustix", "crates.io", "1.1.4"),
            Some("1.0.5".to_string()),
        );

        // Version 0.38.44 should match the 0.38.x range → fix 0.38.37
        assert_eq!(
            extract_fix_version(&detail, "rustix", "crates.io", "0.38.44"),
            Some("0.38.37".to_string()),
        );

        // Version 0.35.10 should match the 0.0-0.35 range → fix 0.35.15
        assert_eq!(
            extract_fix_version(&detail, "rustix", "crates.io", "0.35.10"),
            Some("0.35.15".to_string()),
        );
    }
}
