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

pub const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

pub fn build_vuln_detail_url(vuln_id: &str) -> String {
    format!("https://api.osv.dev/v1/vulns/{}", vuln_id)
}

pub fn query_osv(packages: &[crate::providers::PackageId]) -> Result<OsvResponse, String> {
    query_osv_at(OSV_BATCH_URL, packages)
}

/// Query OSV using a configurable URL — enables HTTP-level testing (M2)
/// against a local mock server without having to hit api.osv.dev.
pub fn query_osv_at(
    url: &str,
    packages: &[crate::providers::PackageId],
) -> Result<OsvResponse, String> {
    let body = build_query(packages);
    let resp = ureq::agent()
        .post(url)
        .timeout(std::time::Duration::from_secs(30))
        .set("Content-Type", "application/json")
        .set(
            "User-Agent",
            &format!(
                "ccmd/{} (https://github.com/juliensimon/cache-commander)",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .send_string(&body)
        .map_err(|e| format!("OSV request failed: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("OSV read failed: {e}"))?;
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
        if let Some(pkg) = &affected.package
            && pkg.name == package_name
            && pkg.ecosystem == ecosystem
        {
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
                if let (Some(i), Some(f)) = (intro, fix)
                    && !f.is_empty()
                {
                    candidates.push((i, f));
                }
            }

            if candidates.is_empty() {
                return None;
            }

            // Find the best matching range: the one whose introduced version
            // is <= pkg_version with the highest introduced version.
            // This picks the most specific range that covers our version.
            let best = candidates
                .iter()
                .filter(|(intro, _)| version_lte(intro, pkg_version))
                .max_by(|(a, _), (b, _)| compare_versions(a, b));

            if let Some((_, fix)) = best {
                return Some(fix.to_string());
            }

            // No range matched — we don't know which range applies
            return None;
        }
    }
    None
}

/// Compare two version strings with semver + PEP 440 pre-release semantics.
///
/// M5: previously this was a pure numeric component compare, which meant
/// `1.0.0-rc1 == 1.0.0` and `2.0.0a1 == 2.0.0`, silently producing false-
/// negative vuln matches near the fix boundary. We now normalize each
/// input to `(core_nums, stage, stage_nums)` and order lexicographically.
///
/// Build metadata (everything after `+`) is stripped (semver §10: build
/// metadata does not affect precedence).
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_core, a_stage, a_stage_nums) = normalize_version(a);
    let (b_core, b_stage, b_stage_nums) = normalize_version(b);
    // Pad the shorter core with zeros so `1.2` == `1.2.0`.
    let len = a_core.len().max(b_core.len());
    for i in 0..len {
        let av = a_core.get(i).copied().unwrap_or(0);
        let bv = b_core.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    match a_stage.cmp(&b_stage) {
        std::cmp::Ordering::Equal => a_stage_nums.cmp(&b_stage_nums),
        other => other,
    }
}

/// Ordered tuple key for a version string.
fn normalize_version(v: &str) -> (Vec<u64>, u8, Vec<u64>) {
    // 1. Strip build metadata (everything after '+').
    let v = v.split('+').next().unwrap_or(v);

    // 2. Split at '-' for semver-style pre-release tail.
    let (head, tail_dash) = match v.split_once('-') {
        Some((h, t)) => (h, Some(t)),
        None => (v, None),
    };

    // 3. If no '-', try PEP 440 inline suffix: find the first non-numeric,
    //    non-dot char in `head` and split there.
    let (core, tail_inline) = if tail_dash.is_some() {
        (head, None)
    } else {
        let mut split_at = head.len();
        for (i, c) in head.char_indices() {
            if !c.is_ascii_digit() && c != '.' {
                split_at = i;
                break;
            }
        }
        if split_at == head.len() {
            (head, None)
        } else {
            (&head[..split_at], Some(&head[split_at..]))
        }
    };

    let core_nums: Vec<u64> = core.split('.').filter_map(|s| s.parse().ok()).collect();

    // Stage rank: dev < alpha < beta < rc < stable < post
    const STAGE_DEV: u8 = 0;
    const STAGE_ALPHA: u8 = 1;
    const STAGE_BETA: u8 = 2;
    const STAGE_RC: u8 = 3;
    const STAGE_STABLE: u8 = 4;
    const STAGE_POST: u8 = 5;

    let tail = tail_dash
        .or(tail_inline)
        .unwrap_or("")
        .trim_start_matches('.');
    if tail.is_empty() {
        return (core_nums, STAGE_STABLE, Vec::new());
    }
    let tail_lower = tail.to_ascii_lowercase();
    let (stage, rest) = if let Some(r) = tail_lower.strip_prefix("post") {
        (STAGE_POST, r)
    } else if let Some(r) = tail_lower.strip_prefix("dev") {
        (STAGE_DEV, r)
    } else if let Some(r) = tail_lower.strip_prefix("alpha") {
        (STAGE_ALPHA, r)
    } else if let Some(r) = tail_lower.strip_prefix("beta") {
        (STAGE_BETA, r)
    } else if let Some(r) = tail_lower.strip_prefix("rc") {
        (STAGE_RC, r)
    } else if let Some(r) = tail_lower.strip_prefix('a') {
        (STAGE_ALPHA, r)
    } else if let Some(r) = tail_lower.strip_prefix('b') {
        (STAGE_BETA, r)
    } else {
        // Unknown tail — treat as pre-release of lowest precedence so we
        // never falsely upgrade an unparseable version above stable.
        (STAGE_DEV, tail_lower.as_str())
    };

    let stage_nums: Vec<u64> = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    (core_nums, stage, stage_nums)
}

/// Check if version a <= version b.
pub fn version_lte(a: &str, b: &str) -> bool {
    compare_versions(a, b) != std::cmp::Ordering::Greater
}

pub fn fetch_vuln_detail(vuln_id: &str) -> Result<OsvVulnDetail, String> {
    fetch_vuln_detail_at(&build_vuln_detail_url(vuln_id))
}

/// Fetch a single OSV vuln detail from a configurable URL — enables
/// HTTP-level tests (M2).
pub fn fetch_vuln_detail_at(url: &str) -> Result<OsvVulnDetail, String> {
    let resp = ureq::agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(15))
        .set(
            "User-Agent",
            &format!(
                "ccmd/{} (https://github.com/juliensimon/cache-commander)",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .call()
        .map_err(|e| format!("OSV detail request failed: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("OSV detail read failed: {e}"))?;
    parse_vuln_detail(&text).map_err(|e| format!("OSV detail parse failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_batch_url_constant() {
        assert_eq!(OSV_BATCH_URL, "https://api.osv.dev/v1/querybatch");
    }

    #[test]
    fn build_vuln_detail_url_formats_correctly() {
        assert_eq!(
            build_vuln_detail_url("CVE-2023-1234"),
            "https://api.osv.dev/v1/vulns/CVE-2023-1234"
        );
        assert_eq!(
            build_vuln_detail_url("GHSA-abcd-efgh-ijkl"),
            "https://api.osv.dev/v1/vulns/GHSA-abcd-efgh-ijkl"
        );
    }

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
        assert_eq!(
            resp.results[0].vulns[0].summary.as_deref(),
            Some("Bad thing")
        );
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
        assert_eq!(
            extract_fix_version(&detail, "requests", "PyPI", "2.31.0"),
            Some("2.32.0".to_string())
        );
        assert_eq!(
            extract_fix_version(&detail, "urllib3", "PyPI", "1.26.5"),
            Some("1.26.18".to_string())
        );
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
        assert_eq!(
            extract_fix_version(&detail, "requests", "npm", "2.31.0"),
            None
        );
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

    // --- Group 1: compare_versions ---

    #[test]
    fn compare_versions_basic_less() {
        assert_eq!(compare_versions("1.2.3", "1.2.4"), std::cmp::Ordering::Less);
    }

    #[test]
    fn compare_versions_basic_greater() {
        assert_eq!(
            compare_versions("2.0.0", "1.9.9"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_versions_equal() {
        assert_eq!(
            compare_versions("2.0.0", "2.0.0"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn compare_versions_major_dominates() {
        assert_eq!(compare_versions("1.9.9", "2.0.0"), std::cmp::Ordering::Less);
    }

    #[test]
    fn compare_versions_different_lengths_equal() {
        // "1.2" treated as "1.2.0"
        assert_eq!(compare_versions("1.2", "1.2.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_versions_different_lengths_less() {
        assert_eq!(compare_versions("1.2", "1.2.1"), std::cmp::Ordering::Less);
    }

    // M5: pre-release / build-metadata ordering — semver + PEP 440 rules.
    #[test]
    fn compare_versions_semver_prerelease_less_than_stable() {
        assert_eq!(
            compare_versions("1.0.0-rc1", "1.0.0"),
            std::cmp::Ordering::Less,
            "semver pre-release must rank below the stable release"
        );
    }

    #[test]
    fn compare_versions_semver_prerelease_progression() {
        // alpha < beta < rc < stable
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-beta"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_versions("1.0.0-beta", "1.0.0-rc"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_versions("1.0.0-rc1", "1.0.0-rc2"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn compare_versions_pep440_alpha_less_than_stable() {
        // PEP 440 inline style — no dash
        assert_eq!(
            compare_versions("2.0.0a1", "2.0.0"),
            std::cmp::Ordering::Less,
            "PEP 440 alpha must rank below stable"
        );
        assert_eq!(
            compare_versions("1.0.0rc1", "1.0.0"),
            std::cmp::Ordering::Less,
            "PEP 440 rc must rank below stable"
        );
    }

    #[test]
    fn compare_versions_build_metadata_ignored() {
        // Build metadata after '+' does not affect precedence (semver §10).
        assert_eq!(
            compare_versions("1.0.0+build1", "1.0.0"),
            std::cmp::Ordering::Equal,
        );
        assert_eq!(
            compare_versions("1.0.0+a", "1.0.0+b"),
            std::cmp::Ordering::Equal,
        );
    }

    #[test]
    fn compare_versions_pep440_post_greater_than_stable() {
        assert_eq!(
            compare_versions("1.0.0.post1", "1.0.0"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_versions_non_semantic() {
        // "latest" has no numeric parts → []
        assert_eq!(
            compare_versions("latest", "1.0.0"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn compare_versions_both_non_semantic() {
        assert_eq!(
            compare_versions("latest", "main"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn compare_versions_empty_strings() {
        assert_eq!(compare_versions("", ""), std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_versions_empty_vs_version() {
        assert_eq!(compare_versions("", "1.0.0"), std::cmp::Ordering::Less);
    }

    #[test]
    fn compare_versions_long_versions() {
        assert_eq!(
            compare_versions("1.2.3.4.5", "1.2.3.4.6"),
            std::cmp::Ordering::Less
        );
    }

    // --- Group 2: version_lte ---

    #[test]
    fn version_lte_basic_true() {
        assert!(version_lte("1.0.0", "2.0.0"));
    }

    #[test]
    fn version_lte_equal_is_true() {
        assert!(version_lte("1.0.0", "1.0.0"));
    }

    #[test]
    fn version_lte_greater_is_false() {
        assert!(!version_lte("2.0.0", "1.0.0"));
    }

    #[test]
    fn version_lte_empty_lhs() {
        assert!(version_lte("", "1.0.0"));
    }

    #[test]
    fn version_lte_empty_rhs() {
        assert!(!version_lte("1.0.0", ""));
    }

    #[test]
    fn version_lte_both_empty() {
        assert!(version_lte("", ""));
    }

    // --- Group 3: extract_fix_version edge cases ---

    #[test]
    fn extract_fix_version_empty_fix_string_returns_none() {
        let json = r#"{
            "id": "CVE-test",
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": ""}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(extract_fix_version(&detail, "pkg", "PyPI", "1.0.0"), None);
    }

    #[test]
    fn extract_fix_version_multiple_events_last_wins() {
        let json = r#"{
            "id": "CVE-test",
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "1.0"},
                    {"introduced": "2.0"}, {"fixed": "3.0"}
                ]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        // Last introduced=2.0, last fixed=3.0 → single candidate (2.0, 3.0)
        assert_eq!(
            extract_fix_version(&detail, "pkg", "PyPI", "2.5"),
            Some("3.0".to_string())
        );
    }

    #[test]
    fn extract_fix_version_no_range_matches_returns_none() {
        let json = r#"{
            "id": "CVE-test",
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "5.0"}, {"fixed": "5.1"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "6.0"}, {"fixed": "6.1"}]}
                ]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        // pkg_version 3.0 is before all ranges — no match, should return None (not fallback)
        assert_eq!(extract_fix_version(&detail, "pkg", "PyPI", "3.0"), None);
    }

    #[test]
    fn extract_fix_version_introduced_zero() {
        let json = r#"{
            "id": "CVE-test",
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(
            extract_fix_version(&detail, "pkg", "PyPI", "0.5"),
            Some("1.5".to_string())
        );
    }

    #[test]
    fn extract_fix_version_fix_equals_pkg_version() {
        let json = r#"{
            "id": "CVE-test",
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        // Fix version is still extracted even when equal to installed — filtering happens elsewhere
        assert_eq!(
            extract_fix_version(&detail, "pkg", "PyPI", "2.0.0"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn extract_fix_version_case_sensitive_name() {
        let json = r#"{
            "id": "CVE-test",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
            }]
        }"#;
        let detail = parse_vuln_detail(json).unwrap();
        assert_eq!(
            extract_fix_version(&detail, "Requests", "PyPI", "1.0"),
            None
        );
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
