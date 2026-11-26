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
            // Package name goes into the JSON body, not a URL path —
            // serde_json escapes it for JSON. Percent-encoding here would
            // make OSV look up the literal encoded string (e.g. Maven
            // coordinates like `org.apache.logging.log4j:log4j-core` would
            // become `org%2Eapache%2E…` and never match).
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
    let mut resp = ureq::post(url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            &format!(
                "ccmd/{} (https://github.com/juliensimon/cache-commander)",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .send(&body)
        .map_err(|e| format!("OSV request failed: {e}"))?;
    let text = resp
        .body_mut()
        .read_to_string()
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
    /// `SEMVER`, `ECOSYSTEM` or `GIT`. Only the first two carry package
    /// versions; a `GIT` range's events are commit hashes.
    #[serde(rename = "type", default)]
    pub range_type: Option<String>,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

impl OsvRange {
    /// True for ranges whose events are package versions. A missing `type` is
    /// tolerated (older/hand-written data); `GIT` ranges are not versions.
    pub fn is_version_range(&self) -> bool {
        !self
            .range_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("GIT"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    /// Inclusive end of an affected interval (unlike `fixed`, which is
    /// exclusive). It ends an interval without naming a version that fixes it.
    #[serde(default)]
    pub last_affected: Option<String>,
    /// Exclusive end of an interval that has no fixing version (used mostly by
    /// GIT ranges, but the spec allows it on any range).
    #[serde(default)]
    pub limit: Option<String>,
}

pub fn parse_vuln_detail(json: &str) -> Result<OsvVulnDetail, serde_json::Error> {
    serde_json::from_str(json)
}

/// How an affected interval ends.
enum IntervalEnd<'a> {
    /// Exclusive upper bound: the version that fixes it.
    Fixed(&'a str),
    /// Inclusive upper bound: no fixed version exists.
    LastAffected(&'a str),
    /// Exclusive upper bound with no fixing version.
    Limit(&'a str),
    /// Never ended: every later version is affected.
    Open,
}

struct Interval<'a> {
    introduced: &'a str,
    end: IntervalEnd<'a>,
}

impl Interval<'_> {
    /// Whether the interval has begun by `version`. An `introduced` that is not
    /// a real version (`9.x`, `main`) cannot be ordered against it, so the
    /// interval is treated as possibly applicable rather than skipped (the
    /// mirror of an unknown upper bound): skipping it would let another
    /// interval's fix clear an advisory that may still apply.
    fn started_by(&self, version: &str) -> bool {
        !is_concrete_version(self.introduced) || version_lte(self.introduced, version)
    }

    /// Whether `version` lies in this interval. The `fixed` bound is treated
    /// as inclusive here, so an installed version equal to the fix still picks
    /// this interval and reports that fix; `is_vuln_active` is what then
    /// recognizes it as fixed. (A version below `introduced` or past the end is
    /// handled by the second stage of `extract_fix_version`.)
    fn contains(&self, version: &str) -> bool {
        self.started_by(version)
            && match self.end {
                IntervalEnd::Fixed(bound)
                | IntervalEnd::LastAffected(bound)
                | IntervalEnd::Limit(bound)
                    if is_concrete_version(bound) =>
                {
                    version_lte(version, bound)
                }
                // An end that is not a real version (`main`, `1.x`, a hash)
                // cannot be compared; the interval's extent is unknown, and for
                // a security check unknown means possibly affected.
                IntervalEnd::Fixed(_)
                | IntervalEnd::LastAffected(_)
                | IntervalEnd::Limit(_)
                | IntervalEnd::Open => true,
            }
    }

    /// Whether `version` is affected by this interval with the bounds exactly as
    /// specified: `fixed` and `limit` are exclusive, `last_affected` inclusive.
    /// Used to check a candidate upgrade target, where being AT a `fixed` bound
    /// already means "not affected" (unlike `contains`, which is boundary
    /// tolerant so an installed version equal to the fix still reports it).
    fn affects(&self, version: &str) -> bool {
        self.started_by(version)
            && match self.end {
                IntervalEnd::Fixed(bound) | IntervalEnd::Limit(bound)
                    if is_concrete_version(bound) =>
                {
                    compare_versions(version, bound) == std::cmp::Ordering::Less
                }
                IntervalEnd::LastAffected(bound) if is_concrete_version(bound) => {
                    version_lte(version, bound)
                }
                _ => true,
            }
    }
}

/// The event's string value, treating an empty string as absent.
fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|x| !x.is_empty())
}

/// A range's `events` are an ORDERED sequence: `introduced` opens an interval
/// and the next `fixed` or `last_affected` closes it; an `introduced` with no
/// closing event stays open. One range can hold several intervals
/// (`[0,1.0)` then `[1.5,2.0)`), so it must not be collapsed to a single
/// (last introduced, last fixed) pair, which pairs a later `introduced` with an
/// earlier `fixed` and invents a fix below the version it applies to.
fn range_intervals(range: &OsvRange) -> Vec<Interval<'_>> {
    let mut out = Vec::new();
    let mut open: Option<&str> = None;
    for event in &range.events {
        if let Some(introduced) = event.introduced.as_deref() {
            // A second `introduced` while one is still open: the earlier one
            // never ended.
            if let Some(previous) = open.replace(introduced) {
                out.push(Interval {
                    introduced: previous,
                    end: IntervalEnd::Open,
                });
            }
        }
        let end = match (
            non_empty(&event.fixed),
            non_empty(&event.last_affected),
            non_empty(&event.limit),
        ) {
            (Some(f), _, _) => Some(IntervalEnd::Fixed(f)),
            (None, Some(l), _) => Some(IntervalEnd::LastAffected(l)),
            (None, None, Some(l)) => Some(IntervalEnd::Limit(l)),
            (None, None, None) => None,
        };
        if let (Some(end), Some(introduced)) = (end, open) {
            out.push(Interval { introduced, end });
            open = None;
        }
    }
    if let Some(introduced) = open {
        out.push(Interval {
            introduced,
            end: IntervalEnd::Open,
        });
    }
    out
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
            let intervals: Vec<Interval<'_>> = affected
                .ranges
                .iter()
                .filter(|r| r.is_version_range())
                .flat_map(range_intervals)
                .collect();

            // Stage 1: the installed version is INSIDE one or more intervals,
            // so it is affected. A fix is only offered when EVERY containing
            // interval ends in a concrete `fixed` version; an open or
            // `last_affected` interval, or a non-version fix (`main`, `1.x`, a
            // hash), means there is no known fix and the advisory stays active.
            // Never borrow another interval's fix. With several containing
            // intervals the fix must leave all of them, so take the highest.
            let containing: Vec<&Interval<'_>> = intervals
                .iter()
                .filter(|iv| iv.contains(pkg_version))
                .collect();
            if !containing.is_empty() {
                let mut fixes: Vec<&str> = Vec::new();
                for iv in containing {
                    match iv.end {
                        IntervalEnd::Fixed(f) if is_concrete_version(f) => fixes.push(f),
                        _ => return None,
                    }
                }
                // The highest containing fix is only a candidate: it may itself
                // sit inside ANOTHER interval (`[0,4.0)`, `[1.0,2.0)` and
                // `[3.0,open)` give 4.0 for 1.5, which is still affected), so
                // advance through concrete fixes until no interval affects it,
                // or give up if one has no concrete end.
                let mut candidate = fixes.into_iter().max_by(|a, b| compare_versions(a, b))?;
                for _ in 0..=intervals.len() {
                    let Some(blocker) = intervals.iter().find(|iv| iv.affects(candidate)) else {
                        return Some(candidate.to_string());
                    };
                    match blocker.end {
                        IntervalEnd::Fixed(f)
                            if is_concrete_version(f)
                                && compare_versions(f, candidate)
                                    == std::cmp::Ordering::Greater =>
                        {
                            candidate = f;
                        }
                        _ => return None,
                    }
                }
                return None;
            }

            // Stage 2: inside no interval, so it is already past a fix or in a
            // gap between intervals. OSV can still report such a version (the
            // "rustix case": installed 1.1.4 against a 1.0.5 fix), so return the
            // fix of the most specific interval that starts at or below it
            // (greatest `introduced`); `is_vuln_active` then sees installed >=
            // fix and drops the advisory instead of raising a false alarm.
            let governing = intervals
                .iter()
                .filter(|iv| {
                    is_concrete_version(iv.introduced) && version_lte(iv.introduced, pkg_version)
                })
                .max_by(|a, b| compare_versions(a.introduced, b.introduced));
            return match governing.map(|iv| &iv.end) {
                Some(IntervalEnd::Fixed(f)) if is_concrete_version(f) => Some(f.to_string()),
                _ => None,
            };
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

/// True if `v` is a concrete version that can be ordered against an installed
/// version. It must be made only of version characters (`A-Za-z0-9` and
/// `._+~-`, so ranges, wildcards and spaces are out), start with a digit after
/// an optional Go-style `v`, have no standalone `x` component (`1.x`, `1.2.x`
/// are selectors that the comparator would rank below `2.0.0`), and not be a
/// commit hash. Tags and branches (`main`, `latest`), selectors and hashes
/// must never be read as "fixed". All-digit strings such as date versions
/// (`20240101`) are versions.
pub fn is_concrete_version(v: &str) -> bool {
    if v.is_empty() || v != v.trim() {
        return false;
    }
    if !v
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._+~-".contains(&b))
    {
        return false;
    }
    let digits = v.strip_prefix(['v', 'V']).unwrap_or(v);
    if !digits.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    if v.split('.').any(|part| part.eq_ignore_ascii_case("x")) {
        return false;
    }
    let looks_like_hash = v.len() >= 7
        && v.bytes().all(|b| b.is_ascii_hexdigit())
        && v.bytes().any(|b| b.is_ascii_alphabetic());
    !looks_like_hash
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
    let mut resp = ureq::get(url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .header(
            "User-Agent",
            &format!(
                "ccmd/{} (https://github.com/juliensimon/cache-commander)",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .call()
        .map_err(|e| format!("OSV detail request failed: {e}"))?;
    let text = resp
        .body_mut()
        .read_to_string()
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
    fn build_query_does_not_url_encode_names() {
        // Regression guard: package names go into the JSON body and must
        // not be percent-encoded. A Maven coordinate like
        // `org.apache.logging.log4j:log4j-core` previously got encoded to
        // `org%2Eapache%2E…`, which OSV looked up verbatim and never
        // matched (Log4Shell E2E tests went green-but-empty).
        let packages = vec![
            crate::providers::PackageId {
                ecosystem: "Maven",
                name: "org.apache.logging.log4j:log4j-core".to_string(),
                version: "2.14.1".to_string(),
            },
            crate::providers::PackageId {
                ecosystem: "PyPI",
                name: "python-dateutil".to_string(),
                version: "2.9.0".to_string(),
            },
            crate::providers::PackageId {
                ecosystem: "npm",
                name: "@types/node".to_string(),
                version: "20.0.0".to_string(),
            },
        ];
        let query = build_query(&packages);
        assert!(
            query.contains("\"name\":\"org.apache.logging.log4j:log4j-core\""),
            "Maven coord must appear unencoded in body, got: {query}"
        );
        assert!(
            query.contains("\"name\":\"python-dateutil\""),
            "PyPI hyphenated name must appear unencoded, got: {query}"
        );
        assert!(
            query.contains("\"name\":\"@types/node\""),
            "npm scoped name must appear unencoded, got: {query}"
        );
        assert!(
            !query.contains('%'),
            "no percent-encoding should appear in JSON body, got: {query}"
        );
    }

    // ---- range `type`: only package-version ranges carry a fix version (#102) ----

    const GIT_HASH: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";

    fn detail_with_ranges(ranges_json: &str) -> OsvVulnDetail {
        let json = format!(
            r#"{{"id":"GHSA-test","affected":[{{"package":{{"name":"pkg","ecosystem":"npm"}},"ranges":{ranges_json}}}]}}"#
        );
        parse_vuln_detail(&json).unwrap()
    }

    #[test]
    fn is_concrete_version_accepts_real_versions_and_rejects_selectors() {
        for ok in [
            "0",
            "1.2.3",
            "v1.2.3",
            "2.0.0a1",
            "1.0.0-rc.1",
            "1.2.3+build.5",
            "20240101",
            "1.0.0.Final",
            "2.0.0.post1",
            "1.26.17",
        ] {
            assert!(is_concrete_version(ok), "must accept {ok}");
        }
        // Digit-prefixed but NOT a concrete version: selectors, ranges,
        // wildcards. The comparator would rank `1.x` below `2.0.0`, which
        // reads an affected package as already fixed.
        for bad in [
            "1.x",
            "1.X",
            "1.2.x",
            "1.*",
            "1.2.*",
            "x",
            "*",
            "main",
            "HEAD",
            "latest",
            "^1.2.3",
            "~1.2",
            ">=1.0",
            "1.0 - 2.0",
            "1.0,2.0",
            "[1.0,2.0)",
            "1.2.3 ",
            "",
            "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        ] {
            assert!(!is_concrete_version(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn a_range_without_a_usable_fix_does_not_fall_back_to_another_ranges_fix() {
        // Ranges: [0, 1.0) and [1.5, <no usable fix>). Installed 1.6 is inside
        // the SECOND range. Choosing the range by `introduced` must not skip a
        // range just because its fix is missing or not a version and then fall
        // back to the first range's fix `1.0`, which would read 1.6 as fixed.
        for second in [
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"1.5"},{"fixed":"main"}]}"#,
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"1.5"},{"fixed":"1.x"}]}"#,
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"1.5"}]}"#,
        ] {
            let detail = detail_with_ranges(&format!(
                r#"[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"1.0"}}]}},{second}]"#
            ));
            assert_eq!(
                extract_fix_version(&detail, "pkg", "npm", "1.6.0"),
                None,
                "installed 1.6.0 is in the second range: {second}"
            );
        }
    }

    // ---- events are ordered intervals, not (last introduced, last fixed) (#101) ----

    fn fix_for(events: &str, installed: &str) -> Option<String> {
        let detail = detail_with_ranges(&format!(r#"[{{"type":"ECOSYSTEM","events":{events}}}]"#));
        extract_fix_version(&detail, "pkg", "npm", installed)
    }

    #[test]
    fn interleaved_intervals_in_one_range_each_get_their_own_fix() {
        // [0, 1.0) and [1.5, 2.0) in ONE range. Collapsing to the last
        // introduced/fixed lost the first interval entirely.
        let ev = r#"[{"introduced":"0"},{"fixed":"1.0"},{"introduced":"1.5"},{"fixed":"2.0"}]"#;
        assert_eq!(fix_for(ev, "0.5.0"), Some("1.0".to_string()));
        assert_eq!(fix_for(ev, "1.6.0"), Some("2.0".to_string()));
        // In the gap between the intervals (1.2.0) or past the last one (2.5.0)
        // the version is NOT affected, so the fix of the interval that starts at
        // or below it is reported: installed >= fix, which `is_vuln_active`
        // reads as "already fixed" and drops, as with the rustix case.
        assert_eq!(fix_for(ev, "1.2.0"), Some("1.0".to_string()));
        assert_eq!(fix_for(ev, "2.5.0"), Some("2.0".to_string()));
    }

    #[test]
    fn an_open_last_interval_never_borrows_an_earlier_fix() {
        // [0, 1.0) then [1.5, open). Pairing the last `introduced` (1.5) with the
        // earlier `fixed` (1.0) produced a "fix" below the introduced version, so
        // installed 1.6.0 (affected, no fix exists) was read as already fixed.
        let ev = r#"[{"introduced":"0"},{"fixed":"1.0"},{"introduced":"1.5"}]"#;
        assert_eq!(fix_for(ev, "1.6.0"), None);
        assert_eq!(fix_for(ev, "0.5.0"), Some("1.0".to_string()));
    }

    #[test]
    fn last_affected_ends_an_interval_without_offering_a_fix() {
        // [0, 1.0) then [2.0, 2.5] (last_affected is inclusive, not a fix).
        let ev =
            r#"[{"introduced":"0"},{"fixed":"1.0"},{"introduced":"2.0"},{"last_affected":"2.5"}]"#;
        assert_eq!(
            fix_for(ev, "2.2.0"),
            None,
            "affected, and there is no fixed version"
        );
        assert_eq!(fix_for(ev, "0.5.0"), Some("1.0".to_string()));
    }

    #[test]
    fn last_affected_closes_its_interval_so_it_does_not_leak_into_the_next() {
        // [0, 1.2] (last_affected) then [2.0, 3.0). If last_affected were
        // ignored, the first interval would stay open and swallow 2.5.0 too,
        // turning a known fix into "no fix".
        let ev =
            r#"[{"introduced":"0"},{"last_affected":"1.2"},{"introduced":"2.0"},{"fixed":"3.0"}]"#;
        assert_eq!(fix_for(ev, "2.5.0"), Some("3.0".to_string()));
        assert_eq!(
            fix_for(ev, "1.0.0"),
            None,
            "inside the last_affected interval"
        );
    }

    #[test]
    fn one_containing_interval_without_a_fix_means_no_fix_at_all() {
        // Installed 1.5 is inside [0, 3.0) AND a second interval with no usable
        // fix. Upgrading to 3.0 would still leave it in the second one, so
        // offering 3.0 would be a false fix. Check an open interval, a
        // last_affected interval and a non-version fix.
        for second in [
            r#"{"introduced":"1.0"}"#,
            r#"{"introduced":"1.0"},{"last_affected":"9.0"}"#,
            r#"{"introduced":"1.0"},{"fixed":"main"}"#,
        ] {
            let detail = detail_with_ranges(&format!(
                r#"[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"3.0"}}]}},
                    {{"type":"ECOSYSTEM","events":[{second}]}}]"#
            ));
            assert_eq!(
                extract_fix_version(&detail, "pkg", "npm", "1.5.0"),
                None,
                "second interval: {second}"
            );
        }
    }

    #[test]
    fn a_fix_must_not_land_inside_another_interval() {
        // Installed 1.5 is inside [0, 4.0) and [1.0, 2.0), so the candidate fix
        // is 4.0. But 4.0 is inside a third interval [3.0, ...). If that one is
        // open there is no safe version to upgrade to; if it ends at 5.0 the
        // fix is 5.0. Offering 4.0 would make the upgrade command useless.
        let with_third = |third: &str| {
            let detail = detail_with_ranges(&format!(
                r#"[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"4.0"}}]}},
                    {{"type":"ECOSYSTEM","events":[{{"introduced":"1.0"}},{{"fixed":"2.0"}}]}},
                    {{"type":"ECOSYSTEM","events":[{third}]}}]"#
            ));
            extract_fix_version(&detail, "pkg", "npm", "1.5.0")
        };
        assert_eq!(with_third(r#"{"introduced":"3.0"}"#), None, "open interval");
        assert_eq!(
            with_third(r#"{"introduced":"3.0"},{"last_affected":"9.0"}"#),
            None,
            "last_affected interval"
        );
        assert_eq!(
            with_third(r#"{"introduced":"3.0"},{"fixed":"5.0"}"#),
            Some("5.0".to_string()),
            "advance through a concrete fix"
        );
        // A fix exactly at another interval's exclusive end is already clear.
        assert_eq!(
            with_third(r#"{"introduced":"3.0"},{"fixed":"4.0"}"#),
            Some("4.0".to_string())
        );
    }

    #[test]
    fn an_unrecognized_introduced_bound_is_treated_as_possibly_applicable() {
        // `introduced: "9.x"` is not a version, so comparing it as text ranked it
        // above 2.0 and the interval was skipped; the first range's fix then
        // cleared the advisory. An unknown lower bound must fail toward affected.
        for bad in ["9.x", "main", "latest", "*"] {
            let detail = detail_with_ranges(&format!(
                r#"[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"1.0"}}]}},
                    {{"type":"ECOSYSTEM","events":[{{"introduced":"{bad}"}}]}}]"#
            ));
            assert_eq!(
                extract_fix_version(&detail, "pkg", "npm", "2.0.0"),
                None,
                "introduced {bad:?}: possibly applicable, so no known fix"
            );
        }
    }

    #[test]
    fn an_unrecognized_introduced_bound_also_blocks_a_candidate_upgrade() {
        // Installed 1.0 is in [0, 4.0), candidate fix 4.0. A second interval with
        // an unrecognized `introduced` and an open end might cover 4.0, so 4.0
        // must not be offered as a safe upgrade. (It is rejected at stage 1: that
        // interval also "contains" the installed version, since an unknown lower
        // bound counts as started. `affects` shares the same `started_by`, but any
        // interval that affects a candidate above the installed version also
        // contains the installed one, so its use there is not separately testable.)
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.0"}]},
                {"type":"ECOSYSTEM","events":[{"introduced":"9.x"}]}]"#,
        );
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "1.0.0"), None);
    }

    #[test]
    fn limit_closes_an_interval_without_offering_a_fix() {
        // `limit` is an exclusive end (no fix). Ignoring it left [0, 1.0) open,
        // and that open interval vetoed the applicable 3.0 fix for 2.5.0.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"limit":"1.0"}]},
                {"type":"ECOSYSTEM","events":[{"introduced":"2.0"},{"fixed":"3.0"}]}]"#,
        );
        assert_eq!(
            extract_fix_version(&detail, "pkg", "npm", "2.5.0"),
            Some("3.0".to_string())
        );
        // Inside the limit interval: affected, and no fix is known.
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "0.5.0"), None);
    }

    #[test]
    fn overlapping_intervals_offer_a_fix_that_leaves_all_of_them() {
        // Installed 1.5 is inside [0, 3.0) and [1.0, 2.0). Upgrading to 2.0
        // would still be inside the first, so the offered fix is 3.0.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0"}]},
                {"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]"#,
        );
        assert_eq!(
            extract_fix_version(&detail, "pkg", "npm", "1.5.0"),
            Some("3.0".to_string())
        );
    }

    #[test]
    fn the_matching_range_still_supplies_its_own_fix() {
        // Control: installed 0.5 is only in the first range, so its fix is used
        // even though a later range has no usable fix.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0"}]},
                {"type":"ECOSYSTEM","events":[{"introduced":"1.5"},{"fixed":"main"}]}]"#,
        );
        assert_eq!(
            extract_fix_version(&detail, "pkg", "npm", "0.5.0"),
            Some("1.0".to_string())
        );
    }

    #[test]
    fn selector_fix_is_not_extracted_as_a_fix_version() {
        for bad in ["1.x", "main", "*"] {
            let detail = detail_with_ranges(&format!(
                r#"[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{bad}"}}]}}]"#
            ));
            assert_eq!(
                extract_fix_version(&detail, "pkg", "npm", "1.0.0"),
                None,
                "fixed {bad:?} must not surface as a fix"
            );
        }
    }

    #[test]
    fn git_range_commit_hash_is_not_a_fix_version() {
        // A GIT range's `fixed` is a commit hash. Treated as a version it sorted
        // below everything, which made the advisory look already fixed.
        let detail = detail_with_ranges(&format!(
            r#"[{{"type":"GIT","repo":"https://example.test/r","events":[{{"introduced":"0"}},{{"fixed":"{GIT_HASH}"}}]}}]"#
        ));
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "1.0.0"), None);
    }

    #[test]
    fn git_range_is_ignored_when_a_semver_range_exists() {
        let detail = detail_with_ranges(&format!(
            r#"[
              {{"type":"GIT","events":[{{"introduced":"0"}},{{"fixed":"{GIT_HASH}"}}]}},
              {{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"1.4.0"}}]}}
            ]"#
        ));
        assert_eq!(
            extract_fix_version(&detail, "pkg", "npm", "1.0.0"),
            Some("1.4.0".to_string())
        );
    }

    #[test]
    fn ecosystem_and_semver_ranges_still_yield_fixes_and_missing_type_is_tolerated() {
        for ty in [r#""type":"ECOSYSTEM","#, r#""type":"SEMVER","#, ""] {
            let detail = detail_with_ranges(&format!(
                r#"[{{{ty}"events":[{{"introduced":"0"}},{{"fixed":"2.0.0"}}]}}]"#
            ));
            assert_eq!(
                extract_fix_version(&detail, "pkg", "npm", "1.0.0"),
                Some("2.0.0".to_string()),
                "type {ty:?}"
            );
        }
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
