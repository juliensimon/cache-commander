use super::version;
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
    fn started_by(&self, eco: &str, version: &str) -> bool {
        !is_concrete_version(self.introduced)
            || version::lte(eco, self.introduced, version).unwrap_or(true)
    }

    /// Whether `version` lies in this interval. The `fixed` bound is treated
    /// as inclusive here, so an installed version equal to the fix still picks
    /// this interval and reports that fix; `is_vuln_active` is what then
    /// recognizes it as fixed. (A version below `introduced` or past the end is
    /// handled by the second stage of `extract_fix_version`.)
    fn contains(&self, eco: &str, version: &str) -> bool {
        self.started_by(eco, version)
            && match self.end {
                IntervalEnd::Fixed(bound)
                | IntervalEnd::LastAffected(bound)
                | IntervalEnd::Limit(bound)
                    if is_concrete_version(bound) =>
                {
                    // Ordered by the ecosystem's rules; a pair it cannot order
                    // is possibly affected.
                    version::lte(eco, version, bound).unwrap_or(true)
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
    fn affects(&self, eco: &str, version: &str) -> bool {
        self.started_by(eco, version)
            && match self.end {
                IntervalEnd::Fixed(bound) | IntervalEnd::Limit(bound)
                    if is_concrete_version(bound) =>
                {
                    version::compare(eco, version, bound)
                        .is_none_or(|o| o == std::cmp::Ordering::Less)
                }
                IntervalEnd::LastAffected(bound) if is_concrete_version(bound) => {
                    version::lte(eco, version, bound).unwrap_or(true)
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
                .filter(|iv| iv.contains(ecosystem, pkg_version))
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
                // Ordered by the ecosystem's rules; a fix that cannot be ordered
                // against the others is not a known fix.
                let mut candidate = fixes[0];
                for &f in &fixes[1..] {
                    if version::compare(ecosystem, f, candidate)? == std::cmp::Ordering::Greater {
                        candidate = f;
                    }
                }
                for _ in 0..=intervals.len() {
                    let Some(blocker) =
                        intervals.iter().find(|iv| iv.affects(ecosystem, candidate))
                    else {
                        // `contains` is inclusive of the `fixed` bound, so the
                        // candidate is normally at or above the installed version
                        // (equal means "already fixed", and `is_vuln_active` clears
                        // it). With a non-transitive ordering such as Maven's the
                        // walk can end BELOW it, or at something that cannot be
                        // ordered against it; that is not a known fix, and
                        // offering it would make `is_vuln_active` drop an advisory
                        // that still applies.
                        return matches!(
                            version::compare(ecosystem, candidate, pkg_version),
                            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
                        )
                        .then(|| candidate.to_string());
                    };
                    match blocker.end {
                        IntervalEnd::Fixed(f)
                            if is_concrete_version(f)
                                && version::compare(ecosystem, f, candidate)
                                    == Some(std::cmp::Ordering::Greater) =>
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
                    // Started at or below the installed version, or, ONLY when the
                    // start cannot be ordered (`9.x`), ended at a real version at
                    // or below it: then the installed version is certainly past
                    // it. An interval with an orderable start above the installed
                    // version has not begun, and must not be admitted through its
                    // `fixed` bound (malformed `[5.0, fixed 1.0]` would otherwise
                    // clear an advisory from inconsistent data).
                    if is_concrete_version(iv.introduced) {
                        version::lte(ecosystem, iv.introduced, pkg_version) == Some(true)
                    } else {
                        matches!(
                            iv.end,
                            IntervalEnd::Fixed(f)
                                if is_concrete_version(f)
                                    && version::lte(ecosystem, f, pkg_version) == Some(true)
                        )
                    }
                })
                .max_by(|a, b| {
                    // An orderable start outranks an unknown one, so a text
                    // comparison of `9.x` can never pick the governing interval.
                    match (
                        is_concrete_version(a.introduced),
                        is_concrete_version(b.introduced),
                    ) {
                        (true, true) => version::compare(ecosystem, a.introduced, b.introduced)
                            .unwrap_or(std::cmp::Ordering::Equal),
                        (true, false) => std::cmp::Ordering::Greater,
                        (false, true) => std::cmp::Ordering::Less,
                        (false, false) => std::cmp::Ordering::Equal,
                    }
                });
            return match governing.map(|iv| &iv.end) {
                Some(IntervalEnd::Fixed(f)) if is_concrete_version(f) => Some(f.to_string()),
                _ => None,
            };
        }
    }
    None
}

/// True if `v` is a concrete version that can be ordered against an installed
/// version. It must be made only of version characters (`A-Za-z0-9` and
/// `._+~-!`, the `!` being a PEP 440 epoch as in `1!2.0`; ranges, wildcards and
/// spaces are out), start with a digit after
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
        .all(|b| b.is_ascii_alphanumeric() || b"._+~-!".contains(&b))
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
            "1!2.0",
            "2!1.0.0rc1",
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
    fn a_fix_that_is_not_valid_for_the_ecosystem_is_not_offered() {
        // `1.2.3.4` passes the generic "looks like a version" check but is not
        // SemVer, so it cannot be ordered against npm versions; offering it as a
        // fix (or using it to clear the advisory) would be a guess.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3.4"}]}]"#,
        );
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "1.0.0"), None);
    }

    #[test]
    fn a_fix_is_not_offered_when_it_cannot_be_ordered_against_the_installed_version() {
        // The installed version `9.0.0.0` is not SemVer, so it is treated as
        // possibly affected (inside [0, 1.0.0)), but the fix 1.0.0 cannot be
        // ordered against it: offering it as the upgrade target would be a guess.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]"#,
        );
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "9.0.0.0"), None);
    }

    #[test]
    fn interval_bounds_are_ordered_by_the_ecosystems_rules() {
        // [0, 1.0.0) for npm: installed 1.0.0-rc.1 is a PRE-release of 1.0.0, so
        // it is inside the interval and gets the fix; 1.0.0 itself is the fix.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]"#,
        );
        assert_eq!(
            extract_fix_version(&detail, "pkg", "npm", "1.0.0-rc.1"),
            Some("1.0.0".to_string())
        );
        // Maven: 1.0.CR1 is before 1.0.Final, so [0, 1.0.Final) contains it.
        let maven = parse_vuln_detail(
            r#"{"id":"X","affected":[{"package":{"name":"g:a","ecosystem":"Maven"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.Final"}]}]}]}"#,
        )
        .unwrap();
        assert_eq!(
            extract_fix_version(&maven, "g:a", "Maven", "1.0.CR1"),
            Some("1.0.Final".to_string())
        );
    }

    #[test]
    fn a_final_fix_that_orders_below_the_installed_version_is_not_offered() {
        // Maven's ordering is not transitive. Installed `1.0.0.alpha-1` is inside
        // `[0, 1)`, so it is affected. The walk then moves from `1` (blocked by
        // `[1, 1-1)`) to `1-1`, and Maven orders `1-1` BELOW `1.0.0.alpha-1`.
        // Offering it makes `is_vuln_active` see installed >= fix and drop an
        // advisory that still applies. A fix must not order below the installed version
        // (equal is allowed: that is the already-fixed case), otherwise there is no
        // known fix and the advisory stays active.
        let detail = parse_vuln_detail(
            r#"{"id":"X","affected":[{"package":{"name":"g:a","ecosystem":"Maven"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]},
                          {"type":"ECOSYSTEM","events":[{"introduced":"1"},{"fixed":"1-1"}]}]}]}"#,
        )
        .unwrap();
        assert_eq!(
            extract_fix_version(&detail, "g:a", "Maven", "1.0.0.alpha-1"),
            None
        );
        // Control: a well-ordered installed version in the same advisory still
        // gets the chained fix.
        assert_eq!(
            extract_fix_version(&detail, "g:a", "Maven", "0.5"),
            Some("1-1".to_string())
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
    fn an_interval_with_an_unknown_start_but_a_known_end_below_installed_is_past() {
        // `[introduced 9.x, fixed 1.0]`: whatever the unknown start is, installed
        // 2.0.0 is past its end, so it is already fixed. Stage 2 must still see
        // this interval (via its concrete `fixed`) and report 1.0 so the
        // advisory is dropped, instead of excluding it for the unorderable start
        // and leaving a fixed vulnerability showing as active.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"9.x"},{"fixed":"1.0"}]}]"#,
        );
        assert_eq!(
            extract_fix_version(&detail, "pkg", "npm", "2.0.0"),
            Some("1.0".to_string())
        );
    }

    #[test]
    fn an_inconsistent_interval_is_not_admitted_through_its_fixed_bound() {
        // `[introduced 5.0, fixed 1.0]` is malformed (starts above its own end).
        // Installed 2.0.0 is below its start, so it has not begun; admitting it
        // only because its `fixed` is below the installed version would clear
        // the advisory from inconsistent data. The `fixed` clause is only for an
        // interval whose start cannot be ordered at all.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"5.0"},{"fixed":"1.0"}]}]"#,
        );
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "2.0.0"), None);
    }

    #[test]
    fn stage_two_prefers_an_orderable_interval_over_an_unknown_start() {
        // Installed 10.0.0 is past both: [8.0, last_affected 9.0] (no fix, so
        // None) and [9.x, fixed 1.0]. The interval with a real start wins; the
        // unknown one must not be picked by comparing "9.x" as text.
        let detail = detail_with_ranges(
            r#"[{"type":"ECOSYSTEM","events":[{"introduced":"8.0"},{"last_affected":"9.0"}]},
                {"type":"ECOSYSTEM","events":[{"introduced":"9.x"},{"fixed":"1.0"}]}]"#,
        );
        assert_eq!(extract_fix_version(&detail, "pkg", "npm", "10.0.0"), None);
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

    // M5: pre-release / build-metadata ordering — semver + PEP 440 rules.
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
