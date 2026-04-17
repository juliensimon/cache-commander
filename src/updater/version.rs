// `allow(dead_code)` until consumed by `check()` in Task 5.
#![allow(dead_code)]

/// Parses a version string like `v0.3.0`, `0.3.0`, or `0.3.0-dev`.
/// Returns `None` for unparseable input. Pre-release and build metadata
/// are stripped before parsing.
pub fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let core = s.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// True iff `current` is a pre-release (contains `-` after the version core).
pub fn is_prerelease(current: &str) -> bool {
    let s = current.strip_prefix('v').unwrap_or(current);
    s.contains('-')
}

/// True iff `latest` is strictly newer than `current` AND `current` is not
/// a pre-release. Returns false on any parse failure.
pub fn is_newer(current: &str, latest: &str) -> bool {
    if is_prerelease(current) {
        return false;
    }
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        assert_eq!(parse_semver("0.3.0"), Some((0, 3, 0)));
    }

    #[test]
    fn parse_with_v_prefix() {
        assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_strips_prerelease() {
        assert_eq!(parse_semver("0.3.0-dev"), Some((0, 3, 0)));
        assert_eq!(parse_semver("v0.3.0-rc.1"), Some((0, 3, 0)));
    }

    #[test]
    fn parse_strips_build_metadata() {
        assert_eq!(parse_semver("0.3.0+build.5"), Some((0, 3, 0)));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("abc"), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("1.2.x"), None);
    }

    #[test]
    fn parse_rejects_too_many_components() {
        assert_eq!(parse_semver("1.2.3.4"), None);
        assert_eq!(parse_semver("v1.2.3.4"), None);
    }

    #[test]
    fn is_prerelease_detects_dash() {
        assert!(is_prerelease("0.3.0-dev"));
        assert!(is_prerelease("v0.3.0-rc.1"));
    }

    #[test]
    fn is_prerelease_false_for_plain() {
        assert!(!is_prerelease("0.3.0"));
        assert!(!is_prerelease("v1.2.3"));
    }

    #[test]
    fn is_newer_strictly_greater() {
        assert!(is_newer("0.3.0", "0.3.1"));
        assert!(is_newer("0.3.0", "0.4.0"));
        assert!(is_newer("0.3.0", "1.0.0"));
        assert!(is_newer("0.3.0", "v0.3.1"));
    }

    #[test]
    fn is_newer_false_when_equal_or_older() {
        assert!(!is_newer("0.3.1", "0.3.0"));
        assert!(!is_newer("0.3.0", "0.3.0"));
        assert!(!is_newer("1.0.0", "0.9.9"));
    }

    #[test]
    fn is_newer_suppresses_for_prerelease_current() {
        assert!(!is_newer("0.4.0-dev", "0.3.0"));
        assert!(!is_newer("0.4.0-dev", "0.4.0"));
        assert!(!is_newer("0.4.0-dev", "0.5.0"));
    }

    #[test]
    fn is_newer_false_on_parse_failure() {
        assert!(!is_newer("garbage", "0.3.0"));
        assert!(!is_newer("0.3.0", "garbage"));
    }
}
