//! Outbound privacy policy (#95).
//!
//! A scan sends each package's name, version and ecosystem to OSV.dev and the
//! public registries. For a private package that discloses its existence, so
//! the user needs a way to keep names out of those requests entirely.
//!
//! The policy is applied BEFORE any request is built, in the same place for
//! the TUI scanner and the MCP server (`security::scan_vulns*` /
//! `check_versions*`). It must never depend on a registry's answer: a 404
//! arrives after the name has already been sent.

use crate::providers::PackageId;
use std::path::PathBuf;

/// Which packages may not be sent to public services.
#[derive(Debug, Clone, Default)]
pub struct PrivacyPolicy {
    /// Lowercased patterns; see [`PrivacyPolicy::is_private`].
    patterns: Vec<String>,
    /// Refuse every lookup. Used when the configuration could not be read, so
    /// a typo can never silently turn a deny list into "send everything".
    block_all: bool,
}

impl PrivacyPolicy {
    /// A policy that treats packages matching any of `patterns` as private.
    /// Empty patterns are dropped: an empty string would otherwise be a
    /// prefix of every name.
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            patterns: patterns
                .into_iter()
                .map(|p| p.as_ref().trim().to_ascii_lowercase())
                .map(|p| {
                    // `@acme/` and `github.com/acme/` are the usual way to
                    // write a scope or module prefix; the separator is the
                    // boundary, not part of the name. (A glob keeps them: in
                    // `acme/*` the slash is part of what is being matched.)
                    if p.contains('*') {
                        p
                    } else {
                        p.trim_end_matches(NAMESPACE_BOUNDARIES).to_string()
                    }
                })
                .filter(|p| !p.is_empty())
                .collect(),
            block_all: false,
        }
    }

    /// A policy that refuses every lookup.
    pub fn block_all() -> Self {
        Self {
            patterns: Vec::new(),
            block_all: true,
        }
    }

    /// Whether this policy refuses every lookup (see [`Self::block_all`]).
    #[cfg_attr(not(feature = "mcp"), allow(dead_code))] // only the MCP reports use it
    pub fn blocks_everything(&self) -> bool {
        self.block_all
    }

    /// Whether `pkg` must not leave the machine.
    ///
    /// A pattern matches the whole name when it is equal to it, or when it
    /// contains `*` (any run of characters, including `/`, `:` and `.`) and
    /// the glob matches. A pattern without `*` also matches every name that
    /// continues it across a namespace boundary (`/`, `:` or `.`), so
    /// `@acme` covers `@acme/ui`, `github.com/acme` covers
    /// `github.com/acme/tool`, and `com.acme` covers `com.acme:lib` and
    /// `com.acme.sub:lib` — the way `GOPRIVATE` treats module prefixes.
    /// Matching is case-insensitive. PyPI names are also compared in their
    /// PEP 503 normalised form, since `Acme_Core`, `acme-core` and
    /// `acme.core` name the same project there.
    ///
    /// Over-matching is the safe direction here: it skips a lookup, and the
    /// skip is reported; under-matching discloses a name.
    pub fn is_private(&self, pkg: &PackageId) -> bool {
        self.is_private_name(pkg.ecosystem, &pkg.name)
    }

    /// [`Self::is_private`] for a name read back from a cache file, where only
    /// the strings are at hand.
    pub fn is_private_name(&self, ecosystem: &str, name: &str) -> bool {
        if self.block_all {
            return true;
        }
        let name = name.to_ascii_lowercase();
        let pypi = ecosystem == "PyPI";
        let normalised = pypi.then(|| pep503(&name));
        self.patterns.iter().any(|pattern| {
            matches_pattern(pattern, &name, NAMESPACE_BOUNDARIES)
                || (pypi
                    && normalised.as_deref().is_some_and(|n| {
                        // Normalised, every separator is `-`, so that is the
                        // boundary: `acme` then covers `acme.core`,
                        // `acme-core` and `acme_core` alike.
                        matches_pattern(&pep503(pattern), n, PYPI_NORMALISED_BOUNDARIES)
                    }))
        })
    }

    /// Split `packages` into those that may be looked up and a count of those
    /// that may not.
    pub fn partition(
        &self,
        packages: &[(PathBuf, PackageId)],
    ) -> (Vec<(PathBuf, PackageId)>, usize) {
        let allowed: Vec<_> = packages
            .iter()
            .filter(|(_, pkg)| !self.is_private(pkg))
            .cloned()
            .collect();
        let skipped = packages.len() - allowed.len();
        (allowed, skipped)
    }
}

/// PEP 503: runs of `-`, `_` and `.` are one `-`.
fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out
}

/// What ends a namespace in a package name: an npm scope (`@acme/ui`), a Go
/// module path (`github.com/acme/tool`), a Maven group (`com.acme:lib`).
const NAMESPACE_BOUNDARIES: [char; 3] = ['/', ':', '.'];

/// PEP 503 turns every `.`, `_` and `-` into `-`.
const PYPI_NORMALISED_BOUNDARIES: [char; 4] = ['/', ':', '.', '-'];

fn matches_pattern<const N: usize>(pattern: &str, name: &str, boundaries: [char; N]) -> bool {
    if pattern.contains('*') {
        return glob(pattern.as_bytes(), name.as_bytes());
    }
    match name.strip_prefix(pattern) {
        Some("") => true,
        Some(rest) => rest.starts_with(boundaries),
        None => false,
    }
}

/// `*`-only glob. Iterative, so a hostile pattern cannot recurse deeply.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(ecosystem: &'static str, name: &str) -> PackageId {
        PackageId {
            ecosystem,
            name: name.to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn private(patterns: &[&str], ecosystem: &'static str, name: &str) -> bool {
        PrivacyPolicy::new(patterns).is_private(&pkg(ecosystem, name))
    }

    #[test]
    fn an_empty_policy_sends_everything() {
        // The default must not change behaviour for anyone who has not opted in.
        assert!(!PrivacyPolicy::default().is_private(&pkg("npm", "left-pad")));
    }

    #[test]
    fn exact_name_matches() {
        assert!(private(&["internal-tool"], "npm", "internal-tool"));
        assert!(!private(&["internal-tool"], "npm", "internal-tool-2"));
    }

    #[test]
    fn npm_scope_covers_its_packages_but_not_a_lookalike() {
        assert!(private(&["@acme"], "npm", "@acme/ui"));
        assert!(!private(&["@acme"], "npm", "@acmecorp/ui"));
    }

    #[test]
    fn go_module_prefix_works_like_goprivate() {
        assert!(private(
            &["github.com/acme"],
            "Go",
            "github.com/acme/tool/v2"
        ));
        assert!(!private(
            &["github.com/acme"],
            "Go",
            "github.com/acmeco/tool"
        ));
    }

    #[test]
    fn maven_group_covers_subgroups_and_artifacts() {
        assert!(private(&["com.acme"], "Maven", "com.acme:lib"));
        assert!(private(&["com.acme"], "Maven", "com.acme.sub:lib"));
        assert!(!private(&["com.acme"], "Maven", "com.acmeco:lib"));
    }

    #[test]
    fn wildcard_matches_across_separators() {
        assert!(private(&["acme-*"], "PyPI", "acme-core"));
        assert!(private(&["*-internal"], "crates.io", "billing-internal"));
        assert!(private(&["com.*.secret:*"], "Maven", "com.acme.secret:lib"));
        assert!(!private(&["acme-*"], "PyPI", "other-acme"));
    }

    #[test]
    fn matching_ignores_case() {
        assert!(private(&["@ACME"], "npm", "@acme/ui"));
        assert!(private(&["acme-core"], "PyPI", "Acme-Core"));
    }

    #[test]
    fn pypi_spelling_variants_are_one_project() {
        // `Acme_Core`, `acme-core` and `acme.core` are the same distribution,
        // so one pattern must cover every spelling.
        for name in ["Acme_Core", "acme-core", "acme.core", "ACME__core"] {
            assert!(private(&["acme-core"], "PyPI", name), "{name}");
            assert!(private(&["acme_core"], "PyPI", name), "{name}");
        }
        // Normalisation is PyPI's rule; it must not leak into other ecosystems.
        assert!(!private(&["acme-core"], "npm", "acme_core"));
    }

    #[test]
    fn a_pattern_written_with_a_trailing_separator_still_matches() {
        // `@acme/` and `github.com/acme/` are the natural way to write a scope
        // or a GOPRIVATE-style prefix. The separator must not stop the match.
        assert!(private(&["@acme/"], "npm", "@acme/ui"));
        assert!(private(&["github.com/acme/"], "Go", "github.com/acme/tool"));
        assert!(private(&["com.acme."], "Maven", "com.acme.sub:lib"));
        assert!(private(&["com.acme:"], "Maven", "com.acme:lib"));
        // And it is still bounded: not a lookalike.
        assert!(!private(&["@acme/"], "npm", "@acmecorp/ui"));
    }

    #[test]
    fn a_pattern_of_only_separators_matches_nothing() {
        // Trimming "/" must not leave an empty prefix that matches everything.
        assert!(!private(&["/", ".", ":"], "npm", "left-pad"));
    }

    #[test]
    fn pypi_prefix_covers_every_spelling_of_the_project() {
        // `acme.core`, `acme-core` and `acme_core` are one project. A prefix
        // that withholds one spelling must withhold them all, or what leaks
        // depends on how a cache happens to spell the directory.
        for name in ["acme.core", "acme-core", "acme_core", "Acme__Core"] {
            assert!(private(&["acme"], "PyPI", name), "{name}");
        }
        assert!(!private(&["acme"], "PyPI", "acmecorp"));
    }

    #[test]
    fn empty_and_blank_patterns_match_nothing() {
        // "" is a prefix of every name; honouring it would skip everything.
        assert!(!private(&["", "   "], "npm", "left-pad"));
        // An empty prefix would also "continue across a boundary" for any
        // name that starts with one.
        assert!(!private(&[""], "npm", ".bin"));
        assert!(!private(&[""], "Go", "/odd"));
    }

    #[test]
    fn a_lone_star_matches_everything() {
        assert!(private(&["*"], "npm", "left-pad"));
    }

    #[test]
    fn block_all_refuses_every_package() {
        assert!(PrivacyPolicy::block_all().is_private(&pkg("npm", "left-pad")));
    }

    #[test]
    fn partition_splits_and_counts() {
        let pkgs = vec![
            (PathBuf::from("/a"), pkg("npm", "@acme/ui")),
            (PathBuf::from("/b"), pkg("npm", "left-pad")),
            (PathBuf::from("/c"), pkg("npm", "@acme/api")),
        ];
        let (allowed, skipped) = PrivacyPolicy::new(["@acme"]).partition(&pkgs);
        assert_eq!(skipped, 2);
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].1.name, "left-pad");
    }

    #[test]
    fn glob_is_not_exponential() {
        // Pathological backtracking patterns must finish promptly.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(200);
        assert!(!glob(pattern.as_bytes(), text.as_bytes()));
    }
}
