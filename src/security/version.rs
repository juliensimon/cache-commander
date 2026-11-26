//! Ecosystem-aware version ordering.
//!
//! Each ecosystem orders versions by its own rules (SemVer pre-release
//! identifiers, PEP 440, Maven qualifiers). A single universal comparator gets
//! the boundary cases wrong, and a wrong answer near a fix boundary makes a
//! vulnerable package look fixed. `compare` therefore returns `None` when it
//! cannot order two versions by the ecosystem's rules (unparseable input or an
//! unsupported ecosystem); callers must treat `None` as "possibly affected".

use std::cmp::Ordering;

/// Order `a` and `b` by `ecosystem`'s rules, or `None` if either cannot be
/// parsed or the ecosystem is not supported.
pub fn compare(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    match ecosystem {
        // Go module versions are SemVer with a leading `v`; pseudo-versions are
        // SemVer pre-releases.
        "npm" | "crates.io" | "Go" => semver_compare(a, b),
        "PyPI" => pep440_compare(a, b),
        "Maven" => maven_compare(a, b),
        _ => None,
    }
}

/// `a <= b` by `ecosystem`'s rules, or `None` if they cannot be ordered.
pub fn lte(ecosystem: &str, a: &str, b: &str) -> Option<bool> {
    compare(ecosystem, a, b).map(|o| o != Ordering::Greater)
}

// ---------------------------------------------------------------- SemVer ----

#[derive(Debug, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Alpha(String),
}

struct SemVer {
    core: [u64; 3],
    pre: Option<Vec<Ident>>,
}

/// SemVer 2.0 plus the conveniences npm/Go/crates.io versions carry: a leading
/// `v`, and 1 or 2 component cores padded with zeros. Build metadata is dropped.
fn parse_semver(s: &str) -> Option<SemVer> {
    let s = s.trim();
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    // Build metadata is ignored for precedence, but only if it is well formed:
    // non-empty dot-separated identifiers of [0-9A-Za-z-]. `1.0.0+` is not a
    // version, and must not compare equal to `1.0.0`.
    let s = match s.split_once('+') {
        Some((head, build)) => {
            let valid = build.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
            if !valid {
                return None;
            }
            head
        }
        None => s,
    };
    let (core, pre) = match s.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3 {
        return None;
    }
    let mut nums = [0u64; 3];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // SemVer forbids leading zeros: `01.0.0` is invalid, not `1.0.0`.
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        nums[i] = part.parse().ok()?;
    }
    let pre = match pre {
        None => None,
        Some("") => return None,
        Some(pre) => {
            let mut ids = Vec::new();
            for id in pre.split('.') {
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return None;
                }
                ids.push(if id.bytes().all(|b| b.is_ascii_digit()) {
                    // Numeric pre-release identifiers also forbid leading zeros.
                    if id.len() > 1 && id.starts_with('0') {
                        return None;
                    }
                    Ident::Num(id.parse().ok()?)
                } else {
                    Ident::Alpha(id.to_string())
                });
            }
            Some(ids)
        }
    };
    Some(SemVer { core: nums, pre })
}

/// SemVer §11: identifiers compare left to right; numeric ones numerically and
/// below alphanumeric ones; alphanumeric ones in ASCII order; with all shared
/// identifiers equal, the shorter list is lower.
fn compare_pre(a: &[Ident], b: &[Ident]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let ord = match (x, y) {
            (Ident::Num(m), Ident::Num(n)) => m.cmp(n),
            (Ident::Num(_), Ident::Alpha(_)) => Ordering::Less,
            (Ident::Alpha(_), Ident::Num(_)) => Ordering::Greater,
            (Ident::Alpha(s), Ident::Alpha(t)) => s.cmp(t),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

fn semver_compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (parse_semver(a)?, parse_semver(b)?);
    Some(a.core.cmp(&b.core).then_with(|| match (&a.pre, &b.pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater, // a release is above its pre-releases
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => compare_pre(x, y),
    }))
}

// --------------------------------------------------------------- PEP 440 ----

/// `NegInf < Val(_) < Inf`: lets "absent" sort below or above any present value.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key<T> {
    NegInf,
    Val(T),
    Inf,
}

/// One `.`-separated segment of a PEP 440 local version label. Derived ordering
/// is the spec's: any alphanumeric segment is below any numeric one, numeric
/// segments compare by value, alphanumeric ones lexically (case folded).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSeg {
    Alpha(String),
    Num(u64),
}

struct Pep {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<LocalSeg>>,
}

fn parse_pep440(input: &str) -> Option<Pep> {
    let lowered = input.trim().to_ascii_lowercase();
    let s = lowered.strip_prefix('v').unwrap_or(&lowered);
    let (public, local) = match s.split_once('+') {
        Some((public, local)) => (public, Some(local)),
        None => (s, None),
    };
    let local = match local {
        None => None,
        Some(l) => {
            let mut segs = Vec::new();
            for seg in l.split(['.', '-', '_']) {
                if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return None;
                }
                segs.push(if seg.bytes().all(|b| b.is_ascii_digit()) {
                    LocalSeg::Num(seg.parse().ok()?)
                } else {
                    LocalSeg::Alpha(seg.to_string())
                });
            }
            Some(segs)
        }
    };
    let (epoch, rest) = match public.split_once('!') {
        Some((epoch, rest)) => (epoch.parse::<u64>().ok()?, rest),
        None => (0, public),
    };

    // Release segment: digits separated by dots; a dot not followed by a digit
    // ends it (`1.0.post1`, `1.0.dev1`).
    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut release = Vec::new();
    loop {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            return None;
        }
        release.push(rest[start..i].parse::<u64>().ok()?);
        if i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
            i += 1;
            continue;
        }
        break;
    }

    let mut tail = &rest[i..];
    let (mut pre, mut post, mut dev) = (None, None, None);
    // 0: a pre-release may follow, 1: a post-release, 2: a dev release, 3: nothing.
    let mut stage = 0;
    while !tail.is_empty() {
        let after_sep = tail.strip_prefix(['.', '-', '_']);
        let t = after_sep.unwrap_or(tail);
        let word_len = t.bytes().take_while(|b| b.is_ascii_alphabetic()).count();
        let (word, after_word) = t.split_at(word_len);
        // An optional separator between the word and its number, only if a
        // number actually follows it.
        let digits_from = |x: &str| x.bytes().take_while(|b| b.is_ascii_digit()).count();
        let (number_src, consumed_sep) = match after_word.strip_prefix(['.', '-', '_']) {
            Some(r) if r.starts_with(|c: char| c.is_ascii_digit()) => (r, true),
            _ => (after_word, false),
        };
        let dlen = digits_from(number_src);
        let number = if dlen > 0 {
            number_src[..dlen].parse::<u64>().ok()?
        } else {
            0
        };
        let next = &number_src[dlen..];
        match word {
            // Implicit post-release: `1.0-1`, exactly one hyphen then digits.
            // `1.0--1` and `1.0-.1` consumed a second separator and are rejected.
            "" if tail.starts_with('-') && dlen > 0 && !consumed_sep && stage <= 1 => {
                post = Some(number);
                stage = 2;
            }
            "a" | "alpha" if stage == 0 => {
                pre = Some((0, number));
                stage = 1;
            }
            "b" | "beta" if stage == 0 => {
                pre = Some((1, number));
                stage = 1;
            }
            "c" | "rc" | "pre" | "preview" if stage == 0 => {
                pre = Some((2, number));
                stage = 1;
            }
            "post" | "rev" | "r" if stage <= 1 => {
                post = Some(number);
                stage = 2;
            }
            "dev" if stage <= 2 => {
                dev = Some(number);
                stage = 3;
            }
            _ => return None,
        }
        tail = next;
    }
    Some(Pep {
        epoch,
        release,
        pre,
        post,
        dev,
        local,
    })
}

type PepKey = (
    u64,
    Vec<u64>,
    Key<(u8, u64)>,
    Key<u64>,
    Key<u64>,
    Option<Vec<LocalSeg>>,
);

fn pep_key(p: &Pep) -> PepKey {
    let mut release = p.release.clone();
    while release.last() == Some(&0) {
        release.pop();
    }
    let pre = match (p.pre, p.post, p.dev) {
        // `1.0.dev1` sorts before `1.0a1`.
        (None, None, Some(_)) => Key::NegInf,
        (None, _, _) => Key::Inf,
        (Some(pre), _, _) => Key::Val(pre),
    };
    let post = p.post.map_or(Key::NegInf, Key::Val);
    let dev = p.dev.map_or(Key::Inf, Key::Val);
    (p.epoch, release, pre, post, dev, p.local.clone())
}

fn pep440_compare(a: &str, b: &str) -> Option<Ordering> {
    Some(pep_key(&parse_pep440(a)?).cmp(&pep_key(&parse_pep440(b)?)))
}

// ----------------------------------------------------------------- Maven ----

#[derive(Debug)]
enum MItem {
    Num(u64),
    /// (rank, text). Known qualifiers carry an empty text; an unknown one ranks
    /// above every known qualifier and is ordered by its text.
    Qual(u8, String),
}

const MAVEN_RELEASE_RANK: u8 = 5;
const MAVEN_UNKNOWN_RANK: u8 = 7;

fn maven_qualifier(word: &str, followed_by_digit: bool) -> MItem {
    let rank = match word {
        "alpha" => 0,
        "a" if followed_by_digit => 0,
        "beta" => 1,
        "b" if followed_by_digit => 1,
        "milestone" => 2,
        "m" if followed_by_digit => 2,
        "rc" | "cr" => 3,
        "snapshot" => 4,
        "" | "ga" | "final" | "release" => MAVEN_RELEASE_RANK,
        "sp" => 6,
        _ => return MItem::Qual(MAVEN_UNKNOWN_RANK, word.to_string()),
    };
    MItem::Qual(rank, String::new())
}

/// A deliberately restricted model of Maven's `ComparableVersion`: digits, dots,
/// hyphens, and qualifiers (with optional numbers). Anything it does not model,
/// including a hyphen before a plain number after a number (Maven's nested
/// build-number list, `1.0-1`), is `None` so that it fails closed.
fn maven_items(v: &str) -> Option<Vec<MItem>> {
    let v = v.trim().to_ascii_lowercase();
    if v.is_empty()
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    // Split into (separator-before, token); a token is a run of digits or letters.
    let mut tokens: Vec<(Option<u8>, String)> = Vec::new();
    let mut sep: Option<u8> = None;
    let mut cur = String::new();
    let mut cur_digit = false;
    let mut expect_token = true; // after a separator (or at the start)
    for b in v.bytes() {
        if b == b'.' || b == b'-' {
            if cur.is_empty() {
                return None; // empty segment: `1..2`, leading or trailing separator
            }
            tokens.push((sep, std::mem::take(&mut cur)));
            sep = Some(b);
            expect_token = true;
            continue;
        }
        let is_digit = b.is_ascii_digit();
        if !cur.is_empty() && is_digit != cur_digit {
            // digit <-> letter transition starts a new token with no separator
            tokens.push((sep, std::mem::take(&mut cur)));
            sep = None;
        }
        cur_digit = is_digit;
        cur.push(b as char);
        expect_token = false;
    }
    if cur.is_empty() || expect_token {
        return None;
    }
    tokens.push((sep, cur));

    let mut items: Vec<MItem> = Vec::new();
    for (idx, (sep, tok)) in tokens.iter().enumerate() {
        if tok.bytes().all(|b| b.is_ascii_digit()) {
            // `<number>-<number>` is a nested build list in Maven; not modelled.
            if *sep == Some(b'-') && matches!(items.last(), Some(MItem::Num(_))) {
                return None;
            }
            items.push(MItem::Num(tok.parse().ok()?));
        } else {
            let followed_by_digit = tokens.get(idx + 1).is_some_and(|(next_sep, next)| {
                next_sep.is_none() && next.as_bytes()[0].is_ascii_digit()
            });
            // `-` and a digit/letter transition start a sublist in Maven, after
            // trailing zeros are dropped: `1.0.0-alpha` is `1-alpha`, and so is
            // `1.0.0alpha`. A `.` does not, so `1.0.CR1` keeps its zero. Without
            // this a flat comparison ranks `1.0.0-alpha` above `1.0-sp` while
            // `1.0.0-alpha < 1.0 < 1.0-sp`: not an order.
            if *sep != Some(b'.') {
                while matches!(
                    items.last(),
                    Some(MItem::Num(0)) | Some(MItem::Qual(MAVEN_RELEASE_RANK, _))
                ) {
                    items.pop();
                }
            }
            items.push(maven_qualifier(tok, followed_by_digit));
        }
    }
    // Trailing "null" items (0, release qualifiers) do not change the version.
    while matches!(
        items.last(),
        Some(MItem::Num(0)) | Some(MItem::Qual(MAVEN_RELEASE_RANK, _))
    ) {
        items.pop();
    }
    Some(items)
}

fn maven_item_to_null(item: &MItem) -> Ordering {
    match item {
        MItem::Num(n) => n.cmp(&0),
        MItem::Qual(rank, _) => rank.cmp(&MAVEN_RELEASE_RANK),
    }
}

fn maven_item_cmp(a: Option<&MItem>, b: Option<&MItem>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (Some(x), None) => maven_item_to_null(x),
        (None, Some(y)) => maven_item_to_null(y).reverse(),
        (Some(MItem::Num(m)), Some(MItem::Num(n))) => m.cmp(n),
        (Some(MItem::Num(_)), Some(MItem::Qual(..))) => Ordering::Greater,
        (Some(MItem::Qual(..)), Some(MItem::Num(_))) => Ordering::Less,
        (Some(MItem::Qual(r1, s1)), Some(MItem::Qual(r2, s2))) => {
            r1.cmp(r2).then_with(|| s1.cmp(s2))
        }
    }
}

fn maven_compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (maven_items(a)?, maven_items(b)?);
    for i in 0..a.len().max(b.len()) {
        let ord = maven_item_cmp(a.get(i), b.get(i));
        if ord != Ordering::Equal {
            return Some(ord);
        }
    }
    Some(Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    /// Assert `a < b` in both directions, and that each equals itself.
    fn lt(eco: &str, a: &str, b: &str) {
        assert_eq!(compare(eco, a, b), Some(Less), "{eco}: {a} < {b}");
        assert_eq!(compare(eco, b, a), Some(Greater), "{eco}: {b} > {a}");
    }
    fn eq(eco: &str, a: &str, b: &str) {
        assert_eq!(compare(eco, a, b), Some(Equal), "{eco}: {a} == {b}");
        assert_eq!(compare(eco, b, a), Some(Equal), "{eco}: {b} == {a}");
    }

    // ---- SemVer: npm, crates.io, Go ----

    #[test]
    fn semver_core_is_numeric_not_lexical() {
        for eco in ["npm", "crates.io", "Go"] {
            lt(eco, "1.2.3", "1.2.10");
            lt(eco, "1.9.0", "1.10.0");
            lt(eco, "2.0.0", "10.0.0");
            eq(eco, "1.2.3", "1.2.3");
        }
    }

    #[test]
    fn semver_prerelease_precedence_follows_the_spec() {
        // The exact chain from semver.org section 11.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for eco in ["npm", "crates.io", "Go"] {
            for w in chain.windows(2) {
                lt(eco, w[0], w[1]);
            }
        }
    }

    #[test]
    fn semver_numeric_identifiers_are_compared_as_numbers_and_rank_below_alphanumeric() {
        lt("npm", "1.0.0-2", "1.0.0-10"); // numeric, not lexical
        lt("npm", "1.0.0-9", "1.0.0-a"); // numeric < alphanumeric
        lt("npm", "1.0.0-alpha", "1.0.0-alpha.0"); // fewer identifiers < more
    }

    #[test]
    fn semver_build_metadata_is_ignored_and_a_v_prefix_is_accepted() {
        eq("npm", "1.2.3+build.5", "1.2.3+other");
        eq("Go", "v1.2.3", "1.2.3");
        eq("Go", "v1.2.3+incompatible", "1.2.3");
        lt("Go", "v1.2.3-rc.1", "1.2.3");
        lt("Go", "v1.6.0", "1.7.0");
    }

    #[test]
    fn go_pseudo_versions_order_by_their_timestamp() {
        lt(
            "Go",
            "v0.0.0-20210101120000-abcdef123456",
            "v0.0.0-20220101120000-123456abcdef",
        );
        lt("Go", "v0.0.0-20210101120000-abcdef123456", "v0.0.1");
    }

    #[test]
    fn semver_rejects_what_is_not_a_semver() {
        for bad in [
            "",
            "x",
            "1.x",
            "1.2.3.4",
            "1..3",
            "1.2.3-",
            "1.2.3-a..b",
            "a.b.c",
            "latest",
        ] {
            assert_eq!(compare("npm", bad, "1.0.0"), None, "{bad:?}");
            assert_eq!(compare("npm", "1.0.0", bad), None, "{bad:?}");
        }
    }

    // ---- PEP 440: PyPI ----

    #[test]
    fn pep440_release_chain() {
        let chain = [
            "1.0.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1",
            "1.1.dev1",
            "1.1",
        ];
        for w in chain.windows(2) {
            lt("PyPI", w[0], w[1]);
        }
    }

    #[test]
    fn pep440_normalizes_spellings_and_trailing_zeros() {
        eq("PyPI", "1.0", "1.0.0");
        eq("PyPI", "1.0.0", "1");
        eq("PyPI", "1.0alpha1", "1.0a1");
        eq("PyPI", "1.0-beta.2", "1.0b2");
        eq("PyPI", "1.0c1", "1.0rc1");
        eq("PyPI", "1.0.post1", "1.0-1");
        eq("PyPI", "V1.0", "1.0");
        lt("PyPI", "1.0.dev1", "1.0.dev2");
        lt("PyPI", "1.0a1.dev1", "1.0a1");
    }

    #[test]
    fn pep440_epoch_dominates_and_local_sorts_after_public() {
        lt("PyPI", "2.0", "1!1.0");
        lt("PyPI", "1.0", "1.0+local");
        lt("PyPI", "1.0+a", "1.0+b");
        lt("PyPI", "1.0+local", "1.0.post1");
    }

    #[test]
    fn pep440_rejects_what_is_not_pep440() {
        for bad in ["", "latest", "1.x", "1.0.0.", "1.0-foo", "a1", "1.0!2"] {
            assert_eq!(compare("PyPI", bad, "1.0"), None, "{bad:?}");
        }
    }

    // ---- Maven ----

    #[test]
    fn maven_qualifier_order() {
        // alpha < beta < milestone < rc (= cr) < snapshot < release < sp
        let chain = [
            "1.0-alpha-1",
            "1.0-beta-1",
            "1.0-milestone-1",
            "1.0-rc-1",
            "1.0-snapshot",
            "1.0",
            "1.0-sp-1",
            "1.0.1",
        ];
        for w in chain.windows(2) {
            lt("Maven", w[0], w[1]);
        }
    }

    #[test]
    fn maven_cr1_is_before_final_not_after_it() {
        // The case from the issue: `CR1` and `Final` read as unknown/garbage to a
        // universal comparator.
        lt("Maven", "1.0.CR1", "1.0.Final");
        lt("Maven", "1.0.RC1", "1.0.Final");
        eq("Maven", "1.0.CR1", "1.0.RC1");
        eq("Maven", "1.0.Final", "1.0");
        eq("Maven", "1.0.GA", "1.0");
        eq("Maven", "1.0.0", "1");
        lt("Maven", "2.0.0.Beta1", "2.0.0.RC1");
        lt("Maven", "2.0.0.RC1", "2.0.0.Final");
    }

    #[test]
    fn maven_numbers_compare_numerically_and_short_letters_expand() {
        lt("Maven", "1.2.3", "1.2.10");
        lt("Maven", "1.0a1", "1.0b1");
        lt("Maven", "1.0a1", "1.0");
        lt("Maven", "1.0m1", "1.0rc1");
    }

    #[test]
    fn maven_rejects_forms_it_does_not_model() {
        // A hyphen before a plain number is a nested build list in Maven; not
        // modelled, so it must be "cannot order", not guessed.
        for bad in ["", "1.0-1", "1..2", "1.0 final", "[1.0,2.0)", "1.0+x"] {
            assert_eq!(compare("Maven", bad, "1.0"), None, "{bad:?}");
        }
    }

    // ---- malformed versions must not compare equal to a valid one (review of #125) ----

    #[test]
    fn semver_build_metadata_is_validated_before_it_is_ignored() {
        // `1.0.0+` and `1.0.0+foo..bar` are not valid SemVer; dropping the suffix
        // unchecked made them equal to 1.0.0, so an unparseable installed version
        // could clear an advisory.
        for bad in [
            "1.0.0+",
            "1.0.0+foo..bar",
            "1.0.0+.x",
            "1.0.0+a.",
            "1.0.0+a b",
            "1.0.0+!",
        ] {
            assert_eq!(compare("npm", bad, "1.0.0"), None, "{bad:?}");
            assert_eq!(compare("npm", "1.0.0", bad), None, "{bad:?}");
        }
        eq("npm", "1.0.0+build.5", "1.0.0");
        eq("npm", "1.0.0+20130313144700", "1.0.0");
        eq("npm", "1.0.0+a-b.c", "1.0.0");
    }

    #[test]
    fn semver_rejects_leading_zeros_in_numeric_identifiers() {
        // `01.0.0` / `1.0.0-01` are invalid and used to equal `1.0.0` / `1.0.0-1`.
        for bad in [
            "01.0.0",
            "1.00.0",
            "1.0.00",
            "1.0.0-01",
            "1.0.0-alpha.01",
            "v01.2.3",
        ] {
            assert_eq!(compare("npm", bad, "1.0.0"), None, "{bad:?}");
        }
        // A lone zero is fine, and zeros inside alphanumeric identifiers are fine.
        eq("npm", "0.0.0", "0.0.0");
        lt("npm", "1.0.0-0", "1.0.0-1");
        lt("npm", "1.0.0-0.3.7", "1.0.0-0.3.8");
        eq("npm", "1.0.0-0a", "1.0.0-0a");
        lt("Go", "v0.0.0-20210101120000-abcdef123456", "v0.0.1");
    }

    #[test]
    fn pep440_implicit_post_release_allows_exactly_one_hyphen_then_digits() {
        // `1.0--1` and `1.0-.1` were accepted as the implicit post-release `1.0-1`
        // and compared equal to `1.0.post1`.
        for bad in ["1.0--1", "1.0-.1", "1.0-_1", "1.0-1-1x"] {
            assert_eq!(compare("PyPI", bad, "1.0.post1"), None, "{bad:?}");
        }
        eq("PyPI", "1.0-1", "1.0.post1");
    }

    #[test]
    fn pep440_local_versions_compare_segment_by_segment() {
        // Compared as text, `vendor.2` came out ABOVE `vendor.10`.
        lt("PyPI", "1.0+vendor.2", "1.0+vendor.10");
        // A numeric segment ranks above an alphanumeric one.
        lt("PyPI", "1.0+abc", "1.0+1");
        // A shorter local version is lower when it is a prefix.
        lt("PyPI", "1.0+a", "1.0+a.1");
        // Case-insensitive, and `-`/`_` are the same as `.`.
        eq("PyPI", "1.0+ABC", "1.0+abc");
        eq("PyPI", "1.0+a-b_c", "1.0+a.b.c");
        lt("PyPI", "1.0+local", "1.0.post1");
    }

    #[test]
    fn maven_zeros_before_a_hyphen_qualifier_are_normalized_away() {
        // Maven starts a sublist at `-` (and at a digit/letter transition) after
        // dropping trailing zeros, so `1.0.0-alpha` is `1-alpha`. A flat model kept
        // the zeros, which made `1.0.0-alpha` rank ABOVE `1.0-sp` while it also
        // ranked below `1.0` and `1.0` below `1.0-sp`: not an order.
        eq("Maven", "1.0.0-alpha", "1-alpha");
        eq("Maven", "1.0.0alpha", "1-alpha");
        lt("Maven", "1.0.0-alpha", "1.0");
        lt("Maven", "1.0", "1.0-sp");
        lt("Maven", "1.0.0-alpha", "1.0-sp");
        lt("Maven", "1.0.0-beta", "1.0.0-rc");
        // A dot does NOT normalize, so a dotted qualifier keeps its zeros.
        lt("Maven", "1.0.CR1", "1.0.Final");
    }

    // ---- unsupported ecosystems ----

    #[test]
    fn unsupported_ecosystems_cannot_be_ordered() {
        assert_eq!(compare("RubyGems", "1.0", "2.0"), None);
        assert_eq!(compare("", "1.0", "2.0"), None);
        assert_eq!(lte("npm", "1.0.0", "1.0.1"), Some(true));
        assert_eq!(lte("npm", "1.0.1", "1.0.0"), Some(false));
        assert_eq!(lte("npm", "1.0.0", "1.0.0"), Some(true));
        assert_eq!(lte("npm", "x", "1.0.0"), None);
    }
}
