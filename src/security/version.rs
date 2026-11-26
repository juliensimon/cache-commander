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
//
// A port of Maven's `ComparableVersion` (maven-artifact 3.10), validated against
// the real implementation: see `maven_matches_comparable_version_golden_pairs`.
// A version parses to a nested list: a digit/letter transition and a `-` open a
// sublist, a `.` does not, trailing "null" items (0, release qualifiers, empty
// lists) are dropped when a list is closed, and the items compare as Maven's
// `IntItem`/`StringItem`/`ListItem` do. The ordering is NOT a total order
// (Maven's own is not), which is why it is checked against Maven, not derived.

#[derive(Debug)]
enum MItem {
    Int(u64),
    /// A qualifier, lowercased with Maven's aliases applied (`cr` -> `rc`,
    /// `ga`/`final`/`release` -> "").
    Str(String),
    List(Vec<MItem>),
}

const MAVEN_QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

/// Maven's `StringItem.comparableQualifier`: the index of a known qualifier, or
/// `"7-<qualifier>"` so unknown ones sort after every known one, by text.
fn maven_comparable_qualifier(q: &str) -> String {
    match MAVEN_QUALIFIERS.iter().position(|k| *k == q) {
        Some(i) => i.to_string(),
        None => format!("{}-{}", MAVEN_QUALIFIERS.len(), q),
    }
}

fn maven_str_item(word: &str, followed_by_digit: bool) -> MItem {
    let mut value = word;
    if followed_by_digit && word.len() == 1 {
        value = match word {
            "a" => "alpha",
            "b" => "beta",
            "m" => "milestone",
            other => other,
        };
    }
    let value = match value {
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        other => other,
    };
    MItem::Str(value.to_string())
}

fn maven_is_null(item: &MItem) -> bool {
    match item {
        MItem::Int(n) => *n == 0,
        MItem::Str(s) => s.is_empty(),
        MItem::List(v) => v.is_empty(),
    }
}

/// Parse into a nested item list. `None` for input Maven would accept but this
/// port deliberately does not (empty segments, characters other than
/// `[A-Za-z0-9.-]`, numbers beyond u64): those fail closed instead of being guessed.
fn maven_parse(version: &str) -> Option<Vec<MItem>> {
    let v = version.trim().to_ascii_lowercase();
    if v.is_empty()
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    // Arena of lists; `Marker::List(i)` refers to `lists[i]`.
    enum Node {
        Item(MItem),
        List(usize),
    }
    let mut lists: Vec<Vec<Node>> = vec![Vec::new()];
    let mut cur = 0usize;

    /// Open a sublist inside the current list and make it current.
    fn open_sub(lists: &mut Vec<Vec<Node>>, cur: &mut usize) {
        lists.push(Vec::new());
        let new = lists.len() - 1;
        lists[*cur].push(Node::List(new));
        *cur = new;
    }
    /// A qualifier directly followed by a digit (`RC2`, `alpha1`) or ending the
    /// version (`1.0.0.alpha`) is treated as if introduced by `-` whatever its
    /// separator (`1.0.RC2` is `1.0-RC2`): it opens its own sublist unless the
    /// current list is still empty. A qualifier terminated by a separator
    /// (`.alpha-1`, `.rc.1`) does not.
    fn push_qualifier(lists: &mut Vec<Vec<Node>>, cur: &mut usize, item: MItem) {
        if !lists[*cur].is_empty() {
            open_sub(lists, cur);
        }
        lists[*cur].push(Node::Item(item));
    }
    let bytes = v.as_bytes();
    let mut is_digit = false;
    let mut start = 0usize;

    let parse_item = |digit: bool, tok: &str| -> Option<MItem> {
        if digit {
            Some(MItem::Int(tok.parse().ok()?))
        } else {
            Some(maven_str_item(tok, false))
        }
    };

    for i in 0..bytes.len() {
        let c = bytes[i];
        if c == b'.' || c == b'-' {
            if i == start {
                return None; // empty segment: `1..2`, a leading or trailing separator
            }
            lists[cur].push(Node::Item(parse_item(is_digit, &v[start..i])?));
            start = i + 1;
            if c == b'-' {
                open_sub(&mut lists, &mut cur);
            }
        } else if c.is_ascii_digit() {
            if !is_digit && i > start {
                // letters then a digit (`alpha1`): the qualifier is followed by a
                // digit, and the digits open a sublist.
                push_qualifier(&mut lists, &mut cur, maven_str_item(&v[start..i], true));
                start = i;
                open_sub(&mut lists, &mut cur);
            }
            is_digit = true;
        } else {
            if is_digit && i > start {
                // digits then a letter (`1alpha`): the number closes, the letters open a sublist.
                lists[cur].push(Node::Item(parse_item(true, &v[start..i])?));
                start = i;
                open_sub(&mut lists, &mut cur);
            }
            is_digit = false;
        }
    }
    if v.len() > start {
        if is_digit {
            lists[cur].push(Node::Item(parse_item(true, &v[start..])?));
        } else {
            // A trailing qualifier (`1.0.0.alpha`) is treated as `-alpha` too.
            push_qualifier(&mut lists, &mut cur, maven_str_item(&v[start..], false));
        }
    } else if v.ends_with(['.', '-']) {
        return None; // trailing separator
    }

    // Maven normalizes each list as it is popped, innermost first: arena indices
    // grow with nesting, so descending order closes children before parents.
    // Normalization drops trailing null items, skipping over non-null sublists.
    fn is_null(lists: &[Vec<Node>], node: &Node) -> bool {
        match node {
            Node::Item(item) => maven_is_null(item),
            Node::List(i) => lists[*i].is_empty(),
        }
    }
    for idx in (0..lists.len()).rev() {
        let mut i = lists[idx].len();
        while i > 0 {
            i -= 1;
            let null = is_null(&lists, &lists[idx][i]);
            if null {
                lists[idx].remove(i);
            } else if !matches!(lists[idx][i], Node::List(_)) {
                break;
            }
        }
    }

    // Resolve the arena into a tree.
    fn build(lists: &mut Vec<Vec<Node>>, idx: usize) -> Vec<MItem> {
        let nodes = std::mem::take(&mut lists[idx]);
        nodes
            .into_iter()
            .map(|n| match n {
                Node::Item(item) => item,
                Node::List(i) => MItem::List(build(lists, i)),
            })
            .collect()
    }
    Some(build(&mut lists, 0))
}

/// `item.compareTo(null)` in Maven.
fn maven_cmp_null(item: &MItem) -> Ordering {
    match item {
        MItem::Int(n) => {
            if *n == 0 {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        MItem::Str(q) => maven_comparable_qualifier(q).cmp(&maven_comparable_qualifier("")),
        // The WHOLE list is compared with null, not only its first item: `0-00.70`
        // is above `0` because of the 70, even though its first item is a zero.
        MItem::List(v) => v
            .iter()
            .map(maven_cmp_null)
            .find(|o| *o != Ordering::Equal)
            .unwrap_or(Ordering::Equal),
    }
}

fn maven_cmp(a: Option<&MItem>, b: Option<&MItem>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (Some(x), None) => maven_cmp_null(x),
        (None, Some(y)) => maven_cmp_null(y).reverse(),
        (Some(MItem::Int(m)), Some(MItem::Int(n))) => m.cmp(n),
        (Some(MItem::Int(_)), Some(_)) => Ordering::Greater,
        (Some(MItem::Str(_)), Some(MItem::Int(_))) => Ordering::Less,
        (Some(MItem::Str(x)), Some(MItem::Str(y))) => {
            maven_comparable_qualifier(x).cmp(&maven_comparable_qualifier(y))
        }
        (Some(MItem::Str(_)), Some(MItem::List(_))) => Ordering::Less,
        (Some(MItem::List(_)), Some(MItem::Int(_))) => Ordering::Less,
        (Some(MItem::List(_)), Some(MItem::Str(_))) => Ordering::Greater,
        (Some(MItem::List(x)), Some(MItem::List(y))) => maven_cmp_lists(x, y),
    }
}

fn maven_cmp_lists(x: &[MItem], y: &[MItem]) -> Ordering {
    for i in 0..x.len().max(y.len()) {
        let ord = maven_cmp(x.get(i), y.get(i));
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn maven_compare(a: &str, b: &str) -> Option<Ordering> {
    Some(maven_cmp_lists(&maven_parse(a)?, &maven_parse(b)?))
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
    fn maven_rejects_what_the_port_deliberately_does_not_accept() {
        // Maven itself would accept some of these (an empty segment reads as 0);
        // the port fails closed instead of guessing, and refuses anything that is
        // not made of `[A-Za-z0-9.-]` or that overflows a u64.
        for bad in [
            "",
            "1..2",
            ".1",
            "-1",
            "1.0.",
            "1.0-",
            "1.0 final",
            "[1.0,2.0)",
            "1.0+x",
            "1.99999999999999999999",
        ] {
            assert_eq!(compare("Maven", bad, "1.0"), None, "{bad:?}");
            assert_eq!(compare("Maven", "1.0", bad), None, "{bad:?}");
        }
    }

    #[test]
    fn maven_nested_and_dotted_forms_match_maven() {
        // Every expectation here was produced by running the pair through the real
        // maven-artifact 3.10.0 `ComparableVersion`, not derived from reading it.
        // A digit/letter transition and a hyphen open a sublist, a dot does not,
        // except that a qualifier followed by a digit or ending the version is
        // treated as if introduced by a hyphen.
        lt("Maven", "1.0-rc2", "1.0-rc.1"); // rc2 is a sublist, rc.1 a plain number
        eq("Maven", "1.0-rc2", "1.0-rc-2");
        eq("Maven", "1.0.RC2", "1.0-rc2"); // `.RC2` is `-RC2`
        eq("Maven", "1.0.RC2", "1.0.rc2");
        lt("Maven", "1.0-rc2", "1.0-rc3");
        lt("Maven", "1.0-rc2", "1.0");
        lt("Maven", "1.0-rc.1", "1.0-rc.2");
        lt("Maven", "1.0-1", "1.0-2");
        lt("Maven", "1.0", "1.0-1"); // a hyphen number is a build above the release
        lt("Maven", "1.0-1", "1.0.1");
        lt("Maven", "1.0-sp-1", "1.0.1");
        lt("Maven", "1.0.0-alpha", "1.0-sp");
        lt("Maven", "1.0.0-alpha", "1.0");
        lt("Maven", "1.0", "1.0-sp");
        eq("Maven", "1-RC2", "1.0.RC2");
        eq("Maven", "1.0.0alpha", "1-alpha");
        eq("Maven", "3.2.1.RELEASE", "3.2.1");
        eq("Maven", "1.0.CR1", "1.0.RC1");
        lt("Maven", "2.0.0.Beta1", "2.0.0.RC1");
        // A dotted qualifier then a hyphen number keeps its zeros; compared with
        // `1-1` it is above, while the bare dotted qualifier is below.
        lt("Maven", "1-1", "1.0.0.alpha-1");
        lt("Maven", "1.0.0.alpha", "1-1");
        // The whole list is compared with "null", not just its first item.
        lt("Maven", "0", "0-00.70");
    }

    /// The Maven comparator against the real thing: every pair in the golden file
    /// was answered by maven-artifact 3.10.0's `ComparableVersion`. Regenerate with
    /// a throwaway program such as
    ///
    /// ```java
    /// for (i < j) println(v[i] + "\t" + v[j] + "\t" +
    ///     Integer.signum(new ComparableVersion(v[i]).compareTo(new ComparableVersion(v[j]))));
    /// ```
    ///
    /// over a version list (JDK + `maven-artifact-*.jar` from a Maven install).
    /// The checked-in list mixes structured forms (dot, hyphen and transition
    /// qualifiers, zero components, numbers after qualifiers) with random ones.
    /// The port was also validated offline against ~675k further pairs with no
    /// disagreement; this file is the part that can run in CI.
    #[test]
    fn maven_matches_comparable_version_golden_pairs() {
        let golden = include_str!("testdata/maven_comparable_version.tsv");
        let (mut checked, mut wrong): (usize, Vec<String>) = (0, Vec::new());
        for line in golden
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let mut cols = line.split('\t');
            let (a, b, sign) = (
                cols.next().unwrap(),
                cols.next().unwrap(),
                cols.next().unwrap(),
            );
            let expected = match sign {
                "-1" => Ordering::Less,
                "0" => Ordering::Equal,
                "1" => Ordering::Greater,
                other => panic!("bad sign {other:?} in golden file"),
            };
            checked += 1;
            if compare("Maven", a, b) != Some(expected) {
                wrong.push(format!(
                    "{a} vs {b}: expected {expected:?}, got {:?}",
                    compare("Maven", a, b)
                ));
            }
        }
        assert!(
            checked > 5000,
            "golden file looks truncated: {checked} pairs"
        );
        assert!(
            wrong.is_empty(),
            "{} of {checked} pairs disagree with Maven, e.g. {:#?}",
            wrong.len(),
            &wrong[..wrong.len().min(8)]
        );
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
