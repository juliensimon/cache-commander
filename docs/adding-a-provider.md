# Adding a New Cache Provider

This is the checklist for adding a new provider (e.g. Go modules, Conda,
SPM, Nix, Bazel). It captures the wire-up sites you *will* forget and the
test-sharpening rules we've learned from past review findings.

Work through the sections in order. When a provider ships, append a
one-line **Lessons learned** entry so the next contributor inherits what
you discovered.

---

## 0. Prior art

Before touching anything, read two existing providers that have a layout
similar to yours:

- **Flat-ish layout** (one file per package-version): `cargo.rs`, `pip.rs`
- **Deep group/artifact layout**: `maven.rs`, `gradle.rs`
- **Index-file-in-hash-dir layout**: `pnpm.rs`
- **Symlink-heavy layout**: `homebrew.rs`
- **Packs + manifests**: `huggingface.rs`

Your provider will likely look more like one of these than all of them.
Copy the closest match as a scaffold, don't write from scratch.

---

## 1. Design questions (answer *before* writing code)

Write the answers inline as comments in your draft `src/providers/<name>.rs`.
If any answer is "I'll figure it out while coding," stop and figure it out
first — the answers drive every subsequent decision.

**Disk layout**
- [ ] What's the default cache root on macOS? On Linux?
- [ ] Is there a CLI (`go env GOMODCACHE`, `conda info --base`) that reports
      a non-default location? If yes, the `config::probe_*_paths()` pattern
      applies — wrap the call in `run_with_timeout` so a hung tool can't
      block startup.
- [ ] What's the path from the root to a single `(name, version)` pair?
      Draw it as a tree and mark where `name` and `version` live.
- [ ] Are there *multiple* files per `(name, version)` (jar + pom + sha1)?
      If yes, you must dedup in `package_id` on a single canonical file
      so one package isn't counted N times.

**Package identity**
- [ ] What's the OSV ecosystem name? Valid values include `crates.io`,
      `npm`, `PyPI`, `Go`, `Maven`, `RubyGems`, `NuGet`, `Packagist`,
      `Pub`, `Hex`, `Conan`. If OSV doesn't cover it, vuln scanning is a
      no-op for this provider — say so in the CHANGELOG.
- [ ] How does the OSV ecosystem name the package?
      (`pkg:golang/github.com/foo/bar`, `pkg:maven/org.foo:bar`, etc.)
      `PackageId.name` must match what OSV expects.
- [ ] Which registry serves version-check queries? If there's no public
      JSON/XML endpoint, version-check is a no-op for this provider.

**Deletion safety**
- [ ] Which paths under this cache are `Safe` (purely re-downloadable)?
- [ ] Which are `Caution` (deletion triggers slow rebuilds — e.g. a
      Gradle daemon cache)?
- [ ] Which are `Unsafe` (config, auth tokens, state — e.g. `settings.xml`,
      credentials, a local Bazel workspace)?

**Upgrade command**
- [ ] Is there a single-line CLI to upgrade (`pip install pkg==ver`)?
      If yes, return it.
- [ ] If not, is there a project-file snippet that's paste-ready
      (Maven's `<dependency>`, Gradle's `implementation '…'`,
      Go's `require github.com/foo/bar v1.2.3`)? Return that.
- [ ] If neither applies, return `None` and note it in the CHANGELOG so
      users aren't surprised the `c` key is a no-op.

---

## 2. Wire-up checklist

Each item is one edit site. Miss one and the provider will appear to
work but silently fail on that axis.

### Provider module

- [ ] `src/providers/<name>.rs` — new file with at minimum:
  - `pub fn semantic_name(path: &Path) -> Option<String>`
  - `pub fn package_id(path: &Path) -> Option<super::PackageId>`
  - `pub fn metadata(path: &Path) -> Vec<MetadataField>`
  - Unit tests for each, with at least one happy path and one
    "shouldn't match" path per function.

### Dispatch layer (`src/providers/mod.rs`)

- [ ] `pub mod <name>;` at the top (stays alphabetical).
- [ ] `detect()` — add a direct-name arm **and** an ancestor-walk arm so
      paths deep inside the cache still detect correctly. If the root
      name is ambiguous with another tool's dir, gate the detection on
      a second path component.
- [ ] `semantic_name()` dispatch arm.
- [ ] `metadata()` dispatch arm.
- [ ] `package_id()` dispatch arm.
- [ ] `upgrade_command()` arm (or accept the `_ => None` fall-through if
      there's no CLI — note it in the CHANGELOG explicitly).
- [ ] `safety()` arm if any path inside the cache is not `Safe` by
      default.
- [ ] `pre_delete()` arm **only if** the cache needs custodial setup
      before `remove_dir_all` — e.g. Go `chmod -w`'s its extracted
      module tree so the hook must `chmod -R +w` before delete.
      Default is a no-op `Ok(())` via the `_` fall-through; don't add
      an arm unless your provider actually needs one. A returned
      `Err(String)` aborts the delete and increments the `errored`
      counter in the status line.

### Tree & config (`src/tree/node.rs`, `src/config.rs`)

- [ ] `CacheKind::<Name>` variant added to the enum.
- [ ] Label / description / URL entries for the new variant (whatever
      fields the enum carries).
- [ ] `config::Config::default()` — add the default root(s) when they
      exist on disk.
- [ ] `config::Config::default_for_test()` — keep the test config
      subprocess-probe-free; do **not** call `probe_*_paths()` here.
- [ ] A test in `src/config.rs` asserting the default config includes
      the new root when `~/.cache/<whatever>` exists on the host. Skip
      the assertion cleanly when the dir isn't present, so CI without
      the tool installed stays green.

### Security pipeline

- [ ] `src/security/registry.rs` — add the registry arm for version
      lookups if the ecosystem has one. Mirror an existing provider's
      `ureq::agent().get().timeout().set("User-Agent", ...).call()`
      pattern; don't invent new HTTP scaffolding.
- [ ] No changes needed in `src/security/osv.rs` — it forwards the
      ecosystem string untouched. But **verify the ecosystem name
      matches what OSV expects**; a typo here silently disables vuln
      scanning.

### Integration tests

- [ ] `tests/e2e_<name>_provider.rs` (feature-gated on `e2e`).
      Must install a real version of the tool, download at least one
      *outdated and known-vulnerable* package, run the full scanner
      pipeline, and assert OSV + version-check both fired.
      Clean up host state on green (tempdir / env var redirection);
      leave it on red for post-mortem.

### Docs

- [ ] `README.md` — add a row to the Supported Caches table, bump the
      provider count in the Features bullet, and mention the ecosystem
      in the "Why" list if it's a widely-used package manager.
- [ ] `CHANGELOG.md` — `[Unreleased]` section gets an `### Added` bullet.
      If upgrade-command is a no-op for this provider, **say so**.
- [ ] `doc/ccmd.1` — no changes unless you added a CLI flag.
- [ ] `TODO.md` — tick the box for this provider.

### Milestone & release

- [ ] Attach the PR to the next milestone so release notes pick it up.

---

## 3. Test sharpening — lessons from past review findings

Every new provider's test suite must explicitly guard against the
patterns below. They are not theoretical — each one was a real bug
shipped in a prior provider and caught by adversarial review. Port the
relevant check into your provider's test file and name the test after
the pattern so future readers understand *why* the test exists.

### L1. Path matching uses components, not substrings

> *Caught in Bun (H7):* `install/cache-backup` was marked `Safe`
> because the safety check used a substring match for `install/cache`.

When classifying a path (safety level, cache-kind detection, anything),
**match on path components**, not substrings. Add a test like
`safety_rejects_confusable_suffix` with inputs `install/cache-backup`,
`install/cachelike`, etc. and assert they are *not* treated as the real
match.

### L2. Multi-byte filenames don't panic

> *Caught in pnpm (M1):* `parse_index_filename` sliced by byte index
> without checking `is_char_boundary` and panicked on UTF-8 filenames.

If you do any byte-level string work (slicing at an offset, truncating),
add a test with a non-ASCII filename (`café-1.0.jar`, `日本語-1.0.tgz`).
If the provider uses only `split`/`strip_prefix`/`char_indices`, this
test is a cheap regression guard anyway — add it.

### L3. Version comparison handles pre-release and metadata

> *Caught in registry comparisons (M5):* semver `-rc1`, PEP 440
> `a1`/`b2`/`rc1`/`.post1`, and `+build` suffixes all caused bogus
> "outdated" results before M5 fixed the comparator.

If your ecosystem versioning has anything beyond `X.Y.Z`, add explicit
tests for those variants. If in doubt, copy the happy-path tests from
`src/security/mod.rs::compare_versions` and adapt.

### L4. E2E tests never touch the contributor's real cache

> *Caught in yarn (H1):* an E2E test wiped the developer's real
> `~/.yarn-cache` during local runs.

E2E tests must isolate via env vars (`YARN_CACHE_FOLDER`,
`GRADLE_USER_HOME`, `GOMODCACHE`, `PIP_CACHE_DIR`, etc.) or via tool
flags (`--store-dir`, `-Dmaven.repo.local=...`). **Never** operate on
the default cache location from a test. Add a sanity assertion at the
top of the test that the configured cache dir is under `tempdir()`.

### L5. Length calculations use `chars().count()`, not bytes

> *Caught in banner centering (L5):* centering used `s.len()`, which
> returns bytes, breaking alignment on multi-byte names.

Any alignment, padding, or truncation in your provider's `metadata()`
or `semantic_name()` output must use `chars().count()` (or
`unicode-width` for display width). Emoji/CJK/accented chars in a
package name will expose this.

### L6. Tests don't shell out to real tools

> *Caught in config (L9):* `Config::default()` shelled out to
> `yarn cache dir` / `pnpm store path` in every test, coupling the
> suite to host tool availability and slowing CI.

Use `Config::default_for_test()` in your tests. If you genuinely need
probe behavior, mock the subprocess call or put the test behind the
`e2e` feature flag.

### L7. Partial failures don't look like success

> *Caught in vuln scanning (H5):* OSV network errors made packages
> drop out of the result map silently, so a partial scan looked
> identical to "all clean."

If your provider's version-check or metadata lookup can fail
transiently, surface the failure in the return type (an outcome struct
tracking `unchecked` count, or a separate error variant). A test with
a mocked failing HTTP response should assert the failure is reported,
not swallowed.

### L8. TOCTOU in delete paths

> *Caught in MCP delete (H6):* checked `is_under_roots()`, then
> `remove_dir_all()` — a race let a symlink swap the target between
> the two calls.

If your provider's safety classification depends on a path traversal
(e.g. "is this under `~/.cache`?"), make sure the path used for the
check is the same path used for the delete — canonicalize once and
reuse, don't re-resolve.

### L9. Dedup keys are stable across scans

> *Caught in Maven:* both `.jar` and `.pom` can produce a `PackageId`,
> which would double-count every artifact.

If your cache has multiple files per `(name, version)`, decide on a
canonical file and return `Some(PackageId)` **only** for that file.
Test with a directory containing every sibling file type and assert
exactly one `PackageId` is produced.

---

## 4. Before requesting review

- [ ] `cargo test` green
- [ ] `cargo test --features mcp` green
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo package --list --allow-dirty` doesn't ship anything you
      didn't intend (run this — it's cheap and the v0.3.1 review caught
      stowaways here)
- [ ] The three doc sites (README, CHANGELOG, TODO.md) are consistent.
- [ ] The E2E test actually exercises OSV and version-check on a real
      outdated+vulnerable package, not just a placeholder `.jar`.

---

## 5. Lessons learned — append after each provider ships

One line per provider. Keep it terse — this becomes a reading list, not
an essay.

- **Yarn / pnpm (PR #2, v0.3.0):** isolate E2E tests via env vars
  (H1); check `is_char_boundary` before any byte-level slicing (M1).
- **Bun (H7):** use path-component matching, not substring, for
  safety classification; the `install/cache-backup` false-positive
  wouldn't have happened with `components().windows(2)`.
- **Maven / Gradle (PR #25, v0.3.1):** deep group hierarchies forced
  scanner `max_depth` from 6 to 12 — verify yours fits. For
  ecosystems without a CLI upgrade, return a paste-ready project-file
  snippet from `upgrade_command` instead of `None` (PR #28).
- **OSV + version-check caching (PR #27, v0.3.1):** once a provider
  is wired into the scan pipeline, its results go through the 24 h
  cache automatically — no per-provider code. If your ecosystem has
  unusually volatile version data, flag it when adding the provider
  so the TTL can be revisited.
- **SwiftPM / Xcode (#11, #17):** disk-hygiene-only providers are a
  valid shape — return `None` from `package_id`, skip the
  OSV/registry arms entirely, and document the Tier-3 E2E exemption
  in the module header comment so future reviewers don't think the
  E2E test is missing by accident. For Xcode's `Info.plist`, a tiny
  XML string scanner (`find` + byte-index slicing) is sufficient and
  avoids a `plist` crate dependency; Xcode always emits XML for
  DerivedData's `Info.plist`, and char-boundary-safe slicing keeps
  multi-byte workspace paths (日本語) from panicking.
- **Go (#8):** first provider to need a pre-delete hook — Go
  `chmod -R -w`'s its extracted module tree
  (`pkg/mod/<module>@<version>/`), so `remove_dir_all` fails silently
  without a prep step. The `providers::pre_delete` dispatch was added
  in this PR; default is `_ => Ok(())` so existing providers stay
  untouched. If a future cache needs similar prep (xattr strip,
  watcher pause, file-handle release), that's the seam. Also: Go
  bang-escapes uppercase ASCII letters on disk (`github.com/Uber/zap`
  → `github.com/!uber/zap`). Decode at `semantic_name` /
  `package_id` so OSV sees the real module path; re-encode when
  building the proxy.golang.org URL. And: Go's pseudo-versions
  (`v0.0.0-YYYYMMDDHHMMSS-<12hex>`) must be filtered out of the
  registry's `/@v/list` output — otherwise the outdated signal shows
  a random recent commit instead of a real tagged release.

<!--
Template for new entries:

- **<name> (PR #NN, vX.Y.Z):** <one or two sentences on the non-obvious
  thing the next provider should inherit — a subtle path edge case,
  a registry quirk, a safety-classification surprise>.
-->
