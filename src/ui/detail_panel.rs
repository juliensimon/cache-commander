use crate::providers::{self, SafetyLevel};
use crate::tree::node::CacheKind;
use crate::tree::state::TreeState;
use crate::ui::theme;
use humansize::{BINARY, format_size};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use std::time::SystemTime;

pub fn render(
    f: &mut Frame,
    area: Rect,
    tree: &TreeState,
    vuln_results: &std::collections::HashMap<std::path::PathBuf, crate::security::SecurityInfo>,
    version_results: &std::collections::HashMap<std::path::PathBuf, crate::security::VersionInfo>,
    brew_outdated_results: &std::collections::HashMap<
        String,
        crate::providers::homebrew::BrewOutdatedEntry,
    >,
) {
    let node = match tree.selected_node() {
        Some(n) => n,
        None => {
            let empty = Paragraph::new("No item selected");
            f.render_widget(empty, area);
            return;
        }
    };

    let mut lines: Vec<Line> = Vec::new();

    // Title
    lines.push(Line::from(Span::styled(&node.name, theme::TITLE)));
    lines.push(Line::from(""));

    // Path
    lines.push(Line::from(vec![
        Span::styled("Path     ", theme::DIM),
        Span::styled(node.path.to_string_lossy().to_string(), theme::NORMAL),
    ]));

    // Size
    lines.push(Line::from(vec![
        Span::styled("Size     ", theme::DIM),
        Span::styled(
            if node.size > 0 {
                format_size(node.size, BINARY)
            } else if node.children_loaded || !node.has_children {
                "0 B".to_string()
            } else {
                "calculating...".to_string()
            },
            theme::NORMAL,
        ),
    ]));

    // Last modified
    if let Some(modified) = node.last_modified {
        let elapsed = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        let label = format_elapsed(elapsed);
        lines.push(Line::from(vec![
            Span::styled("Modified ", theme::DIM),
            Span::styled(label, theme::NORMAL),
        ]));
    }

    // Provider
    if node.kind != CacheKind::Unknown {
        lines.push(Line::from(vec![
            Span::styled("Provider ", theme::DIM),
            Span::styled(node.kind.label(), theme::PROVIDER),
        ]));
        let desc = node.kind.description();
        if !desc.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("         {desc}"),
                theme::DIM,
            )));
        }
        let url = node.kind.url();
        if !url.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("URL      ", theme::DIM),
                Span::styled(url, theme::NORMAL),
            ]));
        }
    }

    // Provider metadata
    let metadata = providers::metadata(node.kind, &node.path);
    if !metadata.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("DETAILS", theme::DIM)));
        for field in &metadata {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<9}", field.label), theme::DIM),
                Span::styled(&field.value, theme::NORMAL),
            ]));
        }
    }

    // Safety
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("SAFETY", theme::DIM)));

    let safety = providers::safety(node.kind, &node.path);
    let safety_style = match safety {
        SafetyLevel::Safe => theme::SAFE,
        SafetyLevel::Caution => theme::CAUTION,
        SafetyLevel::Unsafe => theme::DANGER,
    };
    lines.push(Line::from(Span::styled(
        format!("{} {}", safety.icon(), safety.label()),
        safety_style,
    )));

    // Package name for remediation commands. For npm this reads package.json,
    // and the panel redraws ~every 60ms, so resolve it at most once per render
    // (and only if a command line is actually shown) rather than per advisory.
    let command_pkg_name = std::cell::LazyCell::new(|| {
        crate::providers::command_package_name(
            node.kind,
            &node.path,
            &extract_package_name(&node.name),
        )
    });

    // Vulnerabilities
    if let Some(sec) = vuln_results.get(&node.path) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("VULNERABILITIES ({})", sec.vulns.len()),
            theme::DANGER,
        )));
        let mut sorted_vulns = sec.vulns.clone();
        sorted_vulns.sort_by(|a, b| {
            let a_parts: Vec<u64> = a
                .fix_version
                .as_deref()
                .unwrap_or("0")
                .split('.')
                .filter_map(|s| s.parse().ok())
                .collect();
            let b_parts: Vec<u64> = b
                .fix_version
                .as_deref()
                .unwrap_or("0")
                .split('.')
                .filter_map(|s| s.parse().ok())
                .collect();
            let len = a_parts.len().max(b_parts.len());
            for i in 0..len {
                let av = a_parts.get(i).copied().unwrap_or(0);
                let bv = b_parts.get(i).copied().unwrap_or(0);
                match bv.cmp(&av) {
                    std::cmp::Ordering::Equal => continue,
                    ord => return ord,
                }
            }
            std::cmp::Ordering::Equal
        });
        for vuln in &sorted_vulns {
            let sev_str = match &vuln.severity {
                Some(s) if !s.is_empty() => format!(" ({})", s),
                _ => String::new(),
            };
            lines.push(Line::from(Span::styled(
                format!("  ⚠ {}{}", vuln.id, sev_str),
                theme::DANGER,
            )));
            if !vuln.summary.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("    {}", vuln.summary),
                    theme::DIM,
                )));
            }
            if let Some(fix) = &vuln.fix_version {
                lines.push(Line::from(Span::styled(
                    format!("    Fix: ≥{}", fix),
                    theme::SAFE,
                )));
                if let Some(name) = command_pkg_name.as_ref()
                    && let Some(cmd) = crate::providers::upgrade_command(node.kind, name, fix)
                {
                    lines.push(Line::from(Span::styled(
                        format!("    → {}", cmd),
                        theme::DIM,
                    )));
                }
            }
            lines.push(Line::from(Span::styled(
                format!("    osv.dev/vulnerability/{}", vuln.id),
                theme::DIM,
            )));
        }
    }

    // Version info
    if let Some(ver) = version_results.get(&node.path) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("VERSION", theme::DIM)));
        lines.push(Line::from(vec![
            Span::styled("  Current  ", theme::DIM),
            Span::styled(&ver.current, theme::NORMAL),
            Span::styled("  →  ", theme::DIM),
            Span::styled(
                &ver.latest,
                if ver.is_outdated {
                    theme::CAUTION
                } else {
                    theme::SAFE
                },
            ),
        ]));
        if ver.is_outdated {
            lines.push(Line::from(Span::styled(
                "  ↓ Update available",
                theme::CAUTION,
            )));
            if let Some(name) = command_pkg_name.as_ref()
                && let Some(cmd) = crate::providers::upgrade_command(node.kind, name, &ver.latest)
            {
                lines.push(Line::from(Span::styled(format!("  → {}", cmd), theme::DIM)));
            }
        }
    }

    // Brew outdated info — try semantic name first, fall back to parsing raw filename
    let brew_pkg_name = {
        let from_semantic = extract_package_name(&node.name);
        if brew_outdated_results.contains_key(&from_semantic) {
            from_semantic
        } else if let Some((name, _)) = crate::providers::homebrew::parse_bottle_name(
            &node.path.file_name().unwrap_or_default().to_string_lossy(),
        ) {
            name
        } else if let Some((name, _)) = crate::providers::homebrew::parse_manifest_name(
            &node.path.file_name().unwrap_or_default().to_string_lossy(),
        ) {
            name
        } else {
            from_semantic
        }
    };
    if let Some(entry) = brew_outdated_results.get(&brew_pkg_name) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("BREW VERSION", theme::DIM)));
        lines.push(Line::from(vec![
            Span::styled("  Current  ", theme::DIM),
            Span::styled(&entry.installed, theme::NORMAL),
            Span::styled("  →  ", theme::DIM),
            Span::styled(&entry.current, theme::CAUTION),
        ]));
        lines.push(Line::from(Span::styled(
            "  ↓ Update available",
            theme::CAUTION,
        )));
        if entry.pinned {
            lines.push(Line::from(Span::styled(
                "  Pinned — run `brew upgrade --force` to update",
                theme::DIM,
            )));
        } else {
            lines.push(Line::from(Span::styled(
                format!("  → brew upgrade {brew_pkg_name}"),
                theme::DIM,
            )));
        }
    }

    // Contextual delete hint
    let has_vuln = vuln_results.contains_key(&node.path);
    let has_outdated = version_results
        .get(&node.path)
        .is_some_and(|v| v.is_outdated);
    if has_vuln || has_outdated {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("ACTION", theme::DIM)));

        if has_vuln {
            if let Some(ver) = version_results.get(&node.path) {
                if ver.latest != ver.current {
                    lines.push(Line::from(Span::styled(
                        format!("  ● Safe to delete — {} also available", ver.latest),
                        theme::SAFE,
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        "  ○ Delete to force re-download of patched version",
                        theme::CAUTION,
                    )));
                }
            } else {
                lines.push(Line::from(Span::styled(
                    "  ○ Delete to force re-download of patched version",
                    theme::CAUTION,
                )));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "  ○ Delete to free space (outdated cached artifact)",
                theme::CAUTION,
            )));
        }
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, area);
}

fn format_elapsed(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86400 {
        format!("{} hours ago", secs / 3600)
    } else if secs < 86400 * 30 {
        format!("{} days ago", secs / 86400)
    } else if secs < 86400 * 365 {
        format!("{} months ago", secs / (86400 * 30))
    } else {
        format!("{} years ago", secs / (86400 * 365))
    }
}

fn extract_package_name(name: &str) -> String {
    let stripped = if let Some(rest) = name.strip_prefix('[') {
        rest.split_once("] ").map(|(_, n)| n).unwrap_or(name)
    } else {
        name
    };
    stripped
        .split_whitespace()
        .next()
        .unwrap_or(stripped)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SortField;
    use crate::providers::homebrew::BrewOutdatedEntry;
    use crate::security::{SecurityInfo, VersionInfo, Vulnerability};
    use crate::tree::node::TreeNode;
    use crate::tree::state::TreeState;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::collections::HashMap;
    use std::path::PathBuf;

    // ---- extract_package_name -------------------------------------------------

    #[test]
    fn extract_plain_name() {
        assert_eq!(extract_package_name("flask"), "flask");
    }

    #[test]
    fn extract_name_with_version() {
        assert_eq!(extract_package_name("requests 2.31.0"), "requests");
    }

    #[test]
    fn extract_name_with_bracket_prefix() {
        assert_eq!(extract_package_name("[model] llama"), "llama");
    }

    #[test]
    fn extract_name_with_bracket_prefix_and_version() {
        assert_eq!(extract_package_name("[PyPI] requests 2.31.0"), "requests");
    }

    #[test]
    fn extract_name_empty_string() {
        assert_eq!(extract_package_name(""), "");
    }

    #[test]
    fn extract_name_bracket_no_close() {
        // "[broken" has no "] " separator, falls back to original name
        let result = extract_package_name("[broken");
        assert_eq!(result, "[broken");
    }

    #[test]
    fn extract_name_multiple_spaces() {
        assert_eq!(extract_package_name("serde  1.0.200  extra"), "serde");
    }

    // ---- format_elapsed -------------------------------------------------------

    #[test]
    fn format_elapsed_buckets() {
        use std::time::Duration;
        assert_eq!(format_elapsed(Duration::from_secs(10)), "just now");
        assert_eq!(format_elapsed(Duration::from_secs(120)), "2 min ago");
        assert_eq!(format_elapsed(Duration::from_secs(7200)), "2 hours ago");
        assert_eq!(format_elapsed(Duration::from_secs(86400 * 3)), "3 days ago");
        assert_eq!(
            format_elapsed(Duration::from_secs(86400 * 60)),
            "2 months ago"
        );
        assert_eq!(
            format_elapsed(Duration::from_secs(86400 * 800)),
            "2 years ago"
        );
    }

    // ---- render test harness --------------------------------------------------

    /// Build a TreeState containing a single visible root node with the given
    /// name/kind/size. The path is synthetic (`/tmp/<name>`) so behavior is
    /// deterministic and no real filesystem is touched.
    fn tree_with_node(name: &str, kind: CacheKind, size: u64) -> TreeState {
        let mut node = TreeNode::new(PathBuf::from(format!("/tmp/{name}")), 0, None);
        node.name = name.to_string();
        node.kind = kind;
        node.size = size;
        node.has_children = false;
        node.children_loaded = true;
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![node]);
        tree
    }

    /// Render `detail_panel::render` into a TestBackend and return the
    /// rendered buffer as one big string (rows joined by newlines). This lets
    /// tests assert on visible text without coupling to style attributes.
    fn render_to_string(
        tree: &TreeState,
        vuln: &HashMap<PathBuf, SecurityInfo>,
        ver: &HashMap<PathBuf, VersionInfo>,
        brew: &HashMap<String, BrewOutdatedEntry>,
    ) -> String {
        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, tree, vuln, ver, brew);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    // ---- render: empty state --------------------------------------------------

    #[test]
    fn render_empty_tree_shows_placeholder() {
        let tree = TreeState::new(SortField::Size, true);
        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(
            out.contains("No item selected"),
            "expected placeholder, got:\n{out}"
        );
    }

    // ---- render: basic node ---------------------------------------------------

    #[test]
    fn render_basic_node_shows_name_path_size_provider() {
        let tree = tree_with_node("requests 2.31.0", CacheKind::Pip, 1024 * 1024 * 5);
        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(out.contains("requests 2.31.0"), "missing name:\n{out}");
        assert!(out.contains("Path"), "missing Path label:\n{out}");
        assert!(out.contains("/tmp/requests"), "missing path value:\n{out}");
        assert!(out.contains("Size"), "missing Size label:\n{out}");
        assert!(out.contains("5 MiB"), "missing formatted size:\n{out}");
        assert!(out.contains("Provider"), "missing Provider label:\n{out}");
        assert!(out.contains("pip"), "missing provider label:\n{out}");
        assert!(out.contains("SAFETY"), "missing SAFETY section:\n{out}");
    }

    // ---- render: size placeholder states --------------------------------------

    #[test]
    fn render_zero_size_with_children_loaded_shows_zero_bytes() {
        let tree = tree_with_node("empty-dir", CacheKind::Cargo, 0);
        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(out.contains("0 B"), "expected '0 B' literal:\n{out}");
    }

    #[test]
    fn render_zero_size_pending_scan_shows_calculating() {
        // has_children=true, children_loaded=false — scanner hasn't walked yet.
        let mut node = TreeNode::new(PathBuf::from("/tmp/pending"), 0, None);
        node.name = "pending".into();
        node.kind = CacheKind::Npm;
        node.size = 0;
        node.has_children = true;
        node.children_loaded = false;
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![node]);

        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(
            out.contains("calculating..."),
            "expected 'calculating...' while scan pending:\n{out}"
        );
    }

    // ---- render: vulnerability section ----------------------------------------

    #[test]
    fn render_vulnerability_section_lists_id_summary_and_fix() {
        let tree = tree_with_node("urllib3 1.26.5", CacheKind::Pip, 2048);
        let mut vuln = HashMap::new();
        vuln.insert(
            PathBuf::from("/tmp/urllib3 1.26.5"),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "GHSA-v845-jxx5-vc9f".into(),
                    summary: "urllib3 redirect issue".into(),
                    severity: Some("HIGH".into()),
                    fix_version: Some("1.26.17".into()),
                }],
            },
        );
        let out = render_to_string(&tree, &vuln, &HashMap::new(), &HashMap::new());
        assert!(out.contains("VULNERABILITIES (1)"), "header:\n{out}");
        assert!(out.contains("GHSA-v845-jxx5-vc9f"), "id:\n{out}");
        assert!(out.contains("HIGH"), "severity:\n{out}");
        assert!(out.contains("urllib3 redirect issue"), "summary:\n{out}");
        assert!(out.contains("Fix: \u{2265}1.26.17"), "fix version:\n{out}");
        assert!(out.contains("osv.dev/vulnerability/"), "osv link:\n{out}");
    }

    #[test]
    fn render_multiple_vulns_sorted_by_fix_version_descending() {
        let tree = tree_with_node("pkg 1.0.0", CacheKind::Pip, 1);
        let mut vuln = HashMap::new();
        vuln.insert(
            PathBuf::from("/tmp/pkg 1.0.0"),
            SecurityInfo {
                vulns: vec![
                    Vulnerability {
                        id: "CVE-OLD".into(),
                        summary: "".into(),
                        severity: None,
                        fix_version: Some("1.2.0".into()),
                    },
                    Vulnerability {
                        id: "CVE-NEW".into(),
                        summary: "".into(),
                        severity: None,
                        fix_version: Some("2.5.0".into()),
                    },
                ],
            },
        );
        let out = render_to_string(&tree, &vuln, &HashMap::new(), &HashMap::new());
        // Newest fix (2.5.0) should appear before oldest (1.2.0).
        let pos_new = out.find("CVE-NEW").expect("CVE-NEW missing");
        let pos_old = out.find("CVE-OLD").expect("CVE-OLD missing");
        assert!(
            pos_new < pos_old,
            "expected CVE-NEW (fix 2.5.0) before CVE-OLD (fix 1.2.0):\n{out}"
        );
    }

    // ---- render: version section ----------------------------------------------

    #[test]
    fn render_outdated_version_shows_update_hint() {
        let tree = tree_with_node("serde 1.0.100", CacheKind::Cargo, 1);
        let mut ver = HashMap::new();
        ver.insert(
            PathBuf::from("/tmp/serde 1.0.100"),
            VersionInfo {
                current: "1.0.100".into(),
                latest: "1.0.200".into(),
                is_outdated: true,
            },
        );
        let out = render_to_string(&tree, &HashMap::new(), &ver, &HashMap::new());
        assert!(out.contains("VERSION"), "version header:\n{out}");
        assert!(out.contains("1.0.100"), "current version:\n{out}");
        assert!(out.contains("1.0.200"), "latest version:\n{out}");
        assert!(out.contains("Update available"), "update hint:\n{out}");
    }

    #[test]
    fn render_up_to_date_version_has_no_update_hint() {
        let tree = tree_with_node("serde 1.0.200", CacheKind::Cargo, 1);
        let mut ver = HashMap::new();
        ver.insert(
            PathBuf::from("/tmp/serde 1.0.200"),
            VersionInfo {
                current: "1.0.200".into(),
                latest: "1.0.200".into(),
                is_outdated: false,
            },
        );
        let out = render_to_string(&tree, &HashMap::new(), &ver, &HashMap::new());
        assert!(out.contains("VERSION"));
        assert!(
            !out.contains("Update available"),
            "should not advertise updates when up-to-date:\n{out}"
        );
    }

    // ---- render: brew outdated -----------------------------------------------

    #[test]
    fn render_brew_outdated_shows_upgrade_command() {
        let tree = tree_with_node("wget 1.21", CacheKind::Homebrew, 1);
        let mut brew = HashMap::new();
        brew.insert(
            "wget".into(),
            BrewOutdatedEntry {
                installed: "1.21".into(),
                current: "1.24".into(),
                pinned: false,
            },
        );
        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &brew);
        assert!(out.contains("BREW VERSION"), "brew header:\n{out}");
        assert!(out.contains("brew upgrade wget"), "upgrade cmd:\n{out}");
        assert!(
            !out.contains("Pinned"),
            "non-pinned pkg should not show pinned hint:\n{out}"
        );
    }

    #[test]
    fn render_brew_pinned_shows_pinned_hint_instead_of_upgrade() {
        let tree = tree_with_node("wget 1.21", CacheKind::Homebrew, 1);
        let mut brew = HashMap::new();
        brew.insert(
            "wget".into(),
            BrewOutdatedEntry {
                installed: "1.21".into(),
                current: "1.24".into(),
                pinned: true,
            },
        );
        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &brew);
        assert!(out.contains("Pinned"), "expected pinned hint:\n{out}");
        assert!(
            !out.contains("→ brew upgrade wget"),
            "pinned pkg should not show plain upgrade cmd:\n{out}"
        );
    }

    // ---- render: ACTION hint --------------------------------------------------

    #[test]
    fn render_action_safe_to_delete_when_vuln_and_newer_version_available() {
        let tree = tree_with_node("urllib3 1.26.5", CacheKind::Pip, 1);
        let path = PathBuf::from("/tmp/urllib3 1.26.5");

        let mut vuln = HashMap::new();
        vuln.insert(
            path.clone(),
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-X".into(),
                    summary: "".into(),
                    severity: None,
                    fix_version: Some("1.26.17".into()),
                }],
            },
        );
        let mut ver = HashMap::new();
        ver.insert(
            path,
            VersionInfo {
                current: "1.26.5".into(),
                latest: "2.0.0".into(),
                is_outdated: true,
            },
        );

        let out = render_to_string(&tree, &vuln, &ver, &HashMap::new());
        assert!(out.contains("ACTION"), "ACTION section:\n{out}");
        assert!(
            out.contains("Safe to delete"),
            "expected 'Safe to delete' when newer version exists:\n{out}"
        );
        assert!(
            out.contains("2.0.0"),
            "should mention the newer version:\n{out}"
        );
    }

    #[test]
    fn render_action_force_redownload_when_vuln_but_no_newer_version() {
        let tree = tree_with_node("urllib3 1.26.5", CacheKind::Pip, 1);
        let path = PathBuf::from("/tmp/urllib3 1.26.5");
        let mut vuln = HashMap::new();
        vuln.insert(
            path,
            SecurityInfo {
                vulns: vec![Vulnerability {
                    id: "CVE-X".into(),
                    summary: "".into(),
                    severity: None,
                    fix_version: Some("1.26.17".into()),
                }],
            },
        );
        let out = render_to_string(&tree, &vuln, &HashMap::new(), &HashMap::new());
        assert!(out.contains("ACTION"));
        assert!(
            out.contains("force re-download"),
            "expected re-download hint:\n{out}"
        );
    }

    #[test]
    fn render_no_action_section_when_clean() {
        let tree = tree_with_node("serde 1.0.200", CacheKind::Cargo, 1024);
        let out = render_to_string(&tree, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(
            !out.contains("ACTION"),
            "clean package should not show ACTION section:\n{out}"
        );
    }
}
