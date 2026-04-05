use crate::providers::{self, SafetyLevel};
use crate::tree::node::CacheKind;
use crate::tree::state::TreeState;
use crate::ui::theme;
use humansize::{format_size, BINARY};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
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
                if let Some(cmd) = crate::providers::upgrade_command(
                    node.kind,
                    &extract_package_name(&node.name),
                    fix,
                ) {
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
            if let Some(cmd) = crate::providers::upgrade_command(
                node.kind,
                &extract_package_name(&node.name),
                &ver.latest,
            ) {
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
}
