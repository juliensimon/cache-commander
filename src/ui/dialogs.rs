use crate::tree::node::TreeNode;
use crate::ui::theme;
use humansize::{BINARY, format_size};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

pub fn render_delete_confirm(f: &mut Frame, items: &[&TreeNode]) {
    let area = centered_rect(50, 40, f.area());

    f.render_widget(Clear, area);

    let total_size: u64 = items.iter().map(|n| n.size).sum();
    let count = items.len();

    let block = Block::default()
        .title(format!(
            " Delete {count} item{}? ",
            if count == 1 { "" } else { "s" }
        ))
        .title_style(theme::DANGER)
        .borders(Borders::ALL)
        .border_style(theme::DIALOG_BORDER);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));

    for item in items.iter().take(10) {
        lines.push(Line::from(vec![
            Span::styled("  ", theme::NORMAL),
            Span::styled(&item.name, theme::NORMAL),
            Span::styled(format!(" ({})", format_size(item.size, BINARY)), theme::DIM),
        ]));
    }

    if count > 10 {
        lines.push(Line::from(Span::styled(
            format!("  ...and {} more", count - 10),
            theme::DIM,
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  Total: {} will be freed", format_size(total_size, BINARY)),
        theme::NORMAL,
    )));
    lines.push(Line::from(""));

    // Per-item safety classification (H3): resolve the real SafetyLevel for
    // each item instead of the coarse "Unknown vs. anything else" check, and
    // surface the worst tier in the summary.
    let mut caution_count = 0usize;
    let mut unsafe_count = 0usize;
    for item in items {
        match crate::providers::safety(item.kind, &item.path) {
            crate::providers::SafetyLevel::Safe => {}
            crate::providers::SafetyLevel::Caution => caution_count += 1,
            crate::providers::SafetyLevel::Unsafe => unsafe_count += 1,
        }
    }

    if unsafe_count > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "  ○ {} Unsafe item{} — will be refused on confirm",
                unsafe_count,
                if unsafe_count == 1 { "" } else { "s" }
            ),
            theme::DANGER,
        )));
        if caution_count > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "  ◐ {} Caution item{} — may cause rebuilds",
                    caution_count,
                    if caution_count == 1 { "" } else { "s" }
                ),
                theme::CAUTION,
            )));
        }
    } else if caution_count > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "  ◐ {} Caution item{} — may cause rebuilds (re-verify before deleting)",
                caution_count,
                if caution_count == 1 { "" } else { "s" }
            ),
            theme::CAUTION,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  ● All items are safe to delete (re-downloadable)",
            theme::SAFE,
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  [y]", theme::KEY),
        Span::styled(" confirm   ", theme::NORMAL),
        Span::styled("[n]", theme::DIM),
        Span::styled(" cancel", theme::NORMAL),
    ]));

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

pub fn render_help(f: &mut Frame) {
    let area = centered_rect(60, 70, f.area());

    f.render_widget(Clear, area);

    let block = Block::default()
        .title(" Help ")
        .title_style(theme::TITLE)
        .borders(Borders::ALL)
        .border_style(theme::HELP_BORDER);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let keys = vec![
        ("↑/k", "Move up"),
        ("↓/j", "Move down"),
        ("→/l", "Expand"),
        ("←/h", "Collapse / go to parent"),
        ("Enter", "Toggle expand"),
        ("g", "Jump to top"),
        ("G", "Jump to bottom"),
        ("", ""),
        ("Space", "Mark / unmark item"),
        ("u", "Unmark all"),
        ("d/D", "Delete marked items"),
        ("s", "Cycle sort (size/name/modified)"),
        ("r", "Refresh selected"),
        ("R", "Refresh all"),
        ("/", "Search / filter"),
        ("c", "Copy upgrade command to clipboard"),
        ("f", "Cycle status filter (vuln/outdated)"),
        ("m", "Mark all visible items"),
        ("Esc", "Clear filter / cancel"),
        ("", ""),
        ("v", "Scan selected for CVEs"),
        ("V", "Scan all for CVEs"),
        ("o", "Check selected for updates"),
        ("O", "Check all for updates"),
        ("?", "Toggle help"),
        ("q", "Quit"),
    ];

    let mut lines: Vec<Line> = vec![Line::from("")];
    for (key, desc) in keys {
        if key.is_empty() {
            lines.push(Line::from(""));
        } else {
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<10}", key), theme::KEY),
                Span::styled(desc, theme::NORMAL),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  By Julien Simon <julien@julien.org>",
        theme::DIM,
    )));
    lines.push(Line::from(Span::styled(
        "  Docs & code: github.com/juliensimon/cache-commander",
        theme::DIM,
    )));

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)])
        .flex(Flex::Center)
        .split(area);
    Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .split(vertical[0])[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::node::{CacheKind, TreeNode};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    fn make_node(name: &str, kind: CacheKind, size: u64) -> TreeNode {
        let mut n = TreeNode::new(PathBuf::from(format!("/tmp/{name}")), 0, None);
        n.name = name.into();
        n.kind = kind;
        n.size = size;
        n
    }

    fn render_dialog<F>(draw: F) -> String
    where
        F: FnOnce(&mut Frame),
    {
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f)).unwrap();
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

    #[test]
    fn delete_confirm_single_item_uses_singular_title_and_all_safe() {
        let node = make_node("serde 1.0.200", CacheKind::Cargo, 1024 * 1024);
        let out = render_dialog(|f| render_delete_confirm(f, &[&node]));
        assert!(out.contains("Delete 1 item?"), "singular title:\n{out}");
        assert!(out.contains("serde 1.0.200"), "item name:\n{out}");
        assert!(out.contains("1 MiB"), "item size:\n{out}");
        assert!(out.contains("Total:"), "total line:\n{out}");
        assert!(out.contains("safe to delete"), "safe badge:\n{out}");
        assert!(out.contains("[y]"), "y key:\n{out}");
        assert!(out.contains("[n]"), "n key:\n{out}");
        assert!(
            !out.contains("and "),
            "single item should not show 'and N more':\n{out}"
        );
    }

    #[test]
    fn delete_confirm_plural_title_and_total_freed() {
        let a = make_node("a", CacheKind::Cargo, 1024 * 1024);
        let b = make_node("b", CacheKind::Npm, 2 * 1024 * 1024);
        let out = render_dialog(|f| render_delete_confirm(f, &[&a, &b]));
        assert!(out.contains("Delete 2 items?"), "plural title:\n{out}");
        assert!(out.contains("3 MiB"), "summed total:\n{out}");
    }

    #[test]
    fn delete_confirm_truncates_to_ten_and_shows_more() {
        let nodes: Vec<TreeNode> = (0..15)
            .map(|i| make_node(&format!("pkg-{i}"), CacheKind::Cargo, 1024))
            .collect();
        let refs: Vec<&TreeNode> = nodes.iter().collect();
        let out = render_dialog(|f| render_delete_confirm(f, &refs));
        assert!(out.contains("Delete 15 items?"));
        assert!(out.contains("pkg-0"), "first shown:\n{out}");
        assert!(out.contains("pkg-9"), "tenth shown:\n{out}");
        assert!(
            !out.contains("pkg-10"),
            "eleventh must not appear in first-10 list:\n{out}"
        );
        assert!(out.contains("and 5 more"), "overflow hint:\n{out}");
    }

    #[test]
    fn delete_confirm_unknown_kind_shows_caution_summary() {
        // Unknown kind resolves to Caution via providers::safety().
        let node = make_node("mystery", CacheKind::Unknown, 1024);
        let out = render_dialog(|f| render_delete_confirm(f, &[&node]));
        assert!(
            out.contains("Caution") || out.contains("caution"),
            "expected caution banner:\n{out}"
        );
        assert!(
            !out.contains("All items are safe"),
            "should not claim safety:\n{out}"
        );
    }

    fn make_node_with_path(name: &str, kind: CacheKind, size: u64, path: &str) -> TreeNode {
        let mut n = make_node(name, kind, size);
        n.path = PathBuf::from(path);
        n
    }

    #[test]
    fn delete_confirm_caution_item_shows_caution_banner() {
        // Yarn Berry `.yarn/cache` is Caution, not Safe.
        let node = make_node_with_path(
            "pkg",
            CacheKind::Yarn,
            4096,
            "/project/.yarn/cache/pkg-1.0.0",
        );
        let out = render_dialog(|f| render_delete_confirm(f, &[&node]));
        assert!(
            out.contains("caution") || out.contains("Caution"),
            "expected caution banner:\n{out}"
        );
        assert!(
            !out.contains("All items are safe"),
            "caution item should not render the 'all safe' line:\n{out}"
        );
    }

    #[test]
    fn delete_confirm_unsafe_item_shows_refuse_banner() {
        // `.bun/bin/bun` is now Unsafe — dialog must surface that and
        // indicate that Unsafe items will be skipped on confirm.
        let node = make_node_with_path(
            "bun binary",
            CacheKind::Bun,
            1024 * 1024,
            "/home/user/.bun/bin/bun",
        );
        let out = render_dialog(|f| render_delete_confirm(f, &[&node]));
        assert!(
            out.contains("unsafe") || out.contains("Unsafe") || out.contains("refuse"),
            "expected Unsafe/refuse banner:\n{out}"
        );
    }

    #[test]
    fn delete_confirm_mixed_safety_surfaces_worst_level() {
        let safe = make_node_with_path(
            "lodash 4.17.21",
            CacheKind::Bun,
            1024,
            "/home/user/.bun/install/cache/lodash@4.17.21",
        );
        let unsafe_item =
            make_node_with_path("bun", CacheKind::Bun, 1024, "/home/user/.bun/bin/bun");
        let out = render_dialog(|f| render_delete_confirm(f, &[&safe, &unsafe_item]));
        // Even though one item is Safe, the Unsafe item must be flagged.
        assert!(
            out.contains("unsafe") || out.contains("Unsafe") || out.contains("refuse"),
            "mixed batch must surface Unsafe:\n{out}"
        );
        assert!(
            !out.contains("All items are safe"),
            "mixed batch must not claim 'all items are safe':\n{out}"
        );
    }

    #[test]
    fn help_dialog_lists_all_keybindings_and_author() {
        // Use a tall terminal so the 70%-height centered dialog fits the full
        // keybinding list + author credit without ratatui clipping the bottom.
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(render_help).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        assert!(out.contains("Help"), "title:\n{out}");
        for k in &[
            "↑/k", "↓/j", "g", "G", "Space", "d/D", "/", "v", "V", "o", "O", "?", "q",
        ] {
            assert!(out.contains(k), "missing key {k}:\n{out}");
        }
        for d in &["Move up", "Move down", "Jump to top", "Quit"] {
            assert!(out.contains(d), "missing desc {d}:\n{out}");
        }
        assert!(out.contains("Julien Simon"), "author credit:\n{out}");
        assert!(
            out.contains("github.com/juliensimon/cache-commander"),
            "repo link:\n{out}"
        );
    }

    #[test]
    fn centered_rect_is_centered_and_smaller() {
        let area = Rect::new(0, 0, 100, 40);
        let r = centered_rect(50, 40, area);
        assert_eq!(r.width, 50);
        assert_eq!(r.height, 16);
        assert_eq!(r.x, 25); // (100-50)/2
        assert_eq!(r.y, 12); // (40-16)/2
    }
}
