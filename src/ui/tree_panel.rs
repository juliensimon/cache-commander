use crate::tree::state::TreeState;
use crate::ui::theme;
use humansize::{BINARY, format_size};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

pub fn render(
    f: &mut Frame,
    area: Rect,
    tree: &TreeState,
    node_status: &std::collections::HashMap<std::path::PathBuf, crate::security::NodeStatus>,
) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(theme::BORDER);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let width = inner.width as usize;

    let mut lines: Vec<Line> = Vec::new();

    let start = tree.scroll_offset;
    let end = (start + height).min(tree.visible.len());

    for vis_idx in start..end {
        let node_idx = tree.visible[vis_idx];
        let node = &tree.nodes[node_idx];
        let is_selected = vis_idx == tree.selected;
        let is_marked = tree.marked.contains(&node_idx);
        let is_dimmed = tree.dimmed.contains(&node_idx);

        // Indentation
        let indent = "  ".repeat(node.depth as usize);

        // Arrow
        let arrow = if !node.has_children {
            "  "
        } else if tree.expanded.contains(&node_idx) {
            "▾ "
        } else {
            "▸ "
        };

        // Size string
        let size_str = if node.size > 0 {
            format_size(node.size, BINARY)
        } else {
            String::new()
        };

        // Name (potentially with marker)
        let marker = if is_marked { "● " } else { "" };

        // Status icon based on vuln/outdated flags
        let status = node_status.get(&node.path);
        let status_icon = status
            .map(|s| match (s.has_vuln, s.has_outdated) {
                (true, true) => "⚠↓",
                (true, false) => "⚠ ",
                (false, true) => "↓ ",
                (false, false) => "",
            })
            .unwrap_or("");

        let name = &*crate::ui::printable(&node.name);

        // Calculate available space for name
        // Use char count for display width: arrow (▾/▸), marker (●), and status
        // icons (⚠/↓) are all single-column characters but multi-byte in UTF-8.
        let prefix_len = indent.len()
            + arrow.chars().count()
            + marker.chars().count()
            + status_icon.chars().count();
        let size_len = size_str.len() + 1; // +1 for padding
        let available = width.saturating_sub(prefix_len + size_len + 1);
        let name_char_count = name.chars().count();
        let truncated_name = if name_char_count > available {
            let truncated: String = name.chars().take(available.saturating_sub(1)).collect();
            format!("{truncated}…")
        } else {
            name.to_string()
        };

        // Padding between name and size
        let padding_len =
            width.saturating_sub(prefix_len + truncated_name.chars().count() + size_len);
        let padding = " ".repeat(padding_len);

        let style = if is_dimmed {
            theme::DIMMED
        } else {
            match (is_selected, is_marked) {
                (true, true) => theme::MARKED_SELECTED,
                (true, false) => theme::SELECTED,
                (false, true) => theme::MARKED,
                (false, false) => {
                    if node.is_root {
                        theme::DIM
                    } else {
                        theme::NORMAL
                    }
                }
            }
        };

        let icon_style = if is_dimmed {
            theme::DIMMED
        } else if let Some(s) = status {
            if s.has_vuln {
                theme::DANGER
            } else {
                theme::CAUTION
            }
        } else {
            style
        };

        let line = Line::from(vec![
            Span::styled(format!("{indent}{arrow}{marker}"), style),
            Span::styled(status_icon, if is_selected { style } else { icon_style }),
            Span::styled(truncated_name, style),
            Span::styled(padding, style),
            Span::styled(
                format!("{size_str} "),
                if is_dimmed {
                    theme::DIMMED
                } else if is_selected {
                    style
                } else {
                    theme::SIZE
                },
            ),
        ]);

        lines.push(line);
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);

    // Scrollbar
    if tree.visible.len() > height {
        let mut scrollbar_state =
            ScrollbarState::new(tree.visible.len()).position(tree.scroll_offset);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(ratatui::style::Style::default().fg(ratatui::style::Color::DarkGray))
            .track_style(
                ratatui::style::Style::default().fg(ratatui::style::Color::Rgb(30, 30, 50)),
            );
        f.render_stateful_widget(scrollbar, inner, &mut scrollbar_state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SortField;
    use crate::security::NodeStatus;
    use crate::tree::node::{CacheKind, TreeNode};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn render_tree(
        tree: &TreeState,
        status: &HashMap<PathBuf, NodeStatus>,
        width: u16,
        height: u16,
    ) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = f.area();
                render(f, area, tree, status);
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

    fn make_root(name: &str, size: u64, has_children: bool) -> TreeNode {
        let mut n = TreeNode::new(PathBuf::from(format!("/tmp/{name}")), 0, None);
        n.name = name.into();
        n.kind = CacheKind::Cargo;
        n.size = size;
        n.has_children = has_children;
        n.is_root = true;
        n
    }

    fn tree_of(nodes: Vec<TreeNode>) -> TreeState {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(nodes);
        tree
    }

    #[test]
    fn renders_node_names_and_sizes() {
        let tree = tree_of(vec![
            make_root("alpha", 1024 * 1024, false),
            make_root("beta", 2 * 1024 * 1024, false),
        ]);
        let out = render_tree(&tree, &HashMap::new(), 50, 10);
        assert!(out.contains("alpha"), "name alpha:\n{out}");
        assert!(out.contains("beta"), "name beta:\n{out}");
        assert!(out.contains("1 MiB"), "size 1 MiB:\n{out}");
        assert!(out.contains("2 MiB"), "size 2 MiB:\n{out}");
    }

    #[test]
    fn renders_collapsed_and_expanded_arrows() {
        let mut root = make_root("proj", 0, true);
        root.has_children = true;
        let tree = tree_of(vec![root]);
        let out = render_tree(&tree, &HashMap::new(), 40, 5);
        assert!(out.contains("▸"), "collapsed arrow:\n{out}");
        assert!(!out.contains("▾"), "not yet expanded:\n{out}");
    }

    #[test]
    fn renders_marker_for_marked_node() {
        let mut tree = tree_of(vec![make_root("alpha", 1024, false)]);
        tree.marked.insert(0);
        tree.recompute_visible();
        let out = render_tree(&tree, &HashMap::new(), 40, 5);
        assert!(out.contains("●"), "marker dot:\n{out}");
    }

    #[test]
    fn renders_status_icons_for_vuln_and_outdated() {
        let tree = tree_of(vec![
            make_root("vulned", 1024, false),
            make_root("stale", 1024, false),
            make_root("both", 1024, false),
        ]);
        let mut status = HashMap::new();
        status.insert(
            PathBuf::from("/tmp/vulned"),
            NodeStatus {
                has_vuln: true,
                has_outdated: false,
            },
        );
        status.insert(
            PathBuf::from("/tmp/stale"),
            NodeStatus {
                has_vuln: false,
                has_outdated: true,
            },
        );
        status.insert(
            PathBuf::from("/tmp/both"),
            NodeStatus {
                has_vuln: true,
                has_outdated: true,
            },
        );
        let out = render_tree(&tree, &status, 50, 10);
        assert!(out.contains("⚠"), "vuln icon:\n{out}");
        assert!(out.contains("↓"), "outdated arrow:\n{out}");
    }

    #[test]
    fn renders_scrollbar_path_without_panic_when_overflowing() {
        // 30 nodes in a 10-row viewport exercises the scrollbar render branch.
        // We don't assert on the scrollbar glyph itself (ratatui's Scrollbar
        // uses different chars across versions); the point is that the branch
        // runs end-to-end and still displays the first page of visible rows.
        let nodes: Vec<TreeNode> = (0..30)
            .map(|i| make_root(&format!("pkg-{i:02}"), 1024, false))
            .collect();
        let tree = tree_of(nodes);
        let out = render_tree(&tree, &HashMap::new(), 40, 10);
        assert!(out.contains("pkg-00"), "first row:\n{out}");
        // Later rows are off-screen in a 10-row viewport.
        assert!(!out.contains("pkg-29"), "should be scrolled off:\n{out}");
    }

    #[test]
    fn truncates_long_names_with_ellipsis() {
        let long = "a".repeat(200);
        let tree = tree_of(vec![make_root(&long, 1024, false)]);
        let out = render_tree(&tree, &HashMap::new(), 40, 5);
        assert!(out.contains("…"), "ellipsis present:\n{out}");
    }

    #[test]
    fn renders_zero_size_as_empty_not_zero_text() {
        let tree = tree_of(vec![make_root("empty", 0, false)]);
        let out = render_tree(&tree, &HashMap::new(), 40, 5);
        assert!(out.contains("empty"));
        // Size column should NOT print "0 B" for a zero-sized tree panel row.
        assert!(
            !out.contains("0 B"),
            "tree panel renders blank size for zero:\n{out}"
        );
    }

    #[test]
    fn renders_dimmed_nodes_without_crashing() {
        let mut tree = tree_of(vec![
            make_root("visible", 1024, false),
            make_root("hidden", 1024, false),
        ]);
        tree.dimmed.insert(1);
        let out = render_tree(&tree, &HashMap::new(), 40, 5);
        assert!(out.contains("visible"));
        assert!(out.contains("hidden"));
    }
}
