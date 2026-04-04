use crate::tree::state::TreeState;
use crate::ui::theme;
use humansize::{format_size, BINARY};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Frame;

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

        let name = &node.name;

        // Calculate available space for name
        let prefix_len = indent.len() + arrow.len() + marker.len() + status_icon.len();
        let size_len = size_str.len() + 1; // +1 for padding
        let available = width.saturating_sub(prefix_len + size_len + 1);
        let truncated_name = if name.len() > available {
            format!("{}…", &name[..available.saturating_sub(1)])
        } else {
            name.to_string()
        };

        // Padding between name and size
        let padding_len = width
            .saturating_sub(prefix_len + truncated_name.len() + size_len);
        let padding = " ".repeat(padding_len);

        let style = match (is_selected, is_marked) {
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
        };

        let icon_style = if let Some(s) = status {
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
            Span::styled(format!("{size_str} "), if is_selected { style } else { theme::SIZE }),
        ]);

        lines.push(line);
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);

    // Scrollbar
    if tree.visible.len() > height {
        let mut scrollbar_state = ScrollbarState::new(tree.visible.len())
            .position(tree.scroll_offset);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(ratatui::style::Style::default().fg(ratatui::style::Color::DarkGray))
            .track_style(ratatui::style::Style::default().fg(ratatui::style::Color::Rgb(30, 30, 50)));
        f.render_stateful_widget(scrollbar, inner, &mut scrollbar_state);
    }
}
