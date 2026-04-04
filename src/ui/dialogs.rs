use crate::tree::node::TreeNode;
use crate::ui::theme;
use humansize::{format_size, BINARY};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_delete_confirm(f: &mut Frame, items: &[&TreeNode]) {
    let area = centered_rect(50, 40, f.area());

    f.render_widget(Clear, area);

    let total_size: u64 = items.iter().map(|n| n.size).sum();
    let count = items.len();

    let block = Block::default()
        .title(format!(" Delete {count} item{}? ", if count == 1 { "" } else { "s" }))
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
            Span::styled(
                format!(" ({})", format_size(item.size, BINARY)),
                theme::DIM,
            ),
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

    // Safety summary
    let all_safe = items.iter().all(|n| n.kind != crate::tree::node::CacheKind::Unknown);
    if all_safe {
        lines.push(Line::from(Span::styled(
            "  ● All items are safe to delete (re-downloadable)",
            theme::SAFE,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  ◐ Some items have unknown safety — inspect before deleting",
            theme::CAUTION,
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
        ("d/D", "Delete marked items"),
        ("s", "Cycle sort (size/name/modified)"),
        ("r", "Refresh selected"),
        ("R", "Refresh all"),
        ("/", "Search / filter"),
        ("Esc", "Clear filter / cancel"),
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
