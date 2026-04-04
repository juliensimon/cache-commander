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

pub fn render(f: &mut Frame, area: Rect, tree: &TreeState) {
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
