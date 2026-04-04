use ratatui::style::{Color, Modifier, Style};

pub const TITLE: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
pub const SELECTED: Style = Style::new().bg(Color::Rgb(40, 40, 70)).fg(Color::Cyan);
pub const MARKED: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
pub const MARKED_SELECTED: Style = Style::new()
    .bg(Color::Rgb(40, 40, 70))
    .fg(Color::Yellow)
    .add_modifier(Modifier::BOLD);
pub const DIM: Style = Style::new().fg(Color::DarkGray);
pub const NORMAL: Style = Style::new().fg(Color::White);
pub const SIZE: Style = Style::new().fg(Color::Gray);
pub const HEADER: Style = Style::new().fg(Color::Gray);
pub const SAFE: Style = Style::new().fg(Color::Green);
pub const CAUTION: Style = Style::new().fg(Color::Yellow);
pub const DANGER: Style = Style::new().fg(Color::Red);
pub const PROVIDER: Style = Style::new().fg(Color::Rgb(251, 191, 36));
pub const _BAR_BG: Color = Color::Rgb(30, 30, 50);
pub const _BAR_FG: Color = Color::Cyan;
pub const DIMMED: Style = Style::new()
    .fg(Color::Rgb(80, 80, 100))
    .add_modifier(Modifier::DIM);
pub const BORDER: Style = Style::new().fg(Color::Rgb(68, 68, 68));
pub const KEY: Style = Style::new().fg(Color::Cyan);
pub const DIALOG_BORDER: Style = Style::new().fg(Color::Red);
pub const HELP_BORDER: Style = Style::new().fg(Color::Cyan);
