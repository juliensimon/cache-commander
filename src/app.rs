use crate::config::Config;
use crate::scanner::ScanResult;
use crate::tree::state::TreeState;
use crate::ui::{detail_panel, dialogs, tree_panel};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, PartialEq)]
pub enum AppMode {
    Normal,
    Deleting,
    Help,
    Filtering,
}

pub struct App {
    pub tree: TreeState,
    pub config: Config,
    pub mode: AppMode,
    pub filter_text: String,
    pub should_quit: bool,
    pub scan_rx: mpsc::Receiver<ScanResult>,
    pub scan_tx: mpsc::Sender<crate::scanner::ScanRequest>,
    pub status_msg: Option<String>,
    delete_candidates: Vec<usize>,
}

impl App {
    pub fn new(
        config: Config,
        scan_rx: mpsc::Receiver<ScanResult>,
        scan_tx: mpsc::Sender<crate::scanner::ScanRequest>,
    ) -> Self {
        let tree = TreeState::new(config.sort_by, config.sort_desc);
        Self {
            tree,
            config,
            mode: AppMode::Normal,
            filter_text: String::new(),
            should_quit: false,
            scan_rx,
            scan_tx,
            status_msg: None,
            delete_candidates: Vec::new(),
        }
    }

    pub fn init(&self) {
        let roots = self.config.roots.clone();
        let _ = self.scan_tx.send(crate::scanner::ScanRequest::ScanRoots(roots));
    }

    pub fn tick(&mut self) {
        // Process scan results
        while let Ok(result) = self.scan_rx.try_recv() {
            match result {
                ScanResult::RootsScanned(nodes) => {
                    self.tree.set_roots(nodes);
                }
                ScanResult::ChildrenScanned(parent_path, children) => {
                    if let Some(parent_idx) =
                        self.tree.nodes.iter().position(|n| n.path == parent_path)
                    {
                        self.tree.insert_children(parent_idx, children);
                    }
                }
                ScanResult::SizeUpdated(path, size) => {
                    if let Some(node) = self.tree.nodes.iter_mut().find(|n| n.path == path) {
                        node.size = size;
                    }
                }
            }
        }
    }

    pub fn handle_event(&mut self) -> bool {
        if event::poll(Duration::from_millis(60)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                self.process_key(key);
            }
        }
        self.tick();
        self.should_quit
    }

    pub fn process_key(&mut self, key: KeyEvent) {
        match self.mode {
            AppMode::Normal => self.handle_normal_key(key),
            AppMode::Deleting => self.handle_delete_key(key),
            AppMode::Help => self.handle_help_key(key),
            AppMode::Filtering => self.handle_filter_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true
            }
            KeyCode::Up | KeyCode::Char('k') => self.tree.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.tree.move_down(),
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(idx) = self.tree.expand() {
                    let path = self.tree.nodes[idx].path.clone();
                    let _ = self
                        .scan_tx
                        .send(crate::scanner::ScanRequest::ExpandNode(path));
                }
            }
            KeyCode::Left | KeyCode::Char('h') => self.tree.collapse(),
            KeyCode::Enter => {
                if let Some(idx) = self.tree.toggle_expand() {
                    let path = self.tree.nodes[idx].path.clone();
                    let _ = self
                        .scan_tx
                        .send(crate::scanner::ScanRequest::ExpandNode(path));
                }
            }
            KeyCode::Char('g') => self.tree.go_top(),
            KeyCode::Char('G') => self.tree.go_bottom(),
            KeyCode::Char(' ') => self.tree.toggle_mark(),
            KeyCode::Char('d') => {
                if let Some(idx) = self.tree.selected_node_index() {
                    self.delete_candidates = vec![idx];
                    if self.config.confirm_delete {
                        self.mode = AppMode::Deleting;
                    } else {
                        self.perform_delete();
                    }
                }
            }
            KeyCode::Char('D') => {
                if !self.tree.marked.is_empty() {
                    self.delete_candidates = self.tree.marked.iter().copied().collect();
                    if self.config.confirm_delete {
                        self.mode = AppMode::Deleting;
                    } else {
                        self.perform_delete();
                    }
                }
            }
            KeyCode::Char('s') => self.tree.cycle_sort(),
            KeyCode::Char('r') => {
                if let Some(idx) = self.tree.selected_node_index() {
                    let path = self.tree.nodes[idx].path.clone();
                    self.tree.nodes[idx].children_loaded = false;
                    // Remove existing children
                    let end = find_subtree_end(&self.tree.nodes, idx);
                    if end > idx + 1 {
                        let to_remove: Vec<usize> = (idx + 1..end).collect();
                        self.tree.remove_nodes(&to_remove);
                    }
                    self.tree.expanded.insert(idx);
                    let _ = self
                        .scan_tx
                        .send(crate::scanner::ScanRequest::ExpandNode(path));
                }
            }
            KeyCode::Char('R') => {
                self.init();
            }
            KeyCode::Char('/') => {
                self.mode = AppMode::Filtering;
                self.filter_text.clear();
            }
            KeyCode::Char('?') => self.mode = AppMode::Help,
            _ => {}
        }
    }

    fn handle_delete_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.perform_delete();
                self.mode = AppMode::Normal;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.delete_candidates.clear();
                self.mode = AppMode::Normal;
            }
            _ => {}
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = AppMode::Normal;
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter_text.clear();
                self.tree.clear_filter();
                self.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                self.mode = AppMode::Normal;
                // Keep the filter active
            }
            KeyCode::Backspace => {
                self.filter_text.pop();
                self.tree.set_filter(&self.filter_text);
            }
            KeyCode::Char(c) => {
                self.filter_text.push(c);
                self.tree.set_filter(&self.filter_text);
            }
            _ => {}
        }
    }

    fn perform_delete(&mut self) {
        let mut deleted = Vec::new();
        for &idx in &self.delete_candidates {
            if idx < self.tree.nodes.len() {
                let path = &self.tree.nodes[idx].path;
                if path.is_dir() {
                    if std::fs::remove_dir_all(path).is_ok() {
                        deleted.push(idx);
                    }
                } else if std::fs::remove_file(path).is_ok() {
                    deleted.push(idx);
                }
            }
        }

        let freed: u64 = deleted
            .iter()
            .map(|&idx| self.tree.nodes[idx].size)
            .sum();

        if !deleted.is_empty() {
            self.tree.remove_nodes(&deleted);
            self.status_msg = Some(format!(
                "Deleted {} item{}, freed {}",
                deleted.len(),
                if deleted.len() == 1 { "" } else { "s" },
                humansize::format_size(freed, humansize::BINARY)
            ));
        }

        self.tree.marked.clear();
        self.delete_candidates.clear();
    }

    pub fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // top bar
                Constraint::Min(0),   // main area
                Constraint::Length(1), // bottom bar
            ])
            .split(f.area());

        self.render_top_bar(f, chunks[0]);
        self.render_main(f, chunks[1]);
        self.render_bottom_bar(f, chunks[2]);

        // Overlays
        match self.mode {
            AppMode::Deleting => {
                let items: Vec<&_> = self
                    .delete_candidates
                    .iter()
                    .filter_map(|&idx| self.tree.nodes.get(idx))
                    .collect();
                dialogs::render_delete_confirm(f, &items);
            }
            AppMode::Help => {
                dialogs::render_help(f);
            }
            _ => {}
        }
    }

    fn render_top_bar(&self, f: &mut Frame, area: Rect) {
        let total_size: u64 = self
            .tree
            .nodes
            .iter()
            .filter(|n| n.parent.is_none())
            .map(|n| n.size)
            .sum();

        let roots_count = self
            .tree
            .nodes
            .iter()
            .filter(|n| n.parent.is_none())
            .count();

        let size_str = if total_size > 0 {
            humansize::format_size(total_size, humansize::BINARY)
        } else {
            "scanning...".to_string()
        };

        let left = Span::styled(" cache-explorer", crate::ui::theme::TITLE);

        let right_text = format!(
            "{} total across {} root{}  │  Sort: {} {}  │  ? help ",
            size_str,
            roots_count,
            if roots_count == 1 { "" } else { "s" },
            self.tree.sort_by.label(),
            if self.tree.sort_desc { "↓" } else { "↑" },
        );
        let right = Span::styled(right_text, crate::ui::theme::HEADER);

        // Pad between left and right
        let pad_len = (area.width as usize)
            .saturating_sub(16 + right.width());
        let padding = Span::raw(" ".repeat(pad_len));

        let line = Line::from(vec![left, padding, right]);
        let bar = Paragraph::new(line).style(
            ratatui::style::Style::default().bg(ratatui::style::Color::Rgb(30, 30, 50)),
        );
        f.render_widget(bar, area);
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area);

        let viewport_height = chunks[0].height as usize;
        self.tree.adjust_scroll(viewport_height);

        tree_panel::render(f, chunks[0], &self.tree);
        detail_panel::render(f, chunks[1], &self.tree);
    }

    fn render_bottom_bar(&self, f: &mut Frame, area: Rect) {
        let line = if self.mode == AppMode::Filtering {
            Line::from(vec![
                Span::styled(" /", crate::ui::theme::KEY),
                Span::styled(&self.filter_text, crate::ui::theme::NORMAL),
                Span::styled("█", crate::ui::theme::KEY),
            ])
        } else if let Some(msg) = &self.status_msg {
            Line::from(Span::styled(
                format!(" {msg}"),
                crate::ui::theme::SAFE,
            ))
        } else {
            Line::from(vec![
                Span::styled(" ↑↓", crate::ui::theme::KEY),
                Span::styled(" navigate  ", crate::ui::theme::NORMAL),
                Span::styled("←→", crate::ui::theme::KEY),
                Span::styled(" expand  ", crate::ui::theme::NORMAL),
                Span::styled("d", crate::ui::theme::KEY),
                Span::styled(" delete  ", crate::ui::theme::NORMAL),
                Span::styled("s", crate::ui::theme::KEY),
                Span::styled(" sort  ", crate::ui::theme::NORMAL),
                Span::styled("r", crate::ui::theme::KEY),
                Span::styled(" refresh  ", crate::ui::theme::NORMAL),
                Span::styled("/", crate::ui::theme::KEY),
                Span::styled(" search", crate::ui::theme::NORMAL),
            ])
        };

        let bar = Paragraph::new(line).style(
            ratatui::style::Style::default().bg(ratatui::style::Color::Rgb(30, 30, 50)),
        );
        f.render_widget(bar, area);
    }
}

fn find_subtree_end(nodes: &[crate::tree::node::TreeNode], idx: usize) -> usize {
    let mut end = idx + 1;
    while end < nodes.len() {
        let mut current = end;
        let mut is_descendant = false;
        while let Some(parent) = nodes[current].parent {
            if parent == idx {
                is_descendant = true;
                break;
            }
            current = parent;
        }
        if !is_descendant {
            break;
        }
        end += 1;
    }
    end
}
