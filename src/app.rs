use crate::config::Config;
use crate::scanner::ScanResult;
use crate::tree::state::TreeState;
use crate::ui::{detail_panel, dialogs, tree_panel};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::collections::HashMap;
use std::path::PathBuf;
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
    pub vuln_results: HashMap<PathBuf, crate::security::SecurityInfo>,
    pub version_results: HashMap<PathBuf, crate::security::VersionInfo>,
    pub node_status: HashMap<PathBuf, crate::security::NodeStatus>,
    delete_candidates: Vec<std::path::PathBuf>,
    auto_vulnscan_pending: bool,
    auto_versioncheck_pending: bool,
    vulnscan_in_progress: bool,
    versioncheck_in_progress: bool,
}

impl App {
    pub fn new(
        config: Config,
        scan_rx: mpsc::Receiver<ScanResult>,
        scan_tx: mpsc::Sender<crate::scanner::ScanRequest>,
    ) -> Self {
        let tree = TreeState::new(config.sort_by, config.sort_desc);
        let auto_vuln = config.vulncheck.enabled;
        let auto_ver = config.versioncheck.enabled;
        Self {
            tree,
            config,
            mode: AppMode::Normal,
            filter_text: String::new(),
            should_quit: false,
            scan_rx,
            scan_tx,
            status_msg: None,
            vuln_results: HashMap::new(),
            version_results: HashMap::new(),
            node_status: HashMap::new(),
            delete_candidates: Vec::new(),
            auto_vulnscan_pending: auto_vuln,
            auto_versioncheck_pending: auto_ver,
            vulnscan_in_progress: false,
            versioncheck_in_progress: false,
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
                ScanResult::VulnsScanned(scanned, results) => {
                    self.vuln_results.extend(results);
                    self.vulnscan_in_progress = false;
                    self.recompute_node_status();
                    let vuln_count = self.vuln_results.values().map(|s| s.vulns.len()).sum::<usize>();
                    self.status_msg = Some(if vuln_count > 0 {
                        format!("Scanned {} packages — {} vulnerabilit{} found", scanned, vuln_count, if vuln_count == 1 { "y" } else { "ies" })
                    } else {
                        format!("Scanned {} packages — no vulnerabilities found", scanned)
                    });
                }
                ScanResult::VersionsChecked(checked, results) => {
                    self.version_results.extend(results);
                    self.versioncheck_in_progress = false;
                    self.recompute_node_status();
                    let outdated = self.version_results.values().filter(|v| v.is_outdated).count();
                    self.status_msg = Some(if outdated > 0 {
                        format!("Checked {} packages — {} outdated", checked, outdated)
                    } else {
                        format!("Checked {} packages — all up to date", checked)
                    });
                }
            }
        }

        // Auto-scan on startup when CLI flags are set
        if (self.auto_vulnscan_pending || self.auto_versioncheck_pending)
            && !self.tree.nodes.is_empty()
        {
            let roots = self.config.roots.clone();
            if self.auto_vulnscan_pending {
                self.auto_vulnscan_pending = false;
                self.vulnscan_in_progress = true;
                let _ = self
                    .scan_tx
                    .send(crate::scanner::ScanRequest::ScanVulns(roots.clone()));
            }
            if self.auto_versioncheck_pending {
                self.auto_versioncheck_pending = false;
                self.versioncheck_in_progress = true;
                let _ = self
                    .scan_tx
                    .send(crate::scanner::ScanRequest::CheckVersions(roots));
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
            KeyCode::Char(' ') => {
                if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.tree.marked.clear();
                } else {
                    self.tree.toggle_mark();
                }
            }
            KeyCode::Char('u') => self.tree.marked.clear(),
            KeyCode::Char('v') => {
                if let Some(idx) = self.tree.selected_node_index() {
                    self.vulnscan_in_progress = true;
                    let path = self.tree.nodes[idx].path.clone();
                    let _ = self.scan_tx.send(crate::scanner::ScanRequest::ScanVulns(vec![path]));
                }
            }
            KeyCode::Char('V') => {
                self.vulnscan_in_progress = true;
                let _ = self.scan_tx.send(crate::scanner::ScanRequest::ScanVulns(
                    self.config.roots.clone(),
                ));
            }
            KeyCode::Char('o') => {
                if let Some(idx) = self.tree.selected_node_index() {
                    self.versioncheck_in_progress = true;
                    let path = self.tree.nodes[idx].path.clone();
                    let _ = self.scan_tx.send(crate::scanner::ScanRequest::CheckVersions(vec![path]));
                }
            }
            KeyCode::Char('O') => {
                self.versioncheck_in_progress = true;
                let _ = self.scan_tx.send(crate::scanner::ScanRequest::CheckVersions(
                    self.config.roots.clone(),
                ));
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                if !self.tree.marked.is_empty() {
                    self.delete_candidates = self.tree.marked.iter()
                        .filter_map(|&idx| self.tree.nodes.get(idx).map(|n| n.path.clone()))
                        .collect();
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
        let mut deleted_count = 0usize;
        let mut freed = 0u64;
        let mut deleted_paths = Vec::new();

        for path in &self.delete_candidates {
            // Measure size before deleting
            let size = crate::scanner::walker::dir_size(path);
            let ok = if path.is_dir() {
                std::fs::remove_dir_all(path).is_ok()
            } else {
                std::fs::remove_file(path).is_ok()
            };
            if ok {
                deleted_count += 1;
                freed += size;
                deleted_paths.push(path.clone());
            }
        }

        if deleted_count > 0 {
            // Remove nodes from tree by matching paths
            let indices: Vec<usize> = deleted_paths
                .iter()
                .filter_map(|p| self.tree.nodes.iter().position(|n| &n.path == p))
                .collect();
            self.tree.remove_nodes(&indices);

            self.status_msg = Some(format!(
                "Deleted {} item{}, freed {}",
                deleted_count,
                if deleted_count == 1 { "" } else { "s" },
                humansize::format_size(freed, humansize::BINARY)
            ));
        }

        self.tree.marked.clear();
        self.delete_candidates.clear();
    }


    pub fn recompute_node_status(&mut self) {
        self.node_status.clear();

        for path in self.vuln_results.keys() {
            self.node_status
                .entry(path.clone())
                .or_default()
                .has_vuln = true;
        }
        for (path, info) in &self.version_results {
            if info.is_outdated {
                self.node_status
                    .entry(path.clone())
                    .or_default()
                    .has_outdated = true;
            }
        }

        // Propagate to all filesystem ancestors so parent folders
        // inherit status even if they're not expanded in the tree
        let affected: Vec<(PathBuf, bool, bool)> = self
            .node_status
            .iter()
            .map(|(p, s)| (p.clone(), s.has_vuln, s.has_outdated))
            .collect();
        for (path, has_vuln, has_outdated) in affected {
            let mut ancestor = path.parent().map(|p| p.to_path_buf());
            while let Some(anc) = ancestor {
                let s = self.node_status.entry(anc.clone()).or_default();
                let changed = (has_vuln && !s.has_vuln) || (has_outdated && !s.has_outdated);
                if has_vuln {
                    s.has_vuln = true;
                }
                if has_outdated {
                    s.has_outdated = true;
                }
                if !changed {
                    break;
                }
                ancestor = anc.parent().map(|p| p.to_path_buf());
            }
        }
    }

    pub fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(10), // banner
                Constraint::Min(0),   // main area
                Constraint::Length(1), // bottom bar
            ])
            .split(f.area());

        self.render_banner(f, chunks[0]);
        self.render_main(f, chunks[1]);
        self.render_bottom_bar(f, chunks[2]);

        // Overlays
        match self.mode {
            AppMode::Deleting => {
                let items: Vec<&_> = self
                    .delete_candidates
                    .iter()
                    .filter_map(|p| self.tree.nodes.iter().find(|n| &n.path == p))
                    .collect();
                dialogs::render_delete_confirm(f, &items);
            }
            AppMode::Help => {
                dialogs::render_help(f);
            }
            _ => {}
        }
    }

    fn render_banner(&self, f: &mut Frame, area: Rect) {
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

        let vuln_count = self.vuln_results.values().map(|s| s.vulns.len()).sum::<usize>();
        let outdated_count = self.version_results.values().filter(|v| v.is_outdated).count();

        let mut stats = format!(
            "{}  │  {} root{}  │  sort: {} {}",
            size_str,
            roots_count,
            if roots_count == 1 { "" } else { "s" },
            self.tree.sort_by.label(),
            if self.tree.sort_desc { "↓" } else { "↑" },
        );
        if self.vulnscan_in_progress {
            stats.push_str("  │  ⚠ scanning...");
        } else if vuln_count > 0 {
            stats.push_str(&format!("  │  ⚠ {} vuln{}", vuln_count, if vuln_count == 1 { "" } else { "s" }));
        }
        if self.versioncheck_in_progress {
            stats.push_str("  │  ↓ checking...");
        } else if outdated_count > 0 {
            stats.push_str(&format!("  │  ↓ {} outdated", outdated_count));
        }
        stats.push_str("  │  ? help");

        use crate::ui::theme;

        let cyan = ratatui::style::Style::default()
            .fg(ratatui::style::Color::Cyan)
            .add_modifier(ratatui::style::Modifier::BOLD);
        let gold = ratatui::style::Style::default().fg(ratatui::style::Color::Yellow);

        let art: [(&str, &str); 6] = [
            (" ██████╗ █████╗  ██████╗██╗  ██╗███████╗", " ██████╗ ██████╗ ███╗   ███╗███╗   ███╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗ "),
            ("██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝", "██╔════╝██╔═══██╗████╗ ████║████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗"),
            ("██║     ███████║██║     ███████║█████╗  ", "██║     ██║   ██║██╔████╔██║██╔████╔██║███████║██╔██╗ ██║██║  ██║█████╗  ██████╔╝"),
            ("██║     ██╔══██║██║     ██╔══██║██╔══╝  ", "██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗"),
            ("╚██████╗██║  ██║╚██████╗██║  ██║███████╗", "╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║██║ ╚████║██████╔╝███████╗██║  ██║"),
            (" ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝", " ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝"),
        ];

        // Measure display width using char count (box-drawing chars are multi-byte in UTF-8)
        let art_width = art[0].0.chars().count() + 2 + art[0].1.chars().count();
        let term_width = area.width as usize;
        let pad = if term_width > art_width { (term_width - art_width) / 2 } else { 0 };
        let padding = " ".repeat(pad);

        let mut banner_lines: Vec<Line> = vec![Line::from(Span::raw(""))];
        banner_lines.extend(art.iter().map(|(cache, commander)| {
            Line::from(vec![
                Span::raw(&padding),
                Span::styled(*cache, cyan),
                Span::styled("  ", theme::DIM),
                Span::styled(*commander, gold),
            ])
        }));

        banner_lines.push(Line::from(Span::raw("")));

        // Center the stats line too
        let stats_pad = if term_width > stats.len() { (term_width - stats.len()) / 2 } else { 0 };
        banner_lines.push(Line::from(vec![
            Span::raw(" ".repeat(stats_pad)),
            Span::styled(&stats, theme::HEADER),
        ]));

        let banner = Paragraph::new(banner_lines).style(
            ratatui::style::Style::default().bg(ratatui::style::Color::Rgb(15, 15, 26)),
        );
        f.render_widget(banner, area);
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area);

        let viewport_height = chunks[0].height as usize;
        self.tree.adjust_scroll(viewport_height);

        tree_panel::render(f, chunks[0], &self.tree, &self.node_status);
        detail_panel::render(f, chunks[1], &self.tree, &self.vuln_results, &self.version_results);
    }

    fn render_bottom_bar(&self, f: &mut Frame, area: Rect) {
        let marked_count = self.tree.marked.len();
        let marked_hint = if marked_count > 0 {
            format!(" [{marked_count} marked]")
        } else {
            String::new()
        };

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
                Span::styled("Space", crate::ui::theme::KEY),
                Span::styled(" mark  ", crate::ui::theme::NORMAL),
                Span::styled("d", crate::ui::theme::KEY),
                Span::styled(" delete marked  ", crate::ui::theme::NORMAL),
                Span::styled("s", crate::ui::theme::KEY),
                Span::styled(" sort  ", crate::ui::theme::NORMAL),
                Span::styled("/", crate::ui::theme::KEY),
                Span::styled(" search  ", crate::ui::theme::NORMAL),
                Span::styled(&marked_hint, crate::ui::theme::CAUTION),
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
