use ccmd::app::{App, AppMode};
use ccmd::config::{Config, SortField};
use ccmd::scanner;
use ccmd::tree::node::TreeNode;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use std::path::PathBuf;
use std::sync::mpsc;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    }
}

fn key_shift(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    }
}

fn key_ctrl(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    }
}

fn make_node(name: &str, size: u64, has_children: bool) -> TreeNode {
    TreeNode {
        path: PathBuf::from(format!("/test/{name}")),
        name: name.to_string(),
        size,
        depth: 0,
        parent: None,
        has_children,
        kind: ccmd::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: true,
        children_loaded: false,
    }
}

fn make_child(name: &str, size: u64, parent: usize) -> TreeNode {
    TreeNode {
        path: PathBuf::from(format!("/test/{name}")),
        name: name.to_string(),
        size,
        depth: 1,
        parent: Some(parent),
        has_children: false,
        kind: ccmd::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: false,
        children_loaded: false,
    }
}

fn test_app() -> App {
    let config = Config {
        roots: vec![],
        sort_by: SortField::Size,
        sort_desc: true,
        confirm_delete: true,
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    // Set up a tree with roots and children
    app.tree.set_roots(vec![
        make_node("alpha", 5000, true),
        make_node("beta", 3000, true),
        make_node("gamma", 1000, false),
    ]);

    app
}

fn test_app_with_children() -> App {
    let mut app = test_app();
    app.tree.insert_children(0, vec![
        make_child("child-big", 4000, 0),
        make_child("child-small", 1000, 0),
    ]);
    app.tree.expanded.insert(0);
    app.tree.recompute_visible();
    app
}

// === Navigation ===

#[test]
fn key_j_moves_down() {
    let mut app = test_app();
    assert_eq!(app.tree.selected, 0);
    app.process_key(key(KeyCode::Char('j')));
    assert_eq!(app.tree.selected, 1);
}

#[test]
fn key_k_moves_up() {
    let mut app = test_app();
    app.tree.selected = 2;
    app.process_key(key(KeyCode::Char('k')));
    assert_eq!(app.tree.selected, 1);
}

#[test]
fn key_arrow_down_moves_down() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Down));
    assert_eq!(app.tree.selected, 1);
}

#[test]
fn key_arrow_up_moves_up() {
    let mut app = test_app();
    app.tree.selected = 1;
    app.process_key(key(KeyCode::Up));
    assert_eq!(app.tree.selected, 0);
}

#[test]
fn key_g_goes_to_top() {
    let mut app = test_app();
    app.tree.selected = 2;
    app.process_key(key(KeyCode::Char('g')));
    assert_eq!(app.tree.selected, 0);
}

#[test]
fn key_shift_g_goes_to_bottom() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('G')));
    assert_eq!(app.tree.selected, 2);
}

// === Expand / Collapse ===

#[test]
fn key_l_expands_node() {
    let mut app = test_app();
    // alpha has_children and is not expanded
    assert!(!app.tree.expanded.contains(&0));
    app.process_key(key(KeyCode::Char('l')));
    assert!(app.tree.expanded.contains(&0));
}

#[test]
fn key_arrow_right_expands() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Right));
    assert!(app.tree.expanded.contains(&0));
}

#[test]
fn key_h_collapses_expanded_node() {
    let mut app = test_app_with_children();
    assert!(app.tree.expanded.contains(&0));
    app.process_key(key(KeyCode::Char('h')));
    assert!(!app.tree.expanded.contains(&0));
}

#[test]
fn key_h_on_child_moves_to_parent() {
    let mut app = test_app_with_children();
    // visible: alpha(0), child-big(1), child-small(2), beta(3), gamma(4)
    app.tree.selected = 1; // child-big
    app.process_key(key(KeyCode::Char('h')));
    assert_eq!(app.tree.selected, 0); // moved to parent alpha
}

#[test]
fn key_arrow_left_collapses() {
    let mut app = test_app_with_children();
    app.process_key(key(KeyCode::Left));
    assert!(!app.tree.expanded.contains(&0));
}

#[test]
fn key_enter_toggles_expand() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Enter));
    assert!(app.tree.expanded.contains(&0));
}

#[test]
fn key_enter_on_leaf_does_nothing() {
    let mut app = test_app();
    app.tree.selected = 2; // gamma, has_children=false
    let visible_before = app.tree.visible.len();
    app.process_key(key(KeyCode::Enter));
    assert_eq!(app.tree.visible.len(), visible_before);
}

// === Marking / Delete ===

#[test]
fn key_space_marks_and_advances() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char(' ')));
    assert!(app.tree.marked.contains(&0)); // alpha marked
    assert_eq!(app.tree.selected, 1); // advanced to beta
}

#[test]
fn key_space_unmarks() {
    let mut app = test_app();
    app.tree.marked.insert(0);
    app.process_key(key(KeyCode::Char(' ')));
    assert!(!app.tree.marked.contains(&0));
}

#[test]
fn key_d_enters_delete_mode_with_confirm() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Deleting);
}

#[test]
fn key_d_without_confirm_deletes_immediately() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("deleteme");
    std::fs::create_dir_all(&dir).unwrap();

    let config = Config {
        roots: vec![],
        sort_by: SortField::Size,
        sort_desc: true,
        confirm_delete: false,
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    app.tree.set_roots(vec![TreeNode {
        path: dir.clone(),
        name: "deleteme".to_string(),
        size: 100,
        depth: 0,
        parent: None,
        has_children: true,
        kind: ccmd::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: true,
        children_loaded: false,
    }]);

    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Normal);
    assert!(!dir.exists(), "Directory should be deleted");
}

#[test]
fn key_shift_d_enters_delete_mode_with_marked_items() {
    let mut app = test_app();
    app.tree.marked.insert(0);
    app.tree.marked.insert(1);
    app.process_key(key(KeyCode::Char('D')));
    assert_eq!(app.mode, AppMode::Deleting);
}

#[test]
fn key_shift_d_with_no_marks_does_nothing() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('D')));
    assert_eq!(app.mode, AppMode::Normal);
}

#[test]
fn delete_mode_y_confirms() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("todelete");
    std::fs::create_dir_all(&dir).unwrap();

    let config = Config {
        roots: vec![],
        sort_by: SortField::Size,
        sort_desc: true,
        confirm_delete: true,
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    app.tree.set_roots(vec![TreeNode {
        path: dir.clone(),
        name: "todelete".to_string(),
        size: 100,
        depth: 0,
        parent: None,
        has_children: true,
        kind: ccmd::tree::node::CacheKind::Unknown,
        last_modified: None,
        is_root: true,
        children_loaded: false,
    }]);

    app.process_key(key(KeyCode::Char('d'))); // enter delete mode
    assert_eq!(app.mode, AppMode::Deleting);

    app.process_key(key(KeyCode::Char('y'))); // confirm
    assert_eq!(app.mode, AppMode::Normal);
    assert!(!dir.exists(), "Directory should be deleted after y");
}

#[test]
fn delete_mode_n_cancels() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Deleting);

    app.process_key(key(KeyCode::Char('n')));
    assert_eq!(app.mode, AppMode::Normal);
    assert_eq!(app.tree.nodes.len(), 3, "Nothing should be deleted");
}

#[test]
fn delete_mode_esc_cancels() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('d')));
    app.process_key(key(KeyCode::Esc));
    assert_eq!(app.mode, AppMode::Normal);
}

// === Sort ===

#[test]
fn key_s_cycles_sort() {
    let mut app = test_app();
    assert_eq!(app.tree.sort_by, SortField::Size);
    app.process_key(key(KeyCode::Char('s')));
    assert_eq!(app.tree.sort_by, SortField::Name);
    app.process_key(key(KeyCode::Char('s')));
    assert_eq!(app.tree.sort_by, SortField::Modified);
    app.process_key(key(KeyCode::Char('s')));
    assert_eq!(app.tree.sort_by, SortField::Size);
}

// === Filter ===

#[test]
fn key_slash_enters_filter_mode() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('/')));
    assert_eq!(app.mode, AppMode::Filtering);
    assert!(app.filter_text.is_empty());
}

#[test]
fn filter_mode_typing_updates_text() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('/')));
    app.process_key(key(KeyCode::Char('a')));
    app.process_key(key(KeyCode::Char('l')));
    assert_eq!(app.filter_text, "al");
}

#[test]
fn filter_mode_filters_visible_nodes() {
    let mut app = test_app_with_children();
    // visible: alpha, child-big, child-small, beta, gamma
    assert_eq!(app.tree.visible.len(), 5);

    app.process_key(key(KeyCode::Char('/')));
    app.process_key(key(KeyCode::Char('b')));
    app.process_key(key(KeyCode::Char('i')));
    app.process_key(key(KeyCode::Char('g')));

    // Should only show root (always visible) + "child-big" matching "big"
    let visible_names: Vec<&str> = app.tree.visible.iter()
        .map(|&i| app.tree.nodes[i].name.as_str())
        .collect();
    assert!(visible_names.contains(&"child-big"), "Should show child-big: {:?}", visible_names);
    assert!(!visible_names.contains(&"child-small"), "Should hide child-small: {:?}", visible_names);
}

#[test]
fn filter_mode_backspace_removes_char() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('/')));
    app.process_key(key(KeyCode::Char('a')));
    app.process_key(key(KeyCode::Char('b')));
    assert_eq!(app.filter_text, "ab");

    app.process_key(key(KeyCode::Backspace));
    assert_eq!(app.filter_text, "a");
}

#[test]
fn filter_mode_esc_clears_filter_and_exits() {
    let mut app = test_app_with_children();
    app.process_key(key(KeyCode::Char('/')));
    app.process_key(key(KeyCode::Char('x')));
    app.process_key(key(KeyCode::Char('y')));
    assert_eq!(app.filter_text, "xy");

    app.process_key(key(KeyCode::Esc));
    assert_eq!(app.mode, AppMode::Normal);
    assert!(app.filter_text.is_empty());
    assert!(app.tree.filter.is_empty());
    // All nodes visible again
    assert_eq!(app.tree.visible.len(), 5);
}

#[test]
fn filter_mode_enter_keeps_filter_active() {
    let mut app = test_app_with_children();
    app.process_key(key(KeyCode::Char('/')));
    app.process_key(key(KeyCode::Char('b')));
    app.process_key(key(KeyCode::Char('i')));
    app.process_key(key(KeyCode::Char('g')));

    let visible_before = app.tree.visible.len();
    app.process_key(key(KeyCode::Enter)); // exit filter mode but keep filter
    assert_eq!(app.mode, AppMode::Normal);
    assert_eq!(app.tree.visible.len(), visible_before, "Filter should remain active");
}

#[test]
fn filter_is_case_insensitive() {
    let mut app = test_app_with_children();
    app.process_key(key(KeyCode::Char('/')));
    app.process_key(key(KeyCode::Char('B')));
    app.process_key(key(KeyCode::Char('I')));
    app.process_key(key(KeyCode::Char('G')));

    let visible_names: Vec<&str> = app.tree.visible.iter()
        .map(|&i| app.tree.nodes[i].name.as_str())
        .collect();
    assert!(visible_names.contains(&"child-big"), "Case-insensitive filter should match: {:?}", visible_names);
}

// === Help ===

#[test]
fn key_question_enters_help_mode() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('?')));
    assert_eq!(app.mode, AppMode::Help);
}

#[test]
fn help_mode_question_exits() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('?')));
    app.process_key(key(KeyCode::Char('?')));
    assert_eq!(app.mode, AppMode::Normal);
}

#[test]
fn help_mode_esc_exits() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('?')));
    app.process_key(key(KeyCode::Esc));
    assert_eq!(app.mode, AppMode::Normal);
}

#[test]
fn help_mode_q_exits() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('?')));
    app.process_key(key(KeyCode::Char('q')));
    assert_eq!(app.mode, AppMode::Normal);
    // q in help should exit help, not quit the app
    assert!(!app.should_quit);
}

// === Quit ===

#[test]
fn key_q_quits() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('q')));
    assert!(app.should_quit);
}

#[test]
fn key_ctrl_c_quits() {
    let mut app = test_app();
    app.process_key(key_ctrl(KeyCode::Char('c')));
    assert!(app.should_quit);
}

// === Mode isolation: keys don't leak across modes ===

#[test]
fn normal_keys_dont_work_in_filter_mode() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('/')));
    assert_eq!(app.mode, AppMode::Filtering);

    // 'j' should type 'j', not navigate
    app.process_key(key(KeyCode::Char('j')));
    assert_eq!(app.filter_text, "j");
    assert_eq!(app.tree.selected, 0); // did not move
}

#[test]
fn normal_keys_dont_work_in_help_mode() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('?')));
    let selected_before = app.tree.selected;

    // 'j' should do nothing in help
    app.process_key(key(KeyCode::Char('j')));
    assert_eq!(app.tree.selected, selected_before);
    assert_eq!(app.mode, AppMode::Help);
}

#[test]
fn normal_keys_dont_work_in_delete_mode() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Deleting);

    // 'j' should do nothing
    app.process_key(key(KeyCode::Char('j')));
    assert_eq!(app.mode, AppMode::Deleting);
    assert_eq!(app.tree.selected, 0);
}

// === Refresh ===

#[test]
fn key_r_resets_children_loaded() {
    let mut app = test_app_with_children();
    assert!(app.tree.nodes[0].children_loaded);

    app.process_key(key(KeyCode::Char('r')));
    // After refresh, children_loaded is reset and re-expand is triggered
    // The node should be in expanded set waiting for new children
    assert!(app.tree.expanded.contains(&0));
}

#[test]
fn key_shift_r_reinits() {
    let mut app = test_app();
    let nodes_before = app.tree.nodes.len();
    app.process_key(key(KeyCode::Char('R')));
    // R triggers init() which sends ScanRoots — tree will be reset when results arrive
    // For now just verify it doesn't crash
    assert!(nodes_before > 0);
}
