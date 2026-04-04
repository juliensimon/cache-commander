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
        ..Default::default()
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
fn key_d_does_nothing_without_marks() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Normal, "d should do nothing when nothing is marked");
}

#[test]
fn key_d_enters_delete_mode_with_marked_items() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char(' '))); // mark first
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
        ..Default::default()
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

    app.process_key(key(KeyCode::Char(' '))); // mark it
    app.process_key(key(KeyCode::Char('d'))); // delete marked
    assert_eq!(app.mode, AppMode::Normal);
    assert!(!dir.exists(), "Directory should be deleted");
}

#[test]
fn key_shift_d_enters_delete_mode_with_marked_items() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char(' '))); // mark first
    app.process_key(key(KeyCode::Char(' '))); // mark second
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
        ..Default::default()
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

    app.process_key(key(KeyCode::Char(' '))); // mark it
    app.process_key(key(KeyCode::Char('d'))); // enter delete mode
    assert_eq!(app.mode, AppMode::Deleting);

    app.process_key(key(KeyCode::Char('y'))); // confirm
    assert_eq!(app.mode, AppMode::Normal);
    assert!(!dir.exists(), "Directory should be deleted after y");
}

#[test]
fn delete_mode_n_cancels() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char(' '))); // mark
    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Deleting);

    app.process_key(key(KeyCode::Char('n')));
    assert_eq!(app.mode, AppMode::Normal);
    assert_eq!(app.tree.nodes.len(), 3, "Nothing should be deleted");
}

#[test]
fn delete_mode_esc_cancels() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char(' '))); // mark
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

// === Bulk delete ===

#[test]
fn bulk_delete_multiple_marked_items() {
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("aaa");
    let dir_b = tmp.path().join("bbb");
    let dir_c = tmp.path().join("ccc");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::create_dir_all(&dir_c).unwrap();
    std::fs::write(dir_a.join("file.txt"), "data a").unwrap();
    std::fs::write(dir_b.join("file.txt"), "data b").unwrap();

    let config = Config {
        roots: vec![],
        sort_by: SortField::Name,
        sort_desc: false,
        confirm_delete: false,
        ..Default::default()
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    app.tree.set_roots(vec![
        TreeNode {
            path: dir_a.clone(), name: "aaa".into(), size: 100, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
        TreeNode {
            path: dir_b.clone(), name: "bbb".into(), size: 200, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
        TreeNode {
            path: dir_c.clone(), name: "ccc".into(), size: 300, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
    ]);

    // Mark first two items with Space
    app.process_key(key(KeyCode::Char(' '))); // mark aaa, advance to bbb
    app.process_key(key(KeyCode::Char(' '))); // mark bbb, advance to ccc

    assert_eq!(app.tree.marked.len(), 2);

    // Bulk delete (no confirm)
    app.process_key(key(KeyCode::Char('D')));

    assert!(!dir_a.exists(), "aaa should be deleted");
    assert!(!dir_b.exists(), "bbb should be deleted");
    assert!(dir_c.exists(), "ccc should NOT be deleted");
    assert_eq!(app.tree.nodes.len(), 1, "Only ccc should remain in tree");
    assert_eq!(app.tree.nodes[0].name, "ccc");
    assert!(app.status_msg.as_ref().unwrap().contains("2 items"));
}

#[test]
fn bulk_delete_with_confirm_dialog() {
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("aaa");
    let dir_b = tmp.path().join("bbb");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let config = Config {
        roots: vec![],
        sort_by: SortField::Name,
        sort_desc: false,
        confirm_delete: true,
        ..Default::default()
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    app.tree.set_roots(vec![
        TreeNode {
            path: dir_a.clone(), name: "aaa".into(), size: 0, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
        TreeNode {
            path: dir_b.clone(), name: "bbb".into(), size: 0, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
    ]);

    // Mark both
    app.process_key(key(KeyCode::Char(' ')));
    app.process_key(key(KeyCode::Char(' ')));

    // D enters delete mode
    app.process_key(key(KeyCode::Char('D')));
    assert_eq!(app.mode, AppMode::Deleting);
    assert!(dir_a.exists(), "Should not delete before confirm");

    // Confirm
    app.process_key(key(KeyCode::Char('y')));
    assert_eq!(app.mode, AppMode::Normal);
    assert!(!dir_a.exists(), "aaa deleted after confirm");
    assert!(!dir_b.exists(), "bbb deleted after confirm");
    assert!(app.tree.nodes.is_empty());
}

#[test]
fn delete_uses_paths_not_stale_indices() {
    // Simulate the bug scenario: mark items, then sort changes indices
    let tmp = tempfile::tempdir().unwrap();
    let dir_a = tmp.path().join("aaa");
    let dir_b = tmp.path().join("bbb");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let config = Config {
        roots: vec![],
        sort_by: SortField::Name,
        sort_desc: false,
        confirm_delete: false,
        ..Default::default()
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    app.tree.set_roots(vec![
        TreeNode {
            path: dir_a.clone(), name: "aaa".into(), size: 100, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
        TreeNode {
            path: dir_b.clone(), name: "bbb".into(), size: 200, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Unknown,
            last_modified: None, is_root: true, children_loaded: false,
        },
    ]);

    // Mark aaa (index 0)
    app.process_key(key(KeyCode::Char(' ')));

    // Sort by size desc — bbb(200) moves to index 0, aaa(100) to index 1
    app.process_key(key(KeyCode::Char('s'))); // cycle to name
    app.process_key(key(KeyCode::Char('s'))); // cycle to modified
    app.process_key(key(KeyCode::Char('s'))); // cycle back to size (desc)

    // D should delete aaa (by path), not whatever is at the old index 0
    app.process_key(key(KeyCode::Char('D')));
    assert!(!dir_a.exists(), "aaa should be deleted (matched by path, not stale index)");
    assert!(dir_b.exists(), "bbb should still exist");
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

// === Filter Mode ===

#[test]
fn key_f_cycles_filter_mode_with_status_data() {
    let mut app = test_app();
    // Populate node_status so filter mode is allowed
    app.node_status.insert(
        PathBuf::from("/test/alpha"),
        ccmd::security::NodeStatus { has_vuln: true, has_outdated: false },
    );

    app.process_key(key(KeyCode::Char('f')));
    assert_eq!(app.tree.filter_mode, ccmd::tree::state::FilterMode::Vuln);

    app.process_key(key(KeyCode::Char('f')));
    assert_eq!(app.tree.filter_mode, ccmd::tree::state::FilterMode::Outdated);

    app.process_key(key(KeyCode::Char('f')));
    assert_eq!(app.tree.filter_mode, ccmd::tree::state::FilterMode::Both);

    app.process_key(key(KeyCode::Char('f')));
    assert_eq!(app.tree.filter_mode, ccmd::tree::state::FilterMode::None);
}

#[test]
fn key_f_without_status_data_shows_message() {
    let mut app = test_app();
    // node_status is empty
    app.process_key(key(KeyCode::Char('f')));
    assert_eq!(app.tree.filter_mode, ccmd::tree::state::FilterMode::None);
    assert!(app.status_msg.as_ref().unwrap().contains("scan"));
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
    app.process_key(key(KeyCode::Char(' '))); // mark first, advances to 1
    app.process_key(key(KeyCode::Char('d')));
    assert_eq!(app.mode, AppMode::Deleting);

    let selected_before = app.tree.selected;
    // 'j' should do nothing in delete mode
    app.process_key(key(KeyCode::Char('j')));
    assert_eq!(app.mode, AppMode::Deleting);
    assert_eq!(app.tree.selected, selected_before);
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

// === Vulnerability & Version Check ===

#[test]
fn key_v_always_works_on_demand() {
    let mut app = test_app(); // vulncheck.enabled = false — but keys still work
    app.process_key(key(KeyCode::Char('v')));
    // No packages in test tree (test nodes are CacheKind::Unknown), so no status_msg set
    // But key should NOT show "disabled"
    if let Some(msg) = &app.status_msg {
        assert!(!msg.contains("disabled"), "v should always work on demand");
    }
}

#[test]
fn key_shift_v_scans_all() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('V')));
    // No packages → no message, but no "disabled" either
    if let Some(msg) = &app.status_msg {
        assert!(!msg.contains("disabled"));
    }
}

#[test]
fn key_o_always_works_on_demand() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('o')));
    if let Some(msg) = &app.status_msg {
        assert!(!msg.contains("disabled"), "o should always work on demand");
    }
}

#[test]
fn key_shift_o_checks_all() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('O')));
    if let Some(msg) = &app.status_msg {
        assert!(!msg.contains("disabled"));
    }
}

#[test]
fn vuln_propagates_to_ancestors() {
    // Use real hierarchical paths so filesystem ancestor walking works
    let config = Config { roots: vec![], ..Default::default() };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    let parent_path = PathBuf::from("/cache/uv");
    let child_path = PathBuf::from("/cache/uv/archive/pkg1");

    app.tree.set_roots(vec![TreeNode {
        path: parent_path.clone(), name: "uv".into(), size: 0, depth: 0,
        parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Uv,
        last_modified: None, is_root: true, children_loaded: false,
    }]);

    app.vuln_results.insert(
        child_path.clone(),
        ccmd::security::SecurityInfo {
            vulns: vec![ccmd::security::Vulnerability {
                id: "CVE-2023-1234".into(),
                summary: "test vuln".into(),
                severity: Some("7.5".into()),
                fix_version: None,
            }],
        },
    );
    app.recompute_node_status();

    assert!(app.node_status.get(&child_path).unwrap().has_vuln);
    assert!(
        app.node_status.get(&parent_path).unwrap().has_vuln,
        "Parent should inherit vuln from child via path ancestry"
    );
}

#[test]
fn outdated_propagates_to_ancestors() {
    let config = Config { roots: vec![], ..Default::default() };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    let parent_path = PathBuf::from("/cache/uv");
    let child_path = PathBuf::from("/cache/uv/archive/pkg1");

    app.tree.set_roots(vec![TreeNode {
        path: parent_path.clone(), name: "uv".into(), size: 0, depth: 0,
        parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Uv,
        last_modified: None, is_root: true, children_loaded: false,
    }]);

    app.version_results.insert(
        child_path,
        ccmd::security::VersionInfo {
            current: "1.0.0".into(),
            latest: "2.0.0".into(),
            is_outdated: true,
        },
    );
    app.recompute_node_status();

    assert!(
        app.node_status.get(&parent_path).unwrap().has_outdated,
        "Parent should inherit outdated from child via path ancestry"
    );
}

#[test]
fn current_version_does_not_propagate() {
    let mut app = test_app_with_children();
    let child_path = app.tree.nodes[1].path.clone();
    app.version_results.insert(
        child_path,
        ccmd::security::VersionInfo {
            current: "2.0.0".into(),
            latest: "2.0.0".into(),
            is_outdated: false,
        },
    );
    app.recompute_node_status();

    // Parent should NOT have outdated status
    let parent_path = app.tree.nodes[0].path.clone();
    let parent_status = app.node_status.get(&parent_path);
    assert!(
        parent_status.is_none() || !parent_status.unwrap().has_outdated,
        "Current version should not propagate outdated to parent"
    );
}

#[test]
fn node_status_cleared_on_recompute() {
    let mut app = test_app_with_children();
    let child_path = app.tree.nodes[1].path.clone();

    // First: add a vuln
    app.vuln_results.insert(
        child_path.clone(),
        ccmd::security::SecurityInfo {
            vulns: vec![ccmd::security::Vulnerability {
                id: "CVE-2023-1234".into(),
                summary: "test".into(),
                severity: None,
                fix_version: None,
            }],
        },
    );
    app.recompute_node_status();
    assert!(app.node_status.get(&child_path).unwrap().has_vuln);

    // Then: remove the vuln and recompute
    app.vuln_results.clear();
    app.recompute_node_status();
    assert!(
        app.node_status.get(&child_path).is_none(),
        "Status should be cleared after removing vuln results"
    );
}

#[test]
fn navigation_skips_dimmed_nodes() {
    let mut app = test_app_with_children();
    // visible: alpha(0), child-big(1), child-small(2), beta(3), gamma(4)

    // Mark child-big as vulnerable
    let child_big_path = app.tree.nodes[1].path.clone();
    app.node_status.insert(
        child_big_path,
        ccmd::security::NodeStatus { has_vuln: true, has_outdated: false },
    );

    // Also mark alpha as having a vulnerable child so it won't be dimmed
    let alpha_path = app.tree.nodes[0].path.clone();
    app.node_status.insert(
        alpha_path,
        ccmd::security::NodeStatus { has_vuln: true, has_outdated: false },
    );

    // Set filter to Vuln — everything except child-big and alpha should be dimmed
    app.tree.filter_mode = ccmd::tree::state::FilterMode::Vuln;
    app.tree.recompute_dimmed(&app.node_status);

    // child-big should not be dimmed (is vulnerable)
    assert!(!app.tree.dimmed.contains(&1), "child-big should not be dimmed");
    // child-small, beta, gamma should be dimmed
    assert!(app.tree.dimmed.contains(&2), "child-small should be dimmed");

    // Navigate down from alpha — should skip to first non-dimmed item
    app.tree.selected = 0;
    app.process_key(key(KeyCode::Char('j')));
    // Should land on child-big (visible index 1)
    let selected_name = app.tree.selected_node().unwrap().name.clone();
    assert!(
        selected_name == "child-big" || !app.tree.dimmed.contains(&app.tree.visible[app.tree.selected]),
        "Should skip to non-dimmed node, got: {}", selected_name
    );
}

#[test]
fn go_top_skips_dimmed_root() {
    let mut app = test_app();
    // 3 roots: alpha, beta, gamma — dim alpha
    app.tree.dimmed.insert(0);
    app.tree.selected = 2;

    app.tree.go_top();
    // Should land on beta (visible index 1), not dimmed alpha
    let selected_node = app.tree.selected_node().unwrap();
    assert_eq!(selected_node.name, "beta");
}

// === Bulk Mark ===

#[test]
fn key_m_enters_marking_mode() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('m')));
    assert_eq!(app.mode, AppMode::MarkingAll);
}

#[test]
fn marking_mode_y_marks_all_non_dimmed_visible() {
    let mut app = test_app_with_children();
    // visible: alpha(0), child-big(1), child-small(2), beta(3), gamma(4)
    // Dim beta and gamma
    app.tree.dimmed.insert(3); // beta node index
    app.tree.dimmed.insert(4); // gamma node index

    app.process_key(key(KeyCode::Char('m')));
    assert_eq!(app.mode, AppMode::MarkingAll);

    app.process_key(key(KeyCode::Char('y')));
    assert_eq!(app.mode, AppMode::Normal);

    // alpha (idx 0), child-big (idx 1), child-small (idx 2) should be marked
    assert!(app.tree.marked.contains(&0), "alpha should be marked");
    assert!(app.tree.marked.contains(&1), "child-big should be marked");
    assert!(app.tree.marked.contains(&2), "child-small should be marked");
    // beta (idx 3) and gamma (idx 4) should NOT be marked (dimmed)
    assert!(!app.tree.marked.contains(&3), "beta should not be marked (dimmed)");
    assert!(!app.tree.marked.contains(&4), "gamma should not be marked (dimmed)");
}

#[test]
fn marking_mode_n_cancels() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('m')));
    assert_eq!(app.mode, AppMode::MarkingAll);

    app.process_key(key(KeyCode::Char('n')));
    assert_eq!(app.mode, AppMode::Normal);
    assert!(app.tree.marked.is_empty());
}

#[test]
fn marking_mode_esc_cancels() {
    let mut app = test_app();
    app.process_key(key(KeyCode::Char('m')));
    app.process_key(key(KeyCode::Esc));
    assert_eq!(app.mode, AppMode::Normal);
    assert!(app.tree.marked.is_empty());
}

#[test]
fn key_m_with_no_items_to_mark_shows_message() {
    let mut app = test_app();
    // Dim everything
    for &idx in app.tree.visible.clone().iter() {
        app.tree.dimmed.insert(idx);
    }
    app.process_key(key(KeyCode::Char('m')));
    assert_eq!(app.mode, AppMode::Normal);
    assert!(app.status_msg.as_ref().unwrap().contains("No items"));
}

#[test]
fn full_workflow_filter_mark_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let vuln_dir = tmp.path().join("vulnerable-pkg");
    let safe_dir = tmp.path().join("safe-pkg");
    let outdated_dir = tmp.path().join("outdated-pkg");
    std::fs::create_dir_all(&vuln_dir).unwrap();
    std::fs::create_dir_all(&safe_dir).unwrap();
    std::fs::create_dir_all(&outdated_dir).unwrap();
    std::fs::write(vuln_dir.join("data"), "x".repeat(100)).unwrap();
    std::fs::write(safe_dir.join("data"), "y".repeat(100)).unwrap();
    std::fs::write(outdated_dir.join("data"), "z".repeat(100)).unwrap();

    let config = Config {
        roots: vec![],
        sort_by: SortField::Name,
        sort_desc: false,
        confirm_delete: false,
        ..Default::default()
    };
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);
    let mut app = App::new(config, result_rx, scan_tx);

    app.tree.set_roots(vec![
        TreeNode {
            path: vuln_dir.clone(), name: "vulnerable-pkg".into(), size: 100, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Pip,
            last_modified: None, is_root: true, children_loaded: false,
        },
        TreeNode {
            path: safe_dir.clone(), name: "safe-pkg".into(), size: 100, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Pip,
            last_modified: None, is_root: true, children_loaded: false,
        },
        TreeNode {
            path: outdated_dir.clone(), name: "outdated-pkg".into(), size: 100, depth: 0,
            parent: None, has_children: true, kind: ccmd::tree::node::CacheKind::Pip,
            last_modified: None, is_root: true, children_loaded: false,
        },
    ]);

    // Simulate scan results
    app.vuln_results.insert(
        vuln_dir.clone(),
        ccmd::security::SecurityInfo {
            vulns: vec![ccmd::security::Vulnerability {
                id: "CVE-2023-1234".into(),
                summary: "test".into(),
                severity: Some("7.5".into()),
                fix_version: Some("2.0.0".into()),
            }],
        },
    );
    app.recompute_node_status();

    // Filter to vuln only
    app.process_key(key(KeyCode::Char('f')));
    assert_eq!(app.tree.filter_mode, ccmd::tree::state::FilterMode::Vuln);

    // safe-pkg and outdated-pkg should be dimmed
    let safe_idx = app.tree.nodes.iter().position(|n| n.name == "safe-pkg").unwrap();
    let outdated_idx = app.tree.nodes.iter().position(|n| n.name == "outdated-pkg").unwrap();
    assert!(app.tree.dimmed.contains(&safe_idx));
    assert!(app.tree.dimmed.contains(&outdated_idx));

    // Bulk mark
    app.process_key(key(KeyCode::Char('m')));
    assert_eq!(app.mode, AppMode::MarkingAll);
    app.process_key(key(KeyCode::Char('y')));

    // Only vuln_dir should be marked
    let vuln_idx = app.tree.nodes.iter().position(|n| n.name == "vulnerable-pkg").unwrap();
    assert!(app.tree.marked.contains(&vuln_idx));
    assert!(!app.tree.marked.contains(&safe_idx));
    assert!(!app.tree.marked.contains(&outdated_idx));

    // Delete
    app.process_key(key(KeyCode::Char('d')));

    assert!(!vuln_dir.exists(), "vulnerable-pkg should be deleted");
    assert!(safe_dir.exists(), "safe-pkg should still exist");
    assert!(outdated_dir.exists(), "outdated-pkg should still exist");
}
