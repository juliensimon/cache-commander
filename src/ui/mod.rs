pub mod detail_panel;
pub mod dialogs;
pub mod theme;
pub mod tree_panel;

use std::borrow::Cow;

/// Untrusted text (file and package names, paths) made safe to lay out and draw:
/// every control character (C0, DEL, C1: ESC, BEL, CR, LF, backspace...) becomes a
/// visible U+FFFD, one for one. ratatui already refuses to emit control characters,
/// but it does so by silently dropping them AFTER the caller has measured the text,
/// which misaligns columns, and it makes a hostile name look like an ordinary one.
/// Display only: filesystem operations and comparisons keep the raw value.
pub fn printable(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_control) {
        Cow::Owned(
            text.chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

#[cfg(test)]
mod control_sequence_tests {
    //! Names, paths and versions come from the filesystem and the network, so a
    //! hostile one can contain ESC/OSC/BEL/CR/LF/C1 bytes. What matters is what
    //! reaches the terminal, so these render through the real crossterm backend
    //! and compare the emitted BYTES against the same text with the control
    //! characters already removed: if they are identical, nothing a terminal could
    //! interpret survived. (A buffer-only check could not see an ESC that the
    //! backend would emit.)
    use super::{detail_panel, dialogs, tree_panel};
    use crate::config::SortField;
    use crate::tree::node::{CacheKind, TreeNode};
    use crate::tree::state::TreeState;
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;
    use std::rc::Rc;

    const HOSTILE: &[&str] = &[
        "pkg\x1b]0;pwned\x07-1.0",              // OSC set-title, BEL-terminated
        "pkg\x1b]8;;http://evil\x1b\\link-1.0", // OSC 8 hyperlink, ST-terminated
        "pkg\x1b[2J\x1b[31m-1.0",               // CSI clear screen + colour
        "pkg\u{9b}2J-1.0",                      // C1 CSI (single byte form)
        "pkg\r\nSPOOF-1.0",                     // CR/LF line spoofing
        "pkg\x08\x08\x08\x08fake-1.0",          // backspace overwrite
        "pkg\x7f\x00-1.0",                      // DEL, NUL
    ];

    fn node(name: &str) -> TreeNode {
        let mut n = TreeNode::new(PathBuf::from(format!("/tmp/{name}")), 0, None);
        n.name = name.into();
        n.kind = CacheKind::Cargo;
        n.size = 1024;
        n.is_root = true;
        n
    }

    fn tree_of(name: &str) -> TreeState {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![node(name)]);
        tree
    }

    /// A `Write` that keeps what the backend sends, readable after the terminal
    /// has taken ownership of it.
    #[derive(Clone, Default)]
    struct Sink(Rc<RefCell<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Bytes the crossterm backend writes for one frame.
    fn emitted(draw: impl FnOnce(&mut ratatui::Frame)) -> Vec<u8> {
        let sink = Sink::default();
        let mut terminal = Terminal::with_options(
            CrosstermBackend::new(sink.clone()),
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 100, 40)),
            },
        )
        .unwrap();
        terminal.draw(|f| draw(f)).unwrap();
        let bytes = sink.0.borrow().clone();
        bytes
    }

    fn surfaces(name: &str) -> Vec<(&'static str, Vec<u8>)> {
        let tree = tree_of(name);
        let n = node(name);
        vec![
            (
                "tree panel",
                emitted(|f| {
                    let area = f.area();
                    tree_panel::render(f, area, &tree, &HashMap::new())
                }),
            ),
            (
                "detail panel",
                emitted(|f| {
                    let area = f.area();
                    detail_panel::render(
                        f,
                        area,
                        &tree,
                        &HashMap::new(),
                        &HashMap::new(),
                        &HashMap::new(),
                    )
                }),
            ),
            (
                "delete dialog",
                emitted(|f| dialogs::render_delete_confirm(f, &[&n])),
            ),
        ]
    }

    #[test]
    fn control_characters_in_names_and_paths_never_reach_the_terminal() {
        for hostile in HOSTILE {
            // The expected rendering is the same text with each control character
            // shown as U+FFFD: identical bytes mean nothing a terminal could act on
            // got through AND the layout (padding, truncation) did not shift.
            let shown: String = hostile
                .chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect();
            assert_ne!(*hostile, shown, "fixture must actually contain controls");
            for ((surface, got), (_, want)) in surfaces(hostile).into_iter().zip(surfaces(&shown)) {
                assert_eq!(
                    got, want,
                    "{surface}: {hostile:?} was not rendered as the visibly-replaced {shown:?}"
                );
            }
        }
    }

    #[test]
    fn ratatui_itself_drops_control_characters_before_they_reach_the_terminal() {
        // The fields that do NOT go through `printable` (versions, vulnerability
        // text, metadata, commands) rely on ratatui alone. Render the RAW hostile
        // text through an ordinary widget, bypassing `printable`, and require the
        // bytes to equal those of the same text with the controls removed. This is
        // the test that fails if a ratatui upgrade stops filtering.
        for hostile in HOSTILE {
            let stripped: String = hostile.chars().filter(|c| !c.is_control()).collect();
            assert_ne!(*hostile, stripped, "fixture must actually contain controls");
            let render = |text: &str| {
                let text = text.to_owned();
                emitted(move |f| {
                    let area = f.area();
                    let line = ratatui::text::Line::from(vec![
                        ratatui::text::Span::raw(text.clone()),
                        ratatui::text::Span::raw(" tail"),
                    ]);
                    f.render_widget(ratatui::widgets::Paragraph::new(line), area);
                })
            };
            assert_eq!(
                render(hostile),
                render(&stripped),
                "ratatui let a control character from {hostile:?} through"
            );
        }
    }

    #[test]
    fn printable_replaces_each_control_one_for_one_and_borrows_clean_text() {
        assert_eq!(
            super::printable("a\x1bb\u{9b}c\r\n"),
            "a\u{FFFD}b\u{FFFD}c\u{FFFD}\u{FFFD}"
        );
        assert!(matches!(
            super::printable("plain-1.0 é日本"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn the_comparison_can_tell_a_leaked_escape_from_a_clean_render() {
        // Guard on the guard: the same harness must flag a render in which an ESC
        // does get through, otherwise the test above proves nothing.
        let clean = surfaces("pkg-1.0");
        let leaky = emitted(|f| {
            let area = f.area();
            let tree = tree_of("pkg-1.0");
            tree_panel::render(f, area, &tree, &HashMap::new());
            f.buffer_mut()[(0, 0)].set_symbol("\x1b[2J");
        });
        assert_ne!(
            clean[0].1, leaky,
            "a leaked ESC must change the emitted bytes"
        );
    }
}
