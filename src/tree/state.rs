use super::node::TreeNode;
use crate::config::SortField;
use std::collections::HashSet;

#[derive(Debug)]
pub struct TreeState {
    pub nodes: Vec<TreeNode>,
    pub expanded: HashSet<usize>,
    pub selected: usize,
    pub scroll_offset: usize,
    pub visible: Vec<usize>,
    pub marked: HashSet<usize>,
    pub sort_by: SortField,
    pub sort_desc: bool,
    pub filter: String,
}

impl TreeState {
    pub fn new(sort_by: SortField, sort_desc: bool) -> Self {
        Self {
            nodes: Vec::new(),
            expanded: HashSet::new(),
            selected: 0,
            scroll_offset: 0,
            visible: Vec::new(),
            marked: HashSet::new(),
            sort_by,
            sort_desc,
            filter: String::new(),
        }
    }

    pub fn set_roots(&mut self, roots: Vec<TreeNode>) {
        self.nodes = roots;
        self.expanded.clear();
        self.marked.clear();
        self.selected = 0;
        self.scroll_offset = 0;
        self.recompute_visible();
    }

    pub fn recompute_visible(&mut self) {
        self.visible.clear();
        let filter_lower = self.filter.to_lowercase();
        for i in 0..self.nodes.len() {
            if self.is_visible(i, &filter_lower) {
                self.visible.push(i);
            }
        }
        // Clamp selection
        if !self.visible.is_empty() && self.selected >= self.visible.len() {
            self.selected = self.visible.len() - 1;
        }
    }

    fn is_visible(&self, idx: usize, filter: &str) -> bool {
        let node = &self.nodes[idx];
        // Root nodes are always visible
        if node.parent.is_none() {
            return true;
        }
        // Walk up to root — all ancestors must be expanded
        let mut current = idx;
        while let Some(parent) = self.nodes[current].parent {
            if !self.expanded.contains(&parent) {
                return false;
            }
            current = parent;
        }
        // Apply filter (case-insensitive substring match)
        if !filter.is_empty() {
            return node.name.to_lowercase().contains(filter);
        }
        true
    }

    pub fn set_filter(&mut self, text: &str) {
        self.filter = text.to_string();
        self.recompute_visible();
    }

    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.recompute_visible();
    }

    pub fn selected_node(&self) -> Option<&TreeNode> {
        self.visible
            .get(self.selected)
            .and_then(|&idx| self.nodes.get(idx))
    }

    pub fn selected_node_index(&self) -> Option<usize> {
        self.visible.get(self.selected).copied()
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn move_down(&mut self) {
        if self.selected + 1 < self.visible.len() {
            self.selected += 1;
        }
    }

    pub fn go_top(&mut self) {
        self.selected = 0;
    }

    pub fn go_bottom(&mut self) {
        if !self.visible.is_empty() {
            self.selected = self.visible.len() - 1;
        }
    }

    pub fn toggle_expand(&mut self) -> Option<usize> {
        if let Some(&idx) = self.visible.get(self.selected) {
            let node = &self.nodes[idx];
            if !node.has_children {
                return None;
            }

            if self.expanded.contains(&idx) {
                self.expanded.remove(&idx);
                self.recompute_visible();
                None
            } else {
                self.expanded.insert(idx);
                if node.children_loaded {
                    self.recompute_visible();
                    None
                } else {
                    // Signal that children need loading
                    Some(idx)
                }
            }
        } else {
            None
        }
    }

    pub fn expand(&mut self) -> Option<usize> {
        if let Some(&idx) = self.visible.get(self.selected) {
            let node = &self.nodes[idx];
            if !node.has_children || self.expanded.contains(&idx) {
                return None;
            }
            self.expanded.insert(idx);
            if node.children_loaded {
                self.recompute_visible();
                None
            } else {
                Some(idx)
            }
        } else {
            None
        }
    }

    pub fn collapse(&mut self) {
        if let Some(&idx) = self.visible.get(self.selected) {
            if self.expanded.contains(&idx) {
                self.expanded.remove(&idx);
                self.recompute_visible();
            } else if let Some(parent) = self.nodes[idx].parent {
                // Move to parent
                if let Some(pos) = self.visible.iter().position(|&i| i == parent) {
                    self.selected = pos;
                }
            }
        }
    }

    pub fn toggle_mark(&mut self) {
        if let Some(&idx) = self.visible.get(self.selected) {
            if self.marked.contains(&idx) {
                self.marked.remove(&idx);
            } else {
                self.marked.insert(idx);
            }
            self.move_down();
        }
    }

    pub fn insert_children(&mut self, parent_idx: usize, children: Vec<TreeNode>) {
        if parent_idx >= self.nodes.len() {
            return;
        }
        // Guard against duplicate insertion
        if self.nodes[parent_idx].children_loaded {
            return;
        }
        self.nodes[parent_idx].children_loaded = true;

        // Find insertion point: after parent and all its existing descendants
        let insert_at = self.find_subtree_end(parent_idx);

        // Adjust parent indices and depth for children
        let count = children.len();
        let parent_depth = self.nodes[parent_idx].depth;
        let mut adjusted = children;
        for child in &mut adjusted {
            child.parent = Some(parent_idx);
            child.depth = parent_depth + 1;
        }

        // Shift indices in existing nodes that come after insert_at
        for node in &mut self.nodes {
            if let Some(ref mut p) = node.parent {
                if *p >= insert_at {
                    *p += count;
                }
            }
        }

        // Shift expanded set
        let mut new_expanded = HashSet::new();
        for &idx in &self.expanded {
            if idx >= insert_at {
                new_expanded.insert(idx + count);
            } else {
                new_expanded.insert(idx);
            }
        }
        self.expanded = new_expanded;

        // Shift marked set
        let mut new_marked = HashSet::new();
        for &idx in &self.marked {
            if idx >= insert_at {
                new_marked.insert(idx + count);
            } else {
                new_marked.insert(idx);
            }
        }
        self.marked = new_marked;

        // Insert children
        let mut insert_children: Vec<TreeNode> = Vec::with_capacity(count);
        for child in adjusted {
            insert_children.push(child);
        }
        self.nodes.splice(insert_at..insert_at, insert_children);

        // Sort the newly inserted children
        self.sort_children(parent_idx);

        self.recompute_visible();
    }

    fn find_subtree_end(&self, idx: usize) -> usize {
        let mut end = idx + 1;
        while end < self.nodes.len() {
            // Check if this node is a descendant of idx
            let mut is_descendant = false;
            let mut current = end;
            while let Some(parent) = self.nodes[current].parent {
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

    pub fn sort_children(&mut self, parent_idx: usize) {
        let child_depth = self.nodes[parent_idx].depth + 1;
        let subtree_start = parent_idx + 1;
        let subtree_end = self.find_subtree_end(parent_idx);

        if subtree_start >= subtree_end {
            return;
        }

        // Find direct children and their subtree ranges using depth boundaries.
        // A child's subtree = [child_idx .. next sibling or end of parent's subtree)
        let mut child_starts: Vec<usize> = Vec::new();
        for i in subtree_start..subtree_end {
            if self.nodes[i].depth == child_depth {
                child_starts.push(i);
            }
        }

        if child_starts.len() <= 1 {
            return;
        }

        // Build ranges: each child's subtree goes from its index to the next child's index
        let mut subtrees: Vec<Vec<TreeNode>> = Vec::new();
        for (pos, &start) in child_starts.iter().enumerate() {
            let end = if pos + 1 < child_starts.len() {
                child_starts[pos + 1]
            } else {
                subtree_end
            };
            subtrees.push(self.nodes[start..end].to_vec());
        }

        // Sort by the child node (first element of each subtree)
        let sort_by = self.sort_by;
        let sort_desc = self.sort_desc;
        subtrees.sort_by(|a, b| {
            let ord = match sort_by {
                SortField::Size => a[0].size.cmp(&b[0].size),
                SortField::Name => a[0].name.to_lowercase().cmp(&b[0].name.to_lowercase()),
                SortField::Modified => a[0].last_modified.cmp(&b[0].last_modified),
            };
            if sort_desc { ord.reverse() } else { ord }
        });

        // Save expanded/marked paths for remapping
        let expanded_paths: HashSet<std::path::PathBuf> = self.expanded.iter()
            .filter(|&&idx| idx >= subtree_start && idx < subtree_end)
            .map(|&idx| self.nodes[idx].path.clone())
            .collect();
        let marked_paths: HashSet<std::path::PathBuf> = self.marked.iter()
            .filter(|&&idx| idx >= subtree_start && idx < subtree_end)
            .map(|&idx| self.nodes[idx].path.clone())
            .collect();

        self.expanded.retain(|&idx| idx < subtree_start || idx >= subtree_end);
        self.marked.retain(|&idx| idx < subtree_start || idx >= subtree_end);

        // Rebuild with correct parent references
        let mut new_section: Vec<TreeNode> = Vec::new();
        for subtree in &subtrees {
            let base = subtree_start + new_section.len();
            for (i, node) in subtree.iter().enumerate() {
                let mut n = node.clone();
                if i == 0 {
                    n.parent = Some(parent_idx);
                } else {
                    // Walk backwards in new_section to find nearest ancestor at depth-1
                    let target_depth = n.depth - 1;
                    for j in (0..new_section.len()).rev() {
                        if new_section[j].depth == target_depth
                            && (subtree_start + j) >= base
                        {
                            n.parent = Some(subtree_start + j);
                            break;
                        }
                    }
                }
                new_section.push(n);
            }
        }

        self.nodes.splice(subtree_start..subtree_end, new_section);

        // Restore expanded/marked by path
        let new_end = self.find_subtree_end(parent_idx);
        for idx in subtree_start..new_end {
            if expanded_paths.contains(&self.nodes[idx].path) {
                self.expanded.insert(idx);
            }
            if marked_paths.contains(&self.nodes[idx].path) {
                self.marked.insert(idx);
            }
        }
    }

    pub fn cycle_sort(&mut self) {
        self.sort_by = self.sort_by.cycle();
        // Re-sort all expanded nodes
        let expanded: Vec<usize> = self.expanded.iter().copied().collect();
        for idx in expanded {
            self.sort_children(idx);
        }
        // Sort root nodes
        self.sort_roots();
        self.recompute_visible();
    }

    fn sort_roots(&mut self) {
        let mut root_indices: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.parent.is_none())
            .map(|(i, _)| i)
            .collect();

        if root_indices.len() <= 1 {
            return;
        }

        let sort_by = self.sort_by;
        let sort_desc = self.sort_desc;
        root_indices.sort_by(|&a, &b| {
            let ord = match sort_by {
                SortField::Size => self.nodes[a].size.cmp(&self.nodes[b].size),
                SortField::Name => self.nodes[a].name.to_lowercase().cmp(&self.nodes[b].name.to_lowercase()),
                SortField::Modified => self.nodes[a].last_modified.cmp(&self.nodes[b].last_modified),
            };
            if sort_desc { ord.reverse() } else { ord }
        });

        let already_sorted = root_indices.windows(2).all(|w| w[0] < w[1]);
        if already_sorted {
            return;
        }

        let cloned: Vec<TreeNode> = root_indices.iter().map(|&i| self.nodes[i].clone()).collect();
        for (pos, &orig_idx) in root_indices.iter().enumerate() {
            self.nodes[orig_idx] = cloned[pos].clone();
        }
    }

    pub fn remove_nodes(&mut self, indices: &[usize]) {
        // Sort in reverse to remove from the end first
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        sorted.reverse();

        for &idx in &sorted {
            // Remove the subtree
            let end = self.find_subtree_end(idx);
            let count = end - idx;

            self.nodes.drain(idx..end);

            // Adjust parent references
            for node in &mut self.nodes {
                if let Some(ref mut p) = node.parent {
                    if *p > idx {
                        *p = p.saturating_sub(count);
                    }
                }
            }

            // Adjust expanded/marked sets
            let mut new_expanded = HashSet::new();
            for &e in &self.expanded {
                if e < idx {
                    new_expanded.insert(e);
                } else if e >= end {
                    new_expanded.insert(e - count);
                }
            }
            self.expanded = new_expanded;

            let mut new_marked = HashSet::new();
            for &m in &self.marked {
                if m < idx {
                    new_marked.insert(m);
                } else if m >= end {
                    new_marked.insert(m - count);
                }
            }
            self.marked = new_marked;
        }

        if self.selected >= self.visible.len() {
            self.selected = self.visible.len().saturating_sub(1);
        }

        self.recompute_visible();
    }

    #[cfg(test)]
    pub fn visible_names(&self) -> Vec<&str> {
        self.visible
            .iter()
            .map(|&idx| self.nodes[idx].name.as_str())
            .collect()
    }

    pub fn adjust_scroll(&mut self, viewport_height: usize) {
        if self.visible.is_empty() {
            self.scroll_offset = 0;
            return;
        }
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected - viewport_height + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::node::{CacheKind, TreeNode};
    use std::path::PathBuf;

    /// Helper: create a test TreeNode with the given name and size.
    fn make_node(name: &str, size: u64, depth: u16, parent: Option<usize>) -> TreeNode {
        TreeNode {
            path: PathBuf::from(format!("/test/{name}")),
            name: name.to_string(),
            size,
            depth,
            parent,
            has_children: true,
            kind: CacheKind::Unknown,
            last_modified: None,
            is_root: depth == 0,
            children_loaded: false,
        }
    }

    fn make_leaf(name: &str, size: u64, depth: u16, parent: Option<usize>) -> TreeNode {
        TreeNode {
            has_children: false,
            ..make_node(name, size, depth, parent)
        }
    }

    fn tree_with_roots() -> TreeState {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![
            make_node("root-a", 1000, 0, None),
            make_node("root-b", 2000, 0, None),
            make_node("root-c", 500, 0, None),
        ]);
        tree
    }

    // --- Basic state ---

    #[test]
    fn new_is_empty() {
        let tree = TreeState::new(SortField::Size, true);
        assert!(tree.nodes.is_empty());
        assert!(tree.visible.is_empty());
        assert_eq!(tree.selected, 0);
    }

    #[test]
    fn set_roots_populates_visible() {
        let tree = tree_with_roots();
        assert_eq!(tree.nodes.len(), 3);
        assert_eq!(tree.visible.len(), 3);
        assert_eq!(tree.visible, vec![0, 1, 2]);
    }

    #[test]
    fn set_roots_clears_previous_state() {
        let mut tree = tree_with_roots();
        tree.selected = 2;
        tree.marked.insert(1);
        tree.expanded.insert(0);

        tree.set_roots(vec![make_node("new", 100, 0, None)]);
        assert_eq!(tree.nodes.len(), 1);
        assert_eq!(tree.selected, 0);
        assert!(tree.marked.is_empty());
        assert!(tree.expanded.is_empty());
    }

    // --- Navigation ---

    #[test]
    fn move_down_advances_selection() {
        let mut tree = tree_with_roots();
        assert_eq!(tree.selected, 0);
        tree.move_down();
        assert_eq!(tree.selected, 1);
        tree.move_down();
        assert_eq!(tree.selected, 2);
    }

    #[test]
    fn move_down_stops_at_end() {
        let mut tree = tree_with_roots();
        tree.selected = 2;
        tree.move_down();
        assert_eq!(tree.selected, 2);
    }

    #[test]
    fn move_up_decrements_selection() {
        let mut tree = tree_with_roots();
        tree.selected = 2;
        tree.move_up();
        assert_eq!(tree.selected, 1);
    }

    #[test]
    fn move_up_stops_at_top() {
        let mut tree = tree_with_roots();
        tree.move_up();
        assert_eq!(tree.selected, 0);
    }

    #[test]
    fn go_top_and_bottom() {
        let mut tree = tree_with_roots();
        tree.go_bottom();
        assert_eq!(tree.selected, 2);
        tree.go_top();
        assert_eq!(tree.selected, 0);
    }

    #[test]
    fn go_bottom_empty_tree() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.go_bottom(); // should not panic
        assert_eq!(tree.selected, 0);
    }

    #[test]
    fn selected_node_returns_correct_node() {
        let tree = tree_with_roots();
        let node = tree.selected_node().unwrap();
        assert_eq!(node.name, "root-a");
    }

    #[test]
    fn selected_node_empty_tree_returns_none() {
        let tree = TreeState::new(SortField::Size, true);
        assert!(tree.selected_node().is_none());
    }

    // --- Expand / Collapse ---

    #[test]
    fn toggle_expand_on_unloaded_node_returns_index() {
        let mut tree = tree_with_roots();
        let result = tree.toggle_expand();
        // Node not yet loaded, should return index for scanning
        assert_eq!(result, Some(0));
        assert!(tree.expanded.contains(&0));
    }

    #[test]
    fn toggle_expand_on_loaded_node_shows_children() {
        let mut tree = tree_with_roots();

        let children = vec![
            make_node("child-a", 500, 1, Some(0)),
            make_node("child-b", 300, 1, Some(0)),
        ];
        tree.insert_children(0, children);
        tree.expanded.insert(0);
        tree.recompute_visible();

        assert_eq!(tree.visible.len(), 5); // 3 roots + 2 children
    }

    #[test]
    fn toggle_expand_collapse_hides_children() {
        let mut tree = tree_with_roots();
        tree.insert_children(0, vec![
            make_node("child", 100, 1, Some(0)),
        ]);
        tree.expanded.insert(0);
        tree.recompute_visible();
        assert_eq!(tree.visible.len(), 4);

        // Collapse
        tree.toggle_expand(); // selected is 0, already expanded → collapse
        assert_eq!(tree.visible.len(), 3);
    }

    #[test]
    fn expand_on_leaf_does_nothing() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_leaf("file.txt", 100, 0, None)]);
        let result = tree.toggle_expand();
        assert_eq!(result, None);
    }

    #[test]
    fn expand_already_expanded_returns_none() {
        let mut tree = tree_with_roots();
        tree.nodes[0].children_loaded = true; // simulate already loaded
        tree.expanded.insert(0);
        let result = tree.expand();
        assert_eq!(result, None);
    }

    #[test]
    fn collapse_moves_to_parent_when_not_expanded() {
        let mut tree = tree_with_roots();
        tree.insert_children(0, vec![
            make_node("child", 100, 1, Some(0)),
        ]);
        tree.expanded.insert(0);
        tree.recompute_visible();

        // Select child (index 1 in visible)
        tree.selected = 1;
        assert_eq!(tree.selected_node().unwrap().name, "child");

        // Collapse on child → should move to parent
        tree.collapse();
        assert_eq!(tree.selected_node().unwrap().name, "root-a");
    }

    // --- Insert children ---

    #[test]
    fn insert_children_sets_depth() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("child", 100, 99, Some(0)), // depth=99 should get corrected
        ]);
        assert_eq!(tree.nodes[1].depth, 1); // parent depth=0, so child=1
    }

    #[test]
    fn insert_children_sets_parent() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(0);
        tree.insert_children(0, vec![make_node("child", 100, 0, None)]);
        assert_eq!(tree.nodes[1].parent, Some(0));
    }

    #[test]
    fn insert_children_shifts_subsequent_nodes() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(0);

        let children = vec![
            make_node("child-1", 100, 1, Some(0)),
            make_node("child-2", 200, 1, Some(0)),
        ];
        tree.insert_children(0, children);

        // Original root-b and root-c should have shifted
        assert_eq!(tree.nodes.len(), 5);
        assert_eq!(tree.nodes[0].name, "root-a");
        // Children inserted after root-a
        assert_eq!(tree.nodes[3].name, "root-b");
        assert_eq!(tree.nodes[4].name, "root-c");
    }

    #[test]
    fn insert_children_out_of_bounds_is_noop() {
        let mut tree = tree_with_roots();
        tree.insert_children(999, vec![make_node("orphan", 100, 1, Some(999))]);
        assert_eq!(tree.nodes.len(), 3); // unchanged
    }

    #[test]
    fn insert_children_twice_is_guarded() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(0);
        tree.insert_children(0, vec![make_node("child", 100, 1, Some(0))]);
        assert_eq!(tree.nodes.len(), 4);

        // Second insert should be blocked by children_loaded guard
        tree.insert_children(0, vec![make_node("duplicate", 200, 1, Some(0))]);
        assert_eq!(tree.nodes.len(), 4, "Should not insert duplicate children");
        assert_eq!(tree.nodes[1].name, "child", "Original child should remain");
    }

    #[test]
    fn insert_children_after_refresh_works() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(0);
        tree.insert_children(0, vec![make_node("old-child", 100, 1, Some(0))]);
        assert_eq!(tree.nodes.len(), 4);

        // Simulate refresh: reset children_loaded, remove old children, re-insert
        tree.nodes[0].children_loaded = false;
        tree.remove_nodes(&[1]); // remove old-child
        assert_eq!(tree.nodes.len(), 3);

        tree.insert_children(0, vec![make_node("new-child", 200, 1, Some(0))]);
        assert_eq!(tree.nodes.len(), 4);
        assert_eq!(tree.nodes[1].name, "new-child");
    }

    #[test]
    fn nested_expand_visibility() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);

        // Expand root, insert children
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("level-1", 500, 1, Some(0)),
        ]);

        assert_eq!(tree.visible.len(), 2);

        // Expand level-1, insert grandchild
        tree.expanded.insert(1);
        tree.insert_children(1, vec![
            make_leaf("level-2", 100, 2, Some(1)),
        ]);

        assert_eq!(tree.visible.len(), 3);
        assert_eq!(tree.visible_names(), vec!["root", "level-1", "level-2"]);

        // Collapse root → only root visible
        tree.expanded.remove(&0);
        tree.recompute_visible();
        assert_eq!(tree.visible.len(), 1);
    }

    // --- Marking ---

    #[test]
    fn toggle_mark_marks_and_advances() {
        let mut tree = tree_with_roots();
        tree.toggle_mark();
        assert!(tree.marked.contains(&0));
        assert_eq!(tree.selected, 1);
    }

    #[test]
    fn toggle_mark_unmarks() {
        let mut tree = tree_with_roots();
        tree.marked.insert(0);
        tree.toggle_mark();
        assert!(!tree.marked.contains(&0));
    }

    // --- Remove nodes ---

    #[test]
    fn remove_single_root() {
        let mut tree = tree_with_roots();
        tree.remove_nodes(&[1]); // remove root-b
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(tree.nodes[0].name, "root-a");
        assert_eq!(tree.nodes[1].name, "root-c");
    }

    #[test]
    fn remove_node_with_children_removes_subtree() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("child-1", 100, 1, Some(0)),
            make_node("child-2", 200, 1, Some(0)),
        ]);
        // Tree: root-a, child-1, child-2, root-b, root-c

        tree.remove_nodes(&[0]); // remove root-a and its children
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(tree.nodes[0].name, "root-b");
        assert_eq!(tree.nodes[1].name, "root-c");
    }

    #[test]
    fn remove_adjusts_parent_references() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(1); // expand root-b
        tree.insert_children(1, vec![
            make_node("child-of-b", 100, 1, Some(1)),
        ]);

        // Remove root-a (index 0) — root-b shifts to 0, child shifts too
        tree.remove_nodes(&[0]);
        assert_eq!(tree.nodes[0].name, "root-b");
        assert_eq!(tree.nodes[1].name, "child-of-b");
        assert_eq!(tree.nodes[1].parent, Some(0)); // shifted from 1 to 0
    }

    #[test]
    fn remove_clears_expanded_and_marked_for_removed() {
        let mut tree = tree_with_roots();
        tree.expanded.insert(1);
        tree.marked.insert(1);
        tree.remove_nodes(&[1]);
        assert!(!tree.expanded.contains(&1));
        assert!(!tree.marked.contains(&1));
    }

    // --- Sorting ---

    #[test]
    fn cycle_sort_changes_field() {
        let mut tree = tree_with_roots();
        assert_eq!(tree.sort_by, SortField::Size);
        tree.cycle_sort();
        assert_eq!(tree.sort_by, SortField::Name);
        tree.cycle_sort();
        assert_eq!(tree.sort_by, SortField::Modified);
        tree.cycle_sort();
        assert_eq!(tree.sort_by, SortField::Size);
    }

    #[test]
    fn sort_children_by_size_desc() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("small", 100, 1, Some(0)),
            make_node("big", 900, 1, Some(0)),
            make_node("medium", 500, 1, Some(0)),
        ]);

        // Children should be sorted by size descending
        let child_names: Vec<&str> = tree.nodes[1..4].iter().map(|n| n.name.as_str()).collect();
        assert_eq!(child_names, vec!["big", "medium", "small"]);
    }

    #[test]
    fn sort_children_by_name_asc() {
        let mut tree = TreeState::new(SortField::Name, false);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("cherry", 100, 1, Some(0)),
            make_node("apple", 200, 1, Some(0)),
            make_node("banana", 300, 1, Some(0)),
        ]);

        let child_names: Vec<&str> = tree.nodes[1..4].iter().map(|n| n.name.as_str()).collect();
        assert_eq!(child_names, vec!["apple", "banana", "cherry"]);
    }

    #[test]
    fn sort_children_with_expanded_subtrees() {
        // Use Name sort to avoid initial sort interference
        let mut tree = TreeState::new(SortField::Name, false); // asc by name
        tree.set_roots(vec![make_node("root", 10000, 0, None)]);
        tree.expanded.insert(0);

        // Insert children — they'll be sorted by name asc on insert
        tree.insert_children(0, vec![
            make_node("huggingface", 5000, 1, Some(0)),
            make_node("selenium", 100, 1, Some(0)),
            make_node("whisper", 3000, 1, Some(0)),
        ]);
        // After name-asc sort: root(0), hf(1), selenium(2), whisper(3)
        assert_eq!(tree.nodes[1].name, "huggingface");
        assert_eq!(tree.nodes[2].name, "selenium");
        assert_eq!(tree.nodes[3].name, "whisper");

        // Expand huggingface and add grandchildren
        tree.expanded.insert(1);
        tree.nodes[1].children_loaded = false;
        tree.insert_children(1, vec![
            make_leaf("hub", 4000, 2, Some(1)),
            make_leaf("xet", 1000, 2, Some(1)),
        ]);
        // Tree: root(0), hf(1), hub(2), xet(3), selenium(4), whisper(5)
        assert_eq!(tree.nodes.len(), 6);
        assert_eq!(tree.nodes[2].name, "hub");
        assert_eq!(tree.nodes[2].parent, Some(1));

        // Now re-sort by size descending — hf(5000) > whisper(3000) > selenium(100)
        tree.sort_by = SortField::Size;
        tree.sort_desc = true;
        tree.sort_children(0);
        tree.recompute_visible();

        let names: Vec<&str> = tree.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names[0], "root");
        assert_eq!(names[1], "huggingface");
        assert_eq!(names[2], "hub");
        assert_eq!(names[3], "xet");
        assert_eq!(names[4], "whisper");
        assert_eq!(names[5], "selenium");

        // Verify parent references
        assert_eq!(tree.nodes[1].parent, Some(0)); // hf -> root
        assert_eq!(tree.nodes[2].parent, Some(1)); // hub -> hf
        assert_eq!(tree.nodes[3].parent, Some(1)); // xet -> hf
        assert_eq!(tree.nodes[4].parent, Some(0)); // whisper -> root
        assert_eq!(tree.nodes[5].parent, Some(0)); // selenium -> root

        // Verify expanded state preserved
        assert!(tree.expanded.contains(&0));
        assert!(tree.expanded.contains(&1));
        assert_eq!(tree.visible.len(), 6);
    }

    #[test]
    fn sort_reverses_subtrees_correctly() {
        // Use Name sort initially so we control the order
        let mut tree = TreeState::new(SortField::Name, false); // asc
        tree.set_roots(vec![make_node("root", 10000, 0, None)]);
        tree.expanded.insert(0);

        tree.insert_children(0, vec![
            make_node("big", 9000, 1, Some(0)),
            make_node("small", 100, 1, Some(0)),
        ]);
        // After name-asc sort: root(0), big(1), small(2)

        // Expand "small" and add a child
        let small_idx = tree.nodes.iter().position(|n| n.name == "small").unwrap();
        tree.expanded.insert(small_idx);
        tree.nodes[small_idx].children_loaded = false;
        tree.insert_children(small_idx, vec![
            make_leaf("small-child", 50, 2, Some(small_idx)),
        ]);
        // Tree: root(0), big(1), small(2), small-child(3)

        // Sort by size desc — big(9000) stays first, small(100) stays second
        tree.sort_by = SortField::Size;
        tree.sort_desc = true;
        tree.sort_children(0);
        tree.recompute_visible();

        let names: Vec<&str> = tree.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["root", "big", "small", "small-child"]);
        assert_eq!(tree.nodes[3].parent, Some(2)); // small-child -> small
        assert_eq!(tree.nodes[2].parent, Some(0)); // small -> root
        assert_eq!(tree.nodes[1].parent, Some(0)); // big -> root

        // Now sort by name asc — should reverse: big, small(+child)
        tree.sort_by = SortField::Name;
        tree.sort_desc = false;
        tree.sort_children(0);

        let names: Vec<&str> = tree.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["root", "big", "small", "small-child"]);
        // big < small alphabetically, so order stays same

        // Force reverse: sort name desc
        tree.sort_desc = true;
        tree.sort_children(0);

        let names: Vec<&str> = tree.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["root", "small", "small-child", "big"]);
        assert_eq!(tree.nodes[1].parent, Some(0)); // small -> root
        assert_eq!(tree.nodes[2].parent, Some(1)); // small-child -> small
        assert_eq!(tree.nodes[3].parent, Some(0)); // big -> root
    }

    // --- Scrolling ---

    #[test]
    fn adjust_scroll_follows_selection_down() {
        let mut tree = tree_with_roots();
        tree.selected = 2;
        tree.adjust_scroll(2); // viewport shows 2 items
        assert_eq!(tree.scroll_offset, 1); // scrolled to show item 2
    }

    #[test]
    fn adjust_scroll_follows_selection_up() {
        let mut tree = tree_with_roots();
        tree.scroll_offset = 2;
        tree.selected = 0;
        tree.adjust_scroll(2);
        assert_eq!(tree.scroll_offset, 0);
    }

    #[test]
    fn adjust_scroll_no_change_when_in_viewport() {
        let mut tree = tree_with_roots();
        tree.selected = 1;
        tree.scroll_offset = 0;
        tree.adjust_scroll(3); // all fit
        assert_eq!(tree.scroll_offset, 0);
    }

    #[test]
    fn adjust_scroll_empty_tree() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.scroll_offset = 5;
        tree.adjust_scroll(10);
        assert_eq!(tree.scroll_offset, 0);
    }

    // --- visible_names helper ---

    #[test]
    fn visible_names_reflects_tree() {
        let tree = tree_with_roots();
        assert_eq!(tree.visible_names(), vec!["root-a", "root-b", "root-c"]);
    }

    // --- Filter ---

    #[test]
    fn set_filter_hides_non_matching_children() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("apple", 500, 1, Some(0)),
            make_node("cherry", 300, 1, Some(0)),
            make_node("apricot", 200, 1, Some(0)),
        ]);
        assert_eq!(tree.visible.len(), 4); // root + 3 children

        tree.set_filter("ap");
        // root (always visible) + apple + apricot (match "ap"), cherry hidden
        let names = tree.visible_names();
        assert!(names.contains(&"root"));
        assert!(names.contains(&"apple"));
        assert!(names.contains(&"apricot"));
        assert!(!names.contains(&"cherry"));
    }

    #[test]
    fn set_filter_case_insensitive() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("Apple", 500, 1, Some(0)),
            make_node("banana", 300, 1, Some(0)),
        ]);

        tree.set_filter("APPLE");
        let names = tree.visible_names();
        assert!(names.contains(&"Apple"));
        assert!(!names.contains(&"banana"));
    }

    #[test]
    fn clear_filter_shows_all() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("apple", 500, 1, Some(0)),
            make_node("banana", 300, 1, Some(0)),
        ]);

        tree.set_filter("apple");
        assert_eq!(tree.visible.len(), 2); // root + apple

        tree.clear_filter();
        assert_eq!(tree.visible.len(), 3); // root + apple + banana
    }

    #[test]
    fn filter_empty_string_shows_all() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("apple", 500, 1, Some(0)),
        ]);

        tree.set_filter("");
        assert_eq!(tree.visible.len(), 2);
    }

    #[test]
    fn filter_clamps_selection() {
        let mut tree = TreeState::new(SortField::Size, true);
        tree.set_roots(vec![make_node("root", 1000, 0, None)]);
        tree.expanded.insert(0);
        tree.insert_children(0, vec![
            make_node("apple", 500, 1, Some(0)),
            make_node("banana", 300, 1, Some(0)),
            make_node("cherry", 200, 1, Some(0)),
        ]);
        tree.selected = 3; // cherry

        tree.set_filter("apple");
        // visible: root + apple (2 items), selected should be clamped
        assert!(tree.selected < tree.visible.len());
    }

    #[test]
    fn filter_roots_always_visible() {
        let mut tree = tree_with_roots();
        tree.set_filter("zzzzz"); // matches nothing
        // All roots should still be visible
        assert_eq!(tree.visible.len(), 3);
    }
}
