use super::MetadataField;
use std::path::Path;

pub fn semantic_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();

    // Shared Xet blob store root (huggingface_hub >= 1.32)
    if name == "blobs" && is_shared_store(path) {
        return Some("[shared blobs]".to_string());
    }

    // Hub: models--org--name, datasets--org--name, spaces--org--name
    if name.starts_with("models--") {
        let rest = name.strip_prefix("models--")?;
        return Some(format!("[model] {}", rest.replace("--", "/")));
    }
    if name.starts_with("datasets--") {
        let rest = name.strip_prefix("datasets--")?;
        return Some(format!("[dataset] {}", rest.replace("--", "/")));
    }
    if name.starts_with("spaces--") {
        let rest = name.strip_prefix("spaces--")?;
        return Some(format!("[space] {}", rest.replace("--", "/")));
    }

    // XET server dirs: https___cas_serv-xxx (check before ___ pattern)
    if name.starts_with("https___") {
        let decoded = name.replace("___", "://").replace('_', ".");
        return Some(format!("[xet] {decoded}"));
    }

    // Legacy datasets: org___dataset-name
    if name.contains("___") {
        let cleaned = name.replace("___", "/");
        return Some(format!("[dataset] {cleaned}"));
    }

    // Snapshot hash dirs (inside hub/models--*/snapshots/)
    if is_hex_hash(&name) {
        // Shared blob: name it after the repo(s) listed in its .refs manifest
        if let Some(repos) = shared_blob_repos(path) {
            let first = repos[0]
                .split_once("] ")
                .map_or(repos[0].as_str(), |(_, r)| r);
            return Some(match repos.len() {
                1 => format!("[shared] {first}"),
                n => format!("[shared] {first} +{}", n - 1),
            });
        }
        // Check if parent is "snapshots" → show short hash
        if let Some(parent) = path.parent() {
            let parent_name = parent
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if parent_name == "snapshots" {
                return Some(format!("[rev] {}", &name[..8.min(name.len())]));
            }
            if parent_name == "blobs" {
                // Try to find what file this blob represents via snapshot symlinks
                if let Some(file_name) = identify_blob_via_snapshots(path) {
                    return Some(file_name);
                }
                return Some(format!("[blob] {}", &name[..8.min(name.len())]));
            }
        }
        // Dataset version hash dirs
        if let Some(ds_name) = identify_dataset_hash(path) {
            return Some(ds_name);
        }
        return Some(format!("[hash] {}", &name[..8.min(name.len())]));
    }

    None
}

/// Check if a string looks like a hex hash (40+ chars, all hex)
fn is_hex_hash(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Marker file huggingface_hub writes at the root of the shared blob store.
const SHARED_STORE_MARKER: &str = ".huggingface-shared-blobs";

fn is_shared_store(dir: &Path) -> bool {
    dir.join(SHARED_STORE_MARKER).exists()
}

/// For a blob at `<store>/<prefix>/<hash>`, the repos listed in `<hash>.refs`
/// (one `models--org--name/blobs/<sha>` line each), as semantic labels.
fn shared_blob_repos(blob: &Path) -> Option<Vec<String>> {
    let store = blob.parent()?.parent()?;
    if !is_shared_store(store) {
        return None;
    }
    let mut refs_name = blob.file_name()?.to_os_string();
    refs_name.push(".refs");
    let content = std::fs::read_to_string(blob.with_file_name(refs_name)).ok()?;
    let mut repos: Vec<String> = Vec::new();
    for line in content.lines() {
        let Some(repo_dir) = line.split('/').next().filter(|s| !s.is_empty()) else {
            continue;
        };
        let label = semantic_name(Path::new(repo_dir)).unwrap_or_else(|| repo_dir.to_string());
        if !repos.contains(&label) {
            repos.push(label);
        }
    }
    (!repos.is_empty()).then_some(repos)
}

/// Total size of the shared-store blobs a repo's `blobs/` symlinks point to.
fn shared_bytes_linked_from(repo_dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(repo_dir.join("blobs")) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_symlink()))
        .filter_map(|e| std::fs::canonicalize(e.path()).ok())
        .filter(|target| {
            target
                .parent()
                .and_then(Path::parent)
                .is_some_and(is_shared_store)
        })
        .filter_map(|target| std::fs::metadata(target).ok())
        .map(|m| m.len())
        .sum()
}

/// Try to identify a blob by checking snapshot dirs for symlinks pointing to it.
fn identify_blob_via_snapshots(blob_path: &Path) -> Option<String> {
    let blob_name = blob_path.file_name()?.to_string_lossy().to_string();
    // blobs/ is sibling of snapshots/
    let model_dir = blob_path.parent()?.parent()?;
    let snapshots_dir = model_dir.join("snapshots");
    if !snapshots_dir.exists() {
        return None;
    }

    // Check the first snapshot for symlinks
    let snapshot = std::fs::read_dir(&snapshots_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .next()?;

    let snapshot_path = snapshot.path();
    if let Ok(entries) = std::fs::read_dir(&snapshot_path) {
        for entry in entries.filter_map(|e| e.ok()) {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy();
                if target_str.contains(&blob_name) {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    return Some(file_name);
                }
            }
        }
    }
    None
}

/// Identify a dataset hash dir by reading dataset_info.json
fn identify_dataset_hash(path: &Path) -> Option<String> {
    let info_path = path.join("dataset_info.json");
    if info_path.exists() {
        let content = std::fs::read_to_string(&info_path).ok()?;
        #[derive(serde::Deserialize)]
        struct DatasetInfo {
            #[serde(rename = "dataset_name")]
            dataset_name: Option<String>,
        }
        let info: DatasetInfo = serde_json::from_str(&content).ok()?;
        info.dataset_name.map(|name| format!("[info] {name}"))
    } else {
        None
    }
}

pub fn metadata(path: &Path) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Determine type
    let item_type = if name.starts_with("models--") {
        "Model"
    } else if name.starts_with("datasets--") {
        "Dataset"
    } else if name.starts_with("spaces--") {
        "Space"
    } else if name == "hub" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Downloaded models, datasets, and spaces".to_string(),
        });
        return fields;
    } else if name == "xet" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Git-Xet large file storage".to_string(),
        });
        return fields;
    } else if name == "datasets" {
        fields.push(MetadataField {
            label: "Contents".to_string(),
            value: "Cached datasets (legacy format)".to_string(),
        });
        return fields;
    } else {
        if let Some(repos) = shared_blob_repos(path) {
            fields.push(MetadataField {
                label: "Referenced by".to_string(),
                value: repos.join(", "),
            });
        }
        return fields;
    };

    fields.push(MetadataField {
        label: "Type".to_string(),
        value: item_type.to_string(),
    });

    // Count snapshots
    let snapshots_dir = path.join("snapshots");
    if snapshots_dir.exists()
        && let Ok(entries) = std::fs::read_dir(&snapshots_dir)
    {
        let count = entries.filter_map(|e| e.ok()).count();
        fields.push(MetadataField {
            label: "Revisions".to_string(),
            value: count.to_string(),
        });
    }

    // Count blobs
    let blobs_dir = path.join("blobs");
    if blobs_dir.exists()
        && let Ok(entries) = std::fs::read_dir(&blobs_dir)
    {
        let count = entries.filter_map(|e| e.ok()).count();
        fields.push(MetadataField {
            label: "Files".to_string(),
            value: count.to_string(),
        });
    }

    let shared = shared_bytes_linked_from(path);
    if shared > 0 {
        fields.push(MetadataField {
            label: "Shared data".to_string(),
            value: format!(
                "{} in hub/blobs (not freed by deleting this entry)",
                humansize::format_size(shared, humansize::BINARY)
            ),
        });
    }

    // Check refs
    let refs_dir = path.join("refs");
    if refs_dir.exists()
        && let Ok(entries) = std::fs::read_dir(&refs_dir)
    {
        let refs: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        if !refs.is_empty() {
            fields.push(MetadataField {
                label: "Refs".to_string(),
                value: refs.join(", "),
            });
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn semantic_name_model_single_org() {
        let path = PathBuf::from("/cache/huggingface/hub/models--meta-llama--Llama-3.1-8B");
        assert_eq!(
            semantic_name(&path),
            Some("[model] meta-llama/Llama-3.1-8B".into())
        );
    }

    #[test]
    fn semantic_name_model_nested_org() {
        let path = PathBuf::from("/cache/hub/models--openai--whisper-large-v3");
        assert_eq!(
            semantic_name(&path),
            Some("[model] openai/whisper-large-v3".into())
        );
    }

    #[test]
    fn semantic_name_dataset() {
        let path = PathBuf::from("/cache/hub/datasets--squad--squad");
        assert_eq!(semantic_name(&path), Some("[dataset] squad/squad".into()));
    }

    #[test]
    fn semantic_name_space() {
        let path = PathBuf::from("/cache/hub/spaces--gradio--demo");
        assert_eq!(semantic_name(&path), Some("[space] gradio/demo".into()));
    }

    #[test]
    fn semantic_name_legacy_dataset() {
        let path = PathBuf::from("/cache/datasets/juliensimon___donki-space-weather-events");
        assert_eq!(
            semantic_name(&path),
            Some("[dataset] juliensimon/donki-space-weather-events".into())
        );
    }

    #[test]
    fn semantic_name_snapshot_hash() {
        let path = PathBuf::from(
            "/cache/hub/models--org--m/snapshots/5c38ec7c405ec4b44b94cc5a9bb96e735b38267a",
        );
        assert_eq!(semantic_name(&path), Some("[rev] 5c38ec7c".into()));
    }

    #[test]
    fn semantic_name_dataset_hash_with_info() {
        let tmp = tempfile::tempdir().unwrap();
        let hash_dir = tmp.path().join("64f795d89a0859be0e76c2380cddbe9814e48229");
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(
            hash_dir.join("dataset_info.json"),
            r#"{"dataset_name": "iris", "config_name": "default"}"#,
        )
        .unwrap();
        assert_eq!(semantic_name(&hash_dir), Some("[info] iris".into()));
    }

    #[test]
    fn semantic_name_blob_with_snapshot_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let model = tmp.path().join("models--org--m");
        let blobs = model.join("blobs");
        let snapshots = model.join("snapshots/abc123");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::create_dir_all(&snapshots).unwrap();
        std::fs::write(
            blobs.join("deadbeef1234567890abcdef1234567890abcdef"),
            "data",
        )
        .unwrap();
        // Create symlink in snapshot pointing to blob
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                "../../blobs/deadbeef1234567890abcdef1234567890abcdef",
                snapshots.join("model.safetensors"),
            )
            .unwrap();
        }
        let blob_path = blobs.join("deadbeef1234567890abcdef1234567890abcdef");
        let result = semantic_name(&blob_path);
        #[cfg(unix)]
        assert_eq!(result, Some("model.safetensors".into()));
    }

    #[test]
    fn semantic_name_xet_server() {
        let path = PathBuf::from("/cache/xet/https___cas_serv-tGqkUaZf_CBPHQ6h");
        // Not a hex hash, starts with https___
        assert_eq!(
            semantic_name(&path),
            Some("[xet] https://cas.serv-tGqkUaZf.CBPHQ6h".into())
        );
    }

    #[test]
    fn semantic_name_plain_dir_returns_none() {
        let path = PathBuf::from("/cache/huggingface/hub");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn semantic_name_unrelated_returns_none() {
        let path = PathBuf::from("/cache/huggingface/modules");
        assert_eq!(semantic_name(&path), None);
    }

    #[test]
    fn is_hex_hash_works() {
        assert!(is_hex_hash("64f795d89a0859be0e76c2380cddbe9814e48229"));
        assert!(is_hex_hash("5c38ec7c405ec4b44b"));
        assert!(!is_hex_hash("short"));
        assert!(!is_hex_hash("not-hex-at-all-this-is-words"));
    }

    // Keep existing metadata tests
    #[test]
    fn metadata_hub_dir() {
        let path = PathBuf::from("/tmp/nonexistent/hub");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label, "Contents");
    }

    #[test]
    fn metadata_xet_dir() {
        let path = PathBuf::from("/tmp/nonexistent/xet");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("Xet"));
    }

    #[test]
    fn metadata_datasets_dir() {
        let path = PathBuf::from("/tmp/nonexistent/datasets");
        let fields = metadata(&path);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].value.contains("legacy"));
    }

    #[test]
    fn metadata_model_dir_without_subdirs() {
        let path = PathBuf::from("/tmp/nonexistent/models--org--name");
        let fields = metadata(&path);
        assert_eq!(fields[0].label, "Type");
        assert_eq!(fields[0].value, "Model");
    }

    #[test]
    fn metadata_model_dir_with_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let model_dir = tmp.path().join("models--org--name");
        std::fs::create_dir_all(model_dir.join("snapshots/rev1")).unwrap();
        std::fs::create_dir_all(model_dir.join("snapshots/rev2")).unwrap();
        std::fs::create_dir_all(model_dir.join("blobs")).unwrap();
        std::fs::write(model_dir.join("blobs/abc123"), "data").unwrap();
        std::fs::write(model_dir.join("blobs/def456"), "data").unwrap();

        let fields = metadata(&model_dir);
        let labels: Vec<&str> = fields.iter().map(|f| f.label.as_str()).collect();
        assert!(labels.contains(&"Type"));
        assert!(labels.contains(&"Revisions"));
        assert!(labels.contains(&"Files"));
    }

    /// Shared Xet blob store (huggingface_hub >= 1.32, #52): big files live once
    /// in `hub/blobs/<prefix>/<xet>`, repo blobs are symlinks into it, and
    /// `<xet>.refs` lists the referencing repo blobs.
    #[cfg(unix)]
    fn shared_blob_fixture(repos: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let hub = tmp.path().join("hub");
        let xet = "786820e8958abcfd7a2084c0d273f629ab8d7cbee560178f49a9cecb715b8041";
        let prefix = hub.join("blobs/78");
        std::fs::create_dir_all(&prefix).unwrap();
        std::fs::write(hub.join("blobs/.huggingface-shared-blobs"), "1\n").unwrap();
        std::fs::write(prefix.join(xet), vec![0u8; 4096]).unwrap();
        let mut refs = String::new();
        for (i, repo) in repos.iter().enumerate() {
            let sha = format!("951ed3fc1203e6a62467abb2144a96ce7eafca8fa77e3704fdb8635ff3e7f8a{i}");
            let blobs = hub.join(repo).join("blobs");
            std::fs::create_dir_all(&blobs).unwrap();
            std::os::unix::fs::symlink(format!("../../blobs/78/{xet}"), blobs.join(&sha)).unwrap();
            refs.push_str(&format!("{repo}/blobs/{sha}\n"));
        }
        std::fs::write(prefix.join(format!("{xet}.refs")), refs).unwrap();
        (tmp, hub)
    }

    #[cfg(unix)]
    #[test]
    fn semantic_name_shared_blob_store_root() {
        let (_tmp, hub) = shared_blob_fixture(&["models--org--m"]);
        assert_eq!(
            semantic_name(&hub.join("blobs")),
            Some("[shared blobs]".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn semantic_name_shared_blob_names_owning_repo() {
        // Without this the 1.5 GB payload shows as an anonymous `[hash]`.
        let (_tmp, hub) = shared_blob_fixture(&["models--mlx-community--whisper"]);
        let blob =
            hub.join("blobs/78/786820e8958abcfd7a2084c0d273f629ab8d7cbee560178f49a9cecb715b8041");
        assert_eq!(
            semantic_name(&blob),
            Some("[shared] mlx-community/whisper".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn semantic_name_shared_blob_counts_extra_repos() {
        let (_tmp, hub) = shared_blob_fixture(&["models--org--a", "models--org--b"]);
        let blob =
            hub.join("blobs/78/786820e8958abcfd7a2084c0d273f629ab8d7cbee560178f49a9cecb715b8041");
        assert_eq!(semantic_name(&blob), Some("[shared] org/a +1".into()));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_model_reports_shared_data_not_freed_on_delete() {
        // The model dir is tiny on disk; users must learn where the space is
        // and that deleting the model will not reclaim it.
        let (_tmp, hub) = shared_blob_fixture(&["models--org--m"]);
        let fields = metadata(&hub.join("models--org--m"));
        let shared = fields
            .iter()
            .find(|f| f.label == "Shared data")
            .expect("model linked into the shared store must report it");
        assert!(shared.value.contains("4 KiB"), "{}", shared.value);
        assert!(shared.value.contains("not freed"), "{}", shared.value);
    }

    #[test]
    fn metadata_model_without_shared_links_has_no_shared_field() {
        let tmp = tempfile::tempdir().unwrap();
        let model_dir = tmp.path().join("models--org--name");
        std::fs::create_dir_all(model_dir.join("blobs")).unwrap();
        std::fs::write(model_dir.join("blobs/abc123"), "data").unwrap();
        let fields = metadata(&model_dir);
        assert!(fields.iter().all(|f| f.label != "Shared data"));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_shared_blob_lists_referencing_repos() {
        let (_tmp, hub) = shared_blob_fixture(&["models--org--a", "datasets--org--d"]);
        let blob =
            hub.join("blobs/78/786820e8958abcfd7a2084c0d273f629ab8d7cbee560178f49a9cecb715b8041");
        let fields = metadata(&blob);
        let refs = fields
            .iter()
            .find(|f| f.label == "Referenced by")
            .expect("shared blob must list its repos");
        assert_eq!(refs.value, "[model] org/a, [dataset] org/d");
    }

    #[test]
    fn semantic_name_repo_blobs_dir_is_not_shared_store() {
        // A per-repo `blobs/` (no marker file) must keep its old behavior.
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path().join("models--org--m/blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        assert_eq!(semantic_name(&blobs), None);
    }

    #[test]
    fn metadata_unknown_dir() {
        let path = PathBuf::from("/tmp/nonexistent/random_thing");
        let fields = metadata(&path);
        assert!(fields.is_empty());
    }
}
