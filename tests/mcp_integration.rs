#![cfg(feature = "mcp")]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Maximum wait for a single server response. If the MCP server hangs (for
/// any reason — deadlock, protocol regression) the tests must fail quickly
/// rather than hang CI indefinitely (M4).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn a helper thread that reads stdout line-by-line and forwards each
/// line over an mpsc channel. Returns the receiver. Reads on the caller
/// side become bounded by `recv_timeout`, so a stuck server is detected
/// within `RESPONSE_TIMEOUT` instead of hanging the test forever.
fn spawn_line_reader<R: Read + Send + 'static>(reader: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

/// Read one JSON-RPC response line from the reader channel with a timeout.
fn recv_response(rx: &mpsc::Receiver<String>) -> serde_json::Value {
    let line = rx.recv_timeout(RESPONSE_TIMEOUT).unwrap_or_else(|_| {
        panic!(
            "MCP server did not respond within {:?} — likely hung",
            RESPONSE_TIMEOUT
        )
    });
    serde_json::from_str(&line)
        .unwrap_or_else(|e| panic!("MCP response was not valid JSON: {e}\nline: {line}"))
}

/// Send a JSON-RPC request (bare JSON line, no Content-Length framing).
fn send_jsonrpc(stdin: &mut impl Write, id: u64, method: &str, params: serde_json::Value) {
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let body = serde_json::to_string(&msg).unwrap();
    stdin.write_all(body.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

/// Send a JSON-RPC notification (no id, bare JSON line).
fn send_notification(stdin: &mut impl Write, method: &str) {
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
    });
    let body = serde_json::to_string(&msg).unwrap();
    stdin.write_all(body.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

/// Compat shim for tests that still use a `BufReader<Read>`. New call sites
/// should use `recv_response(&rx)` directly to take advantage of the timeout.
#[allow(dead_code)]
fn read_response(stdout: &mut BufReader<impl Read>) -> serde_json::Value {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// Path to the integration-test binary. Cargo sets `CARGO_BIN_EXE_<name>`
/// at compile time to the exact binary this test crate was built against,
/// which works under --release, cross-targets, and arbitrary cwd.
fn ccmd_binary() -> &'static str {
    env!("CARGO_BIN_EXE_ccmd")
}

#[test]
fn mcp_server_responds_to_initialize() {
    let binary = ccmd_binary();

    let mut child = Command::new(binary)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start mcp server");

    let mut stdin = child.stdin.take().unwrap();
    let rx = spawn_line_reader(child.stdout.take().unwrap());

    // 1. Initialize
    send_jsonrpc(
        &mut stdin,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "0.1" }
        }),
    );

    let response = recv_response(&rx);
    assert_eq!(response["id"], 1);
    let server_name = response["result"]["serverInfo"]["name"]
        .as_str()
        .expect("serverInfo.name should be a string");
    assert!(
        server_name.contains("Cache Commander"),
        "Server info name should contain 'Cache Commander', got: {server_name:?}"
    );

    // 2. Send initialized notification
    send_notification(&mut stdin, "notifications/initialized");

    // 3. List tools
    send_jsonrpc(&mut stdin, 2, "tools/list", serde_json::json!({}));

    let response = recv_response(&rx);
    assert_eq!(response["id"], 2);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");
    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    assert!(tool_names.contains(&"list_caches"), "Missing list_caches");
    assert!(tool_names.contains(&"get_summary"), "Missing get_summary");
    assert!(
        tool_names.contains(&"search_packages"),
        "Missing search_packages"
    );
    assert!(
        tool_names.contains(&"get_package_details"),
        "Missing get_package_details"
    );
    assert!(
        tool_names.contains(&"scan_vulnerabilities"),
        "Missing scan_vulnerabilities"
    );
    assert!(
        tool_names.contains(&"check_outdated"),
        "Missing check_outdated"
    );
    assert!(
        tool_names.contains(&"delete_packages"),
        "Missing delete_packages"
    );
    assert!(
        tool_names.contains(&"preview_delete"),
        "Missing preview_delete"
    );
    assert_eq!(
        tools.len(),
        8,
        "Expected exactly 8 tools, got {}",
        tools.len()
    );

    // 4. Clean shutdown
    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Tool-calling integration tests
// ---------------------------------------------------------------------------

use std::path::Path;
use tempfile::TempDir;

/// Build the fake cache structure used by all tool-calling tests.
///
/// The MCP walker recurses into known-provider dirs up to depth 4.
/// - `.cargo` is NOT a known provider name (Cargo detection relies on a
///   "registry" ancestor with `.cargo` in the path), so the walker treats it
///   as Unknown and does not recurse.  We therefore skip Cargo here.
/// - pip wheels need to be reachable within the depth budget, so we place
///   them at `pip/wheels/<file>` (depth 3 from root) rather than the real
///   `pip/wheels/xx/yy/<file>` layout.
fn setup_test_env() -> TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // HuggingFace  (depth: huggingface/hub/models--org--name = 3)
    let model = root.join("huggingface/hub/models--testorg--testmodel");
    std::fs::create_dir_all(model.join("snapshots/abc123")).unwrap();
    std::fs::create_dir_all(model.join("blobs")).unwrap();
    std::fs::write(model.join("blobs/sha256abc"), "fake model weights data").unwrap();
    std::fs::write(
        model.join("snapshots/abc123/config.json"),
        r#"{"model_type":"test"}"#,
    )
    .unwrap();

    // npm / npx  (depth: .npm/_npx/hash = 3)
    let npx = root.join(".npm/_npx/abc123");
    std::fs::create_dir_all(&npx).unwrap();
    std::fs::write(
        npx.join("package.json"),
        r#"{"_npx":{"packages":["test-pkg"]},"dependencies":{"test-pkg":"^1.0"}}"#,
    )
    .unwrap();

    // pip  (depth: pip/wheels/file.whl = 3)
    let pip_wheels = root.join("pip/wheels");
    std::fs::create_dir_all(&pip_wheels).unwrap();
    std::fs::write(
        pip_wheels.join("requests-2.31.0-py3-none-any.whl"),
        "fake wheel data for testing",
    )
    .unwrap();

    tmp
}

/// Start the MCP server with `--root`, complete the handshake, and return
/// (child, stdin, stdout line-receiver) ready for tool calls. The line
/// receiver is fed by a background thread so every read is bounded by
/// `RESPONSE_TIMEOUT` (M4).
fn start_server(
    root: &Path,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    mpsc::Receiver<String>,
) {
    let binary = ccmd_binary();
    let mut child = Command::new(binary)
        .arg("--root")
        .arg(root)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start mcp server");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let rx = spawn_line_reader(stdout);

    // Initialize
    send_jsonrpc(
        &mut stdin,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "0.1" }
        }),
    );
    let resp = recv_response(&rx);
    assert_eq!(resp["id"], 1);

    // Initialized notification
    send_notification(&mut stdin, "notifications/initialized");

    (child, stdin, rx)
}

/// Send a tools/call request and return the parsed JSON content from the
/// response's `result.content[0].text`.
fn call_tool(
    stdin: &mut impl Write,
    rx: &mpsc::Receiver<String>,
    id: u64,
    tool_name: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    send_jsonrpc(
        stdin,
        id,
        "tools/call",
        serde_json::json!({
            "name": tool_name,
            "arguments": args,
        }),
    );
    let resp = recv_response(rx);
    assert_eq!(resp["id"], id, "Response id mismatch: {resp}");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("No text in tool response: {resp}"));
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("Failed to parse tool response as JSON: {e}\nraw: {text}"))
}

// ---------------------------------------------------------------------------
// 1. list_caches
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_list_caches() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(&mut stdin, &rx, 10, "list_caches", serde_json::json!({}));

    let arr = result
        .as_array()
        .expect("list_caches should return an array");
    assert!(!arr.is_empty(), "Should discover at least one provider");

    let providers: Vec<&str> = arr
        .iter()
        .map(|r| r["provider"].as_str().unwrap())
        .collect();
    // We expect at least HuggingFace, npm/npx, pip
    assert!(
        providers
            .iter()
            .any(|p| p.to_lowercase().contains("hugging")),
        "Missing HuggingFace provider in {providers:?}"
    );
    assert!(
        providers.iter().any(|p| p.to_lowercase().contains("npm")),
        "Missing npm provider in {providers:?}"
    );
    assert!(
        providers.iter().any(|p| p.to_lowercase().contains("pip")),
        "Missing pip provider in {providers:?}"
    );

    // Check fields exist
    for entry in arr {
        assert!(entry.get("provider").is_some());
        assert!(entry.get("item_count").is_some());
        assert!(entry.get("total_size_bytes").is_some());
    }

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 2. get_summary
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_get_summary() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(&mut stdin, &rx, 10, "get_summary", serde_json::json!({}));

    assert!(
        result["total_size_bytes"].as_u64().unwrap_or(0) > 0,
        "total_size_bytes should be > 0"
    );
    assert!(
        result["total_items"].as_u64().unwrap_or(0) > 0,
        "total_items should be > 0"
    );

    let sc = &result["safety_counts"];
    assert!(sc.get("safe").is_some(), "Missing safety_counts.safe");
    assert!(sc.get("caution").is_some(), "Missing safety_counts.caution");
    assert!(sc.get("unsafe").is_some(), "Missing safety_counts.unsafe");

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 3. search_packages (no filter)
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_search_packages_no_filter() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "search_packages",
        serde_json::json!({}),
    );

    let total = result["total_results"].as_u64().unwrap_or(0);
    // We created at least 3 items (HF model, npx pkg, pip wheel)
    assert!(
        total >= 3,
        "Expected at least 3 results, got {total}. Full response: {result}"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 4. search_packages (ecosystem filter)
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_search_packages_ecosystem_filter() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "search_packages",
        serde_json::json!({"ecosystem": "huggingface"}),
    );

    let packages = result["packages"].as_array().expect("packages array");
    assert!(
        !packages.is_empty(),
        "Should find at least one HuggingFace package"
    );
    for pkg in packages {
        let eco = pkg["ecosystem"].as_str().unwrap_or("");
        assert!(
            eco.to_lowercase().contains("hugging"),
            "Non-HuggingFace package in filtered results: {eco}"
        );
    }

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 5. search_packages (query filter)
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_search_packages_query_filter() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "search_packages",
        serde_json::json!({"query": "requests"}),
    );

    let packages = result["packages"].as_array().expect("packages array");
    assert!(!packages.is_empty(), "Should find the requests pip wheel");
    assert!(
        packages.iter().any(|p| p["name"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("requests")),
        "No package named requests in results: {result}"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 6. get_package_details by path
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_get_package_details_by_path() {
    let tmp = setup_test_env();
    let model_path = tmp
        .path()
        .join("huggingface/hub/models--testorg--testmodel");
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "get_package_details",
        serde_json::json!({"path": model_path.to_string_lossy()}),
    );

    assert!(
        result.get("provider").is_some(),
        "Missing provider field: {result}"
    );
    assert!(result.get("name").is_some(), "Missing name field: {result}");
    assert!(
        result.get("safety_level").is_some(),
        "Missing safety_level field: {result}"
    );
    assert!(
        result["size_bytes"].as_u64().unwrap_or(0) > 0,
        "size_bytes should be > 0"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 7. get_package_details by name
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_get_package_details_by_name() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "get_package_details",
        serde_json::json!({"name": "testmodel", "ecosystem": "huggingface"}),
    );

    assert!(
        result.get("provider").is_some(),
        "Missing provider field: {result}"
    );
    let name = result["name"].as_str().unwrap_or("");
    assert!(
        name.to_lowercase().contains("testmodel"),
        "Expected name to contain 'testmodel', got: {name}"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 8. preview_delete
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_preview_delete() {
    let tmp = setup_test_env();
    let wheel_path = tmp
        .path()
        .join("pip/wheels/requests-2.31.0-py3-none-any.whl");
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "preview_delete",
        serde_json::json!({"paths": [wheel_path.to_string_lossy()]}),
    );

    assert!(
        result.get("deletable_count").is_some(),
        "Missing deletable_count: {result}"
    );
    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1, "Should have exactly 1 preview item");
    assert!(
        items[0].get("would_delete").is_some(),
        "Missing would_delete field"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 9. delete_packages
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_delete_packages() {
    let tmp = setup_test_env();
    let wheel_path = tmp
        .path()
        .join("pip/wheels/requests-2.31.0-py3-none-any.whl");
    assert!(wheel_path.exists(), "Wheel file should exist before delete");

    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "delete_packages",
        serde_json::json!({"paths": [wheel_path.to_string_lossy()]}),
    );

    assert_eq!(
        result["deleted_count"].as_u64().unwrap_or(0),
        1,
        "Should delete exactly 1 item: {result}"
    );
    assert!(
        !wheel_path.exists(),
        "Wheel file should be gone after deletion"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 10. delete_packages — path outside root rejected
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_delete_packages_outside_root_rejected() {
    let tmp = setup_test_env();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("rogue.txt");
    std::fs::write(&outside_file, "should not be deleted").unwrap();

    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "delete_packages",
        serde_json::json!({"paths": [outside_file.to_string_lossy()]}),
    );

    assert_eq!(
        result["deleted_count"].as_u64().unwrap_or(99),
        0,
        "Should not delete anything outside root: {result}"
    );
    assert_eq!(
        result["skipped_count"].as_u64().unwrap_or(0),
        1,
        "Should skip the outside path: {result}"
    );
    let skipped = result["skipped"].as_array().expect("skipped array");
    assert!(
        skipped[0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("not inside"),
        "Reason should mention path not inside root: {result}"
    );
    assert!(
        outside_file.exists(),
        "File outside root should still exist"
    );

    drop(stdin);
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// 11. empty search returns JSON (not plain string)
// ---------------------------------------------------------------------------

#[test]
fn mcp_test_empty_search_returns_json() {
    let tmp = setup_test_env();
    let (mut child, mut stdin, rx) = start_server(tmp.path());

    let result = call_tool(
        &mut stdin,
        &rx,
        10,
        "search_packages",
        serde_json::json!({"query": "nonexistent_xyz_zzz_nothing"}),
    );

    assert_eq!(
        result["total_results"].as_u64().unwrap_or(99),
        0,
        "Should return 0 results for nonexistent query: {result}"
    );
    assert!(
        result["packages"].as_array().is_some(),
        "packages should be a JSON array even when empty: {result}"
    );

    drop(stdin);
    let _ = child.wait();
}
