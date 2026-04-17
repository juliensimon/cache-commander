//! HTTP-mocked integration tests for OSV and registry clients (M2).
//!
//! These tests spin up a tiny local TCP server, accept one or more HTTP
//! requests, and return a scripted response. This covers the wire-format
//! plumbing (URL, User-Agent, status-code handling, malformed payloads)
//! without requiring `httpmock`/`mockito` as dev-deps.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ccmd::providers::PackageId;
use ccmd::security::{osv, registry};

/// Spawn a one-shot HTTP/1.1 server on localhost. Returns (base_url,
/// request-receiver) so the test can inspect the captured request line
/// after the call completes.
///
/// `response` is written verbatim once the request headers are consumed.
fn spawn_mock(response: Vec<u8>) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().unwrap().port();
    let (req_tx, req_rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let (mut socket, _) = match listener.accept() {
            Ok(p) => p,
            Err(_) => return,
        };
        socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
        // Read request headers + body (up to content-length), so the
        // response is written only after the request is fully consumed.
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut request_dump = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line.is_empty() {
                break;
            }
            if let Some(stripped) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = stripped.trim().parse::<usize>().unwrap_or(0);
            }
            request_dump.push_str(&line);
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            if reader.read_exact(&mut body).is_ok() {
                request_dump.push_str(&String::from_utf8_lossy(&body));
            }
        }
        let _ = req_tx.send(request_dump);
        let _ = socket.write_all(&response);
        let _ = socket.flush();
    });
    (format!("http://127.0.0.1:{port}/"), req_rx)
}

fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn status_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// --- OSV batch -------------------------------------------------------------

#[test]
fn query_osv_at_happy_path_parses_response() {
    let (url, req_rx) = spawn_mock(ok_response(
        r#"{"results":[{"vulns":[{"id":"CVE-1","summary":"bad"}]}]}"#,
    ));
    let pkgs = vec![PackageId {
        ecosystem: "PyPI",
        name: "requests".into(),
        version: "2.31.0".into(),
    }];
    let resp = osv::query_osv_at(&url, &pkgs).expect("query_osv_at should succeed");
    assert_eq!(resp.results.len(), 1);
    assert_eq!(resp.results[0].vulns.len(), 1);
    assert_eq!(resp.results[0].vulns[0].id, "CVE-1");

    let req = req_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(req.starts_with("POST"), "should be POST, got: {req}");
    assert!(
        req.to_ascii_lowercase().contains("user-agent: ccmd/"),
        "UA missing"
    );
    assert!(
        req.to_ascii_lowercase()
            .contains("content-type: application/json"),
        "Content-Type missing"
    );
    assert!(
        req.contains("\"name\":\"requests\""),
        "body missing pkg name"
    );
}

#[test]
fn query_osv_at_404_returns_err() {
    let (url, _rx) = spawn_mock(status_response("404 Not Found", "not found"));
    let pkgs = vec![PackageId {
        ecosystem: "PyPI",
        name: "requests".into(),
        version: "2.31.0".into(),
    }];
    let res = osv::query_osv_at(&url, &pkgs);
    assert!(res.is_err(), "404 must be an error");
}

#[test]
fn query_osv_at_500_returns_err() {
    let (url, _rx) = spawn_mock(status_response("500 Internal Server Error", "boom"));
    let pkgs = vec![PackageId {
        ecosystem: "PyPI",
        name: "x".into(),
        version: "0.0.0".into(),
    }];
    assert!(osv::query_osv_at(&url, &pkgs).is_err());
}

#[test]
fn query_osv_at_429_returns_err() {
    let (url, _rx) = spawn_mock(status_response("429 Too Many Requests", "slow down"));
    let pkgs = vec![PackageId {
        ecosystem: "PyPI",
        name: "x".into(),
        version: "0.0.0".into(),
    }];
    assert!(osv::query_osv_at(&url, &pkgs).is_err());
}

#[test]
fn query_osv_at_malformed_json_returns_err() {
    let (url, _rx) = spawn_mock(ok_response("not { valid json"));
    let pkgs = vec![PackageId {
        ecosystem: "PyPI",
        name: "x".into(),
        version: "0.0.0".into(),
    }];
    let res = osv::query_osv_at(&url, &pkgs);
    assert!(res.is_err(), "malformed JSON must be an error");
    let msg = res.unwrap_err();
    assert!(msg.contains("parse"), "error must indicate parse: {msg}");
}

// --- OSV vuln detail -------------------------------------------------------

#[test]
fn fetch_vuln_detail_at_happy_path() {
    let (url, _rx) = spawn_mock(ok_response(
        r#"{"id":"CVE-1","summary":"bad","affected":[]}"#,
    ));
    let detail = osv::fetch_vuln_detail_at(&url).expect("fetch_vuln_detail_at should succeed");
    assert_eq!(detail.id, "CVE-1");
}

#[test]
fn fetch_vuln_detail_at_404_returns_err() {
    let (url, _rx) = spawn_mock(status_response("404 Not Found", ""));
    assert!(osv::fetch_vuln_detail_at(&url).is_err());
}

// --- Registry --------------------------------------------------------------

#[test]
fn check_latest_at_pypi_parses_version() {
    let (url, _rx) = spawn_mock(ok_response(r#"{"info":{"version":"2.32.3"}}"#));
    let v = registry::check_latest_at(&url, "PyPI")
        .expect("request ok")
        .expect("some version");
    assert_eq!(v, "2.32.3");
}

#[test]
fn check_latest_at_crates_parses_max_version() {
    let (url, _rx) = spawn_mock(ok_response(r#"{"crate":{"max_version":"1.0.200"}}"#));
    let v = registry::check_latest_at(&url, "crates.io")
        .expect("request ok")
        .expect("some version");
    assert_eq!(v, "1.0.200");
}

#[test]
fn check_latest_at_npm_parses_version() {
    let (url, _rx) = spawn_mock(ok_response(r#"{"version":"18.2.0"}"#));
    let v = registry::check_latest_at(&url, "npm")
        .expect("request ok")
        .expect("some version");
    assert_eq!(v, "18.2.0");
}

#[test]
fn check_latest_at_non_200_is_err() {
    let (url, _rx) = spawn_mock(status_response("503 Service Unavailable", "oops"));
    assert!(registry::check_latest_at(&url, "npm").is_err());
}

#[test]
fn check_latest_at_malformed_json_returns_ok_none() {
    // Malformed JSON → parse fails silently → Ok(None). This is intentional:
    // a single broken registry response shouldn't error the whole scan.
    let (url, _rx) = spawn_mock(ok_response("not { json"));
    let res = registry::check_latest_at(&url, "npm").expect("request ok");
    assert_eq!(res, None);
}
