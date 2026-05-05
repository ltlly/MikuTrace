use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use regex::Regex;
use tower::ServiceExt;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn normalize_api_path(path: &str) -> String {
    let without_qs_template = Regex::new(r#"\$\{\s*qs\s*\?[^}]+\}"#)
        .unwrap()
        .replace_all(path, "");
    let dynamic = Regex::new(r#"\$\{[^}]+\}"#)
        .unwrap()
        .replace_all(&without_qs_template, "{}");
    dynamic.split('?').next().unwrap_or("").to_string()
}

fn normalize_route_path(path: &str) -> String {
    let dynamic_segment = Regex::new(r#":[A-Za-z_][A-Za-z0-9_]*"#).unwrap();
    dynamic_segment
        .replace_all(path, "{}")
        .replace("*path", "{}")
        .to_string()
}

fn normalize_openapi_path(path: &str) -> String {
    let dynamic_segment = Regex::new(r#"\{[^}/]+\}"#).unwrap();
    dynamic_segment.replace_all(path, "{}").to_string()
}

fn frontend_api_paths() -> Vec<String> {
    let client = fs::read_to_string(repo_root().join("frontend/src/api/client.ts")).unwrap();
    let mut paths = Vec::new();
    for pattern in [
        r#"fx\(\s*`([^`]*)`"#,
        r#"fx\(\s*"([^"]*)""#,
        r#"fx\(\s*'([^']*)'"#,
    ] {
        let fx_call = Regex::new(pattern).unwrap();
        paths.extend(fx_call.captures_iter(&client).filter_map(|cap| {
            let raw = cap.get(1)?.as_str();
            (raw.starts_with("/api/") || raw == "/openapi.json").then(|| normalize_api_path(raw))
        }));
    }
    paths.sort();
    paths.dedup();
    paths
}

fn rust_router_paths() -> Vec<String> {
    let mut paths = rust_router_methods()
        .into_iter()
        .map(|(path, _method)| path)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn rust_router_methods() -> BTreeSet<(String, String)> {
    let routes =
        fs::read_to_string(repo_root().join("rust/crates/tracemiku-server/src/routes/mod.rs"))
            .unwrap();
    let route_call = Regex::new(r#"\.route\(\s*"([^"]*)"\s*,\s*(get|post|any)\("#).unwrap();
    route_call
        .captures_iter(&routes)
        .filter_map(|cap| {
            let raw = cap.get(1)?.as_str();
            if !(raw.starts_with("/api/") || raw == "/openapi.json" || raw == "/ws/jobs") {
                return None;
            }
            let method = cap.get(2)?.as_str();
            if method == "any" {
                return None;
            }
            Some((normalize_route_path(raw), method.to_string()))
        })
        .collect()
}

const HEAVY_ROUTE_FILES: &[&str] = &[
    "auto_phase.rs",
    "backward_taint.rs",
    "bn_hlil.rs",
    "call_tree.rs",
    "cfg.rs",
    "cfg_svg.rs",
    "crypto_scan.rs",
    "data_chase.rs",
    "dec_fn.rs",
    "dec_llm_call.rs",
    "dec_summary.rs",
    "diff_traces.rs",
    "fn_summary.rs",
    "forward_taint.rs",
    "functions.rs",
    "hash_finalize.rs",
    "hash_input_search.rs",
    "jni_calls.rs",
    "jni_events.rs",
    "jni_strings.rs",
    "jobj_history.rs",
    "llil_llm.rs",
    "llil_render.rs",
    "mem_dump.rs",
    "mem_flow.rs",
    "memory_query.rs",
    "navigation.rs",
    "ollvm_detect_vm.rs",
    "records.rs",
    "search.rs",
    "so_stats.rs",
    "string_provenance.rs",
    "strings.rs",
    "timeline_diff.rs",
];

const LIGHT_ROUTE_FILES: &[&str] = &[
    "api_infra.rs",
    "asm_tokens.rs",
    "dec_models.rs",
    "dec_options.rs",
    "field_at.rs",
    "fork_events.rs",
    "idxs_for_block.rs",
    "idxs_for_pc.rs",
    "last_write_of_reg.rs",
    "meta.rs",
    "record.rs",
    "reg_value_at.rs",
    "search_pc.rs",
];

const HEAVY_ROUTE_HANDLERS: &[(&str, &str)] = &[
    ("navigation.rs", "block_handler"),
    ("navigation.rs", "loops_handler"),
    ("navigation.rs", "call_chain_handler"),
    ("records.rs", "records_handler"),
];

// Endpoint surface from main:webui/server.py. Keep this list normalized with
// dynamic segments as `{}` so the Rust router can use Axum's `:param` style.
const PYTHON_WEB_API_METHODS: &[(&str, &str)] = &[
    ("/api/asm-tokens-for-pcs", "get"),
    ("/api/auto-phase-detect", "get"),
    ("/api/backtrace", "get"),
    ("/api/backward-taint", "get"),
    ("/api/bg-status", "get"),
    ("/api/block", "get"),
    ("/api/block-for-pc", "get"),
    ("/api/bn-cfg-for-pc", "get"),
    ("/api/bn-cfg-svg-for-pc", "get"),
    ("/api/call-chain", "get"),
    ("/api/call-tree", "get"),
    ("/api/cfg", "get"),
    ("/api/cfg-svg", "get"),
    ("/api/crypto-scan", "get"),
    ("/api/data-chase", "get"),
    ("/api/dec/fn/{}", "get"),
    ("/api/dec/llm-call", "post"),
    ("/api/dec/models", "get"),
    ("/api/dec/summary", "get"),
    ("/api/decomp-status", "get"),
    ("/api/diff-traces", "post"),
    ("/api/field-at", "get"),
    ("/api/find-mem-pattern", "get"),
    ("/api/fn-summary", "get"),
    ("/api/fork-events", "get"),
    ("/api/forward-taint", "get"),
    ("/api/hash-finalize-detect", "get"),
    ("/api/hash-input-search", "post"),
    ("/api/hlil-for-pc", "get"),
    ("/api/idxs-for-block", "get"),
    ("/api/idxs-for-pc", "get"),
    ("/api/idxs-touching-addr", "get"),
    ("/api/idxs-touching-range", "get"),
    ("/api/jni-calls", "get"),
    ("/api/jni-events", "get"),
    ("/api/jni-strings", "get"),
    ("/api/jobj-history", "get"),
    ("/api/last-write-of-addr", "get"),
    ("/api/last-write-of-reg", "get"),
    ("/api/llil/llm", "post"),
    ("/api/llil/render", "post"),
    ("/api/loops", "get"),
    ("/api/mem-diff", "get"),
    ("/api/mem-dump", "get"),
    ("/api/mem-flow", "get"),
    ("/api/mem-writes-in-range", "get"),
    ("/api/meta", "get"),
    ("/api/ollvm-detect-vm", "get"),
    ("/api/record/{}", "get"),
    ("/api/records", "get"),
    ("/api/reg-at-idx", "get"),
    ("/api/reg-timeline", "get"),
    ("/api/reg-value-at", "get"),
    ("/api/search", "get"),
    ("/api/so-stats", "get"),
    ("/api/string-provenance", "get"),
    ("/api/strings", "get"),
];

fn route_rs_files() -> Vec<String> {
    let routes_dir = repo_root().join("rust/crates/tracemiku-server/src/routes");
    let mut files = fs::read_dir(routes_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_string();
            (name.ends_with(".rs") && name != "mod.rs").then_some(name)
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn route_files_are_classified_for_runtime_blocking() {
    let mut classified = HEAVY_ROUTE_FILES
        .iter()
        .chain(LIGHT_ROUTE_FILES.iter())
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    classified.sort();
    classified.dedup();

    let files = route_rs_files();
    let missing = files
        .iter()
        .filter(|file| !classified.contains(file))
        .cloned()
        .collect::<Vec<_>>();
    let stale = classified
        .iter()
        .filter(|file| !files.contains(file))
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty() && stale.is_empty(),
        "route files must be explicitly classified as heavy or light; missing={missing:?} stale={stale:?}"
    );
}

#[test]
fn heavy_route_handlers_stay_off_async_runtime() {
    let routes_dir = repo_root().join("rust/crates/tracemiku-server/src/routes");
    let missing = HEAVY_ROUTE_FILES
        .iter()
        .filter(|file| {
            let src = fs::read_to_string(routes_dir.join(file)).unwrap();
            !src.contains("tokio::task::spawn_blocking")
        })
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "heavy route handlers must move CPU-bound work off the async runtime: {missing:?}"
    );
}

#[test]
fn known_heavy_handlers_stay_off_async_runtime() {
    let routes_dir = repo_root().join("rust/crates/tracemiku-server/src/routes");
    let mut missing = Vec::new();
    for (file, handler) in HEAVY_ROUTE_HANDLERS {
        let src = fs::read_to_string(routes_dir.join(file)).unwrap();
        let needle = format!("pub async fn {handler}");
        let Some(start) = src.find(&needle) else {
            missing.push(format!("{file}::{handler} missing handler"));
            continue;
        };
        let body_prefix = &src[start..src.len().min(start + 1200)];
        if !body_prefix.contains("tokio::task::spawn_blocking") {
            missing.push(format!("{file}::{handler}"));
        }
    }
    assert!(
        missing.is_empty(),
        "known CPU-heavy async handlers must use spawn_blocking: {missing:?}"
    );
}

#[test]
fn server_runtime_does_not_probe_deleted_python_dirs() {
    let server_src = repo_root().join("rust/crates/tracemiku-server/src");
    let mut files = Vec::new();
    collect_rs_files(&server_src, &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let src = fs::read_to_string(&path).unwrap();
        for forbidden in [r#"join("viewer")"#, r#"join("webui")"#] {
            if src.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "Rust server runtime must not probe deleted Python viewer/webui directories: {offenders:?}"
    );
}

#[test]
fn frontend_api_calls_are_registered_in_rust_router() {
    let router_paths = rust_router_paths();
    let missing = frontend_api_paths()
        .into_iter()
        .filter(|path| !router_paths.contains(path))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "frontend API paths missing from Rust router: {missing:?}"
    );
}

#[test]
fn rust_router_preserves_python_web_api_surface() {
    let router_methods = rust_router_methods();
    let missing = PYTHON_WEB_API_METHODS
        .iter()
        .map(|(path, method)| ((*path).to_string(), (*method).to_string()))
        .filter(|method| !router_methods.contains(method))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "Rust router is missing Python web API compatibility routes: {missing:?}"
    );
}

#[tokio::test]
async fn openapi_json_lists_current_paths() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["openapi"], "3.0.3");
    assert!(v["paths"]["/api/bg-status"]["get"].is_object());
    assert!(v["paths"]["/api/decomp-status"]["get"].is_object());
    assert!(v["paths"]["/api/mem-writes-in-range"]["get"].is_object());
    assert!(v["paths"]["/api/hash-input-search"]["post"].is_object());
    assert!(v["paths"]["/ws/jobs"]["get"].is_object());

    let openapi_methods = v["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, methods)| {
            methods
                .as_object()
                .unwrap()
                .keys()
                .map(move |method| (normalize_openapi_path(path), method.to_string()))
        })
        .collect::<BTreeSet<_>>();
    let router_methods = rust_router_methods();

    let missing = router_methods
        .difference(&openapi_methods)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "Rust router paths missing from OpenAPI: {missing:?}"
    );

    let stale = openapi_methods
        .difference(&router_methods)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        stale.is_empty(),
        "OpenAPI paths missing from Rust router: {stale:?}"
    );
}

#[tokio::test]
async fn python_web_compat_status_endpoints_are_available() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");

    for uri in ["/api/bg-status", "/api/decomp-status"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if uri == "/api/bg-status" {
            assert_eq!(v["cfg"]["status"], "ready");
            assert_eq!(v["index"]["status"], "ready");
            assert_eq!(v["mem"]["status"], "ready");
            assert!(v["decomp"]["status"].is_string());
            assert!(v["parallelism"]["available"].is_number());
            assert!(v["parallelism"]["workers"]["index"].is_number());
            assert!(v["parallelism"]["workers"]["jni_calls"].is_number());
        } else {
            assert!(v["status"].is_string());
            assert!(v.get("so_path").is_some());
        }
    }
}

#[tokio::test]
async fn missing_api_route_returns_json_404() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/definitely-missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"], "unknown api endpoint");
    assert_eq!(v["path"], "/api/definitely-missing");
}

#[tokio::test]
async fn ws_jobs_requires_websocket_upgrade() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ws/jobs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
