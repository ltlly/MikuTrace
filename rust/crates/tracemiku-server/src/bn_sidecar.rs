//! Lazy Binary Ninja Python sidecar manager.
//!
//! 协议约定：sidecar 对每条 `{"id": n, "method": .., "params": ..}` 请求回一条
//! `{"id": n, "result": ..}`。读取端必须校验 id：sidecar 向 stdout 打印的杂散行
//! （横幅、日志、崩溃前的半行输出）只允许被丢弃，不允许顶替本请求的结果。

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// 单次请求的默认超时（秒）；`TRACEMIKU_BN_SIDECAR_TIMEOUT_SECS` 可覆盖。
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 60;
/// 单次请求内容忍的连续杂散行/解析失败行数；超过视为协议错位，重建会话。
const MAX_CONSECUTIVE_STRAY_LINES: usize = 4;

pub struct BnSidecarManager {
    so_path: Option<String>,
    command: Vec<String>,
    runtime_base: Option<u64>,
    /// 单次请求超时，构造时从 `TRACEMIKU_BN_SIDECAR_TIMEOUT_SECS` 快照，
    /// 避免每次请求读进程级环境变量（并发请求会互相看到临时改动）。
    timeout: Duration,
    child: Option<ChildSession>,
    next_id: u64,
    status: Arc<BnStatusShared>,
}

/// 无锁 status 快照句柄，与 manager 共享内部状态。
///
/// manager 本体在 `AppStateInner` 中被 Mutex 包裹，且 `request()` 持锁横跨
/// 整个往返（最长为请求超时）；status 查询（async handler）必须绕开该锁，
/// 否则一次挂起的 sidecar 请求会拖住所有 status 路由。
#[derive(Clone)]
pub struct BnStatusHandle {
    shared: Arc<BnStatusShared>,
}

struct BnStatusShared {
    so_path: Option<String>,
    runtime_base: Option<u64>,
    ready: AtomicBool,
    error: Mutex<Option<String>>,
}

impl BnStatusHandle {
    pub fn value(&self) -> Value {
        let error = self
            .shared
            .error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        json!({
            "ready": self.shared.ready.load(Ordering::Acquire),
            "configured": self.shared.so_path.is_some(),
            "so_path": self.shared.so_path.clone(),
            "runtime_base": self.shared.runtime_base.map(|b| format!("{b:#x}")),
            "error": error,
        })
    }
}

struct ChildSession {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<ReaderEvent>,
}

enum ReaderEvent {
    Response(Value),
    ParseError(String),
}

impl BnSidecarManager {
    pub fn from_env() -> Self {
        Self::from_env_with_base(parse_u64_env("TRACEMIKU_BN_BASE"))
    }

    pub fn from_env_with_default_base(default_base: Option<u64>) -> Self {
        Self::from_env_with_base(parse_u64_env("TRACEMIKU_BN_BASE").or(default_base))
    }

    pub fn from_env_with_base(runtime_base: Option<u64>) -> Self {
        let status = Arc::new(BnStatusShared {
            so_path: std::env::var("TRACEMIKU_BN_SO").ok(),
            runtime_base,
            ready: AtomicBool::new(false),
            error: Mutex::new(None),
        });
        Self {
            so_path: status.so_path.clone(),
            command: command_words(
                &std::env::var("TRACEMIKU_BN_SIDECAR")
                    .unwrap_or_else(|_| "tracemiku-bn-sidecar".to_string()),
            ),
            runtime_base,
            timeout: request_timeout_from_env(),
            child: None,
            next_id: 1,
            status,
        }
    }

    pub fn status_handle(&self) -> BnStatusHandle {
        BnStatusHandle {
            shared: Arc::clone(&self.status),
        }
    }

    pub fn status(&self) -> Value {
        self.status_handle().value()
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        if let Err(err) = self.ensure_child() {
            self.publish(false, Some(err.clone()));
            return json!({"ok": false, "ready": false, "error": err});
        }
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"id": id, "method": method, "params": params});
        let Some(mut child) = self.child.take() else {
            let err = "sidecar not running".to_string();
            self.publish(false, Some(err.clone()));
            return json!({"ok": false, "ready": false, "error": err});
        };
        if let Err(err) = writeln!(child.stdin, "{req}") {
            let err = err.to_string();
            drop(child);
            self.publish(false, Some(err.clone()));
            return json!({"ok": false, "ready": false, "error": err});
        }
        if let Err(err) = child.stdin.flush() {
            let err = err.to_string();
            drop(child);
            self.publish(false, Some(err.clone()));
            return json!({"ok": false, "ready": false, "error": err});
        }

        let timeout = self.timeout;
        let mut stray = 0usize;
        loop {
            let event = match child.rx.recv_timeout(timeout) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let err = format!(
                        "sidecar request timeout after {}s (method {method})",
                        timeout.as_secs()
                    );
                    drop(child);
                    self.publish(false, Some(err.clone()));
                    return json!({"ok": false, "ready": false, "error": err});
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let err = "sidecar closed stdout".to_string();
                    drop(child);
                    self.publish(false, Some(err.clone()));
                    return json!({"ok": false, "ready": false, "error": err});
                }
            };
            match event {
                ReaderEvent::Response(v) => {
                    let resp_id = v.get("id").and_then(|i| i.as_u64());
                    if resp_id == Some(id) {
                        self.child = Some(child);
                        self.publish(true, None);
                        return v.get("result").cloned().unwrap_or(v);
                    }
                    stray += 1;
                    tracing::warn!(
                        target: "tracemiku-server",
                        method = method,
                        expected_id = id,
                        "dropping unmatched sidecar response: {v}"
                    );
                }
                ReaderEvent::ParseError(line) => {
                    stray += 1;
                    tracing::warn!(
                        target: "tracemiku-server",
                        method = method,
                        "sidecar emitted non-JSON line: {line}"
                    );
                }
            }
            if stray >= MAX_CONSECUTIVE_STRAY_LINES {
                let err = format!(
                    "sidecar protocol desync: {stray} consecutive stray lines (method {method})"
                );
                drop(child);
                self.publish(false, Some(err.clone()));
                return json!({"ok": false, "ready": false, "error": err});
            }
        }
    }

    fn publish(&self, ready: bool, error: Option<String>) {
        self.status.ready.store(ready, Ordering::Release);
        *self
            .status
            .error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = error;
    }

    fn ensure_child(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }
        let Some(so_path) = self.so_path.clone() else {
            return Err("TRACEMIKU_BN_SO is not set".to_string());
        };
        let command = self
            .command
            .first()
            .cloned()
            .unwrap_or_else(|| "tracemiku-bn-sidecar".to_string());
        let mut args = self.command.iter().skip(1).cloned().collect::<Vec<_>>();
        args.push("--so".to_string());
        args.push(so_path);
        if let Some(base) = self.runtime_base {
            args.push("--base".to_string());
            args.push(format!("{base:#x}"));
        }
        let mut child = Command::new(&command)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {} failed: {e}", self.command.join(" ")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "sidecar stdin unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "sidecar stdout unavailable".to_string())?;
        let (tx, rx) = mpsc::channel::<ReaderEvent>();
        let reader = BufReader::new(stdout);
        if let Err(err) = std::thread::Builder::new()
            .name("tracemiku-bn-reader".to_string())
            .spawn(move || reader_loop(reader, tx))
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("spawn sidecar reader thread failed: {err}"));
        }
        self.child = Some(ChildSession { child, stdin, rx });
        self.publish(true, None);
        Ok(())
    }
}

/// 专职 reader 线程：把 stdout 按行解析后送入 channel，EOF/错误时退出。
/// 线程随 stdout 关闭（子进程被 kill 或退出）自然终止。
fn reader_loop<R: BufRead>(mut reader: R, tx: mpsc::Sender<ReaderEvent>) {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let event = match serde_json::from_str::<Value>(trimmed) {
                    Ok(v) => ReaderEvent::Response(v),
                    Err(_) => ReaderEvent::ParseError(trimmed.to_string()),
                };
                if tx.send(event).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn request_timeout_from_env() -> Duration {
    let secs = std::env::var("TRACEMIKU_BN_SIDECAR_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

fn command_words(raw: &str) -> Vec<String> {
    let words = raw
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if words.is_empty() {
        vec!["tracemiku-bn-sidecar".to_string()]
    } else {
        words
    }
}

fn parse_u64_env(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

impl Drop for ChildSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::{BnSidecarManager, DEFAULT_REQUEST_TIMEOUT_SECS};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_runtime_base_overrides_default_base() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("TRACEMIKU_BN_BASE", "0x12340000");
        let mgr = BnSidecarManager::from_env_with_default_base(Some(0x7777));
        let status = mgr.status();
        assert_eq!(
            status.get("runtime_base").and_then(|v| v.as_str()),
            Some("0x12340000")
        );
        std::env::remove_var("TRACEMIKU_BN_BASE");
    }

    #[test]
    fn default_base_used_when_env_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRACEMIKU_BN_BASE");
        let mgr = BnSidecarManager::from_env_with_default_base(Some(0x7777));
        let status = mgr.status();
        assert_eq!(
            status.get("runtime_base").and_then(|v| v.as_str()),
            Some("0x7777")
        );
    }

    #[test]
    fn status_handle_reflects_manager_updates_without_manager() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TRACEMIKU_BN_SO");
        let mut mgr = BnSidecarManager::from_env_with_base(None);
        let handle = mgr.status_handle();
        let err = mgr.request("functions", serde_json::json!({}));
        assert_eq!(err.get("ready").and_then(|v| v.as_bool()), Some(false));
        let status = handle.value();
        assert_eq!(status.get("ready").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            status.get("error").and_then(|v| v.as_str()),
            Some("TRACEMIKU_BN_SO is not set")
        );
    }

    #[test]
    fn request_defaults_are_sane() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT_SECS, 60);
    }
}
