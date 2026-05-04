//! Lazy Binary Ninja Python sidecar manager.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

use serde_json::{json, Value};

pub struct BnSidecarManager {
    so_path: Option<String>,
    command: String,
    child: Option<ChildSession>,
    next_id: u64,
    last_error: Option<String>,
}

struct ChildSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl BnSidecarManager {
    pub fn from_env() -> Self {
        Self {
            so_path: std::env::var("TRACEMIKU_BN_SO").ok(),
            command: std::env::var("TRACEMIKU_BN_SIDECAR")
                .unwrap_or_else(|_| "tracemiku-bn-sidecar".to_string()),
            child: None,
            next_id: 1,
            last_error: None,
        }
    }

    pub fn status(&self) -> Value {
        json!({
            "ready": self.child.is_some(),
            "configured": self.so_path.is_some(),
            "so_path": self.so_path,
            "error": self.last_error,
        })
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        if let Err(err) = self.ensure_child() {
            self.last_error = Some(err.clone());
            return json!({"ok": false, "ready": false, "error": err});
        }
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"id": id, "method": method, "params": params});
        let Some(child) = self.child.as_mut() else {
            return json!({"ok": false, "ready": false, "error": "sidecar not running"});
        };
        if let Err(err) = writeln!(child.stdin, "{req}") {
            self.child = None;
            self.last_error = Some(err.to_string());
            return json!({"ok": false, "ready": false, "error": err.to_string()});
        }
        if let Err(err) = child.stdin.flush() {
            self.child = None;
            self.last_error = Some(err.to_string());
            return json!({"ok": false, "ready": false, "error": err.to_string()});
        }
        let mut line = String::new();
        match child.stdout.read_line(&mut line) {
            Ok(0) => {
                self.child = None;
                json!({"ok": false, "ready": false, "error": "sidecar closed stdout"})
            }
            Ok(_) => match serde_json::from_str::<Value>(&line) {
                Ok(v) => v.get("result").cloned().unwrap_or(v),
                Err(err) => json!({"ok": false, "ready": false, "error": err.to_string()}),
            },
            Err(err) => {
                self.child = None;
                json!({"ok": false, "ready": false, "error": err.to_string()})
            }
        }
    }

    fn ensure_child(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }
        let Some(so_path) = self.so_path.clone() else {
            return Err("TRACEMIKU_BN_SO is not set".to_string());
        };
        let mut child = Command::new(&self.command)
            .args(["--so", &so_path])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {} failed: {e}", self.command))?;
        let stdin = child.stdin.take().ok_or("sidecar stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("sidecar stdout unavailable")?;
        self.child = Some(ChildSession {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        });
        Ok(())
    }
}

impl Drop for ChildSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
