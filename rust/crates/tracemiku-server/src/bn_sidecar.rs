//! Lazy Binary Ninja Python sidecar manager.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

use serde_json::{json, Value};

pub struct BnSidecarManager {
    so_path: Option<String>,
    command: Vec<String>,
    runtime_base: Option<u64>,
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
        Self::from_env_with_base(parse_u64_env("TRACEMIKU_BN_BASE"))
    }

    pub fn from_env_with_default_base(default_base: Option<u64>) -> Self {
        Self::from_env_with_base(parse_u64_env("TRACEMIKU_BN_BASE").or(default_base))
    }

    pub fn from_env_with_base(runtime_base: Option<u64>) -> Self {
        Self {
            so_path: std::env::var("TRACEMIKU_BN_SO").ok(),
            command: command_words(
                &std::env::var("TRACEMIKU_BN_SIDECAR")
                    .unwrap_or_else(|_| "tracemiku-bn-sidecar".to_string()),
            ),
            runtime_base,
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
            "runtime_base": self.runtime_base.map(|b| format!("{b:#x}")),
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
    use super::BnSidecarManager;
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
}
