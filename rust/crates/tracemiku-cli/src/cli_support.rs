use super::*;

pub(super) fn cmd_mem_export_write(value: &serde_json::Value, out: &Path) -> anyhow::Result<()> {
    let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status != "ready" {
        // Pass the route's miss/ambiguous/error JSON straight through.
        return print_pretty(value);
    }
    let hex = value
        .get("hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("mem-export response missing hex field"))?;
    if !hex.len().is_multiple_of(2) {
        bail!("mem-export hex length is odd ({} chars)", hex.len());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16)
            .with_context(|| format!("bad hex byte at {i}"))?;
        bytes.push(b);
    }
    std::fs::write(out, &bytes).with_context(|| format!("failed to write {}", out.display()))?;
    let mut summary = value.as_object().cloned().unwrap_or_default();
    summary.remove("hex"); // raw bytes are now on disk; don't echo the blob
    summary.insert(
        "out_file".to_string(),
        serde_json::Value::String(out.display().to_string()),
    );
    summary.insert(
        "bytes_written".to_string(),
        serde_json::Value::from(bytes.len()),
    );
    print_pretty(&serde_json::Value::Object(summary))
}

pub(super) fn cmd_list(path: Option<PathBuf>, dir: PathBuf, json: bool) -> anyhow::Result<()> {
    let target = path.unwrap_or(dir);
    if !target.exists() {
        bail!("path does not exist: {}", target.display());
    }
    let rows = if target.join("calls").is_dir() {
        list_calls(&target)?
    } else {
        list_runs(&target)?
    };
    if json {
        print_pretty(&serde_json::Value::Array(rows))
    } else {
        for row in rows {
            println!(
                "{}",
                serde_json::to_string(&row).context("serialize list row")?
            );
        }
        Ok(())
    }
}

pub(super) fn cmd_info(path: PathBuf) -> anyhow::Result<()> {
    print_pretty(&core_reports::info(path)?)
}
