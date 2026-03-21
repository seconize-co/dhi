//! Stub eBPF module for non-Linux platforms

use anyhow::Result;
use tracing::warn;

/// Start monitor (stub for non-Linux)
pub async fn start_monitor(_runtime: &crate::DhiRuntime) -> Result<()> {
    warn!("eBPF monitoring is only available on Linux");
    warn!("Running in agentic-only mode");
    Ok(())
}
