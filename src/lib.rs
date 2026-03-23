//! # Dhi - Runtime Intelligence & Protection System
//!
//! धी (Sanskrit: Intellect | Perception | Clear Vision)
//!
//! High-performance runtime protection for AI agents using eBPF.
//!
//! ## Features
//!
//! - **Kernel-level monitoring** via eBPF syscall hooks
//! - **LLM API tracking** with cost estimation
//! - **Tool invocation monitoring** with risk analysis
//! - **MCP protocol** parsing and analysis
//! - **Prompt security** - injection & jailbreak detection
//! - **Memory protection** - tampering detection
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    DHI RUNTIME (RUST)                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │ eBPF        │  │ Agentic     │  │ Detection   │         │
//! │  │ Monitor     │  │ Runtime     │  │ Engine      │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod agentic;
pub mod detection;
pub mod ebpf;
pub mod monitor;
pub mod proxy;
pub mod server;

#[cfg(test)]
mod proxy_test;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Dhi runtime configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DhiConfig {
    /// Protection level: log, alert, block
    pub protection_level: ProtectionLevel,

    /// Maximum budget for LLM calls (USD)
    pub max_budget_usd: Option<f64>,

    /// Maximum tokens per LLM call
    pub max_tokens_per_call: Option<u64>,

    /// Whitelisted IPs
    pub whitelist_ips: Vec<String>,

    /// Whitelisted file paths
    pub whitelist_files: Vec<String>,

    /// Tool denylist patterns
    pub tool_denylist: Vec<String>,

    /// Tool allowlist (if set, only these tools allowed)
    pub tool_allowlist: Vec<String>,

    /// Enable eBPF kernel monitoring
    pub enable_ebpf: bool,

    /// Run eBPF monitor in SSL-only mode (skip syscall tracepoint monitoring)
    pub ebpf_ssl_only: bool,

    /// Action to take when SSL analysis returns a block decision.
    pub ebpf_block_action: EbpfBlockAction,

    /// Enable agentic runtime monitoring
    pub enable_agentic: bool,
}

impl Default for DhiConfig {
    fn default() -> Self {
        Self {
            protection_level: ProtectionLevel::Alert,
            max_budget_usd: None,
            max_tokens_per_call: Some(100_000),
            whitelist_ips: vec!["127.0.0.1".to_string(), "169.254.169.254".to_string()],
            whitelist_files: vec!["/var/log/".to_string(), "/tmp/".to_string()],
            tool_denylist: vec![
                "sudo".to_string(),
                "rm -rf".to_string(),
                "chmod 777".to_string(),
            ],
            tool_allowlist: vec![],
            enable_ebpf: true,
            ebpf_ssl_only: false,
            ebpf_block_action: EbpfBlockAction::Kill,
            enable_agentic: true,
        }
    }
}

/// eBPF SSL block enforcement action
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EbpfBlockAction {
    /// Do not enforce at process level; only log alerts.
    None,
    /// Send SIGTERM to the offending process.
    Term,
    /// Send SIGKILL to the offending process.
    Kill,
}

/// Protection enforcement levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionLevel {
    /// Log only, no enforcement
    Log,
    /// Alert on suspicious activity
    Alert,
    /// Block high-risk operations
    Block,
}

impl std::fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionLevel::Log => write!(f, "LOG"),
            ProtectionLevel::Alert => write!(f, "ALERT"),
            ProtectionLevel::Block => write!(f, "BLOCK"),
        }
    }
}

/// Global runtime state
pub struct DhiRuntime {
    pub config: Arc<RwLock<DhiConfig>>,
    pub agentic: Arc<agentic::AgenticRuntime>,
    pub detection: Arc<detection::DetectionEngine>,
    pub stats: Arc<RwLock<RuntimeStats>>,
}

/// Runtime statistics
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct RuntimeStats {
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub total_events: u64,
    pub total_alerts: u64,
    pub total_blocks: u64,
    pub events_per_second: f64,
}

impl DhiRuntime {
    /// Create a new Dhi runtime
    pub fn new(config: DhiConfig) -> Self {
        let max_budget_usd = config.max_budget_usd;
        let agentic_runtime = Arc::new(agentic::AgenticRuntime::new());
        if let Some(budget) = max_budget_usd {
            agentic_runtime.configure_max_budget_usd(budget);
        }

        Self {
            config: Arc::new(RwLock::new(config)),
            agentic: agentic_runtime,
            detection: Arc::new(detection::DetectionEngine::new()),
            stats: Arc::new(RwLock::new(RuntimeStats::default())),
        }
    }

    /// Start the runtime
    pub async fn start(&self) -> Result<()> {
        let mut stats = self.stats.write().await;
        stats.start_time = Some(chrono::Utc::now());
        Ok(())
    }

    /// Get runtime statistics
    pub async fn get_stats(&self) -> RuntimeStats {
        self.stats.read().await.clone()
    }
}
