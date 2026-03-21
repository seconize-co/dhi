//! eBPF Module
//!
//! Kernel-level syscall monitoring using eBPF.

use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod stub;

#[cfg(not(target_os = "linux"))]
pub use stub::*;

/// Event types from eBPF
#[derive(Debug, Clone)]
pub enum EbpfEventType {
    FileOpen,
    FileWrite,
    FileDelete,
    FileRename,
    FileChmod,
    NetworkSend,
    ProcessExec,
}

/// File event from eBPF
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub flags: u32,
    pub mode: u32,
    pub event_type: EbpfEventType,
}

/// Network event from eBPF
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub bytes_sent: u64,
    pub protocol: u8,
}

/// Start eBPF monitoring
pub async fn start_ebpf_monitor(_runtime: &crate::DhiRuntime) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::start_monitor(_runtime).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        stub::start_monitor(_runtime).await
    }
}
