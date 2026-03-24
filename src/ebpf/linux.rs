//! Linux eBPF Implementation
//!
//! Real eBPF monitoring using the aya library.

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Bpf;
use std::path::Path;
use std::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{EbpfEventType, FileEvent, NetworkEvent};

/// eBPF program candidates (ordered by preference).
/// Current release artifacts install `dhi_ssl.bpf.o`, while legacy installs may still use
/// `dhi.bpf.o`.
const BPF_PROGRAM_PATH_CANDIDATES: [&str; 2] = ["/usr/share/dhi/dhi_ssl.bpf.o", "/usr/share/dhi/dhi.bpf.o"];

fn resolve_bpf_program_path_from_candidates<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|candidate| Path::new(candidate).exists())
}

fn resolve_bpf_program_path() -> Option<&'static str> {
    resolve_bpf_program_path_from_candidates(&BPF_PROGRAM_PATH_CANDIDATES)
}

/// Event received from eBPF
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileEvent {
    pub pid: u32,
    pub uid: u32,
    pub ts: u64,
    pub flags: u32,
    pub mode: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawNetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub ts: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub bytes_sent: u64,
    pub protocol: u8,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RawSslEventHeader {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub ssl_ptr: u64,
    pub direction: u8,
    pub data_len: u32,
    pub comm: [u8; 16],
}

const SSL_EVENT_MAX_DATA_SIZE: usize = 16384;

fn process_looks_like_copilot(pid: u32, comm_lower: &str) -> Option<bool> {
    if comm_lower.contains("copilot") || comm_lower.contains("mainthread") {
        return Some(true);
    }

    #[cfg(target_os = "linux")]
    {
        let exe_path = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
        if let Ok(target) = std::fs::read_link(exe_path) {
            let exe = target.to_string_lossy().to_ascii_lowercase();
            return Some(exe.contains("copilot") || exe.contains("npm-loader"));
        }
        return None;
    }
    #[allow(unreachable_code)]
    Some(false)
}

/// Start the eBPF monitor
pub async fn start_monitor(runtime: &crate::DhiRuntime) -> Result<()> {
    info!("Starting eBPF monitor on Linux");

    let config = runtime.config.read().await;
    let protection_level = config.protection_level;
    let ssl_only_mode = config.ebpf_ssl_only;
    let block_action = config.ebpf_block_action;
    drop(config);

    let Some(bpf_program_path) = resolve_bpf_program_path() else {
        warn!(
            "BPF program not found in any expected path ({}). Running in simulation mode.",
            BPF_PROGRAM_PATH_CANDIDATES.join(", ")
        );
        return start_simulation_mode(runtime).await;
    };

    // Start SSL/TLS interception
    tokio::spawn(start_ssl_monitor(
        runtime.agentic.clone(),
        runtime.agentic.fingerprinter(),
        runtime.stats.clone(),
        protection_level,
        block_action,
        bpf_program_path,
    ));

    // Check if BPF program exists for syscall monitoring
    let bpf_path = Path::new(bpf_program_path);

    // Load BPF program
    let mut bpf = Bpf::load_file(bpf_path).context("Failed to load BPF program")?;

    // Attach syscall tracepoints if present.
    // Some deployments ship SSL-only BPF objects (no syscall programs/maps).
    let attached_tracepoints = attach_tracepoints(&mut bpf, ssl_only_mode)?;
    if attached_tracepoints == 0 {
        info!(
            "No syscall tracepoint programs found in {}. Running in SSL-only eBPF mode.",
            bpf_program_path
        );
        return Ok(());
    }

    // Create event channel
    let (tx, mut rx) = mpsc::channel::<EbpfEvent>(1000);

    // Spawn ring buffer reader
    let Some(events_map) = bpf.take_map("events") else {
        warn!(
            "No 'events' map found in {}. Syscall monitoring disabled; SSL monitoring remains active.",
            bpf_program_path
        );
        return Ok(());
    };

    let ring_buf: RingBuf<_> = events_map
        .try_into()
        .context("Failed to convert events map to RingBuf")?;

    tokio::spawn(async move {
        read_events(ring_buf, tx).await;
    });

    info!("eBPF probes attached, processing events...");

    while let Some(event) = rx.recv().await {
        match event {
            EbpfEvent::File(file_event) => {
                process_file_event(&file_event, runtime, protection_level).await;
            },
            EbpfEvent::Network(network_event) => {
                process_network_event(&network_event, runtime, protection_level).await;
            },
        }
    }

    Ok(())
}

/// Start SSL/TLS traffic monitoring
async fn start_ssl_monitor(
    agentic: std::sync::Arc<crate::agentic::AgenticRuntime>,
    fingerprinter: std::sync::Arc<crate::agentic::AgentFingerprinter>,
    runtime_stats: std::sync::Arc<tokio::sync::RwLock<crate::RuntimeStats>>,
    protection_level: crate::ProtectionLevel,
    block_action: crate::EbpfBlockAction,
    bpf_program_path: &'static str,
) {
    use super::ssl_hook::{process_ssl_event_with_outcome, RawSslEvent, SslEvent, SslTracer};
    use tokio::sync::mpsc;

    info!("Starting SSL/TLS traffic interception...");

    let (tx, mut rx) = mpsc::channel::<SslEvent>(1000);
    let tracer = SslTracer::new(tx, protection_level, fingerprinter);
    let monitor = tracer.monitor();

    let mut bpf = match Bpf::load_file(bpf_program_path) {
        Ok(bpf) => bpf,
        Err(e) => {
            warn!(
                "Failed to load BPF object for SSL tracing ({}): {}",
                bpf_program_path, e
            );
            return;
        },
    };

    // Start the tracer and attach SSL probes.
    let attach_stats = match tracer.start(&mut bpf).await {
        Ok(stats) => stats,
        Err(e) => {
            warn!("Failed to start SSL tracer: {}", e);
            return;
        },
    };
    {
        let mut stats = runtime_stats.write().await;
        stats.ssl_probe_targets_total = attach_stats.targets_total;
        stats.ssl_probe_targets_with_attached = attach_stats.targets_with_attached;
        stats.ssl_probe_attempts_total = attach_stats.attempts_total;
        stats.ssl_probe_attached_total = attach_stats.attached_total;
        stats.ssl_probe_failed_total = attach_stats.failed_total;
    }
    info!(
        "SSL probe attach summary: targets={} attached_targets={} attempts={} attached={} failed={}",
        attach_stats.targets_total,
        attach_stats.targets_with_attached,
        attach_stats.attempts_total,
        attach_stats.attached_total,
        attach_stats.failed_total
    );
    if attach_stats.attached_total == 0 {
        warn!("No SSL uprobes were attached. SSL tracing disabled.");
        return;
    }

    // Process analyzed SSL events.
    let runtime_stats_for_outcome = runtime_stats.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match process_ssl_event_with_outcome(&event, &monitor).await {
                Ok(outcome) => {
                    if outcome.risk_score > 0 {
                        let mut stats = runtime_stats_for_outcome.write().await;
                        stats.total_alerts = stats.total_alerts.saturating_add(1);
                        let severity = if outcome.risk_score >= 90 {
                            crate::agentic::AlertSeverity::Critical
                        } else if outcome.risk_score >= 70 {
                            crate::agentic::AlertSeverity::Warning
                        } else {
                            crate::agentic::AlertSeverity::Info
                        };
                        let mut alert = crate::agentic::Alert::new(
                            severity,
                            "SSL traffic risk detected",
                            &format!(
                                "SSL risk detected for process {} (pid={})",
                                event.comm, event.pid
                            ),
                        )
                        .with_event_type("ssl_risk_detected")
                        .with_process(Some(&event.comm), Some(event.pid))
                        .with_risk_score(outcome.risk_score);
                        if outcome.blocked {
                            alert = alert.with_action("BLOCKED");
                        } else {
                            alert = alert.with_action("ALERTED");
                        }
                        if let Err(e) = agentic.emit_external_alert(alert).await {
                            warn!("Failed to persist SSL alert to alert pipeline: {}", e);
                        }
                    }
                    if outcome.blocked {
                        let mut stats = runtime_stats_for_outcome.write().await;
                        stats.total_blocks = stats.total_blocks.saturating_add(1);
                    }
                    if outcome.blocked {
                        warn!(
                        "SSL block decision triggered for pid={} comm={}; enforcement action={:?}",
                        event.pid, event.comm, block_action
                    );

                        if let Err(e) = enforce_block_action(event.pid, block_action) {
                            error!("Failed to enforce SSL block for pid={}: {}", event.pid, e);
                        }
                    }
                },
                Err(e) => {
                    error!("Error processing SSL event: {}", e);
                },
            }
        }
    });

    // Consume raw events from the ssl_events ring buffer.
    let Some(ssl_events_map) = bpf.take_map("ssl_events") else {
        warn!("No ssl_events map found in BPF object; SSL event ingestion disabled");
        return;
    };
    let mut ssl_ring_buf: RingBuf<_> = match ssl_events_map.try_into() {
        Ok(rb) => rb,
        Err(e) => {
            warn!("Failed to convert ssl_events map to RingBuf: {}", e);
            return;
        },
    };

    info!("SSL/TLS interception active - monitoring encrypted traffic");
    let runtime_stats_for_ring = runtime_stats.clone();

    loop {
        if let Some(event_data) = ssl_ring_buf.next() {
            let data: &[u8] = event_data.as_ref();
            let header_size = std::mem::size_of::<RawSslEventHeader>();
            if data.len() < header_size {
                continue;
            }

            // Safety: length is validated above for header.
            let header: RawSslEventHeader =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawSslEventHeader) };

            let mut raw = RawSslEvent {
                pid: header.pid,
                tid: header.tid,
                uid: header.uid,
                timestamp_ns: header.timestamp_ns,
                ssl_ptr: header.ssl_ptr,
                direction: header.direction,
                data_len: 0,
                comm: header.comm,
                data: [0u8; SSL_EVENT_MAX_DATA_SIZE],
            };

            let available_payload = data.len().saturating_sub(header_size);
            let declared_len = header.data_len as usize;
            let copy_len = declared_len
                .min(available_payload)
                .min(SSL_EVENT_MAX_DATA_SIZE);
            raw.data_len = copy_len as u32;
            raw.data[..copy_len].copy_from_slice(&data[header_size..header_size + copy_len]);

            debug!(
                "SSL raw event received: pid={} tid={} dir={} data_len={}",
                raw.pid, raw.tid, raw.direction, raw.data_len
            );
            {
                let mut stats = runtime_stats_for_ring.write().await;
                stats.ssl_events_total = stats.ssl_events_total.saturating_add(1);
            }
            let comm_str = std::str::from_utf8(&raw.comm)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_ascii_lowercase();
            let is_copilot_like = process_looks_like_copilot(raw.pid, &comm_str);
            if matches!(is_copilot_like, Some(true)) {
                {
                    let mut stats = runtime_stats_for_ring.write().await;
                    stats.ssl_events_copilot_total =
                        stats.ssl_events_copilot_total.saturating_add(1);
                }
                if !comm_str.contains("copilot") && !comm_str.contains("mainthread") {
                    let mut stats = runtime_stats_for_ring.write().await;
                    stats.ssl_events_copilot_by_exe_total =
                        stats.ssl_events_copilot_by_exe_total.saturating_add(1);
                }
                if comm_str.contains("copilot") || comm_str.contains("mainthread") {
                    info!(
                        "[COPILOT RAW EVENT] pid={} tid={} dir={} data_len={}",
                        raw.pid, raw.tid, raw.direction, raw.data_len
                    );
                }
            } else if is_copilot_like.is_none() {
                let mut stats = runtime_stats_for_ring.write().await;
                stats.ssl_events_exe_resolve_failures =
                    stats.ssl_events_exe_resolve_failures.saturating_add(1);
            }

            if let Err(e) = tracer.monitor().process_raw_event(&raw).await {
                {
                    let mut stats = runtime_stats_for_ring.write().await;
                    stats.ssl_events_parse_errors =
                        stats.ssl_events_parse_errors.saturating_add(1);
                }
                debug!("Failed to process raw SSL event: {}", e);
            }
        } else {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }
}

fn enforce_block_action(pid: u32, action: crate::EbpfBlockAction) -> Result<()> {
    match action {
        crate::EbpfBlockAction::None => {
            warn!(
                "SSL block decision for pid={} configured as log-only (no process signal sent)",
                pid
            );
            Ok(())
        },
        crate::EbpfBlockAction::Term => terminate_process_with_signal(pid, "TERM"),
        crate::EbpfBlockAction::Kill => terminate_process_with_signal(pid, "KILL"),
    }
}

fn terminate_process_with_signal(pid: u32, signal: &str) -> Result<()> {
    // Use Unix kill signals for deterministic enforcement on Linux.
    let status = Command::new("kill")
        .arg(format!("-{}", signal))
        .arg(pid.to_string())
        .status()
        .context("failed to execute kill command")?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "kill -{} exited with status {:?}",
            signal,
            status.code()
        ))
    }
}

/// Attach tracepoints
fn attach_tracepoints(bpf: &mut Bpf, ssl_only_mode: bool) -> Result<usize> {
    if ssl_only_mode {
        info!("SSL-only mode enabled: skipping syscall tracepoint attachment");
        return Ok(0);
    }

    // File operations
    let tracepoints = [
        ("syscalls", "sys_enter_openat", "trace_openat"),
        ("syscalls", "sys_enter_write", "trace_write"),
        ("syscalls", "sys_enter_sendto", "trace_sendto"),
        ("syscalls", "sys_enter_unlinkat", "trace_unlinkat"),
        ("syscalls", "sys_enter_renameat2", "trace_renameat2"),
        ("syscalls", "sys_enter_fchmodat", "trace_fchmodat"),
    ];

    let mut attached = 0usize;
    for (category, name, prog_name) in tracepoints {
        match bpf.program_mut(prog_name) {
            Some(prog) => {
                let tracepoint: &mut TracePoint = prog.try_into()?;
                if let Err(e) = tracepoint.load() {
                    warn!("Failed to load {}: {}", prog_name, e);
                    continue;
                }
                if let Err(e) = tracepoint.attach(category, name) {
                    warn!(
                        "Failed to attach {} to {}/{}: {}",
                        prog_name, category, name, e
                    );
                } else {
                    info!("Attached {} to {}/{}", prog_name, category, name);
                    attached += 1;
                }
            },
            None => {
                debug!("Program {} not found in BPF object", prog_name);
            },
        }
    }

    Ok(attached)
}

/// Event union
enum EbpfEvent {
    File(FileEvent),
    Network(NetworkEvent),
}

/// Read events from ring buffer
async fn read_events(mut ring_buf: RingBuf<aya::maps::MapData>, tx: mpsc::Sender<EbpfEvent>) {
    loop {
        if let Some(event_data) = ring_buf.next() {
            // Parse event based on size
            let data: &[u8] = event_data.as_ref();

            if data.len() >= std::mem::size_of::<RawFileEvent>() {
                // Try to parse as file event
                if let Some(file_event) = parse_file_event(data) {
                    if tx.send(EbpfEvent::File(file_event)).await.is_err() {
                        break;
                    }
                }
            }

            if data.len() >= std::mem::size_of::<RawNetworkEvent>() {
                // Try to parse as network event
                if let Some(network_event) = parse_network_event(data) {
                    if tx.send(EbpfEvent::Network(network_event)).await.is_err() {
                        break;
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

/// Parse file event from raw bytes
fn parse_file_event(data: &[u8]) -> Option<FileEvent> {
    if data.len() < std::mem::size_of::<RawFileEvent>() {
        return None;
    }

    // Safety: we've checked the length
    let raw: RawFileEvent = unsafe { std::ptr::read(data.as_ptr() as *const RawFileEvent) };

    let comm = std::str::from_utf8(&raw.comm)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();

    let filename = std::str::from_utf8(&raw.filename)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();

    let event_type = match raw.flags {
        0 => EbpfEventType::FileDelete,
        1 => EbpfEventType::FileRename,
        2 => EbpfEventType::FileChmod,
        _ => EbpfEventType::FileOpen,
    };

    Some(FileEvent {
        pid: raw.pid,
        uid: raw.uid,
        comm,
        filename,
        flags: raw.flags,
        mode: raw.mode,
        event_type,
    })
}

/// Parse network event from raw bytes
fn parse_network_event(data: &[u8]) -> Option<NetworkEvent> {
    if data.len() < std::mem::size_of::<RawNetworkEvent>() {
        return None;
    }

    let raw: RawNetworkEvent = unsafe { std::ptr::read(data.as_ptr() as *const RawNetworkEvent) };

    let comm = std::str::from_utf8(&raw.comm)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();

    Some(NetworkEvent {
        pid: raw.pid,
        uid: raw.uid,
        comm,
        saddr: raw.saddr,
        daddr: raw.daddr,
        sport: raw.sport,
        dport: raw.dport,
        bytes_sent: raw.bytes_sent,
        protocol: raw.protocol,
    })
}

/// Process file event
async fn process_file_event(
    event: &FileEvent,
    runtime: &crate::DhiRuntime,
    protection_level: crate::ProtectionLevel,
) {
    let config = runtime.config.read().await;

    // Check whitelist
    for whitelist_path in &config.whitelist_files {
        if event.filename.starts_with(whitelist_path) {
            return;
        }
    }

    // Check for suspicious patterns
    let is_suspicious = is_suspicious_file_operation(event);

    if is_suspicious {
        let mut stats = runtime.stats.write().await;
        stats.total_events += 1;
        stats.total_alerts += 1;

        match protection_level {
            crate::ProtectionLevel::Log => {
                info!(
                    "[FILE] PID={} ({}) UID={} FILE={} FLAGS={}",
                    event.pid, event.comm, event.uid, event.filename, event.flags
                );
            },
            crate::ProtectionLevel::Alert => {
                warn!(
                    "[SUSPICIOUS FILE] PID={} ({}) UID={} FILE={} FLAGS={}",
                    event.pid, event.comm, event.uid, event.filename, event.flags
                );
            },
            crate::ProtectionLevel::Block => {
                error!(
                    "[BLOCKED FILE] PID={} ({}) UID={} FILE={} FLAGS={}",
                    event.pid, event.comm, event.uid, event.filename, event.flags
                );
                stats.total_blocks += 1;
                // In production, would use eBPF return codes to block
            },
        }
    }
}

/// Process network event
async fn process_network_event(
    event: &NetworkEvent,
    runtime: &crate::DhiRuntime,
    protection_level: crate::ProtectionLevel,
) {
    let config = runtime.config.read().await;

    // Convert IP to string
    let daddr_str = format!(
        "{}.{}.{}.{}",
        event.daddr & 0xFF,
        (event.daddr >> 8) & 0xFF,
        (event.daddr >> 16) & 0xFF,
        (event.daddr >> 24) & 0xFF
    );

    // Check whitelist
    for whitelist_ip in &config.whitelist_ips {
        if daddr_str == *whitelist_ip || daddr_str.starts_with(whitelist_ip) {
            return;
        }
    }

    // Check for suspicious patterns
    let is_suspicious = is_suspicious_network_activity(event);

    if is_suspicious || event.bytes_sent > 1024 * 1024 {
        // > 1MB
        let mut stats = runtime.stats.write().await;
        stats.total_events += 1;
        stats.total_alerts += 1;

        match protection_level {
            crate::ProtectionLevel::Log => {
                info!(
                    "[NETWORK] PID={} ({}) DEST={}:{} BYTES={}",
                    event.pid, event.comm, daddr_str, event.dport, event.bytes_sent
                );
            },
            crate::ProtectionLevel::Alert => {
                warn!(
                    "[EXFILTRATION RISK] PID={} ({}) DEST={}:{} BYTES={}",
                    event.pid, event.comm, daddr_str, event.dport, event.bytes_sent
                );
            },
            crate::ProtectionLevel::Block => {
                error!(
                    "[BLOCKED EXFILTRATION] PID={} ({}) DEST={}:{} BYTES={}",
                    event.pid, event.comm, daddr_str, event.dport, event.bytes_sent
                );
                stats.total_blocks += 1;
            },
        }
    }
}

/// Check if file operation is suspicious
fn is_suspicious_file_operation(event: &FileEvent) -> bool {
    let sensitive_paths = [
        "/etc/",
        "/.ssh/",
        "/root/",
        "/home/",
        ".bashrc",
        ".bash_history",
    ];

    for path in sensitive_paths {
        if event.filename.contains(path) {
            return true;
        }
    }

    // Suspicious chmod (777)
    if event.mode == 0o777 {
        return true;
    }

    false
}

/// Check if network activity is suspicious
fn is_suspicious_network_activity(event: &NetworkEvent) -> bool {
    // Suspicious ports
    let suspicious_ports = [4444, 5555, 6666, 6667, 8888, 9999];

    if suspicious_ports.contains(&event.dport) {
        return true;
    }

    // Large transfer
    if event.bytes_sent > 10 * 1024 * 1024 {
        // > 10MB
        return true;
    }

    false
}

/// Start simulation mode (when BPF program not available)
async fn start_simulation_mode(runtime: &crate::DhiRuntime) -> Result<()> {
    warn!("Running in simulation mode - no real eBPF monitoring");
    warn!("To enable real monitoring, compile and install the BPF program");

    // Just keep the task alive
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        let stats = runtime.stats.read().await;
        info!(
            "Simulation mode active. Events: {}, Alerts: {}",
            stats.total_events, stats.total_alerts
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforce_block_action_none_is_non_fatal() {
        let result = enforce_block_action(std::process::id(), crate::EbpfBlockAction::None);
        assert!(result.is_ok(), "none action should not attempt signaling");
    }

    #[test]
    fn test_resolve_bpf_program_path_prefers_first_existing_candidate() {
        let unique = format!(
            "dhi-bpf-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be monotonic")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&root).expect("temp dir must be created");

        let first = root.join("dhi_ssl.bpf.o");
        let second = root.join("dhi.bpf.o");
        std::fs::write(&first, b"first").expect("first candidate should be writable");
        std::fs::write(&second, b"second").expect("second candidate should be writable");

        let first_str = first.to_string_lossy().into_owned();
        let second_str = second.to_string_lossy().into_owned();
        let candidates = [first_str.as_str(), second_str.as_str()];
        let resolved = resolve_bpf_program_path_from_candidates(&candidates);

        assert_eq!(resolved, Some(first_str.as_str()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_bpf_program_path_returns_none_when_missing() {
        let candidates = ["/definitely/not/present/a.o", "/definitely/not/present/b.o"];
        let resolved = resolve_bpf_program_path_from_candidates(&candidates);
        assert_eq!(resolved, None);
    }
}
