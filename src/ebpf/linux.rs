//! Linux eBPF Implementation
//!
//! Real eBPF monitoring using the aya library.

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Bpf;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{EbpfEventType, FileEvent, NetworkEvent};

/// eBPF program bytes (would be compiled separately)
/// For now, we'll create a runtime that can load pre-compiled BPF
const BPF_PROGRAM_PATH: &str = "/usr/share/dhi/dhi.bpf.o";

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

/// Start the eBPF monitor
pub async fn start_monitor(runtime: &crate::DhiRuntime) -> Result<()> {
    info!("Starting eBPF monitor on Linux");

    let config = runtime.config.read().await;
    let protection_level = config.protection_level;
    let ssl_only_mode = config.ebpf_ssl_only;
    drop(config);

    // Start SSL/TLS interception
    tokio::spawn(start_ssl_monitor(protection_level));

    // Check if BPF program exists for syscall monitoring
    let bpf_path = std::path::Path::new(BPF_PROGRAM_PATH);
    if !bpf_path.exists() {
        warn!("BPF program not found at {}. Running in simulation mode.", BPF_PROGRAM_PATH);
        return start_simulation_mode(runtime).await;
    }

    // Load BPF program
    let mut bpf = Bpf::load_file(bpf_path)
        .context("Failed to load BPF program")?;

    // Attach syscall tracepoints if present.
    // Some deployments ship SSL-only BPF objects (no syscall programs/maps).
    let attached_tracepoints = attach_tracepoints(&mut bpf, ssl_only_mode)?;
    if attached_tracepoints == 0 {
        info!(
            "No syscall tracepoint programs found in {}. Running in SSL-only eBPF mode.",
            BPF_PROGRAM_PATH
        );
        return Ok(());
    }

    // Create event channel
    let (tx, mut rx) = mpsc::channel::<EbpfEvent>(1000);

    // Spawn ring buffer reader
    let Some(events_map) = bpf.take_map("events") else {
        warn!(
            "No 'events' map found in {}. Syscall monitoring disabled; SSL monitoring remains active.",
            BPF_PROGRAM_PATH
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
            }
            EbpfEvent::Network(network_event) => {
                process_network_event(&network_event, runtime, protection_level).await;
            }
        }
    }

    Ok(())
}

/// Start SSL/TLS traffic monitoring
async fn start_ssl_monitor(protection_level: crate::ProtectionLevel) {
    use super::ssl_hook::{process_ssl_event, RawSslEvent, SslEvent, SslTracer};
    use tokio::sync::mpsc;

    info!("Starting SSL/TLS traffic interception...");

    let (tx, mut rx) = mpsc::channel::<SslEvent>(1000);
    let tracer = SslTracer::new(tx, protection_level);
    let monitor = tracer.monitor();

    let mut bpf = match Bpf::load_file(BPF_PROGRAM_PATH) {
        Ok(bpf) => bpf,
        Err(e) => {
            warn!(
                "Failed to load BPF object for SSL tracing ({}): {}",
                BPF_PROGRAM_PATH, e
            );
            return;
        }
    };

    // Start the tracer and attach SSL probes.
    let attached = match tracer.start(&mut bpf).await {
        Ok(n) => n,
        Err(e) => {
            warn!("Failed to start SSL tracer: {}", e);
            return;
        }
    };
    if attached == 0 {
        warn!("No SSL uprobes were attached. SSL tracing disabled.");
        return;
    }

    // Process analyzed SSL events.
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(e) = process_ssl_event(&event, &monitor).await {
                error!("Error processing SSL event: {}", e);
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
        }
    };

    info!("SSL/TLS interception active - monitoring encrypted traffic");

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

            if let Err(e) = tracer.monitor().process_raw_event(&raw).await {
                debug!("Failed to process raw SSL event: {}", e);
            }
        } else {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
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
                    warn!("Failed to attach {} to {}/{}: {}", prog_name, category, name, e);
                } else {
                    info!("Attached {} to {}/{}", prog_name, category, name);
                    attached += 1;
                }
            }
            None => {
                debug!("Program {} not found in BPF object", prog_name);
            }
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
            let data = event_data.as_ref();
            
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
            }
            crate::ProtectionLevel::Alert => {
                warn!(
                    "[SUSPICIOUS FILE] PID={} ({}) UID={} FILE={} FLAGS={}",
                    event.pid, event.comm, event.uid, event.filename, event.flags
                );
            }
            crate::ProtectionLevel::Block => {
                error!(
                    "[BLOCKED FILE] PID={} ({}) UID={} FILE={} FLAGS={}",
                    event.pid, event.comm, event.uid, event.filename, event.flags
                );
                stats.total_blocks += 1;
                // In production, would use eBPF return codes to block
            }
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
            }
            crate::ProtectionLevel::Alert => {
                warn!(
                    "[EXFILTRATION RISK] PID={} ({}) DEST={}:{} BYTES={}",
                    event.pid, event.comm, daddr_str, event.dport, event.bytes_sent
                );
            }
            crate::ProtectionLevel::Block => {
                error!(
                    "[BLOCKED EXFILTRATION] PID={} ({}) DEST={}:{} BYTES={}",
                    event.pid, event.comm, daddr_str, event.dport, event.bytes_sent
                );
                stats.total_blocks += 1;
            }
        }
    }
}

/// Check if file operation is suspicious
fn is_suspicious_file_operation(event: &FileEvent) -> bool {
    let sensitive_paths = ["/etc/", "/.ssh/", "/root/", "/home/", ".bashrc", ".bash_history"];
    
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
