//! SSL/TLS Hooking via eBPF Uprobes
//!
//! Captures plaintext data before encryption (SSL_write) and after decryption (SSL_read)
//! by attaching uprobes to OpenSSL, BoringSSL, and GnuTLS library functions.
//!
//! This provides full visibility into HTTPS traffic without requiring certificate installation.

use anyhow::Result;
use aya::programs::{ProgramError, UProbe};
use aya::Bpf;
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::agentic::{PiiDetector, PromptSecurityAnalyzer, SecretsDetector};
use crate::ProtectionLevel;

/// Maximum data capture size per SSL operation (16KB - typical TLS record size)
const MAX_CAPTURE_SIZE: usize = 16384;

/// SSL event direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslDirection {
    /// Data being sent (SSL_write) - outbound requests/prompts
    Write,
    /// Data being received (SSL_read) - inbound responses
    Read,
}

/// Captured SSL/TLS data event
#[derive(Debug, Clone)]
pub struct SslEvent {
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// User ID
    pub uid: u32,
    /// Process name
    pub comm: String,
    /// Direction (read/write)
    pub direction: SslDirection,
    /// Captured plaintext data
    pub data: Vec<u8>,
    /// Data length (may be larger than captured)
    pub total_len: usize,
    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
    /// SSL connection ID (for correlation)
    pub ssl_ptr: u64,
}

/// SSL library type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslLibrary {
    OpenSSL,
    BoringSSL,
    LibreSSL,
    GnuTLS,
}

/// Library probe configuration
#[derive(Debug, Clone)]
pub struct LibraryProbe {
    pub library: SslLibrary,
    pub path: PathBuf,
    pub read_symbol: &'static str,
    pub write_symbol: &'static str,
    pub read_ex_symbol: Option<&'static str>,
    pub write_ex_symbol: Option<&'static str>,
}

impl LibraryProbe {
    /// OpenSSL/LibreSSL probe configuration
    pub fn openssl(path: PathBuf) -> Self {
        Self {
            library: SslLibrary::OpenSSL,
            path,
            read_symbol: "SSL_read",
            write_symbol: "SSL_write",
            read_ex_symbol: Some("SSL_read_ex"),
            write_ex_symbol: Some("SSL_write_ex"),
        }
    }

    /// BoringSSL probe configuration (used by Chrome, Go)
    pub fn boringssl(path: PathBuf) -> Self {
        Self {
            library: SslLibrary::BoringSSL,
            path,
            read_symbol: "SSL_read",
            write_symbol: "SSL_write",
            read_ex_symbol: None, // BoringSSL doesn't have _ex variants
            write_ex_symbol: None,
        }
    }

    /// GnuTLS probe configuration
    pub fn gnutls(path: PathBuf) -> Self {
        Self {
            library: SslLibrary::GnuTLS,
            path,
            read_symbol: "gnutls_record_recv",
            write_symbol: "gnutls_record_send",
            read_ex_symbol: None,
            write_ex_symbol: None,
        }
    }
}

/// Find SSL libraries on the system
pub fn find_ssl_libraries() -> Vec<LibraryProbe> {
    let mut libraries = Vec::new();
    let mut seen_targets: HashSet<PathBuf> = HashSet::new();

    // Common OpenSSL paths
    let openssl_paths = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/libssl.so",
    ];

    for path in openssl_paths {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            info!("Found OpenSSL at: {}", path);
            if seen_targets.insert(path_buf.clone()) {
                libraries.push(LibraryProbe::openssl(path_buf));
            }
            break;
        }
    }

    // Common GnuTLS paths
    let gnutls_paths = [
        "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/usr/lib64/libgnutls.so.30",
        "/lib/x86_64-linux-gnu/libgnutls.so.30",
    ];

    for path in gnutls_paths {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            info!("Found GnuTLS at: {}", path);
            if seen_targets.insert(path_buf.clone()) {
                libraries.push(LibraryProbe::gnutls(path_buf));
            }
            break;
        }
    }

    // Check for BoringSSL (often bundled with applications)
    // These are typically in application-specific paths
    let boringssl_indicators = [
        "/opt/google/chrome/libssl.so",
        "/usr/lib/chromium/libssl.so",
    ];

    for path in boringssl_indicators {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            info!("Found BoringSSL at: {}", path);
            if seen_targets.insert(path_buf.clone()) {
                libraries.push(LibraryProbe::boringssl(path_buf));
            }
        }
    }

    // Copilot CLI and similar Rust binaries may embed OpenSSL symbols directly
    // in the executable (not in shared libssl). In that case, attach uprobes to
    // the executable path itself so SSL_* hooks still fire.
    for target in discover_runtime_ssl_targets() {
        if seen_targets.insert(target.clone()) {
            info!("Found runtime SSL target at: {}", target.display());
            libraries.push(LibraryProbe::openssl(target));
        }
    }

    if libraries.is_empty() {
        warn!("No SSL libraries found on system");
    }

    libraries
}

fn discover_runtime_ssl_targets() -> Vec<PathBuf> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    let mut add_target = |p: PathBuf| {
        if !p.exists() {
            return;
        }
        if !is_elf_binary(&p) {
            debug!(
                "Skipping non-ELF runtime SSL target candidate: {}",
                p.display()
            );
            return;
        }
        if seen.insert(p.clone()) {
            targets.push(p);
        }
    };

    // Allow explicit overrides for controlled environments.
    // Example:
    //   DHI_SSL_EXTRA_TARGETS=/home/user/.local/bin/copilot,/opt/custom-agent/bin/agent
    if let Ok(extra) = std::env::var("DHI_SSL_EXTRA_TARGETS") {
        for raw in extra.split(',') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let p = PathBuf::from(trimmed);
            if p.exists() {
                add_target(p);
            } else {
                warn!("Ignoring missing DHI_SSL_EXTRA_TARGETS entry: {}", trimmed);
            }
        }
    }

    // Common Copilot install paths.
    add_target(PathBuf::from("/usr/local/bin/copilot"));
    add_target(PathBuf::from("/root/.local/bin/copilot"));
    if let Ok(home_entries) = std::fs::read_dir("/home") {
        for entry in home_entries.flatten() {
            let p = entry.path().join(".local/bin/copilot");
            add_target(p);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Auto-discover running Copilot executable targets from /proc.
        // This keeps eBPF SSL capture functional when Copilot embeds SSL symbols.
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(pid_str) = name.to_str() else {
                    continue;
                };
                if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                // First try cmdline argv[0] for currently launched executable path.
                let cmdline_path = entry.path().join("cmdline");
                if let Ok(cmdline_bytes) = std::fs::read(cmdline_path) {
                    if let Some(first) = cmdline_bytes.split(|b| *b == 0).next() {
                        if let Ok(arg0) = std::str::from_utf8(first) {
                            let p = PathBuf::from(arg0);
                            if p.file_name().and_then(|n| n.to_str()) == Some("copilot") {
                                add_target(p);
                            }
                        }
                    }
                }

                let exe_link = entry.path().join("exe");
                let Ok(exe_path) = std::fs::read_link(exe_link) else {
                    continue;
                };
                let mut normalized = exe_path.clone();
                if let Some(exe_str) = exe_path.to_str() {
                    if let Some(stripped) = exe_str.strip_suffix(" (deleted)") {
                        normalized = PathBuf::from(stripped);
                    }
                }

                let Some(file_name) = normalized.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if file_name == "copilot" {
                    add_target(normalized);
                }
            }
        }
    }

    targets.sort();
    targets
}

fn is_elf_binary(path: &std::path::Path) -> bool {
    use std::io::Read;

    let mut f = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }

    magic == [0x7F, b'E', b'L', b'F']
}

/// Raw SSL event from eBPF (C struct representation)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSslEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub ssl_ptr: u64,
    pub direction: u8, // 0 = write, 1 = read
    pub data_len: u32,
    pub comm: [u8; 16],
    pub data: [u8; MAX_CAPTURE_SIZE],
}

/// SSL Monitor state
pub struct SslMonitor {
    /// Active SSL connections (ssl_ptr -> connection info)
    connections: Arc<RwLock<HashMap<u64, SslConnectionInfo>>>,
    /// Event sender
    event_tx: mpsc::Sender<SslEvent>,
    /// Secrets detector
    secrets_detector: Arc<SecretsDetector>,
    /// PII detector
    pii_detector: Arc<PiiDetector>,
    /// Prompt security analyzer
    prompt_analyzer: Arc<PromptSecurityAnalyzer>,
    /// Protection level
    protection_level: ProtectionLevel,
}

/// SSL connection tracking info
#[derive(Debug, Clone)]
pub struct SslConnectionInfo {
    pub pid: u32,
    pub comm: String,
    pub first_seen: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub write_count: u64,
    pub read_count: u64,
    pub write_buffer: Vec<u8>,
    pub read_buffer: Vec<u8>,
}

const ANALYSIS_BUFFER_LIMIT: usize = 4096;

impl SslMonitor {
    /// Create a new SSL monitor
    pub fn new(event_tx: mpsc::Sender<SslEvent>, protection_level: ProtectionLevel) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            secrets_detector: Arc::new(SecretsDetector::new()),
            pii_detector: Arc::new(PiiDetector::new()),
            prompt_analyzer: Arc::new(PromptSecurityAnalyzer::new()),
            protection_level,
        }
    }

    /// Process a raw SSL event from eBPF
    pub async fn process_raw_event(&self, raw: &RawSslEvent) -> Result<Option<SslEvent>> {
        let comm = std::str::from_utf8(&raw.comm)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let direction = if raw.direction == 0 {
            SslDirection::Write
        } else {
            SslDirection::Read
        };

        let data_len = (raw.data_len as usize).min(MAX_CAPTURE_SIZE);
        let data = raw.data[..data_len].to_vec();
        debug!(
            "SSL event normalized: pid={} comm={} dir={:?} captured_len={} total_len={}",
            raw.pid, comm, direction, data_len, raw.data_len
        );

        // Update connection tracking
        {
            let mut connections = self.connections.write().await;
            let conn = connections
                .entry(raw.ssl_ptr)
                .or_insert_with(|| SslConnectionInfo {
                    pid: raw.pid,
                    comm: comm.clone(),
                    first_seen: raw.timestamp_ns,
                    bytes_written: 0,
                    bytes_read: 0,
                    write_count: 0,
                    read_count: 0,
                    write_buffer: Vec::new(),
                    read_buffer: Vec::new(),
                });

            match direction {
                SslDirection::Write => {
                    conn.bytes_written += data_len as u64;
                    conn.write_count += 1;
                    conn.write_buffer.extend_from_slice(&data);
                    if conn.write_buffer.len() > ANALYSIS_BUFFER_LIMIT {
                        let excess = conn.write_buffer.len() - ANALYSIS_BUFFER_LIMIT;
                        conn.write_buffer.drain(0..excess);
                    }
                },
                SslDirection::Read => {
                    conn.bytes_read += data_len as u64;
                    conn.read_count += 1;
                    conn.read_buffer.extend_from_slice(&data);
                    if conn.read_buffer.len() > ANALYSIS_BUFFER_LIMIT {
                        let excess = conn.read_buffer.len() - ANALYSIS_BUFFER_LIMIT;
                        conn.read_buffer.drain(0..excess);
                    }
                },
            }
        }

        let event = SslEvent {
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            comm,
            direction,
            data,
            total_len: raw.data_len as usize,
            timestamp_ns: raw.timestamp_ns,
            ssl_ptr: raw.ssl_ptr,
        };

        if let Err(e) = self.event_tx.send(event.clone()).await {
            debug!("SSL event channel closed, dropping event: {}", e);
        }

        Ok(Some(event))
    }

    /// Analyze SSL event for security issues
    pub async fn analyze_event(&self, event: &SslEvent) -> SslAnalysisResult {
        let analysis_bytes = {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&event.ssl_ptr) {
                match event.direction {
                    SslDirection::Write if !conn.write_buffer.is_empty() => {
                        conn.write_buffer.clone()
                    },
                    SslDirection::Read if !conn.read_buffer.is_empty() => conn.read_buffer.clone(),
                    _ => event.data.clone(),
                }
            } else {
                event.data.clone()
            }
        };

        // SSL payloads can mix text and binary framing (e.g., HTTP/2).
        // Use lossy UTF-8 so detectors can still match ASCII patterns.
        let text = String::from_utf8_lossy(&analysis_bytes).to_string();

        let mut result = SslAnalysisResult::default();

        // Detect secrets
        let secrets = self.secrets_detector.scan(&text, "ssl");
        if secrets.secrets_found {
            result.secrets_detected = secrets
                .secrets
                .iter()
                .map(|s| s.secret_type.clone())
                .collect();
            result.has_secrets = true;
            result.risk_score = result.risk_score.max(95);
        }

        // Detect PII
        let pii = self.pii_detector.scan(&text, "ssl");
        if pii.pii_found {
            result.pii_detected = pii.pii_types.iter().map(|p| p.pii_type.clone()).collect();
            result.has_pii = true;
            result.risk_score = result.risk_score.max(70);
        }

        // Check for prompt injection (only on writes/requests)
        if event.direction == SslDirection::Write {
            let prompt_result = self.prompt_analyzer.analyze(&text);
            if prompt_result.injection_detected {
                result.injection_detected = true;
                result.risk_score = result.risk_score.max(90);
            }
            if prompt_result.jailbreak_detected {
                result.jailbreak_detected = true;
                result.risk_score = result.risk_score.max(85);
            }
        }

        // Check for LLM API patterns
        if text.contains("\"model\"") && (text.contains("gpt") || text.contains("claude")) {
            result.is_llm_traffic = true;
        }

        result
    }

    /// Get connection statistics
    pub async fn get_connection_stats(&self) -> Vec<SslConnectionInfo> {
        self.connections.read().await.values().cloned().collect()
    }

    /// Clean up old connections
    pub async fn cleanup_old_connections(&self, max_age_ns: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let mut connections = self.connections.write().await;
        connections.retain(|_, conn| now - conn.first_seen < max_age_ns);
    }
}

/// Result of SSL traffic analysis
#[derive(Debug, Clone, Default)]
pub struct SslAnalysisResult {
    pub has_secrets: bool,
    pub secrets_detected: Vec<String>,
    pub has_pii: bool,
    pub pii_detected: Vec<String>,
    pub injection_detected: bool,
    pub jailbreak_detected: bool,
    pub is_llm_traffic: bool,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SslProcessOutcome {
    pub risk_score: u32,
    pub blocked: bool,
}

/// eBPF SSL Tracer - attaches uprobes to SSL libraries
#[cfg(target_os = "linux")]
pub struct SslTracer {
    libraries: Vec<LibraryProbe>,
    monitor: Arc<SslMonitor>,
}

#[cfg(target_os = "linux")]
impl SslTracer {
    /// Create a new SSL tracer
    pub fn new(event_tx: mpsc::Sender<SslEvent>, protection_level: ProtectionLevel) -> Self {
        let libraries = find_ssl_libraries();
        let monitor = Arc::new(SslMonitor::new(event_tx, protection_level));

        Self { libraries, monitor }
    }

    /// Start tracing SSL functions
    pub async fn start(&self, bpf: &mut Bpf) -> Result<usize> {
        if self.libraries.is_empty() {
            warn!("No SSL libraries found - SSL tracing disabled");
            return Ok(0);
        }

        info!("Starting SSL/TLS traffic interception via eBPF uprobes");

        let mut attached = 0usize;
        for lib in &self.libraries {
            info!(
                "Attaching probes to {:?} at {}",
                lib.library,
                lib.path.display()
            );
            attached += self.attach_probes(bpf, lib).await?;
        }

        Ok(attached)
    }

    /// Attach uprobes to a specific library
    async fn attach_probes(&self, bpf: &mut Bpf, lib: &LibraryProbe) -> Result<usize> {
        let mut attached = 0usize;
        let lib_path = &lib.path;

        match lib.library {
            SslLibrary::OpenSSL | SslLibrary::BoringSSL | SslLibrary::LibreSSL => {
                attached += attach_uprobe_program(
                    bpf,
                    "uprobe_ssl_write",
                    Some(lib.write_symbol),
                    0,
                    lib_path,
                )?;
                attached += attach_uprobe_program(
                    bpf,
                    "uprobe_ssl_read_entry",
                    Some(lib.read_symbol),
                    0,
                    lib_path,
                )?;
                attached += attach_uprobe_program(
                    bpf,
                    "uretprobe_ssl_read",
                    Some(lib.read_symbol),
                    0,
                    lib_path,
                )?;

                if let Some(write_ex) = lib.write_ex_symbol {
                    attached += attach_uprobe_program(
                        bpf,
                        "uprobe_ssl_write_ex",
                        Some(write_ex),
                        0,
                        lib_path,
                    )?;
                }
                if let Some(read_ex) = lib.read_ex_symbol {
                    attached += attach_uprobe_program(
                        bpf,
                        "uprobe_ssl_read_ex_entry",
                        Some(read_ex),
                        0,
                        lib_path,
                    )?;
                    attached += attach_uprobe_program(
                        bpf,
                        "uretprobe_ssl_read_ex",
                        Some(read_ex),
                        0,
                        lib_path,
                    )?;
                }
            },
            SslLibrary::GnuTLS => {
                attached += attach_uprobe_program(
                    bpf,
                    "uprobe_gnutls_send",
                    Some("gnutls_record_send"),
                    0,
                    lib_path,
                )?;
                attached += attach_uprobe_program(
                    bpf,
                    "uprobe_gnutls_recv_entry",
                    Some("gnutls_record_recv"),
                    0,
                    lib_path,
                )?;
                attached += attach_uprobe_program(
                    bpf,
                    "uretprobe_gnutls_recv",
                    Some("gnutls_record_recv"),
                    0,
                    lib_path,
                )?;
            },
        }

        Ok(attached)
    }

    /// Get the monitor for analysis
    pub fn monitor(&self) -> Arc<SslMonitor> {
        Arc::clone(&self.monitor)
    }
}

#[cfg(target_os = "linux")]
fn attach_uprobe_program(
    bpf: &mut Bpf,
    program_name: &str,
    symbol: Option<&str>,
    offset: u64,
    target: &std::path::Path,
) -> Result<usize> {
    let Some(program) = bpf.program_mut(program_name) else {
        debug!("BPF program {} not found; skipping", program_name);
        return Ok(0);
    };

    let uprobe: &mut UProbe = program.try_into()?;
    match uprobe.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {},
        Err(e) => {
            warn!("Failed to load uprobe program {}: {}", program_name, e);
            return Ok(0);
        },
    }

    match uprobe.attach(symbol, offset, target, None) {
        Ok(_) => {
            info!(
                "Attached {} to {}:{}",
                program_name,
                target.display(),
                symbol.unwrap_or("<offset>")
            );
            Ok(1)
        },
        Err(ProgramError::AlreadyAttached) => Ok(0),
        Err(e) => {
            // Some binaries (notably self-contained runtimes) may fail symbol-name
            // resolution through perf_event APIs even when symbols exist. Try
            // resolving the symbol offset from ELF and attaching by offset.
            if symbol.is_some() && offset == 0 {
                if let Some(sym) = symbol {
                    if let Some(fallback_offset) = resolve_symbol_offset(target, sym) {
                        match uprobe.attach(None, fallback_offset, target, None) {
                            Ok(_) => {
                                info!(
                                    "Attached {} to {} at offset 0x{:x} (fallback from symbol {})",
                                    program_name,
                                    target.display(),
                                    fallback_offset,
                                    sym
                                );
                                return Ok(1);
                            },
                            Err(ProgramError::AlreadyAttached) => return Ok(0),
                            Err(e2) => {
                                warn!(
                                    "Fallback attach failed for {} on {} (symbol {} offset 0x{:x}): {}",
                                    program_name,
                                    target.display(),
                                    sym,
                                    fallback_offset,
                                    e2
                                );
                            },
                        }
                    }
                }
            }

            warn!(
                "Failed to attach {} to {}:{}: {}",
                program_name,
                target.display(),
                symbol.unwrap_or("<offset>"),
                e
            );
            Ok(0)
        },
    }
}

fn resolve_symbol_offset(target: &std::path::Path, symbol: &str) -> Option<u64> {
    let bytes = std::fs::read(target).ok()?;
    let file = object::File::parse(&*bytes).ok()?;

    for sym in file.symbols() {
        let Ok(name) = sym.name() else {
            continue;
        };
        if name == symbol {
            // Prefer true file offset mapping (required for reliable uprobe offset attach).
            if let Some(section_idx) = sym.section_index() {
                if let Ok(section) = file.section_by_index(section_idx) {
                    let sec_addr = section.address();
                    if let Some((sec_file_off, sec_file_size)) = section.file_range() {
                        let sym_addr = sym.address();
                        if sym_addr >= sec_addr {
                            let delta = sym_addr - sec_addr;
                            if delta < sec_file_size {
                                return Some(sec_file_off + delta);
                            }
                        }
                    }
                }
            }

            // Fallback for unusual binaries where section mapping is unavailable.
            let sym_addr = sym.address();
            if sym_addr > 0 {
                return Some(sym_addr);
            }
        }
    }

    None
}

/// Process captured SSL event and take action
pub async fn process_ssl_event_with_outcome(
    event: &SslEvent,
    monitor: &SslMonitor,
) -> Result<SslProcessOutcome> {
    let analysis = monitor.analyze_event(event).await;
    let comm_lower = event.comm.to_ascii_lowercase();
    let is_copilot_event = comm_lower.contains("copilot") || comm_lower.contains("mainthread");

    if is_copilot_event {
        let preview_len = event.data.len().min(64);
        let preview = String::from_utf8_lossy(&event.data[..preview_len]).replace('\n', "\\n");
        info!(
            "[COPILOT SSL EVENT] pid={} comm={} dir={:?} len={} risk={} preview=\"{}\"",
            event.pid, event.comm, event.direction, event.total_len, analysis.risk_score, preview
        );
        let text = String::from_utf8_lossy(&event.data);
        if let Some(run_pos) = text.find("RUN-") {
            let marker = text[run_pos..]
                .split_whitespace()
                .next()
                .unwrap_or("RUN-unknown");
            info!("[COPILOT RUN MARKER] pid={} marker={}", event.pid, marker);
        }
    }

    debug!(
        "SSL analysis: pid={} dir={:?} len={} risk={} secrets={} pii={} inj={} jb={}",
        event.pid,
        event.direction,
        event.total_len,
        analysis.risk_score,
        analysis.has_secrets,
        analysis.has_pii,
        analysis.injection_detected,
        analysis.jailbreak_detected
    );

    let direction_str = match event.direction {
        SslDirection::Write => "OUTBOUND",
        SslDirection::Read => "INBOUND",
    };

    // Log based on protection level
    if analysis.risk_score > 0 {
        match monitor.protection_level {
            ProtectionLevel::Log => {
                info!(
                    "[SSL {}] PID={} ({}) LEN={} RISK={}",
                    direction_str, event.pid, event.comm, event.total_len, analysis.risk_score
                );
                if analysis.has_secrets {
                    info!("  Secrets: {:?}", analysis.secrets_detected);
                }
                if analysis.has_pii {
                    info!("  PII: {:?}", analysis.pii_detected);
                }
            },
            ProtectionLevel::Alert => {
                if analysis.risk_score >= 50 {
                    warn!(
                        "[SSL ALERT {}] PID={} ({}) LEN={} RISK={}",
                        direction_str, event.pid, event.comm, event.total_len, analysis.risk_score
                    );
                    if analysis.has_secrets {
                        warn!("  🔐 Secrets detected: {:?}", analysis.secrets_detected);
                    }
                    if analysis.has_pii {
                        warn!("  👤 PII detected: {:?}", analysis.pii_detected);
                    }
                    if analysis.injection_detected {
                        warn!("  💉 Prompt injection detected!");
                    }
                }
            },
            ProtectionLevel::Block => {
                if analysis.risk_score >= 80 {
                    error!(
                        "[SSL BLOCKED {}] PID={} ({}) LEN={} RISK={}",
                        direction_str, event.pid, event.comm, event.total_len, analysis.risk_score
                    );
                    if analysis.has_secrets {
                        error!("  🔐 BLOCKED - Secrets: {:?}", analysis.secrets_detected);
                    }
                    if analysis.injection_detected {
                        error!("  💉 BLOCKED - Injection attempt!");
                    }
                    // Return true to indicate blocking
                    return Ok(SslProcessOutcome {
                        risk_score: analysis.risk_score,
                        blocked: true,
                    });
                }
            },
        }
    }

    // Return false - not blocked
    Ok(SslProcessOutcome {
        risk_score: analysis.risk_score,
        blocked: false,
    })
}

/// Process captured SSL event and return whether it should be blocked.
pub async fn process_ssl_event(event: &SslEvent, monitor: &SslMonitor) -> Result<bool> {
    let outcome = process_ssl_event_with_outcome(event, monitor).await?;
    Ok(outcome.blocked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ssl_libraries() {
        // This will find libraries based on the system
        let libs = find_ssl_libraries();
        // May or may not find libraries depending on system
        println!("Found {} SSL libraries", libs.len());
    }

    #[test]
    fn test_ssl_direction() {
        assert_eq!(SslDirection::Write as u8, 0);
        assert_eq!(SslDirection::Read as u8, 1);
    }

    #[tokio::test]
    async fn test_ssl_monitor_analysis() {
        let (tx, _rx) = mpsc::channel(100);
        let monitor = SslMonitor::new(tx, ProtectionLevel::Alert);

        // Test with text containing a secret
        let event = SslEvent {
            pid: 1234,
            tid: 1234,
            uid: 1000,
            comm: "test".to_string(),
            direction: SslDirection::Write,
            data: b"api_key=abcdefghijklmnopqrstuvwxyz1234567890".to_vec(),
            total_len: 38,
            timestamp_ns: 0,
            ssl_ptr: 0x12345678,
        };

        let result = monitor.analyze_event(&event).await;
        // Should detect secret pattern
        assert!(result.has_secrets || result.risk_score > 0);
    }
}
