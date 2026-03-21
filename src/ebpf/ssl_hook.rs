//! SSL/TLS Hooking via eBPF Uprobes
//!
//! Captures plaintext data before encryption (SSL_write) and after decryption (SSL_read)
//! by attaching uprobes to OpenSSL, BoringSSL, and GnuTLS library functions.
//!
//! This provides full visibility into HTTPS traffic without requiring certificate installation.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::agentic::{PiiDetector, SecretsDetector, PromptSecurityAnalyzer};
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
            libraries.push(LibraryProbe::openssl(path_buf));
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
            libraries.push(LibraryProbe::gnutls(path_buf));
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
            libraries.push(LibraryProbe::boringssl(path_buf));
        }
    }

    if libraries.is_empty() {
        warn!("No SSL libraries found on system");
    }

    libraries
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
}

impl SslMonitor {
    /// Create a new SSL monitor
    pub fn new(
        event_tx: mpsc::Sender<SslEvent>,
        protection_level: ProtectionLevel,
    ) -> Self {
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

        // Update connection tracking
        {
            let mut connections = self.connections.write().await;
            let conn = connections.entry(raw.ssl_ptr).or_insert_with(|| {
                SslConnectionInfo {
                    pid: raw.pid,
                    comm: comm.clone(),
                    first_seen: raw.timestamp_ns,
                    bytes_written: 0,
                    bytes_read: 0,
                    write_count: 0,
                    read_count: 0,
                }
            });

            match direction {
                SslDirection::Write => {
                    conn.bytes_written += data_len as u64;
                    conn.write_count += 1;
                }
                SslDirection::Read => {
                    conn.bytes_read += data_len as u64;
                    conn.read_count += 1;
                }
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

        Ok(Some(event))
    }

    /// Analyze SSL event for security issues
    pub async fn analyze_event(&self, event: &SslEvent) -> SslAnalysisResult {
        // Try to interpret as UTF-8 text
        let text = match std::str::from_utf8(&event.data) {
            Ok(s) => s.to_string(),
            Err(_) => {
                // Binary data - could be encrypted or non-text protocol
                return SslAnalysisResult::default();
            }
        };

        let mut result = SslAnalysisResult::default();

        // Detect secrets
        let secrets = self.secrets_detector.scan(&text);
        if !secrets.is_empty() {
            result.secrets_detected = secrets.iter().map(|s| s.secret_type.clone()).collect();
            result.has_secrets = true;
            result.risk_score = result.risk_score.max(95);
        }

        // Detect PII
        let pii = self.pii_detector.scan(&text);
        if !pii.is_empty() {
            result.pii_detected = pii.iter().map(|p| p.pii_type.clone()).collect();
            result.has_pii = true;
            result.risk_score = result.risk_score.max(70);
        }

        // Check for prompt injection (only on writes/requests)
        if event.direction == SslDirection::Write {
            let prompt_result = self.prompt_analyzer.scan(&text);
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

/// eBPF SSL Tracer - attaches uprobes to SSL libraries
#[cfg(target_os = "linux")]
pub struct SslTracer {
    libraries: Vec<LibraryProbe>,
    monitor: Arc<SslMonitor>,
}

#[cfg(target_os = "linux")]
impl SslTracer {
    /// Create a new SSL tracer
    pub fn new(
        event_tx: mpsc::Sender<SslEvent>,
        protection_level: ProtectionLevel,
    ) -> Self {
        let libraries = find_ssl_libraries();
        let monitor = Arc::new(SslMonitor::new(event_tx, protection_level));

        Self { libraries, monitor }
    }

    /// Start tracing SSL functions
    pub async fn start(&self) -> Result<()> {
        if self.libraries.is_empty() {
            warn!("No SSL libraries found - SSL tracing disabled");
            return Ok(());
        }

        info!("Starting SSL/TLS traffic interception via eBPF uprobes");

        for lib in &self.libraries {
            info!(
                "Attaching probes to {:?} at {}",
                lib.library,
                lib.path.display()
            );

            // In production, this would use aya to attach uprobes:
            // - uprobe on SSL_write entry to capture outgoing data
            // - uretprobe on SSL_read return to capture incoming data
            //
            // The eBPF program would:
            // 1. Read the buffer pointer and length from function arguments
            // 2. Copy data to a ring buffer (up to MAX_CAPTURE_SIZE)
            // 3. Send event to userspace

            self.attach_probes(lib).await?;
        }

        Ok(())
    }

    /// Attach uprobes to a specific library
    async fn attach_probes(&self, lib: &LibraryProbe) -> Result<()> {
        // This is a placeholder for the actual eBPF attachment
        // In production, would use aya::programs::UProbe

        debug!(
            "Would attach uprobe to {}:{} (write)",
            lib.path.display(),
            lib.write_symbol
        );
        debug!(
            "Would attach uretprobe to {}:{} (read)",
            lib.path.display(),
            lib.read_symbol
        );

        if let Some(write_ex) = lib.write_ex_symbol {
            debug!(
                "Would attach uprobe to {}:{} (write_ex)",
                lib.path.display(),
                write_ex
            );
        }

        if let Some(read_ex) = lib.read_ex_symbol {
            debug!(
                "Would attach uretprobe to {}:{} (read_ex)",
                lib.path.display(),
                read_ex
            );
        }

        Ok(())
    }

    /// Get the monitor for analysis
    pub fn monitor(&self) -> Arc<SslMonitor> {
        Arc::clone(&self.monitor)
    }
}

/// Process captured SSL event and take action
pub async fn process_ssl_event(
    event: &SslEvent,
    monitor: &SslMonitor,
    protection_level: ProtectionLevel,
) -> Result<bool> {
    let analysis = monitor.analyze_event(event).await;

    let direction_str = match event.direction {
        SslDirection::Write => "OUTBOUND",
        SslDirection::Read => "INBOUND",
    };

    // Log based on protection level
    if analysis.risk_score > 0 {
        match protection_level {
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
            }
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
            }
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
                    return Ok(true);
                }
            }
        }
    }

    // Return false - not blocked
    Ok(false)
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
            data: b"API key is sk-proj-abc123def456ghi789".to_vec(),
            total_len: 38,
            timestamp_ns: 0,
            ssl_ptr: 0x12345678,
        };

        let result = monitor.analyze_event(&event).await;
        // Should detect secret pattern
        assert!(result.risk_score > 0);
    }
}
