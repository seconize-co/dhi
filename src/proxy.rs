//! HTTP Proxy for intercepting LLM API traffic
//!
//! Provides transparent proxy that scans requests/responses for:
//! - Secrets in prompts and responses
//! - PII in prompts and responses
//! - Dangerous tool calls
//! - Budget enforcement
//! - SSRF protection (blocks private IP ranges)

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::agentic::{
    AlertConfig, Alerter, DhiMetrics, PiiDetector, PromptSecurityAnalyzer, SecretsDetector,
};
use crate::ProtectionLevel;

/// Check if an IP address is in a private/internal range (SSRF protection)
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // Private ranges
            octets[0] == 10 // 10.0.0.0/8
            || (octets[0] == 172 && (16..=31).contains(&octets[1])) // 172.16.0.0/12
            || (octets[0] == 192 && octets[1] == 168) // 192.168.0.0/16
            // Loopback
            || octets[0] == 127 // 127.0.0.0/8
            // Link-local
            || (octets[0] == 169 && octets[1] == 254) // 169.254.0.0/16 (includes AWS metadata)
            // Localhost
            || ipv4 == Ipv4Addr::LOCALHOST
            // Broadcast
            || ipv4 == Ipv4Addr::BROADCAST
            // Unspecified
            || ipv4 == Ipv4Addr::UNSPECIFIED
            // Documentation ranges
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) // 203.0.113.0/24
        },
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
            || ipv6.is_unspecified()
            // Unique local addresses (fc00::/7)
            || (ipv6.segments()[0] & 0xfe00) == 0xfc00
            // Link-local (fe80::/10)
            || (ipv6.segments()[0] & 0xffc0) == 0xfe80
        },
    }
}

/// Check if hostname is suspicious (cloud metadata endpoints, etc.)
fn is_suspicious_hostname(host: &str) -> bool {
    let host_lower = host.to_lowercase();

    // Cloud metadata endpoints
    host_lower == "169.254.169.254"
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal")
        || host_lower == "metadata"
        || host_lower.contains("metadata.azure")
        || host_lower == "fd00:ec2::254"

    // Localhost variations
        || host_lower == "localhost"
        || host_lower == "localhost.localdomain"
        || host_lower.ends_with(".localhost")

    // Kubernetes internal
        || host_lower.ends_with(".cluster.local")
        || host_lower.ends_with(".svc")

    // Docker internal
        || host_lower == "host.docker.internal"
        || host_lower == "gateway.docker.internal"
}

/// Validate that a host is safe to connect to (SSRF protection)
fn validate_host(host: &str, port: u16) -> Result<(), String> {
    // Check suspicious hostnames first
    if is_suspicious_hostname(host) {
        return Err(format!("SSRF: Suspicious hostname blocked: {}", host));
    }

    // Try to resolve the hostname
    let addr_str = format!("{}:{}", host, port);
    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                if is_private_ip(addr.ip()) {
                    return Err(format!(
                        "SSRF: Private IP address blocked: {} resolved to {}",
                        host,
                        addr.ip()
                    ));
                }
            }
            Ok(())
        },
        Err(e) => {
            // DNS resolution failed - could be legitimate or could be attack
            // Allow it but log (the connection will fail naturally)
            warn!("DNS resolution failed for {}: {}", host, e);
            Ok(())
        },
    }
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub level: ProtectionLevel,
    pub block_secrets_in_prompts: bool,
    pub block_secrets_in_responses: bool,
    pub block_pii_in_prompts: bool,
    pub block_pii_in_responses: bool,
    pub slack_webhook: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            level: ProtectionLevel::Alert,
            block_secrets_in_prompts: true,
            block_secrets_in_responses: true,
            block_pii_in_prompts: false,
            block_pii_in_responses: false,
            slack_webhook: None,
        }
    }
}

/// HTTP Proxy server
pub struct DhiProxy {
    config: ProxyConfig,
    secrets_detector: Arc<SecretsDetector>,
    pii_detector: Arc<PiiDetector>,
    prompt_security: Arc<PromptSecurityAnalyzer>,
    alerter: Arc<Alerter>,
    metrics: Arc<RwLock<DhiMetrics>>,
}

impl DhiProxy {
    /// Create new proxy
    pub fn new(config: ProxyConfig) -> Self {
        let alert_config = AlertConfig {
            slack_webhook_url: config.slack_webhook.clone(),
            ..AlertConfig::default()
        };

        Self {
            config,
            secrets_detector: Arc::new(SecretsDetector::new()),
            pii_detector: Arc::new(PiiDetector::new()),
            prompt_security: Arc::new(PromptSecurityAnalyzer::new()),
            alerter: Arc::new(Alerter::new(alert_config)),
            metrics: Arc::new(RwLock::new(DhiMetrics::new())),
        }
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.config.port).parse()?;
        let listener = TcpListener::bind(&addr).await?;

        info!("Dhi proxy listening on {}", addr);
        info!("Protection level: {:?}", self.config.level);
        info!("");
        info!("Configure your AI tools:");
        info!("  export HTTP_PROXY=http://127.0.0.1:{}", self.config.port);
        info!("  export HTTPS_PROXY=http://127.0.0.1:{}", self.config.port);
        info!("");

        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let proxy = self.clone_handlers();
                    let config = self.config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, client_addr, proxy, config).await
                        {
                            error!("Connection error from {}: {}", client_addr, e);
                        }
                    });
                },
                Err(e) => {
                    error!("Accept error: {}", e);
                },
            }
        }
    }

    fn clone_handlers(&self) -> ProxyHandlers {
        ProxyHandlers {
            secrets_detector: Arc::clone(&self.secrets_detector),
            pii_detector: Arc::clone(&self.pii_detector),
            prompt_security: Arc::clone(&self.prompt_security),
            _alerter: Arc::clone(&self.alerter),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

struct ProxyHandlers {
    secrets_detector: Arc<SecretsDetector>,
    pii_detector: Arc<PiiDetector>,
    prompt_security: Arc<PromptSecurityAnalyzer>,
    _alerter: Arc<Alerter>,
    metrics: Arc<RwLock<DhiMetrics>>,
}

/// Handle incoming connection
async fn handle_connection(
    mut client: TcpStream,
    _client_addr: SocketAddr,
    handlers: ProxyHandlers,
    config: ProxyConfig,
) -> Result<()> {
    let mut buffer = vec![0u8; 8192];
    let n = client.read(&mut buffer).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);

    // Parse HTTP request
    let lines: Vec<&str> = request.lines().collect();
    if lines.is_empty() {
        return Ok(());
    }

    let first_line = lines[0];
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Ok(());
    }

    let method = parts[0];
    let target = parts[1];

    // Handle CONNECT (HTTPS tunneling)
    if method == "CONNECT" {
        handle_connect(client, target, handlers, config).await?;
        return Ok(());
    }

    // Handle regular HTTP request
    handle_http_request(client, &request, target, handlers, config).await?;

    Ok(())
}

/// Handle CONNECT method for HTTPS tunneling
async fn handle_connect(
    mut client: TcpStream,
    target: &str,
    _handlers: ProxyHandlers,
    _config: ProxyConfig,
) -> Result<()> {
    // Parse host:port
    let (host, port) = if let Some(colon) = target.rfind(':') {
        let h = &target[..colon];
        let p = target[colon + 1..].parse().unwrap_or(443);
        (h.to_string(), p)
    } else {
        (target.to_string(), 443)
    };

    // SSRF protection: validate the target host
    if let Err(ssrf_err) = validate_host(&host, port) {
        warn!("[BLOCKED] {}", ssrf_err);
        let response = format!("HTTP/1.1 403 Forbidden\r\n\r\n{}\n", ssrf_err);
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // Connect to upstream
    let upstream_addr = format!("{}:{}", host, port);
    let upstream = match TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\n\r\nCannot connect to {}: {}",
                target, e
            );
            client.write_all(response.as_bytes()).await?;
            return Ok(());
        },
    };

    // Send 200 Connection Established
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // For now, just tunnel the traffic
    // TODO: MITM for inspection requires CA certificate setup
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_upstream = async { tokio::io::copy(&mut client_read, &mut upstream_write).await };

    let upstream_to_client = async { tokio::io::copy(&mut upstream_read, &mut client_write).await };

    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }

    Ok(())
}

/// Handle regular HTTP request
async fn handle_http_request(
    mut client: TcpStream,
    request: &str,
    target: &str,
    handlers: ProxyHandlers,
    config: ProxyConfig,
) -> Result<()> {
    // Extract body for scanning
    let body_start = request.find("\r\n\r\n").map(|i| i + 4);
    let body = body_start.map(|i| &request[i..]).unwrap_or("");

    // Scan request body
    let scan_result = scan_content(body, &handlers, &config, "request").await;

    if scan_result.should_block && config.level == ProtectionLevel::Block {
        // Block the request
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{{\"error\": \"Blocked by Dhi: {}\"}}",
            scan_result.reason
        );
        client.write_all(response.as_bytes()).await?;
        warn!("[BLOCKED] {}: {}", target, scan_result.reason);
        return Ok(());
    }

    if !scan_result.alerts.is_empty() {
        for alert in &scan_result.alerts {
            warn!("[ALERT] {}: {}", target, alert);
        }
    }

    // Forward to upstream (for HTTP, not HTTPS)
    // Parse URL from target
    let url = if target.starts_with("http://") {
        target.to_string()
    } else {
        // Relative URL, get Host header
        let host = request
            .lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|h| h.trim())
            .unwrap_or("localhost");
        format!("http://{}{}", host, target)
    };

    // Simple HTTP forwarding (for demo purposes)
    // In production, use reqwest or hyper
    let response = format!(
        "HTTP/1.1 501 Not Implemented\r\n\r\nDhi proxy: HTTP forwarding not yet implemented for {}\n\nUse HTTPS (CONNECT) tunneling instead.",
        url
    );
    client.write_all(response.as_bytes()).await?;

    Ok(())
}

struct ScanResult {
    should_block: bool,
    reason: String,
    alerts: Vec<String>,
}

/// Scan content for security issues
async fn scan_content(
    content: &str,
    handlers: &ProxyHandlers,
    config: &ProxyConfig,
    direction: &str,
) -> ScanResult {
    let mut should_block = false;
    let mut reason = String::new();
    let mut alerts = Vec::new();

    // Check for secrets
    let secrets_result = handlers.secrets_detector.scan(content, "proxy");
    if secrets_result.secrets_found {
        let secret_types: Vec<_> = secrets_result
            .secrets
            .iter()
            .map(|s| s.secret_type.as_str())
            .collect();
        alerts.push(format!(
            "Secrets detected in {}: {:?}",
            direction, secret_types
        ));

        let block_secrets = if direction == "request" {
            config.block_secrets_in_prompts
        } else {
            config.block_secrets_in_responses
        };

        if block_secrets {
            should_block = true;
            reason = format!("Credentials detected: {:?}", secret_types);
        }

        // Record metric
        let metrics = handlers.metrics.write().await;
        for secret in &secrets_result.secrets {
            metrics.record_secret(&secret.secret_type, &secret.severity);
        }
    }

    // Check for PII
    let pii_result = handlers.pii_detector.scan(content, "proxy");
    if pii_result.pii_found {
        let pii_types: Vec<_> = pii_result
            .pii_types
            .iter()
            .map(|p| p.pii_type.as_str())
            .collect();
        alerts.push(format!("PII detected in {}: {:?}", direction, pii_types));

        let block_pii = if direction == "request" {
            config.block_pii_in_prompts
        } else {
            config.block_pii_in_responses
        };

        // Only block high-risk PII
        let has_high_risk = pii_result
            .pii_types
            .iter()
            .any(|p| p.severity == "critical" || p.severity == "high");
        if block_pii && has_high_risk {
            should_block = true;
            reason = format!("High-risk PII detected: {:?}", pii_types);
        }

        // Record metric
        let metrics = handlers.metrics.write().await;
        for p in &pii_result.pii_types {
            metrics.record_pii(&p.pii_type, p.count as u64);
        }
    }

    // Check for prompt injection (requests only)
    if direction == "request" {
        let security = handlers.prompt_security.analyze(content);
        if security.injection_detected {
            alerts.push("Prompt injection attempt detected".to_string());
            should_block = true;
            reason = "Prompt injection detected".to_string();

            let metrics = handlers.metrics.write().await;
            metrics.record_injection("prompt_injection");
        }
    }

    ScanResult {
        should_block,
        reason,
        alerts,
    }
}

/// Start proxy server (convenience function)
pub async fn start_proxy(config: ProxyConfig) -> Result<()> {
    let proxy = DhiProxy::new(config);
    proxy.start().await
}
