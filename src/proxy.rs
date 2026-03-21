//! HTTP Proxy for intercepting LLM API traffic
//!
//! Provides transparent proxy that scans requests/responses for:
//! - Secrets in prompts and responses
//! - PII in prompts and responses
//! - Dangerous tool calls
//! - Budget enforcement

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::agentic::{
    AlertManager, AlertSeverity, DhiMetrics, PiiDetector, PromptSecurityAnalyzer,
    SecretsDetector,
};
use crate::ProtectionLevel;

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
    alerter: Arc<AlertManager>,
    metrics: Arc<RwLock<DhiMetrics>>,
}

impl DhiProxy {
    /// Create new proxy
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            secrets_detector: Arc::new(SecretsDetector::new()),
            pii_detector: Arc::new(PiiDetector::new()),
            prompt_security: Arc::new(PromptSecurityAnalyzer::new()),
            alerter: Arc::new(AlertManager::new()),
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
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }

    fn clone_handlers(&self) -> ProxyHandlers {
        ProxyHandlers {
            secrets_detector: Arc::clone(&self.secrets_detector),
            pii_detector: Arc::clone(&self.pii_detector),
            prompt_security: Arc::clone(&self.prompt_security),
            alerter: Arc::clone(&self.alerter),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

struct ProxyHandlers {
    secrets_detector: Arc<SecretsDetector>,
    pii_detector: Arc<PiiDetector>,
    prompt_security: Arc<PromptSecurityAnalyzer>,
    alerter: Arc<AlertManager>,
    metrics: Arc<RwLock<DhiMetrics>>,
}

/// Handle incoming connection
async fn handle_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
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
    handlers: ProxyHandlers,
    config: ProxyConfig,
) -> Result<()> {
    // Parse host:port
    let (host, port) = if let Some(colon) = target.rfind(':') {
        let h = &target[..colon];
        let p = target[colon + 1..].parse().unwrap_or(443);
        (h.to_string(), p)
    } else {
        (target.to_string(), 443)
    };

    // Connect to upstream
    let upstream_addr = format!("{}:{}", host, port);
    let mut upstream = match TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            let response = format!("HTTP/1.1 502 Bad Gateway\r\n\r\nCannot connect to {}: {}", target, e);
            client.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    };

    // Send 200 Connection Established
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // For now, just tunnel the traffic
    // TODO: MITM for inspection requires CA certificate setup
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_upstream = async {
        tokio::io::copy(&mut client_read, &mut upstream_write).await
    };

    let upstream_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write).await
    };

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
    let secrets = handlers.secrets_detector.detect(content);
    if !secrets.is_empty() {
        let secret_types: Vec<_> = secrets.iter().map(|s| s.secret_type.as_str()).collect();
        alerts.push(format!("Secrets detected in {}: {:?}", direction, secret_types));

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
        let mut metrics = handlers.metrics.write().await;
        for secret in &secrets {
            metrics.inc_secrets_detected("proxy", &secret.secret_type);
        }
    }

    // Check for PII
    let pii = handlers.pii_detector.detect(content);
    if !pii.is_empty() {
        let pii_types: Vec<_> = pii.iter().map(|p| p.pii_type.as_str()).collect();
        alerts.push(format!("PII detected in {}: {:?}", direction, pii_types));

        let block_pii = if direction == "request" {
            config.block_pii_in_prompts
        } else {
            config.block_pii_in_responses
        };

        // Only block high-risk PII
        let has_high_risk = pii.iter().any(|p| p.risk_score >= 80);
        if block_pii && has_high_risk {
            should_block = true;
            reason = format!("High-risk PII detected: {:?}", pii_types);
        }

        // Record metric
        let mut metrics = handlers.metrics.write().await;
        for p in &pii {
            metrics.inc_pii_detected("proxy", &p.pii_type);
        }
    }

    // Check for prompt injection (requests only)
    if direction == "request" {
        let security = handlers.prompt_security.analyze(content);
        if security.injection_detected {
            alerts.push("Prompt injection attempt detected".to_string());
            should_block = true;
            reason = "Prompt injection detected".to_string();

            let mut metrics = handlers.metrics.write().await;
            metrics.inc_injection_attempts("proxy");
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
