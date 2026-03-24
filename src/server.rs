//! HTTP Server for Dhi
//!
//! Provides metrics endpoint and API

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::agentic::{AgentFingerprinter, DhiMetrics};
use crate::RuntimeStats;

/// HTTP Server for Dhi metrics and API
pub struct HttpServer {
    pub addr: SocketAddr,
    pub metrics: Arc<tokio::sync::RwLock<DhiMetrics>>,
    pub runtime_stats: Arc<tokio::sync::RwLock<RuntimeStats>>,
    pub fingerprinter: Arc<AgentFingerprinter>,
}

impl HttpServer {
    /// Create a new HTTP server
    pub fn new(
        addr: SocketAddr,
        metrics: Arc<tokio::sync::RwLock<DhiMetrics>>,
        runtime_stats: Arc<tokio::sync::RwLock<RuntimeStats>>,
        fingerprinter: Arc<AgentFingerprinter>,
    ) -> Self {
        Self {
            addr,
            metrics,
            runtime_stats,
            fingerprinter,
        }
    }

    /// Start the HTTP server
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("HTTP server listening on {}", self.addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let metrics = Arc::clone(&self.metrics);
                    let runtime_stats = Arc::clone(&self.runtime_stats);
                    let fingerprinter = Arc::clone(&self.fingerprinter);
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(stream, metrics, runtime_stats, fingerprinter).await
                        {
                            error!("Connection error from {}: {}", addr, e);
                        }
                    });
                },
                Err(e) => {
                    error!("Accept error: {}", e);
                },
            }
        }
    }
}

/// Handle HTTP connection
async fn handle_connection(
    mut stream: TcpStream,
    metrics: Arc<tokio::sync::RwLock<DhiMetrics>>,
    runtime_stats: Arc<tokio::sync::RwLock<RuntimeStats>>,
    fingerprinter: Arc<AgentFingerprinter>,
) -> Result<()> {
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;

    let request = String::from_utf8_lossy(&buffer[..n]);
    let (status, content_type, body) =
        route_request(&request, &metrics, &runtime_stats, &fingerprinter).await;

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

/// Route request to handler
async fn route_request(
    request: &str,
    metrics: &Arc<tokio::sync::RwLock<DhiMetrics>>,
    runtime_stats: &Arc<tokio::sync::RwLock<RuntimeStats>>,
    fingerprinter: &Arc<AgentFingerprinter>,
) -> (&'static str, &'static str, String) {
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    match path {
        "/metrics" => {
            let m = metrics.read().await;
            ("200 OK", "text/plain; charset=utf-8", m.gather())
        },
        "/health" => (
            "200 OK",
            "application/json",
            r#"{"status":"healthy"}"#.to_string(),
        ),
        "/ready" => (
            "200 OK",
            "application/json",
            r#"{"status":"ready"}"#.to_string(),
        ),
        "/" => ("200 OK", "text/html", get_dashboard_html()),
        "/api/stats" => {
            let m = metrics.read().await;
            let stats = runtime_stats.read().await;
            let llm_calls = m
                .llm_calls_total
                .with_label_values(&["unknown", "unknown", "unknown"])
                .get();
            let tool_calls = m
                .tool_calls_total
                .with_label_values(&["unknown", "unknown", "unknown"])
                .get();
            let alerts = stats.total_alerts;
            let blocked = stats.total_blocks;
            let ssl_probe_targets_total = stats.ssl_probe_targets_total;
            let ssl_probe_targets_with_attached = stats.ssl_probe_targets_with_attached;
            let ssl_probe_attempts_total = stats.ssl_probe_attempts_total;
            let ssl_probe_attached_total = stats.ssl_probe_attached_total;
            let ssl_probe_failed_total = stats.ssl_probe_failed_total;
            let ssl_events = stats.ssl_events_total;
            let ssl_events_copilot = stats.ssl_events_copilot_total;
            let ssl_events_copilot_by_exe = stats.ssl_events_copilot_by_exe_total;
            let ssl_events_exe_resolve_failures = stats.ssl_events_exe_resolve_failures;
            let ssl_events_parse_errors = stats.ssl_events_parse_errors;
            (
                "200 OK",
                "application/json",
                format!(
                    r#"{{"llm_calls":{},"tool_calls":{},"alerts":{},"blocked":{},"ssl_probe_targets_total":{},"ssl_probe_targets_with_attached":{},"ssl_probe_attempts_total":{},"ssl_probe_attached_total":{},"ssl_probe_failed_total":{},"ssl_events":{},"ssl_events_copilot":{},"ssl_events_copilot_by_exe":{},"ssl_events_exe_resolve_failures":{},"ssl_events_parse_errors":{}}}"#,
                    llm_calls,
                    tool_calls,
                    alerts,
                    blocked,
                    ssl_probe_targets_total,
                    ssl_probe_targets_with_attached,
                    ssl_probe_attempts_total,
                    ssl_probe_attached_total,
                    ssl_probe_failed_total,
                    ssl_events,
                    ssl_events_copilot,
                    ssl_events_copilot_by_exe,
                    ssl_events_exe_resolve_failures,
                    ssl_events_parse_errors
                ),
            )
        },
        "/api/agents" => {
            let report = fingerprinter.generate_report();
            match serde_json::to_string(&report) {
                Ok(body) => ("200 OK", "application/json", body),
                Err(_) => (
                    "500 Internal Server Error",
                    "application/json",
                    r#"{"error":"failed to serialize agent report"}"#.to_string(),
                ),
            }
        },
        _ => (
            "404 Not Found",
            "application/json",
            r#"{"error":"not found"}"#.to_string(),
        ),
    }
}

/// Get dashboard HTML
fn get_dashboard_html() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Dhi - Agent Intelligence Platform</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #f59e0b; }
        .card { background: #1e293b; border-radius: 8px; padding: 20px; margin: 10px 0; }
        .metric { display: inline-block; padding: 10px 20px; margin: 5px; 
                  background: #334155; border-radius: 4px; }
        .metric .value { font-size: 24px; font-weight: bold; color: #22d3ee; }
        .metric .label { font-size: 12px; color: #94a3b8; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 4px; }
        .status.healthy { background: #22c55e; }
        .status.warning { background: #f59e0b; }
        .status.critical { background: #ef4444; }
        a { color: #60a5fa; }
        pre { background: #0f172a; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧠 Dhi - Agent Intelligence Platform</h1>
        <p><span class="status healthy">● Healthy</span> Runtime protection active</p>
        
        <div class="card">
            <h2>Real-time Metrics</h2>
            <div id="metrics">
                <div class="metric"><div class="value" id="llm-calls">-</div><div class="label">LLM Calls</div></div>
                <div class="metric"><div class="value" id="tool-calls">-</div><div class="label">Tool Calls</div></div>
                <div class="metric"><div class="value" id="alerts">-</div><div class="label">Alerts</div></div>
                <div class="metric"><div class="value" id="blocked">-</div><div class="label">Blocked</div></div>
            </div>
        </div>
        
        <div class="card">
            <h2>Endpoints</h2>
            <ul>
                <li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
                <li><a href="/health">/health</a> - Health check</li>
                <li><a href="/ready">/ready</a> - Readiness check</li>
                <li><a href="/api/stats">/api/stats</a> - JSON stats</li>
                <li><a href="/api/agents">/api/agents</a> - Fingerprints & sessions</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Quick Start</h2>
            <pre>
# Scrape metrics with Prometheus
curl http://localhost:9090/metrics

# Check health
curl http://localhost:9090/health
            </pre>
        </div>
    </div>
    
    <script>
        async function updateStats() {
            try {
                const resp = await fetch('/api/stats');
                const data = await resp.json();
                document.getElementById('llm-calls').textContent = data.llm_calls;
                document.getElementById('tool-calls').textContent = data.tool_calls;
                document.getElementById('alerts').textContent = data.alerts;
                document.getElementById('blocked').textContent = data.blocked;
            } catch (e) {}
        }
        updateStats();
        setInterval(updateStats, 5000);
    </script>
</body>
</html>"#.to_string()
}

/// Start metrics server
pub async fn start_metrics_server(
    addr: &str,
    metrics: Arc<tokio::sync::RwLock<DhiMetrics>>,
    runtime_stats: Arc<tokio::sync::RwLock<RuntimeStats>>,
    fingerprinter: Arc<AgentFingerprinter>,
) -> Result<()> {
    let addr: SocketAddr = addr.parse()?;
    let server = HttpServer::new(addr, metrics, runtime_stats, fingerprinter);
    server.start().await
}
