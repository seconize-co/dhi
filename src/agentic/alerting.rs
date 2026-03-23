//! Alerting Module
//!
//! Send alerts via Slack, Email, webhooks, etc.
//! Includes rate limiting to prevent alert flooding.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::RwLock;
use tracing::{error, info, warn};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::Error => write!(f, "ERROR"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Alert message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub agent_id: Option<String>,
    pub event_type: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Alert {
    pub fn new(severity: AlertSeverity, title: &str, message: &str) -> Self {
        Self {
            severity,
            title: title.to_string(),
            message: message.to_string(),
            agent_id: None,
            event_type: "alert".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_agent(mut self, agent_id: &str) -> Self {
        self.agent_id = Some(agent_id.to_string());
        self
    }

    pub fn with_event_type(mut self, event_type: &str) -> Self {
        self.event_type = event_type.to_string();
        self
    }

    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    pub fn with_correlation_id(self, correlation_id: &str) -> Self {
        self.with_metadata("correlation_id", serde_json::json!(correlation_id))
    }

    pub fn with_session(self, session_id: &str, session_name: Option<&str>) -> Self {
        let mut alert = self.with_metadata("session_id", serde_json::json!(session_id));
        if let Some(name) = session_name {
            alert = alert.with_metadata("session_name", serde_json::json!(name));
        }
        alert
    }

    pub fn with_process(self, process_name: Option<&str>, pid: Option<u32>) -> Self {
        let mut alert = self;
        if let Some(name) = process_name {
            alert = alert.with_metadata("process_name", serde_json::json!(name));
        }
        if let Some(id) = pid {
            alert = alert.with_metadata("pid", serde_json::json!(id));
        }
        alert
    }

    pub fn with_destination(self, hostname: Option<&str>, path: Option<&str>) -> Self {
        let mut alert = self;
        if let Some(host) = hostname {
            alert = alert.with_metadata("destination", serde_json::json!(host));
        }
        if let Some(route) = path {
            alert = alert.with_metadata("path", serde_json::json!(route));
        }
        alert
    }

    pub fn with_action(self, action: &str) -> Self {
        self.with_metadata("action_taken", serde_json::json!(action))
    }

    pub fn with_risk_score(self, risk_score: u32) -> Self {
        self.with_metadata("risk_score", serde_json::json!(risk_score))
    }

    pub fn with_use_case_id(self, use_case_id: &str) -> Self {
        self.with_metadata("use_case_id", serde_json::json!(use_case_id))
    }
}

/// Slack message format
#[derive(Debug, Serialize)]
struct SlackMessage {
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_emoji: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<SlackAttachment>,
}

#[derive(Debug, Serialize)]
struct SlackAttachment {
    color: String,
    title: String,
    text: String,
    fields: Vec<SlackField>,
    ts: i64,
}

#[derive(Debug, Serialize)]
struct SlackField {
    title: String,
    value: String,
    short: bool,
}

/// Alerter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Slack webhook URL
    pub slack_webhook_url: Option<String>,
    /// Slack channel override
    pub slack_channel: Option<String>,
    /// Email recipients
    pub email_recipients: Vec<String>,
    /// SMTP server (for email)
    pub smtp_server: Option<String>,
    /// Generic webhook URLs
    pub webhook_urls: Vec<String>,
    /// Local append-only alert log file (JSONL)
    pub alert_log_path: Option<String>,
    /// Minimum severity to alert on
    pub min_severity: AlertSeverity,
    /// Enable/disable alerting
    pub enabled: bool,
    /// Rate limit: max alerts per minute
    pub rate_limit_per_minute: u32,
    /// Rate limit: max alerts per hour per agent
    pub rate_limit_per_hour_per_agent: u32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            slack_webhook_url: None,
            slack_channel: None,
            email_recipients: Vec::new(),
            smtp_server: None,
            webhook_urls: Vec::new(),
            alert_log_path: Some("/tmp/log/dhi/alerts.log".to_string()),
            min_severity: AlertSeverity::Warning,
            enabled: true,
            rate_limit_per_minute: 30,
            rate_limit_per_hour_per_agent: 100,
        }
    }
}

/// Rate limiter for alerts (token bucket algorithm)
struct RateLimiter {
    /// Global alerts per minute
    global_bucket: RwLock<TokenBucket>,
    /// Per-agent alerts per hour
    agent_buckets: RwLock<HashMap<String, TokenBucket>>,
    /// Configuration
    _global_limit: u32,
    agent_limit: u32,
}

struct TokenBucket {
    tokens: f64,
    last_update: i64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            last_update: chrono::Utc::now().timestamp(),
            max_tokens,
            refill_rate,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = chrono::Utc::now().timestamp();
        let elapsed = (now - self.last_update) as f64;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;

        // Try to consume
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    fn new(global_per_minute: u32, per_agent_per_hour: u32) -> Self {
        Self {
            global_bucket: RwLock::new(TokenBucket::new(
                global_per_minute as f64,
                global_per_minute as f64 / 60.0, // refill per second
            )),
            agent_buckets: RwLock::new(HashMap::new()),
            _global_limit: global_per_minute,
            agent_limit: per_agent_per_hour,
        }
    }

    fn check(&self, agent_id: Option<&str>) -> bool {
        // Check global limit
        {
            let mut global = match self.global_bucket.write() {
                Ok(g) => g,
                Err(_) => return false, // Poisoned lock, deny
            };
            if !global.try_consume() {
                return false;
            }
        }

        // Check per-agent limit if agent_id provided
        if let Some(agent) = agent_id {
            let mut buckets = match self.agent_buckets.write() {
                Ok(b) => b,
                Err(_) => return false,
            };

            let bucket = buckets.entry(agent.to_string()).or_insert_with(|| {
                TokenBucket::new(
                    self.agent_limit as f64,
                    self.agent_limit as f64 / 3600.0, // refill per second (hourly rate)
                )
            });

            if !bucket.try_consume() {
                return false;
            }
        }

        true
    }
}

/// Alerter - sends alerts to configured channels
pub struct Alerter {
    config: AlertConfig,
    client: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl Alerter {
    pub fn new(config: AlertConfig) -> Self {
        let rate_limiter = RateLimiter::new(
            config.rate_limit_per_minute,
            config.rate_limit_per_hour_per_agent,
        );
        Self {
            config,
            client: reqwest::Client::new(),
            rate_limiter,
        }
    }

    /// Send an alert to all configured channels
    pub async fn send(&self, alert: &Alert) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check severity threshold
        if !self.meets_severity_threshold(alert.severity) {
            return Ok(());
        }

        // Check rate limit
        if !self.rate_limiter.check(alert.agent_id.as_deref()) {
            warn!(
                "Alert rate limited: {} (agent: {:?})",
                alert.title, alert.agent_id
            );
            return Ok(());
        }

        let mut errors = Vec::new();

        if let Err(e) = self.persist_alert(alert) {
            errors.push(format!("LocalLog: {}", e));
        }

        // Send to Slack
        if let Some(ref webhook_url) = self.config.slack_webhook_url {
            if let Err(e) = self.send_slack(webhook_url, alert).await {
                errors.push(format!("Slack: {}", e));
            }
        }

        // Send to generic webhooks
        for webhook_url in &self.config.webhook_urls {
            if let Err(e) = self.send_webhook(webhook_url, alert).await {
                errors.push(format!("Webhook: {}", e));
            }
        }

        // Log errors but don't fail
        for err in &errors {
            error!("Alert delivery failed: {}", err);
        }

        Ok(())
    }

    fn persist_alert(&self, alert: &Alert) -> Result<()> {
        let Some(path) = self.config.alert_log_path.as_deref() else {
            return Ok(());
        };

        let file_path = Path::new(path);
        if let Some(parent) = file_path.parent() {
            create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;
        let line = serde_json::to_string(alert)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Check if severity meets threshold
    fn meets_severity_threshold(&self, severity: AlertSeverity) -> bool {
        match self.config.min_severity {
            AlertSeverity::Info => true,
            AlertSeverity::Warning => matches!(
                severity,
                AlertSeverity::Warning | AlertSeverity::Error | AlertSeverity::Critical
            ),
            AlertSeverity::Error => {
                matches!(severity, AlertSeverity::Error | AlertSeverity::Critical)
            },
            AlertSeverity::Critical => matches!(severity, AlertSeverity::Critical),
        }
    }

    /// Send alert to Slack
    async fn send_slack(&self, webhook_url: &str, alert: &Alert) -> Result<()> {
        let color = match alert.severity {
            AlertSeverity::Info => "#36a64f",
            AlertSeverity::Warning => "#ffcc00",
            AlertSeverity::Error => "#ff6600",
            AlertSeverity::Critical => "#ff0000",
        };

        let emoji = match alert.severity {
            AlertSeverity::Info => "ℹ️",
            AlertSeverity::Warning => "⚠️",
            AlertSeverity::Error => "🚨",
            AlertSeverity::Critical => "🔴",
        };

        let mut fields = vec![
            SlackField {
                title: "Severity".to_string(),
                value: alert.severity.to_string(),
                short: true,
            },
            SlackField {
                title: "Event Type".to_string(),
                value: alert.event_type.clone(),
                short: true,
            },
        ];

        if let Some(ref agent_id) = alert.agent_id {
            fields.push(SlackField {
                title: "Agent".to_string(),
                value: agent_id.clone(),
                short: true,
            });
        }

        // Add metadata fields
        for (key, value) in &alert.metadata {
            fields.push(SlackField {
                title: key.clone(),
                value: value.to_string(),
                short: true,
            });
        }

        let message = SlackMessage {
            text: format!("{} *Dhi Alert*: {}", emoji, alert.title),
            channel: self.config.slack_channel.clone(),
            username: Some("Dhi Runtime".to_string()),
            icon_emoji: Some(":shield:".to_string()),
            attachments: vec![SlackAttachment {
                color: color.to_string(),
                title: alert.title.clone(),
                text: alert.message.clone(),
                fields,
                ts: alert.timestamp,
            }],
        };

        let response = self.client.post(webhook_url).json(&message).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Slack API returned {}", response.status());
        }

        info!("Alert sent to Slack: {}", alert.title);
        Ok(())
    }

    /// Send alert to generic webhook
    async fn send_webhook(&self, webhook_url: &str, alert: &Alert) -> Result<()> {
        let response = self.client.post(webhook_url).json(alert).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Webhook returned {}", response.status());
        }

        info!("Alert sent to webhook: {}", alert.title);
        Ok(())
    }

    /// Create and send a quick alert
    pub async fn alert(&self, severity: AlertSeverity, title: &str, message: &str) -> Result<()> {
        let alert = Alert::new(severity, title, message);
        self.send(&alert).await
    }

    /// Alert for credential detection
    pub async fn alert_credential_detected(
        &self,
        agent_id: &str,
        credential_type: &str,
        location: &str,
    ) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Critical,
            "Credential Detected in Agent Communication",
            &format!(
                "A {} was detected in {} for agent {}. The request was blocked.",
                credential_type, location, agent_id
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id("sze.dhi.secrets.uc01.detect")
        .with_event_type("credential_detected")
        .with_metadata("credential_type", serde_json::json!(credential_type))
        .with_metadata("location", serde_json::json!(location));

        self.send(&alert).await
    }

    /// Alert for PII detection
    pub async fn alert_pii_detected(
        &self,
        agent_id: &str,
        pii_types: &[String],
        count: usize,
    ) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Warning,
            "PII Detected in Agent Communication",
            &format!(
                "PII detected for agent {}: {} instances of {:?}",
                agent_id, count, pii_types
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id("sze.dhi.pii.uc01.detect")
        .with_event_type("pii_detected")
        .with_metadata("pii_types", serde_json::json!(pii_types))
        .with_metadata("count", serde_json::json!(count));

        self.send(&alert).await
    }

    /// Alert for budget exceeded
    pub async fn alert_budget_exceeded(
        &self,
        agent_id: &str,
        spent: f64,
        limit: f64,
    ) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Error,
            "Budget Limit Exceeded",
            &format!(
                "Agent {} has exceeded budget: ${:.2} spent, ${:.2} limit",
                agent_id, spent, limit
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id("sze.dhi.budget.uc02.block")
        .with_event_type("budget_exceeded")
        .with_metadata("spent", serde_json::json!(spent))
        .with_metadata("limit", serde_json::json!(limit));

        self.send(&alert).await
    }

    /// Alert for budget warning threshold
    pub async fn alert_budget_warning(
        &self,
        agent_id: &str,
        spent: f64,
        limit: f64,
        percent_used: f64,
    ) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Warning,
            "Budget Warning Threshold Reached",
            &format!(
                "Agent {} has reached budget warning: ${:.2}/${:.2} ({:.1}%)",
                agent_id, spent, limit, percent_used
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id("sze.dhi.budget.uc01.detect")
        .with_event_type("budget_warning")
        .with_metadata("spent", serde_json::json!(spent))
        .with_metadata("limit", serde_json::json!(limit))
        .with_metadata("percent_used", serde_json::json!(percent_used));

        self.send(&alert).await
    }

    /// Alert for prompt injection
    pub async fn alert_prompt_injection(&self, agent_id: &str, pattern: &str) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Critical,
            "Prompt Injection Attempt Detected",
            &format!(
                "Prompt injection attempt detected for agent {}: {}",
                agent_id, pattern
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id("sze.dhi.prompt.uc01.detect")
        .with_event_type("prompt_injection")
        .with_metadata("pattern", serde_json::json!(pattern));

        self.send(&alert).await
    }

    /// Alert for tool loop
    pub async fn alert_tool_loop(&self, agent_id: &str, tool_name: &str, count: u32) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Warning,
            "Tool Call Loop Detected",
            &format!(
                "Agent {} called {} {} times with same parameters. Loop broken.",
                agent_id, tool_name, count
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id("sze.dhi.tools.uc01.detect")
        .with_event_type("tool_loop")
        .with_metadata("tool_name", serde_json::json!(tool_name))
        .with_metadata("count", serde_json::json!(count));

        self.send(&alert).await
    }

    /// Alert for high-risk tool invocation
    pub async fn alert_tool_risk(
        &self,
        agent_id: &str,
        tool_name: &str,
        risk_level: &str,
        risk_score: u32,
        action: &str,
    ) -> Result<()> {
        let severity = if risk_score >= 80 {
            AlertSeverity::Error
        } else {
            AlertSeverity::Warning
        };
        let alert = Alert::new(
            severity,
            "High-Risk Tool Invocation",
            &format!(
                "Agent {} invoked tool '{}' with {} risk (score: {}).",
                agent_id, tool_name, risk_level, risk_score
            ),
        )
        .with_agent(agent_id)
        .with_use_case_id(if action == "BLOCKED" {
            "sze.dhi.tools.uc02.block"
        } else {
            "sze.dhi.tools.uc01.detect"
        })
        .with_event_type("tool_risk")
        .with_metadata("tool_name", serde_json::json!(tool_name))
        .with_metadata("risk_level", serde_json::json!(risk_level))
        .with_metadata("risk_score", serde_json::json!(risk_score))
        .with_action(action);

        self.send(&alert).await
    }
}

impl Default for Alerter {
    fn default() -> Self {
        Self::new(AlertConfig::default())
    }
}

/// Result of a Slack webhook validation attempt.
#[derive(Debug, PartialEq)]
pub enum SlackWebhookValidation {
    /// URL format is valid and the live test POST returned HTTP 200.
    Ok,
    /// URL format is invalid (not a hooks.slack.com URL).
    InvalidFormat,
    /// Live test POST was rejected by Slack (status code + message supplied).
    LiveTestFailed(u16, String),
    /// Network or transport error during the live test.
    NetworkError(String),
}

/// Validate a Slack webhook URL: check the format then send a test POST.
///
/// Logs an `info!` on success and `warn!` on any failure so every outcome
/// is captured in the Dhi log file without blocking startup.
pub async fn validate_slack_webhook(url: &str) -> SlackWebhookValidation {
    // --- Format check -----------------------------------------------------------
    if !url.starts_with("https://hooks.slack.com/") {
        warn!(
            slack_webhook_url = url,
            "Slack webhook URL has unexpected format (expected https://hooks.slack.com/...); \
             alerts may not be delivered"
        );
        return SlackWebhookValidation::InvalidFormat;
    }

    // --- Live connectivity test -------------------------------------------------
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(
                error = %e,
                "Could not build HTTP client for Slack webhook test; skipping live check"
            );
            return SlackWebhookValidation::NetworkError(e.to_string());
        },
    };

    let payload = serde_json::json!({
        "text": "Dhi startup test - Slack webhook connectivity verified."
    });

    let response = match client.post(url).json(&payload).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                error = %e,
                "Slack webhook live test failed (network error); alerts may not be delivered"
            );
            return SlackWebhookValidation::NetworkError(e.to_string());
        },
    };

    let status = response.status().as_u16();
    match status {
        200 => {
            info!(
                slack_webhook_url = url,
                "Slack webhook validated (HTTP 200); alerts are enabled"
            );
            SlackWebhookValidation::Ok
        },
        400 => {
            let reason = "invalid payload or channel not found";
            warn!(
                slack_webhook_url = url,
                http_status = status,
                reason,
                "Slack webhook test failed (HTTP 400); check webhook configuration"
            );
            SlackWebhookValidation::LiveTestFailed(status, reason.to_string())
        },
        403 => {
            let reason = "webhook URL is invalid or revoked";
            warn!(
                slack_webhook_url = url,
                http_status = status,
                reason,
                "Slack webhook test failed (HTTP 403); re-create the webhook in Slack"
            );
            SlackWebhookValidation::LiveTestFailed(status, reason.to_string())
        },
        404 => {
            let reason = "webhook not found";
            warn!(
                slack_webhook_url = url,
                http_status = status,
                reason,
                "Slack webhook test failed (HTTP 404); webhook may have been deleted"
            );
            SlackWebhookValidation::LiveTestFailed(status, reason.to_string())
        },
        other => {
            let reason = format!("unexpected HTTP {other}");
            warn!(
                slack_webhook_url = url,
                http_status = other,
                "Slack webhook test returned unexpected status; alerts may not be delivered"
            );
            SlackWebhookValidation::LiveTestFailed(other, reason)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_severity_threshold() {
        let alerter = Alerter::new(AlertConfig {
            min_severity: AlertSeverity::Warning,
            ..Default::default()
        });

        assert!(!alerter.meets_severity_threshold(AlertSeverity::Info));
        assert!(alerter.meets_severity_threshold(AlertSeverity::Warning));
        assert!(alerter.meets_severity_threshold(AlertSeverity::Error));
        assert!(alerter.meets_severity_threshold(AlertSeverity::Critical));
    }

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(AlertSeverity::Critical, "Test", "Test message")
            .with_agent("agent-1")
            .with_event_type("test_event")
            .with_metadata("key", serde_json::json!("value"));

        assert_eq!(alert.title, "Test");
        assert_eq!(alert.agent_id, Some("agent-1".to_string()));
        assert!(alert.metadata.contains_key("key"));
    }

    #[test]
    fn test_use_case_id_builder() {
        let alert = Alert::new(AlertSeverity::Warning, "UC", "Use case test")
            .with_use_case_id("sze.dhi.test.uc01.detect");
        assert_eq!(
            alert.metadata.get("use_case_id").and_then(|v| v.as_str()),
            Some("sze.dhi.test.uc01.detect")
        );
    }

    #[tokio::test]
    async fn test_send_persists_alert_to_configured_log_file() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let log_path = format!(
            "/tmp/dhi-alerting-test-{}-{}.jsonl",
            std::process::id(),
            nanos
        );
        let alerter = Alerter::new(AlertConfig {
            alert_log_path: Some(log_path.clone()),
            ..Default::default()
        });

        let alert = Alert::new(AlertSeverity::Error, "Persisted", "Persist me")
            .with_event_type("persist_test")
            .with_use_case_id("sze.dhi.alerts.uc01.dispatch");
        alerter.send(&alert).await.expect("send should succeed");

        let content = fs::read_to_string(&log_path).expect("alert log file should exist");
        assert!(content.contains("\"title\":\"Persisted\""));
        assert!(content.contains("\"use_case_id\":\"sze.dhi.alerts.uc01.dispatch\""));

        let _ = fs::remove_file(&log_path);
    }
}
