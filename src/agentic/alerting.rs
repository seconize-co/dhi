//! Alerting Module
//!
//! Send alerts via Slack, Email, webhooks, etc.
//! Includes rate limiting to prevent alert flooding.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    global_limit: u32,
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
            global_limit: global_per_minute,
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
                alert.title,
                alert.agent_id
            );
            return Ok(());
        }

        let mut errors = Vec::new();

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
            }
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

        let response = self
            .client
            .post(webhook_url)
            .json(&message)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Slack API returned {}", response.status());
        }

        info!("Alert sent to Slack: {}", alert.title);
        Ok(())
    }

    /// Send alert to generic webhook
    async fn send_webhook(&self, webhook_url: &str, alert: &Alert) -> Result<()> {
        let response = self
            .client
            .post(webhook_url)
            .json(alert)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Webhook returned {}", response.status());
        }

        info!("Alert sent to webhook: {}", alert.title);
        Ok(())
    }

    /// Create and send a quick alert
    pub async fn alert(
        &self,
        severity: AlertSeverity,
        title: &str,
        message: &str,
    ) -> Result<()> {
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
        .with_event_type("budget_exceeded")
        .with_metadata("spent", serde_json::json!(spent))
        .with_metadata("limit", serde_json::json!(limit));

        self.send(&alert).await
    }

    /// Alert for prompt injection
    pub async fn alert_prompt_injection(
        &self,
        agent_id: &str,
        pattern: &str,
    ) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Critical,
            "Prompt Injection Attempt Detected",
            &format!(
                "Prompt injection attempt detected for agent {}: {}",
                agent_id, pattern
            ),
        )
        .with_agent(agent_id)
        .with_event_type("prompt_injection")
        .with_metadata("pattern", serde_json::json!(pattern));

        self.send(&alert).await
    }

    /// Alert for tool loop
    pub async fn alert_tool_loop(
        &self,
        agent_id: &str,
        tool_name: &str,
        count: u32,
    ) -> Result<()> {
        let alert = Alert::new(
            AlertSeverity::Warning,
            "Tool Call Loop Detected",
            &format!(
                "Agent {} called {} {} times with same parameters. Loop broken.",
                agent_id, tool_name, count
            ),
        )
        .with_agent(agent_id)
        .with_event_type("tool_loop")
        .with_metadata("tool_name", serde_json::json!(tool_name))
        .with_metadata("count", serde_json::json!(count));

        self.send(&alert).await
    }
}

impl Default for Alerter {
    fn default() -> Self {
        Self::new(AlertConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
