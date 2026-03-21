//! Alerting Module
//!
//! Send alerts via Slack, Email, webhooks, etc.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
}

/// Alerter - sends alerts to configured channels
pub struct Alerter {
    config: AlertConfig,
    client: reqwest::Client,
}

impl Alerter {
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
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
