//! Unit tests for Alerting System

#[cfg(test)]
mod tests {
    use super::*;

    fn alerter() -> AlertManager {
        AlertManager::new()
    }

    // ==================== Alert Creation ====================

    #[test]
    fn test_create_alert() {
        let a = alerter();
        
        let alert = a.create_alert(
            AlertSeverity::High,
            "credential_leak",
            "OpenAI API key detected in output",
        );
        
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.alert_type, "credential_leak");
        assert!(alert.message.contains("OpenAI"));
    }

    #[test]
    fn test_alert_with_metadata() {
        let a = alerter();
        
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("agent_id".to_string(), "agent-1".to_string());
        metadata.insert("tool".to_string(), "shell_execute".to_string());
        
        let alert = a.create_alert_with_metadata(
            AlertSeverity::Critical,
            "dangerous_tool",
            "Blocked rm -rf command",
            metadata,
        );
        
        assert_eq!(alert.metadata.get("agent_id"), Some(&"agent-1".to_string()));
    }

    // ==================== Severity Levels ====================

    #[test]
    fn test_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
    }

    #[test]
    fn test_severity_from_risk_score() {
        assert_eq!(AlertSeverity::from_risk_score(95), AlertSeverity::Critical);
        assert_eq!(AlertSeverity::from_risk_score(75), AlertSeverity::High);
        assert_eq!(AlertSeverity::from_risk_score(50), AlertSeverity::Medium);
        assert_eq!(AlertSeverity::from_risk_score(20), AlertSeverity::Low);
    }

    // ==================== Helper Methods ====================

    #[test]
    fn test_credential_alert() {
        let a = alerter();
        
        let alert = a.credential_alert("agent-1", "aws_access_key", "AKIA...");
        
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert!(alert.alert_type.contains("credential"));
    }

    #[test]
    fn test_pii_alert() {
        let a = alerter();
        
        let alert = a.pii_alert("agent-1", "ssn", "123-45-****");
        
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.alert_type.contains("pii"));
    }

    #[test]
    fn test_budget_alert() {
        let a = alerter();
        
        let alert = a.budget_alert("agent-1", 95.0, 100.0);
        
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.message.contains("95"));
    }

    #[test]
    fn test_injection_alert() {
        let a = alerter();
        
        let alert = a.injection_alert("agent-1", "ignore previous instructions");
        
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert!(alert.alert_type.contains("injection"));
    }

    #[test]
    fn test_tool_blocked_alert() {
        let a = alerter();
        
        let alert = a.tool_blocked_alert("agent-1", "shell_execute", "rm -rf /");
        
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    // ==================== Slack Integration ====================

    #[test]
    fn test_format_slack_message() {
        let a = alerter();
        
        let alert = a.create_alert(
            AlertSeverity::High,
            "test_alert",
            "Test message",
        );
        
        let slack_payload = a.format_slack_message(&alert);
        
        assert!(slack_payload.contains("attachments"));
        assert!(slack_payload.contains("Test message"));
    }

    #[test]
    fn test_slack_color_by_severity() {
        let a = alerter();
        
        let critical = a.create_alert(AlertSeverity::Critical, "t", "m");
        let high = a.create_alert(AlertSeverity::High, "t", "m");
        let medium = a.create_alert(AlertSeverity::Medium, "t", "m");
        let low = a.create_alert(AlertSeverity::Low, "t", "m");
        
        let critical_msg = a.format_slack_message(&critical);
        let high_msg = a.format_slack_message(&high);
        let medium_msg = a.format_slack_message(&medium);
        let low_msg = a.format_slack_message(&low);
        
        assert!(critical_msg.contains("#dc3545") || critical_msg.contains("danger"));
        assert!(high_msg.contains("#fd7e14") || high_msg.contains("warning"));
    }

    // ==================== Email Formatting ====================

    #[test]
    fn test_format_email() {
        let a = alerter();
        
        let alert = a.create_alert(
            AlertSeverity::High,
            "credential_leak",
            "API key detected",
        );
        
        let email = a.format_email(&alert);
        
        assert!(email.subject.contains("Dhi Alert"));
        assert!(email.body.contains("API key"));
    }

    // ==================== Webhook Formatting ====================

    #[test]
    fn test_format_webhook_json() {
        let a = alerter();
        
        let alert = a.create_alert(
            AlertSeverity::Medium,
            "pii_detected",
            "Email address found",
        );
        
        let json = a.format_webhook_json(&alert);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed["severity"], "medium");
        assert_eq!(parsed["type"], "pii_detected");
    }

    // ==================== Alert Queue ====================

    #[test]
    fn test_queue_alert() {
        let mut a = alerter();
        
        let alert = a.create_alert(AlertSeverity::High, "test", "Test");
        a.queue_alert(alert);
        
        assert_eq!(a.pending_alerts(), 1);
    }

    #[test]
    fn test_drain_alerts() {
        let mut a = alerter();
        
        a.queue_alert(a.create_alert(AlertSeverity::High, "t1", "m1"));
        a.queue_alert(a.create_alert(AlertSeverity::Low, "t2", "m2"));
        
        let alerts = a.drain_alerts();
        
        assert_eq!(alerts.len(), 2);
        assert_eq!(a.pending_alerts(), 0);
    }

    // ==================== Deduplication ====================

    #[test]
    fn test_dedupe_same_alert() {
        let mut a = alerter();
        a.enable_deduplication(true);
        
        let alert1 = a.create_alert(AlertSeverity::High, "test", "Same message");
        let alert2 = a.create_alert(AlertSeverity::High, "test", "Same message");
        
        a.queue_alert(alert1);
        a.queue_alert(alert2);
        
        // Should dedupe within time window
        assert!(a.pending_alerts() <= 1);
    }

    #[test]
    fn test_no_dedupe_different_alerts() {
        let mut a = alerter();
        a.enable_deduplication(true);
        
        let alert1 = a.create_alert(AlertSeverity::High, "type1", "Message 1");
        let alert2 = a.create_alert(AlertSeverity::High, "type2", "Message 2");
        
        a.queue_alert(alert1);
        a.queue_alert(alert2);
        
        assert_eq!(a.pending_alerts(), 2);
    }

    // ==================== Rate Limiting ====================

    #[test]
    fn test_rate_limiting() {
        let mut a = alerter();
        a.set_rate_limit(5, std::time::Duration::from_secs(60));
        
        for i in 0..10 {
            let alert = a.create_alert(AlertSeverity::Low, "flood", &format!("Alert {}", i));
            a.queue_alert(alert);
        }
        
        // Should only have 5 after rate limiting
        assert!(a.pending_alerts() <= 5);
    }

    // ==================== Filtering ====================

    #[test]
    fn test_filter_by_severity() {
        let mut a = alerter();
        a.set_minimum_severity(AlertSeverity::High);
        
        let low = a.create_alert(AlertSeverity::Low, "t", "m");
        let high = a.create_alert(AlertSeverity::High, "t", "m");
        
        a.queue_alert(low);
        a.queue_alert(high);
        
        // Only high severity should be queued
        assert_eq!(a.pending_alerts(), 1);
    }

    // ==================== Alert History ====================

    #[test]
    fn test_alert_history() {
        let mut a = alerter();
        a.enable_history(true);
        
        let alert = a.create_alert(AlertSeverity::High, "test", "Test");
        a.send_alert(alert).ok(); // May fail without webhook, that's ok
        
        let history = a.get_history(10);
        assert!(!history.is_empty());
    }

    // ==================== Statistics ====================

    #[test]
    fn test_alert_stats() {
        let mut a = alerter();
        
        a.queue_alert(a.create_alert(AlertSeverity::Critical, "t", "m"));
        a.queue_alert(a.create_alert(AlertSeverity::High, "t", "m"));
        a.queue_alert(a.create_alert(AlertSeverity::High, "t", "m"));
        a.queue_alert(a.create_alert(AlertSeverity::Low, "t", "m"));
        
        let stats = a.get_stats();
        
        assert_eq!(stats.by_severity.get(&AlertSeverity::Critical), Some(&1));
        assert_eq!(stats.by_severity.get(&AlertSeverity::High), Some(&2));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_message() {
        let a = alerter();
        
        let alert = a.create_alert(AlertSeverity::Low, "test", "");
        
        // Should handle empty message
        assert!(alert.message.is_empty() || alert.message == "No message provided");
    }

    #[test]
    fn test_very_long_message() {
        let a = alerter();
        
        let long_message = "x".repeat(10000);
        let alert = a.create_alert(AlertSeverity::Low, "test", &long_message);
        
        // Should truncate or handle gracefully
        let slack = a.format_slack_message(&alert);
        assert!(slack.len() < 50000); // Slack has limits
    }
}
