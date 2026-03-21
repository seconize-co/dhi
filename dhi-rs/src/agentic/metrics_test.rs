//! Unit tests for Metrics System

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> DhiMetrics {
        DhiMetrics::new()
    }

    // ==================== Counter Metrics ====================

    #[test]
    fn test_increment_llm_calls() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.inc_llm_calls("agent-1", "anthropic", "claude-3");
        
        let total = m.get_llm_calls_total();
        assert_eq!(total, 3);
    }

    #[test]
    fn test_increment_tool_calls() {
        let mut m = metrics();
        
        m.inc_tool_calls("agent-1", "web_search");
        m.inc_tool_calls("agent-1", "calculator");
        
        let total = m.get_tool_calls_total();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_increment_alerts() {
        let mut m = metrics();
        
        m.inc_alerts("agent-1", "credential_leak");
        m.inc_alerts("agent-1", "pii_detected");
        m.inc_alerts("agent-2", "credential_leak");
        
        let total = m.get_alerts_total();
        assert_eq!(total, 3);
    }

    #[test]
    fn test_increment_blocked() {
        let mut m = metrics();
        
        m.inc_blocked("agent-1", "tool_denied");
        m.inc_blocked("agent-1", "budget_exceeded");
        
        let total = m.get_blocked_total();
        assert_eq!(total, 2);
    }

    // ==================== Gauge Metrics ====================

    #[test]
    fn test_set_active_agents() {
        let mut m = metrics();
        
        m.set_active_agents(5);
        assert_eq!(m.get_active_agents(), 5);
        
        m.set_active_agents(3);
        assert_eq!(m.get_active_agents(), 3);
    }

    #[test]
    fn test_budget_remaining() {
        let mut m = metrics();
        
        m.set_budget_remaining("agent-1", 75.50);
        
        let remaining = m.get_budget_remaining("agent-1");
        assert!((remaining - 75.50).abs() < 0.01);
    }

    // ==================== Histogram Metrics ====================

    #[test]
    fn test_record_latency() {
        let mut m = metrics();
        
        m.record_latency("agent-1", "openai", 150.0);
        m.record_latency("agent-1", "openai", 200.0);
        m.record_latency("agent-1", "openai", 100.0);
        
        let avg = m.get_avg_latency("agent-1", "openai");
        assert!((avg - 150.0).abs() < 1.0);
    }

    #[test]
    fn test_record_token_count() {
        let mut m = metrics();
        
        m.record_tokens("agent-1", "gpt-4", 500, 200);
        m.record_tokens("agent-1", "gpt-4", 1000, 400);
        
        let total_input = m.get_total_input_tokens("agent-1", "gpt-4");
        let total_output = m.get_total_output_tokens("agent-1", "gpt-4");
        
        assert_eq!(total_input, 1500);
        assert_eq!(total_output, 600);
    }

    // ==================== Cost Tracking ====================

    #[test]
    fn test_record_cost() {
        let mut m = metrics();
        
        m.record_cost("agent-1", "openai", 0.05);
        m.record_cost("agent-1", "openai", 0.03);
        m.record_cost("agent-1", "anthropic", 0.10);
        
        let total = m.get_total_cost("agent-1");
        assert!((total - 0.18).abs() < 0.001);
    }

    #[test]
    fn test_cost_by_provider() {
        let mut m = metrics();
        
        m.record_cost("agent-1", "openai", 0.10);
        m.record_cost("agent-1", "anthropic", 0.20);
        
        let openai_cost = m.get_cost_by_provider("agent-1", "openai");
        let anthropic_cost = m.get_cost_by_provider("agent-1", "anthropic");
        
        assert!((openai_cost - 0.10).abs() < 0.001);
        assert!((anthropic_cost - 0.20).abs() < 0.001);
    }

    // ==================== Prometheus Format ====================

    #[test]
    fn test_gather_prometheus_format() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.inc_tool_calls("agent-1", "search");
        m.record_cost("agent-1", "openai", 0.05);
        
        let output = m.gather();
        
        assert!(output.contains("dhi_llm_calls_total"));
        assert!(output.contains("dhi_tool_calls_total"));
        assert!(output.contains("dhi_cost_usd_total"));
    }

    #[test]
    fn test_prometheus_labels() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        
        let output = m.gather();
        
        assert!(output.contains("agent=\"agent-1\""));
        assert!(output.contains("provider=\"openai\""));
        assert!(output.contains("model=\"gpt-4\""));
    }

    #[test]
    fn test_prometheus_help_text() {
        let m = metrics();
        
        let output = m.gather();
        
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }

    // ==================== Label Handling ====================

    #[test]
    fn test_special_characters_in_labels() {
        let mut m = metrics();
        
        // Labels with special characters should be escaped
        m.inc_llm_calls("agent-with-dash", "provider.with.dots", "model/with/slashes");
        
        let output = m.gather();
        
        // Should be valid Prometheus format
        assert!(output.contains("agent="));
    }

    // ==================== Filtering ====================

    #[test]
    fn test_filter_by_agent() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.inc_llm_calls("agent-2", "openai", "gpt-4");
        
        let agent1_calls = m.get_llm_calls_for_agent("agent-1");
        assert_eq!(agent1_calls, 1);
    }

    #[test]
    fn test_filter_by_provider() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.inc_llm_calls("agent-1", "anthropic", "claude-3");
        m.inc_llm_calls("agent-1", "openai", "gpt-4o");
        
        let openai_calls = m.get_llm_calls_for_provider("openai");
        assert_eq!(openai_calls, 2);
    }

    // ==================== Time-based Metrics ====================

    #[test]
    fn test_calls_per_minute() {
        let mut m = metrics();
        
        for _ in 0..10 {
            m.inc_llm_calls("agent-1", "openai", "gpt-4");
        }
        
        let rate = m.get_llm_calls_per_minute();
        assert!(rate > 0.0);
    }

    // ==================== Reset ====================

    #[test]
    fn test_reset_metrics() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.inc_alerts("agent-1", "test");
        
        m.reset();
        
        assert_eq!(m.get_llm_calls_total(), 0);
        assert_eq!(m.get_alerts_total(), 0);
    }

    // ==================== Snapshot ====================

    #[test]
    fn test_snapshot() {
        let mut m = metrics();
        
        m.inc_llm_calls("agent-1", "openai", "gpt-4");
        m.record_cost("agent-1", "openai", 0.05);
        
        let snapshot = m.snapshot();
        
        assert_eq!(snapshot.llm_calls, 1);
        assert!((snapshot.total_cost - 0.05).abs() < 0.001);
    }

    // ==================== Security Metrics ====================

    #[test]
    fn test_secrets_detected_metric() {
        let mut m = metrics();
        
        m.inc_secrets_detected("agent-1", "openai_api_key");
        m.inc_secrets_detected("agent-1", "aws_access_key");
        
        let total = m.get_secrets_detected_total();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_pii_detected_metric() {
        let mut m = metrics();
        
        m.inc_pii_detected("agent-1", "email");
        m.inc_pii_detected("agent-1", "ssn");
        m.inc_pii_detected("agent-1", "credit_card");
        
        let total = m.get_pii_detected_total();
        assert_eq!(total, 3);
    }

    #[test]
    fn test_injection_attempts_metric() {
        let mut m = metrics();
        
        m.inc_injection_attempts("agent-1");
        m.inc_injection_attempts("agent-1");
        
        let total = m.get_injection_attempts_total();
        assert_eq!(total, 2);
    }

    // ==================== Efficiency Metrics ====================

    #[test]
    fn test_duplicate_prompts_metric() {
        let mut m = metrics();
        
        m.inc_duplicate_prompts("agent-1");
        
        let total = m.get_duplicate_prompts_total();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_loop_detected_metric() {
        let mut m = metrics();
        
        m.inc_loops_detected("agent-1");
        
        let total = m.get_loops_detected_total();
        assert_eq!(total, 1);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_gather() {
        let m = metrics();
        
        let output = m.gather();
        
        // Should still have valid format even with no data
        assert!(output.contains("# HELP") || output.is_empty());
    }

    #[test]
    fn test_concurrent_updates() {
        use std::sync::Arc;
        use std::thread;
        
        let m = Arc::new(std::sync::Mutex::new(metrics()));
        let mut handles = vec![];
        
        for i in 0..10 {
            let m_clone = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                let mut m = m_clone.lock().unwrap();
                m.inc_llm_calls(&format!("agent-{}", i), "openai", "gpt-4");
            }));
        }
        
        for h in handles {
            h.join().unwrap();
        }
        
        let m = m.lock().unwrap();
        assert_eq!(m.get_llm_calls_total(), 10);
    }
}
