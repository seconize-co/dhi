//! Unit tests for LLM Monitor

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> LlmMonitor {
        LlmMonitor::new()
    }

    // ==================== Cost Estimation ====================

    #[test]
    fn test_cost_gpt4() {
        let m = monitor();
        let cost = m.estimate_cost("gpt-4", 1000, 500);
        // GPT-4: $0.03/1K input, $0.06/1K output
        let expected = (1000.0 * 0.03 / 1000.0) + (500.0 * 0.06 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_cost_gpt4o() {
        let m = monitor();
        let cost = m.estimate_cost("gpt-4o", 1000, 500);
        // GPT-4o: $0.005/1K input, $0.015/1K output
        let expected = (1000.0 * 0.005 / 1000.0) + (500.0 * 0.015 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_cost_gpt35_turbo() {
        let m = monitor();
        let cost = m.estimate_cost("gpt-3.5-turbo", 1000, 500);
        // GPT-3.5: $0.0005/1K input, $0.0015/1K output
        let expected = (1000.0 * 0.0005 / 1000.0) + (500.0 * 0.0015 / 1000.0);
        assert!((cost - expected).abs() < 0.0001);
    }

    #[test]
    fn test_cost_claude_opus() {
        let m = monitor();
        let cost = m.estimate_cost("claude-3-opus", 1000, 500);
        // Claude Opus: $0.015/1K input, $0.075/1K output
        let expected = (1000.0 * 0.015 / 1000.0) + (500.0 * 0.075 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_cost_claude_sonnet() {
        let m = monitor();
        let cost = m.estimate_cost("claude-3-sonnet", 1000, 500);
        // Claude Sonnet: $0.003/1K input, $0.015/1K output
        let expected = (1000.0 * 0.003 / 1000.0) + (500.0 * 0.015 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_cost_unknown_model() {
        let m = monitor();
        let cost = m.estimate_cost("unknown-model-xyz", 1000, 500);
        // Should use default pricing
        assert!(cost > 0.0);
    }

    #[test]
    fn test_cost_zero_tokens() {
        let m = monitor();
        let cost = m.estimate_cost("gpt-4", 0, 0);
        assert_eq!(cost, 0.0);
    }

    // ==================== Call Tracking ====================

    #[test]
    fn test_track_call() {
        let m = monitor();
        
        let result = m.track_call(
            "agent-1",
            "openai",
            "gpt-4",
            500,
            200,
            Some("Hello"),
            true,
        );
        
        assert_eq!(result.input_tokens, 500);
        assert_eq!(result.output_tokens, 200);
        assert!(result.cost_usd > 0.0);
    }

    #[test]
    fn test_track_multiple_calls() {
        let m = monitor();
        
        m.track_call("agent-1", "openai", "gpt-4", 100, 50, None, true);
        m.track_call("agent-1", "openai", "gpt-4", 200, 100, None, true);
        m.track_call("agent-1", "openai", "gpt-4", 300, 150, None, true);
        
        let stats = m.get_agent_stats("agent-1");
        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.total_input_tokens, 600);
        assert_eq!(stats.total_output_tokens, 300);
    }

    // ==================== Provider Statistics ====================

    #[test]
    fn test_stats_by_provider() {
        let m = monitor();
        
        m.track_call("agent-1", "openai", "gpt-4", 100, 50, None, true);
        m.track_call("agent-1", "anthropic", "claude-3-opus", 200, 100, None, true);
        m.track_call("agent-1", "openai", "gpt-4o", 150, 75, None, true);
        
        let stats = m.get_stats_by_provider("agent-1");
        assert_eq!(stats.get("openai").map(|s| s.calls), Some(2));
        assert_eq!(stats.get("anthropic").map(|s| s.calls), Some(1));
    }

    // ==================== Model Statistics ====================

    #[test]
    fn test_stats_by_model() {
        let m = monitor();
        
        m.track_call("agent-1", "openai", "gpt-4", 100, 50, None, true);
        m.track_call("agent-1", "openai", "gpt-4", 200, 100, None, true);
        m.track_call("agent-1", "openai", "gpt-4o", 150, 75, None, true);
        
        let stats = m.get_stats_by_model("agent-1");
        assert_eq!(stats.get("gpt-4").map(|s| s.calls), Some(2));
        assert_eq!(stats.get("gpt-4o").map(|s| s.calls), Some(1));
    }

    // ==================== Token Limits ====================

    #[test]
    fn test_token_limit_exceeded() {
        let m = monitor();
        m.set_max_tokens_per_call(1000);
        
        let result = m.track_call("agent-1", "openai", "gpt-4", 800, 300, None, true);
        assert!(result.flags.contains(&"token_limit_exceeded".to_string()));
    }

    #[test]
    fn test_token_limit_ok() {
        let m = monitor();
        m.set_max_tokens_per_call(1000);
        
        let result = m.track_call("agent-1", "openai", "gpt-4", 400, 300, None, true);
        assert!(!result.flags.contains(&"token_limit_exceeded".to_string()));
    }

    // ==================== Streaming Calls ====================

    #[test]
    fn test_streaming_call() {
        let m = monitor();
        
        let result = m.track_call("agent-1", "openai", "gpt-4", 500, 200, None, true);
        assert!(result.streaming);
    }

    #[test]
    fn test_non_streaming_call() {
        let m = monitor();
        
        let result = m.track_call("agent-1", "openai", "gpt-4", 500, 200, None, false);
        assert!(!result.streaming);
    }

    // ==================== Prompt Analysis ====================

    #[test]
    fn test_prompt_with_sensitive_content() {
        let m = monitor();
        
        let result = m.track_call(
            "agent-1",
            "openai",
            "gpt-4",
            500,
            200,
            Some("My password is secret123"),
            true,
        );
        
        assert!(result.risk_score >= 50);
    }

    #[test]
    fn test_prompt_safe() {
        let m = monitor();
        
        let result = m.track_call(
            "agent-1",
            "openai",
            "gpt-4",
            500,
            200,
            Some("What is the weather like?"),
            true,
        );
        
        assert!(result.risk_score < 30);
    }

    // ==================== Tool Use ====================

    #[test]
    fn test_track_with_tools() {
        let m = monitor();
        
        let result = m.track_call_with_tools(
            "agent-1",
            "openai",
            "gpt-4",
            500,
            200,
            Some("Search for something"),
            true,
            vec!["web_search".to_string(), "calculator".to_string()],
        );
        
        assert_eq!(result.tools_used.len(), 2);
    }

    // ==================== Latency Tracking ====================

    #[test]
    fn test_latency_recording() {
        let m = monitor();
        
        let result = m.track_call_with_latency(
            "agent-1",
            "openai",
            "gpt-4",
            500,
            200,
            None,
            true,
            150, // 150ms latency
        );
        
        assert_eq!(result.latency_ms, Some(150));
    }

    // ==================== Cost Aggregation ====================

    #[test]
    fn test_total_cost() {
        let m = monitor();
        
        m.track_call("agent-1", "openai", "gpt-4", 1000, 500, None, true);
        m.track_call("agent-1", "openai", "gpt-4", 1000, 500, None, true);
        
        let stats = m.get_agent_stats("agent-1");
        // Each call: (1000 * 0.03 + 500 * 0.06) / 1000 = 0.03 + 0.03 = 0.06
        assert!((stats.total_cost_usd - 0.12).abs() < 0.001);
    }

    // ==================== Time-based Statistics ====================

    #[test]
    fn test_calls_per_minute() {
        let m = monitor();
        
        for _ in 0..10 {
            m.track_call("agent-1", "openai", "gpt-4", 100, 50, None, true);
        }
        
        let rate = m.get_calls_per_minute("agent-1");
        assert!(rate > 0.0);
    }

    // ==================== Alerts ====================

    #[test]
    fn test_high_cost_alert() {
        let m = monitor();
        m.set_cost_alert_threshold(0.10);
        
        // Large call that exceeds threshold
        let result = m.track_call("agent-1", "openai", "gpt-4", 5000, 2000, None, true);
        
        // Should have alert
        assert!(result.alerts.iter().any(|a| a.contains("cost")));
    }

    // ==================== Error Handling ====================

    #[test]
    fn test_empty_agent_id() {
        let m = monitor();
        let result = m.track_call("", "openai", "gpt-4", 100, 50, None, true);
        // Should handle gracefully
    }

    #[test]
    fn test_empty_model() {
        let m = monitor();
        let result = m.track_call("agent-1", "openai", "", 100, 50, None, true);
        // Should use default pricing
        assert!(result.cost_usd > 0.0);
    }
}
