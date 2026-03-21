//! Unit tests for Efficiency Analyzer

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer() -> EfficiencyAnalyzer {
        EfficiencyAnalyzer::new()
    }

    // ==================== Duplicate Prompt Detection ====================

    #[test]
    fn test_detect_exact_duplicate() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "What is the weather?");
        a.record_prompt("agent-1", "What is the weather?");
        
        let dupes = a.find_duplicates("agent-1");
        assert!(!dupes.is_empty(), "Should detect exact duplicate");
    }

    #[test]
    fn test_detect_similar_prompt() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "What is the weather today?");
        a.record_prompt("agent-1", "What is the weather right now?");
        
        let similar = a.find_similar("agent-1", 0.8);
        assert!(!similar.is_empty(), "Should detect similar prompts");
    }

    #[test]
    fn test_no_duplicate_different_prompts() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "What is the weather?");
        a.record_prompt("agent-1", "Calculate 2+2");
        
        let dupes = a.find_duplicates("agent-1");
        assert!(dupes.is_empty(), "Should not flag different prompts");
    }

    // ==================== Loop Detection ====================

    #[test]
    fn test_detect_tool_loop() {
        let a = analyzer();
        
        // Same tool called repeatedly
        for _ in 0..10 {
            a.record_tool_call("agent-1", "web_search", serde_json::json!({"q": "test"}));
        }
        
        let loops = a.detect_loops("agent-1");
        assert!(loops.tool_loops.len() > 0, "Should detect tool loop");
    }

    #[test]
    fn test_detect_llm_loop() {
        let a = analyzer();
        
        // Same prompt pattern repeated
        for i in 0..5 {
            a.record_llm_call("agent-1", "gpt-4", &format!("Retry attempt {}", i));
        }
        
        let loops = a.detect_loops("agent-1");
        // Should detect if prompts are similar
    }

    #[test]
    fn test_no_loop_varied_calls() {
        let a = analyzer();
        
        a.record_tool_call("agent-1", "search", serde_json::json!({"q": "weather"}));
        a.record_tool_call("agent-1", "calculator", serde_json::json!({"expr": "2+2"}));
        a.record_tool_call("agent-1", "file_read", serde_json::json!({"path": "/tmp"}));
        
        let loops = a.detect_loops("agent-1");
        assert!(loops.tool_loops.is_empty(), "Should not flag varied calls");
    }

    // ==================== Token Waste Detection ====================

    #[test]
    fn test_detect_token_waste_verbose() {
        let a = analyzer();
        
        // Very verbose prompt that could be shorter
        let verbose_prompt = "Please, if you would be so kind, I would really appreciate it if you could possibly help me by telling me what the weather might be like today, if that's not too much trouble for you.";
        
        a.record_llm_call("agent-1", "gpt-4", verbose_prompt);
        
        let waste = a.detect_token_waste("agent-1");
        assert!(waste.verbose_prompts > 0, "Should detect verbose prompt");
    }

    #[test]
    fn test_detect_token_waste_repeated_context() {
        let a = analyzer();
        
        // Same context sent multiple times
        let context = "You are a helpful assistant that answers questions about weather.";
        for _ in 0..5 {
            a.record_llm_call("agent-1", "gpt-4", &format!("{} What is today's weather?", context));
        }
        
        let waste = a.detect_token_waste("agent-1");
        assert!(waste.repeated_context > 0, "Should detect repeated context");
    }

    // ==================== Inefficiency Scoring ====================

    #[test]
    fn test_efficiency_score_optimal() {
        let a = analyzer();
        
        // Efficient usage: varied prompts, no loops
        a.record_prompt("agent-1", "What is 2+2?");
        a.record_tool_call("agent-1", "calculator", serde_json::json!({}));
        a.record_prompt("agent-1", "Weather forecast?");
        a.record_tool_call("agent-1", "weather_api", serde_json::json!({}));
        
        let score = a.calculate_efficiency_score("agent-1");
        assert!(score >= 80, "Efficient usage should have high score");
    }

    #[test]
    fn test_efficiency_score_poor() {
        let a = analyzer();
        
        // Inefficient: lots of duplicates and loops
        for _ in 0..20 {
            a.record_prompt("agent-1", "What is the weather?");
            a.record_tool_call("agent-1", "search", serde_json::json!({"q": "weather"}));
        }
        
        let score = a.calculate_efficiency_score("agent-1");
        assert!(score < 50, "Inefficient usage should have low score");
    }

    // ==================== Recommendations ====================

    #[test]
    fn test_recommendations_for_duplicates() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "What is the capital of France?");
        a.record_prompt("agent-1", "What is the capital of France?");
        a.record_prompt("agent-1", "What is the capital of France?");
        
        let recs = a.get_recommendations("agent-1");
        assert!(recs.iter().any(|r| r.contains("cache") || r.contains("duplicate")));
    }

    #[test]
    fn test_recommendations_for_loops() {
        let a = analyzer();
        
        for _ in 0..15 {
            a.record_tool_call("agent-1", "api_call", serde_json::json!({}));
        }
        
        let recs = a.get_recommendations("agent-1");
        assert!(recs.iter().any(|r| r.contains("loop") || r.contains("repeated")));
    }

    // ==================== Cost Optimization ====================

    #[test]
    fn test_suggest_cheaper_model() {
        let a = analyzer();
        
        // Simple queries using expensive model
        a.record_llm_call("agent-1", "gpt-4", "What is 2+2?");
        a.record_llm_call("agent-1", "gpt-4", "Hello");
        a.record_llm_call("agent-1", "gpt-4", "Thanks");
        
        let suggestions = a.suggest_cost_optimization("agent-1");
        assert!(suggestions.iter().any(|s| s.contains("gpt-3.5") || s.contains("cheaper")));
    }

    // ==================== Call Patterns ====================

    #[test]
    fn test_identify_patterns() {
        let a = analyzer();
        
        // Pattern: search -> parse -> summarize
        for _ in 0..5 {
            a.record_tool_call("agent-1", "search", serde_json::json!({}));
            a.record_tool_call("agent-1", "parse", serde_json::json!({}));
            a.record_tool_call("agent-1", "summarize", serde_json::json!({}));
        }
        
        let patterns = a.identify_patterns("agent-1");
        assert!(!patterns.is_empty(), "Should identify repeated pattern");
    }

    // ==================== Time Analysis ====================

    #[test]
    fn test_slow_tool_detection() {
        let a = analyzer();
        
        a.record_tool_call_with_duration("agent-1", "slow_api", serde_json::json!({}), 5000);
        a.record_tool_call_with_duration("agent-1", "fast_api", serde_json::json!({}), 100);
        
        let slow_tools = a.identify_slow_tools("agent-1");
        assert!(slow_tools.contains(&"slow_api".to_string()));
    }

    // ==================== Multi-Agent Analysis ====================

    #[test]
    fn test_cross_agent_duplicates() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "What is the weather?");
        a.record_prompt("agent-2", "What is the weather?");
        
        let cross_dupes = a.find_cross_agent_duplicates();
        assert!(!cross_dupes.is_empty(), "Should detect cross-agent duplicates");
    }

    // ==================== Statistics ====================

    #[test]
    fn test_efficiency_stats() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "Prompt 1");
        a.record_prompt("agent-1", "Prompt 2");
        a.record_prompt("agent-1", "Prompt 1"); // duplicate
        a.record_tool_call("agent-1", "tool1", serde_json::json!({}));
        a.record_tool_call("agent-1", "tool1", serde_json::json!({})); // duplicate
        
        let stats = a.get_stats("agent-1");
        
        assert_eq!(stats.total_prompts, 3);
        assert_eq!(stats.unique_prompts, 2);
        assert_eq!(stats.total_tool_calls, 2);
        assert!(stats.duplicate_rate > 0.0);
    }

    // ==================== Batching Suggestions ====================

    #[test]
    fn test_suggest_batching() {
        let a = analyzer();
        
        // Multiple separate API calls that could be batched
        a.record_tool_call("agent-1", "api_call", serde_json::json!({"id": 1}));
        a.record_tool_call("agent-1", "api_call", serde_json::json!({"id": 2}));
        a.record_tool_call("agent-1", "api_call", serde_json::json!({"id": 3}));
        
        let suggestions = a.suggest_batching("agent-1");
        assert!(!suggestions.is_empty(), "Should suggest batching");
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_agent() {
        let a = analyzer();
        
        let score = a.calculate_efficiency_score("unknown-agent");
        // Should handle gracefully, return 100 (optimal) or default
    }

    #[test]
    fn test_single_call() {
        let a = analyzer();
        
        a.record_prompt("agent-1", "Single prompt");
        
        let dupes = a.find_duplicates("agent-1");
        assert!(dupes.is_empty(), "Single call shouldn't be duplicate");
    }
}
