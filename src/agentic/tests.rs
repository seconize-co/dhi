//! Agentic runtime smoke tests.

#[cfg(test)]
mod smoke_tests {
    use crate::agentic::AgenticRuntime;

    #[tokio::test]
    async fn test_agent_lifecycle_smoke() {
        let runtime = AgenticRuntime::new();
        runtime.register_agent("test-agent", "test", None).await;

        let llm = runtime
            .track_llm_call(
                "test-agent",
                "openai",
                "gpt-4",
                100,
                50,
                Some("hello".to_string()),
                false,
                vec![],
            )
            .await;
        assert!(llm.total_tokens > 0);

        let stats = runtime.get_agent_stats("test-agent").await;
        assert!(stats.is_some());
    }

    #[tokio::test]
    async fn test_memory_verify_smoke() {
        let runtime = AgenticRuntime::new();
        runtime.register_agent("mem-agent", "test", None).await;
        runtime
            .protect_memory("mem-agent", "system_prompt", "You are helpful")
            .await;

        let verified = runtime
            .verify_memory("mem-agent", "system_prompt", "You are helpful")
            .await;
        assert!(verified.verified);
    }

    #[tokio::test]
    async fn test_budget_enforcement_alerts_and_events() {
        let runtime = AgenticRuntime::new();
        runtime.configure_max_budget_usd(0.0001);
        runtime.register_agent("budget-agent", "test", None).await;

        let result = runtime
            .track_llm_call(
                "budget-agent",
                "openai",
                "gpt-4",
                1000,
                1000,
                Some("hello".to_string()),
                false,
                vec![],
            )
            .await;

        assert!(
            result.alerts.iter().any(|a| a == "budget_exceeded"),
            "budget_exceeded alert should be present"
        );
        assert!(result.risk_score >= 50, "budget overage should raise risk");
    }

    #[tokio::test]
    async fn test_budget_warning_after_prior_spend() {
        let runtime = AgenticRuntime::new();
        runtime.configure_max_budget_usd(0.01);
        runtime.register_agent("warn-agent", "test", None).await;

        let first = runtime
            .track_llm_call("warn-agent", "openai", "gpt-4", 300, 0, None, false, vec![])
            .await;
        assert!(
            !first.alerts.iter().any(|a| a == "budget_warning"),
            "initial call should not warn"
        );

        let second = runtime
            .track_llm_call("warn-agent", "openai", "gpt-4", 1, 0, None, false, vec![])
            .await;
        assert!(
            second.alerts.iter().any(|a| a == "budget_warning"),
            "second call should emit budget warning"
        );
    }
}
